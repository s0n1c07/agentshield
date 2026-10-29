from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from engine.audit import SQLiteAuditTrail
from engine.budget import SQLiteSpendLedger
from engine.state_machine import (
    InvalidTransactionTransition,
    TransactionStateMachine,
)
from engine.telemetry import WebhookTelemetryStore
from engine.transaction_store import SQLiteTransactionStore
from models.audit import AuditEventType
from models.telemetry import (
    WebhookTelemetryEvent,
    WebhookTelemetryEventType,
)
from models.transaction import (
    TransactionRecord,
    TransactionState,
)
from models.webhook import (
    WebhookEvent,
    WebhookEventRecord,
    WebhookEventType,
    WebhookProcessingStatus,
)


class ReconciliationError(Exception):
    """
    Raised when a verified webhook cannot safely reconcile
    with the current AgentShield transaction.
    """


class WebhookEventStore:
    """
    Persistent SQLite-backed webhook deduplication store.

    A webhook event ID is processed at most once.

    This ledger is deliberately separate from payment execution
    idempotency because webhook delivery identity and execution
    identity represent different things.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=10.0,
        )

        connection.execute(
            "PRAGMA journal_mode=WAL;"
        )

        connection.execute(
            "PRAGMA foreign_keys=ON;"
        )

        return connection

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_event_ledger (
                    event_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    processed_at TEXT
                )
                """
            )

            connection.commit()

    def receive(self, event_id: str) -> bool:
        """
        Register a webhook for processing.

        Returns:
            True  -> event was newly received.
            False -> event already exists.
        """
        if not event_id.strip():
            raise ValueError("event_id cannot be empty")

        received_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO webhook_event_ledger (
                    event_id,
                    status,
                    received_at,
                    processed_at
                )
                VALUES (?, ?, ?, NULL)
                """,
                (
                    event_id,
                    WebhookProcessingStatus.RECEIVED.value,
                    received_at,
                ),
            )

            connection.commit()

            return cursor.rowcount == 1

    def get(
        self,
        event_id: str,
    ) -> WebhookEventRecord | None:
        if not event_id.strip():
            raise ValueError("event_id cannot be empty")

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    event_id,
                    status,
                    received_at,
                    processed_at
                FROM webhook_event_ledger
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

        if row is None:
            return None

        return WebhookEventRecord(
            event_id=row[0],
            status=WebhookProcessingStatus(row[1]),
            received_at=datetime.fromisoformat(row[2]),
            processed_at=(
                datetime.fromisoformat(row[3])
                if row[3] is not None
                else None
            ),
        )

    def mark_processed(self, event_id: str) -> bool:
        if not event_id.strip():
            raise ValueError("event_id cannot be empty")

        processed_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE webhook_event_ledger
                SET
                    status = ?,
                    processed_at = ?
                WHERE
                    event_id = ?
                    AND status = ?
                """,
                (
                    WebhookProcessingStatus.PROCESSED.value,
                    processed_at,
                    event_id,
                    WebhookProcessingStatus.RECEIVED.value,
                ),
            )

            connection.commit()

            return cursor.rowcount == 1

    def mark_rejected(self, event_id: str) -> bool:
        if not event_id.strip():
            raise ValueError("event_id cannot be empty")

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE webhook_event_ledger
                SET status = ?
                WHERE event_id = ?
            """,
                (
                    WebhookProcessingStatus.REJECTED.value,
                    event_id,
                ),
            )

            connection.commit()

            return cursor.rowcount == 1


class ReconciliationEngine:
    """
    Deterministic reconciliation engine.

    Responsibilities:
    - correlate verified webhook evidence with a transaction
    - deduplicate webhook events
    - resolve transaction state through the state machine
    """

    def __init__(
        self,
        webhook_store: WebhookEventStore,
        transaction_store: SQLiteTransactionStore | None = None,
        audit_trail: SQLiteAuditTrail | None = None,
        telemetry_store: WebhookTelemetryStore | None = None,
        state_machine: type[
            TransactionStateMachine
        ] = TransactionStateMachine,
        spend_ledger: SQLiteSpendLedger | None = None,
    ) -> None:
        self._webhook_store = webhook_store
        self._transaction_store = transaction_store
        self._audit_trail = audit_trail
        self._telemetry_store = telemetry_store
        self._state_machine = state_machine
        self._spend_ledger = spend_ledger

    def _telemetry(
        self,
        *,
        event_type: WebhookTelemetryEventType,
        event: WebhookEvent,
        transaction: TransactionRecord | None = None,
        details: dict | None = None,
    ) -> None:
        if self._telemetry_store is None:
            return

        self._telemetry_store.append(
            WebhookTelemetryEvent(
                telemetry_id=f"telemetry_{uuid4().hex}",
                event_type=event_type,
                webhook_event_id=event.event_id,
                transaction_id=(
                    transaction.transaction_id
                    if transaction is not None
                    else None
                ),
                payment_id=event.payment_id,
                order_id=event.order_id,
                details=details or {},
            )
        )

    def _audit(
        self,
        *,
        event_type,
        transaction: TransactionRecord,
        details: dict | None = None,
    ) -> None:
        if self._audit_trail is None:
            return

        self._audit_trail.append(
            event_type=event_type,
            transaction_id=transaction.transaction_id,
            intent_id=transaction.intent_id,
            user_id=transaction.user_id,
            agent_id=transaction.agent_id,
            state=transaction.state,
            intent_hash=transaction.intent_hash,
            details=details,
        )

    def reconcile_event(
        self,
        *,
        event: WebhookEvent,
    ) -> TransactionRecord:
        if self._transaction_store is None:
            raise ReconciliationError(
                "Transaction store is required for event reconciliation"
            )

        transaction = None
        if event.order_id is not None:
            transaction = self._transaction_store.get_by_order_id(
                event.order_id
            )

        if transaction is None:
            transaction = self._transaction_store.get_by_payment_id(
                event.payment_id
            )

        if transaction is None:
            self._telemetry(
                event_type=(
                    WebhookTelemetryEventType
                    .WEBHOOK_UNKNOWN_TRANSACTION
                ),
                event=event,
            )

            raise ReconciliationError(
                "No transaction found for webhook event"
            )

        self._telemetry(
            event_type=(
                WebhookTelemetryEventType
                .WEBHOOK_CORRELATED
            ),
            event=event,
            transaction=transaction,
        )

        return self.reconcile(
            transaction=transaction,
            event=event,
        )

    def reconcile(
        self,
        *,
        transaction: TransactionRecord,
        event: WebhookEvent,
    ) -> TransactionRecord:
        """
        Reconcile one verified webhook against one transaction.
        """

        # 1. Correlate webhook with transaction

        if event.order_id is not None:
            if transaction.razorpay_order_id is None:
                raise ReconciliationError(
                    "Transaction has no Razorpay order ID"
                )

            if event.order_id != transaction.razorpay_order_id:
                raise ReconciliationError(
                    "Webhook order does not match transaction"
                )

        if event.amount_paise != transaction.amount_paise:
            raise ReconciliationError(
                "Webhook amount does not match transaction"
            )

        if event.currency != transaction.currency:
            raise ReconciliationError(
                "Webhook currency does not match transaction"
            )

        if (
            transaction.razorpay_payment_id is not None
            and event.payment_id
            != transaction.razorpay_payment_id
        ):
            raise ReconciliationError(
                "Webhook payment does not match transaction"
            )

        # 2. Webhook deduplication

        existing = self._webhook_store.get(
            event.event_id
        )

        if existing is not None:
            if existing.status == WebhookProcessingStatus.PROCESSED:
                self._telemetry(
                    event_type=(
                        WebhookTelemetryEventType
                        .WEBHOOK_DUPLICATE
                    ),
                    event=event,
                    transaction=transaction,
                    details={
                        "status": existing.status.value,
                    },
                )

                return transaction

            if existing.status == WebhookProcessingStatus.REJECTED:
                self._telemetry(
                    event_type=(
                        WebhookTelemetryEventType
                        .WEBHOOK_DUPLICATE
                    ),
                    event=event,
                    transaction=transaction,
                    details={
                        "status": existing.status.value,
                    },
                )

                return transaction

            # RECEIVED means a previous attempt did not finish.
            # Allow processing to continue.
        else:
            self._webhook_store.receive(
                event.event_id
            )

        # 3. Establish reconciliation state

        current_state = transaction.state

        try:
            if current_state == TransactionState.DISPATCHED:
                current_state = self._state_machine.transition(
                    current_state,
                    TransactionState.UNKNOWN,
                )

            if current_state == TransactionState.UNKNOWN:
                current_state = self._state_machine.transition(
                    current_state,
                    TransactionState.RECONCILE_PENDING,
                )

        except InvalidTransactionTransition as exc:
            raise ReconciliationError(
                "Transaction cannot enter reconciliation: "
                f"{transaction.state.value}"
            ) from exc

        # 4. Resolve external payment result

        if (
            event.event_type
            == WebhookEventType.PAYMENT_CAPTURED
        ):
            try:
                next_state = self._state_machine.transition(
                    current_state,
                    TransactionState.SUCCESS,
                )
            except InvalidTransactionTransition as exc:
                raise ReconciliationError(
                    "Captured payment cannot be applied to transaction "
                    f"state {current_state.value}"
                ) from exc

        elif (
            event.event_type
            == WebhookEventType.PAYMENT_FAILED
        ):
            try:
                next_state = self._state_machine.transition(
                    current_state,
                    TransactionState.FAILED_SAFE_TO_RETRY,
                )
            except InvalidTransactionTransition as exc:
                raise ReconciliationError(
                    "Failed payment cannot be applied to transaction "
                    f"state {current_state.value}"
                ) from exc

        else:
            raise ReconciliationError(
                "Unsupported reconciliation event: "
                f"{event.event_type.value}"
            )

        # 5. Persist updated transaction

        updated_transaction = transaction.model_copy(
            update={
                "state": next_state,
                "razorpay_payment_id": event.payment_id,
                "updated_at": datetime.now(timezone.utc),
            }
        )

        if self._transaction_store is not None:
            if self._transaction_store.get(transaction.transaction_id) is None:
                self._transaction_store.create(transaction)
            self._transaction_store.update(updated_transaction)

        if self._spend_ledger is not None:
            if next_state == TransactionState.SUCCESS:
                self._spend_ledger.consume(transaction.transaction_id)
                self._audit(
                    event_type=AuditEventType.BUDGET_CONSUMED,
                    transaction=updated_transaction,
                )
            elif next_state == TransactionState.FAILED_SAFE_TO_RETRY:
                self._spend_ledger.release(transaction.transaction_id)
                self._audit(
                    event_type=AuditEventType.BUDGET_RELEASED,
                    transaction=updated_transaction,
                    details={"reason": "payment_failed_reconciliation"},
                )

        self._telemetry(
            event_type=(
                WebhookTelemetryEventType
                .PAYMENT_RECONCILED
            ),
            event=event,
            transaction=updated_transaction,
            details={
                "transaction_state": updated_transaction.state.value,
            },
        )

        self._audit(
            event_type=AuditEventType.WEBHOOK_RECEIVED,
            transaction=transaction,
            details={
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "payment_id": event.payment_id,
                "order_id": event.order_id,
                "amount_paise": event.amount_paise,
                "currency": event.currency,
            },
        )

        self._audit(
            event_type=AuditEventType.PAYMENT_RECONCILED,
            transaction=updated_transaction,
            details={
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "payment_id": event.payment_id,
                "amount_paise": event.amount_paise,
                "currency": event.currency,
            },
        )

        if not self._webhook_store.mark_processed(event.event_id):
            raise ReconciliationError(
                "Webhook event could not be marked processed"
            )

        return updated_transaction