from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from engine.audit import SQLiteAuditTrail
from engine.budget import SQLiteSpendLedger
from engine.catalog import SQLiteCatalog
from engine.hashing import IntentHasher
from engine.idempotency import WALIdempotencyStore
from engine.mandate import AP2AlignedMandateEngine
from engine.policy import DeterministicPolicyEngine
from engine.state_machine import (
    InvalidTransactionTransition,
    TransactionStateMachine,
)
from engine.transaction_store import SQLiteTransactionStore
from integrations.intent_parser import IntentParser
from integrations.razorpay import (
    RazorpayClient,
    RazorpayNetworkError,
)
from models.audit import AuditEventType
from models.authorization import AuthorizationEvaluation
from models.intent import AgentRequestAnalysis
from models.mandate import Mandate
from models.orchestration import OrchestrationResult
from models.policy import (
    PolicyDecision,
    TransactionPolicy,
)
from models.transaction import (
    TransactionRecord,
    TransactionState,
)


class OrchestrationError(Exception):
    """
    Raised when the AgentShield workflow cannot safely continue.
    """


class AgentShieldOrchestrator:
    """
    Application-level coordinator for AgentShield.

    The orchestrator controls the order in which the security
    and execution layers are applied.

    The LLM provider is treated only as an intent interpreter.
    Authorization, policy, mandate, idempotency and financial
    execution remain server-owned.

    Only a fully governed transaction can reach Razorpay.
    """

    def __init__(
        self,
        *,
        intent_parser: IntentParser | None = None,
        claude: IntentParser | None = None,
        authorization_check: Callable[
            [AgentRequestAnalysis],
            AuthorizationEvaluation,
        ],
        policy_engine: DeterministicPolicyEngine,
        intent_hasher: IntentHasher,
        mandate_engine: AP2AlignedMandateEngine,
        idempotency_store: WALIdempotencyStore,
        razorpay: RazorpayClient,
        policy_provider: Callable[
            [AgentRequestAnalysis],
            TransactionPolicy,
        ],
        audit_trail: SQLiteAuditTrail,
        transaction_store: SQLiteTransactionStore,
        state_machine: type[
            TransactionStateMachine
        ] = TransactionStateMachine,
        catalog: SQLiteCatalog,
        spend_ledger: SQLiteSpendLedger | None = None,
    ) -> None:
        # Provider-neutral dependency is authoritative.
        # "claude" remains as a temporary compatibility alias for
        # existing tests/integration callers during the migration.
        if intent_parser is None:
            intent_parser = claude

        if intent_parser is None:
            raise ValueError(
                "intent_parser must be provided"
            )

        self._intent_parser = intent_parser
        self._authorization_check = authorization_check
        self._policy_engine = policy_engine
        self._intent_hasher = intent_hasher
        self._mandate_engine = mandate_engine
        self._idempotency_store = idempotency_store
        self._razorpay = razorpay
        self._state_machine = state_machine
        self._policy_provider = policy_provider
        self._audit_trail = audit_trail
        self._transaction_store = transaction_store
        self._catalog = catalog
        self._spend_ledger = spend_ledger

    def _audit(
        self,
        *,
        event_type: AuditEventType,
        transaction: TransactionRecord,
        details: dict[str, Any] | None = None,
    ) -> None:
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

    async def execute(
        self,
        *,
        user_message: str,
        user_id: str,
        agent_id: str,
        intent_id: str,
        transaction_id: str,
        idempotency_key: str,
        merchant_context: dict[str, Any] | None = None,
    ) -> OrchestrationResult:
        """
        Execute one complete AgentShield governance flow.
        """

        # 0. Validate server-owned execution identifiers

        self._require_non_empty(
            user_id,
            "user_id",
        )

        self._require_non_empty(
            agent_id,
            "agent_id",
        )

        self._require_non_empty(
            intent_id,
            "intent_id",
        )

        self._require_non_empty(
            transaction_id,
            "transaction_id",
        )

        self._require_non_empty(
            idempotency_key,
            "idempotency_key",
        )

        # 1. Intent interpretation

        analysis = self._intent_parser.parse(
            user_message,
            user_id=user_id,
            agent_id=agent_id,
            intent_id=intent_id,
            merchant_context=merchant_context,
        )

        self._assert_identity_binding(
            analysis=analysis,
            user_id=user_id,
            agent_id=agent_id,
            intent_id=intent_id,
        )

        proposal = analysis.intent_proposal

        # 2. Create initial server-owned transaction

        existing_transaction = self._transaction_store.get(
            transaction_id
        )

        transaction = TransactionRecord(
            transaction_id=transaction_id,
            intent_id=intent_id,
            user_id=user_id,
            agent_id=agent_id,
            merchant_id=proposal.merchant_id,
            amount_paise=proposal.amount_paise,
            currency=proposal.currency,
            items=proposal.items,
            intent_hash="0" * 64,
            idempotency_key=idempotency_key,
            state=TransactionState.CREATED,
        )

        if existing_transaction is not None:
            self._assert_existing_transaction_matches(
                existing=existing_transaction,
                candidate=transaction,
            )
            transaction = existing_transaction

            if (
                existing_transaction.idempotency_key == idempotency_key
                and existing_transaction.state
                != TransactionState.CREATED
            ):
                self._audit(
                    event_type=AuditEventType.IDEMPOTENCY_REJECTED,
                    transaction=transaction,
                )
                raise OrchestrationError(
                    "Execution already claimed for idempotency key"
                )
        else:
            self._transaction_store.create(transaction)

        self._audit(
            event_type=AuditEventType.INTENT_RECEIVED,
            transaction=transaction,
        )

        # 3. CREATED → INTENT_VALIDATED

        transaction = self._transition(
            transaction,
            TransactionState.INTENT_VALIDATED,
        )
        self._transaction_store.update(transaction)

        self._audit(
            event_type=AuditEventType.INTENT_VALIDATED,
            transaction=transaction,
        )

        # 4. Authorization

        authorization_evaluation = self._authorization_check(
            analysis
        )

        if not isinstance(
            authorization_evaluation,
            AuthorizationEvaluation,
        ):
            raise OrchestrationError(
                "Authorization check returned invalid result"
            )

        authorization_result = authorization_evaluation.decision
        server_authorization = authorization_evaluation.authorization

        if not authorization_result.allowed:
            self._audit(
                event_type=AuditEventType.AUTHORIZATION_REJECTED,
                transaction=transaction,
                details={
                    "authorization_id": (
                        authorization_result.authorization_id
                    ),
                    "reason": authorization_result.reason,
                },
            )

            raise OrchestrationError(
                "authorization rejected: "
                f"{authorization_result.reason}"
            )

        self._audit(
            event_type=AuditEventType.AUTHORIZATION_APPROVED,
            transaction=transaction,
            details={
                "authorization_id": (
                    authorization_result.authorization_id
                ),
                "reason": authorization_result.reason,
            },
        )

        if server_authorization is None:
            raise OrchestrationError(
                "Authorization approved without "
                "server-owned authorization record"
            )

        transaction = transaction.model_copy(
            update={
                "authorization_snapshot": server_authorization,
                "updated_at": datetime.now(timezone.utc),
            }
        )

        self._transaction_store.update(transaction)

        # 5. Policy

        policy = self._policy_provider(analysis)

        policy_result: PolicyDecision = (
            self._policy_engine.evaluate(
                proposal,
                server_authorization,
                policy,
                catalog=self._catalog,
            )
        )

        if not policy_result.allowed:
            self._audit(
                event_type=AuditEventType.POLICY_REJECTED,
                transaction=transaction,
                details={
                    "reason": policy_result.reason,
                },
            )

            raise OrchestrationError(
                "Policy rejected transaction: "
                f"{policy_result.reason}"
            )

        transaction = self._transition(
            transaction,
            TransactionState.POLICY_APPROVED,
        )
        self._transaction_store.update(transaction)

        self._audit(
            event_type=AuditEventType.POLICY_APPROVED,
            transaction=transaction,
            details={
                "reason": policy_result.reason,
            },
        )

        # 6. Hash governed intent

        intent_hash = self._intent_hasher.hash(
            server_authorization,
            proposal,
        )

        transaction = transaction.model_copy(
            update={
                "intent_hash": intent_hash,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        self._transaction_store.update(transaction)

        # 7. Create and verify mandate

        mandate = self._mandate_engine.create(
            authorization=server_authorization,
            proposal=proposal,
        )

        self._audit(
            event_type=AuditEventType.MANDATE_CREATED,
            transaction=transaction,
            details={
                "expires_at": mandate.expires_at.isoformat(),
            },
        )

        mandate_valid = self._mandate_engine.verify(
            mandate=mandate,
            authorization=server_authorization,
            proposal=proposal,
        )

        if not mandate_valid:
            raise OrchestrationError(
                "Mandate verification failed"
            )

        transaction = self._transition(
            transaction,
            TransactionState.MANDATE_VALID,
        )
        self._transaction_store.update(transaction)

        self._audit(
            event_type=AuditEventType.MANDATE_VERIFIED,
            transaction=transaction,
        )

        # 7b. Revalidate authorization before external dispatch
        revalidation = self._authorization_check(analysis)
        if not revalidation.decision.allowed or revalidation.authorization is None:
            self._audit(
                event_type=AuditEventType.AUTHORIZATION_REJECTED,
                transaction=transaction,
                details={
                    "stage": "pre_dispatch_revalidation",
                    "reason": revalidation.decision.reason,
                },
            )
            raise OrchestrationError(
                f"Authorization revalidation failed before dispatch: {revalidation.decision.reason}"
            )

        # 7c. Atomic Cumulative Budget Reservation (Extension 1)
        if self._spend_ledger is not None:
            reserved, budget_reason = self._spend_ledger.reserve(
                transaction_id=transaction.transaction_id,
                authorization=server_authorization,
                amount_paise=transaction.amount_paise,
            )
            if not reserved:
                self._audit(
                    event_type=AuditEventType.BUDGET_REJECTED,
                    transaction=transaction,
                    details={"reason": budget_reason},
                )
                raise OrchestrationError(
                    f"Budget limit exceeded: {budget_reason}"
                )

            self._audit(
                event_type=AuditEventType.BUDGET_RESERVED,
                transaction=transaction,
                details={"amount_paise": transaction.amount_paise},
            )

        # 8. Idempotency / execution lock

        acquired = self._idempotency_store.acquire(
            idempotency_key=idempotency_key,
            transaction_id=transaction_id,
        )

        if not acquired:
            # Compensating release if budget reservation was acquired
            if self._spend_ledger is not None:
                self._spend_ledger.release(transaction_id)
                self._audit(
                    event_type=AuditEventType.BUDGET_RELEASED,
                    transaction=transaction,
                    details={"reason": "idempotency_acquisition_failed"},
                )

            self._audit(
                event_type=AuditEventType.IDEMPOTENCY_REJECTED,
                transaction=transaction,
            )

            raise OrchestrationError(
                "Execution already claimed for idempotency key"
            )

        self._audit(
            event_type=AuditEventType.IDEMPOTENCY_ACQUIRED,
            transaction=transaction,
        )

        transaction = self._transition(
            transaction,
            TransactionState.LOCK_ACQUIRED,
        )
        self._transaction_store.update(transaction)

        # 9. Dispatch to Razorpay

        try:
            order = await self._razorpay.create_order(
                amount_paise=transaction.amount_paise,
                currency=transaction.currency,
                receipt=transaction.transaction_id,
                notes={
                    "transaction_id": transaction.transaction_id,
                    "intent_id": transaction.intent_id,
                    "intent_hash": transaction.intent_hash,
                },
            )

        except Exception as exc:
            transaction = self._transition(
                transaction,
                TransactionState.DISPATCHED,
            )
            self._transaction_store.update(transaction)

            transaction = self._transition(
                transaction,
                TransactionState.UNKNOWN,
            )
            self._transaction_store.update(transaction)

            reason = (
                "network_error"
                if isinstance(exc, RazorpayNetworkError)
                else "external_execution_error"
            )

            self._audit(
                event_type=AuditEventType.RAZORPAY_UNKNOWN,
                transaction=transaction,
                details={
                    "reason": reason,
                    "error_type": type(exc).__name__,
                },
            )

            raise OrchestrationError(
                "Razorpay outcome is unknown after dispatch failure"
            ) from exc

        # 10. Verify Razorpay order response

        if order.amount_paise != transaction.amount_paise:
            if self._spend_ledger is not None:
                self._spend_ledger.release(transaction.transaction_id)
            raise OrchestrationError(
                "Razorpay order amount does not match "
                "the governed transaction"
            )

        if order.currency != transaction.currency:
            if self._spend_ledger is not None:
                self._spend_ledger.release(transaction.transaction_id)
            raise OrchestrationError(
                "Razorpay order currency does not match "
                "the governed transaction"
            )

        if order.status != "created":
            if self._spend_ledger is not None:
                self._spend_ledger.release(transaction.transaction_id)
            raise OrchestrationError(
                "Razorpay order status is not created"
            )

        # 11. Record Razorpay order

        transaction = transaction.model_copy(
            update={
                "razorpay_order_id": order.order_id,
                "updated_at": datetime.now(timezone.utc),
            }
        )
        self._transaction_store.update(transaction)

        # 12. LOCK_ACQUIRED → DISPATCHED

        transaction = self._transition(
            transaction,
            TransactionState.DISPATCHED,
        )
        self._transaction_store.update(transaction)

        self._audit(
            event_type=AuditEventType.RAZORPAY_DISPATCHED,
            transaction=transaction,
            details={
                "razorpay_order_id": order.order_id,
                "amount_paise": order.amount_paise,
                "currency": order.currency,
            },
        )

        return OrchestrationResult(
            transaction=transaction,
            mandate=mandate,
            status="DISPATCHED",
        )

    def _transition(
        self,
        transaction: TransactionRecord,
        target: TransactionState,
    ) -> TransactionRecord:
        """
        Apply exactly one legal state transition through
        the configured transaction state machine.
        """

        try:
            next_state = self._state_machine.transition(
                transaction.state,
                target,
            )
        except InvalidTransactionTransition as exc:
            raise OrchestrationError(
                "Invalid orchestration state transition: "
                f"{transaction.state.value} -> {target.value}"
            ) from exc

        return transaction.model_copy(
            update={
                "state": next_state,
                "updated_at": datetime.now(timezone.utc),
            }
        )

    @staticmethod
    def _assert_identity_binding(
        *,
        analysis: AgentRequestAnalysis,
        user_id: str,
        agent_id: str,
        intent_id: str,
    ) -> None:
        """
        Ensure LLM output cannot override server-owned identity.
        """

        proposal = analysis.intent_proposal

        if proposal.user_id != user_id:
            raise OrchestrationError(
                "Intent analysis contains unexpected user_id"
            )

        if proposal.agent_id != agent_id:
            raise OrchestrationError(
                "Intent analysis contains unexpected agent_id"
            )

        if proposal.intent_id != intent_id:
            raise OrchestrationError(
                "Intent analysis contains unexpected intent_id"
            )

        if analysis.raw_user_prompt != proposal.raw_user_prompt:
            raise OrchestrationError(
                "Intent analysis contains inconsistent raw user prompts"
            )

        if not analysis.raw_user_prompt.strip():
            raise OrchestrationError(
                "Intent analysis contains an empty raw prompt"
            )

    @staticmethod
    def _assert_existing_transaction_matches(
        *,
        existing: TransactionRecord,
        candidate: TransactionRecord,
    ) -> None:
        immutable_fields = (
            "intent_id",
            "user_id",
            "agent_id",
            "merchant_id",
            "amount_paise",
            "currency",
            "items",
            "idempotency_key",
        )

        for field_name in immutable_fields:
            if getattr(existing, field_name) != getattr(
                candidate,
                field_name,
            ):
                raise OrchestrationError(
                    "Existing transaction does not match governed request"
                )

    @staticmethod
    def _require_non_empty(
        value: str,
        field_name: str,
    ) -> None:
        if not value.strip():
            raise ValueError(
                f"{field_name} cannot be empty"
            )