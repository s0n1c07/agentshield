from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from models.authorization import AgentAuthorization
from pydantic import ValidationError

from models.transaction import (
    TransactionRecord,
    TransactionState,
)


class TransactionStoreError(Exception):
    """
    Raised when a transaction cannot be safely persisted or retrieved.
    """


class SQLiteTransactionStore:
    """
    Persistent SQLite-backed transaction store.

    Responsibilities:
    - persist the current TransactionRecord
    - retrieve transactions by transaction ID
    - correlate Razorpay webhooks by order/payment ID
    - update the current transaction snapshot

    This store is separate from:
    - IdempotencyStore: execution-claim protection
    - WebhookEventStore: webhook delivery lifecycle
    - AuditTrail: immutable historical evidence
    """

    def __init__(
        self,
        db_path: str | Path,
    ) -> None:
        self._db_path = str(db_path)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=30.0,
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA journal_mode=WAL"
        )

        connection.execute(
            "PRAGMA foreign_keys=ON"
        )

        return connection

    def _initialize_database(self) -> None:
        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    intent_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    merchant_id TEXT NOT NULL,
                    amount_paise INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    items_json TEXT NOT NULL,
                    authorization_snapshot_json TEXT,
                    intent_hash TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    razorpay_order_id TEXT UNIQUE,
                    razorpay_payment_id TEXT UNIQUE,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )

            columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(transactions)"
                ).fetchall()
            }

            if "authorization_snapshot_json" not in columns:
                connection.execute(
                    """
                    ALTER TABLE transactions
                    ADD COLUMN authorization_snapshot_json TEXT
                    """
                )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_transactions_order_id
                ON transactions(razorpay_order_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_transactions_payment_id
                ON transactions(razorpay_payment_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_transactions_idempotency_key
                ON transactions(idempotency_key)
                """
            )

            connection.commit()

        finally:
            connection.close()

    def create(
        self,
        transaction: TransactionRecord,
    ) -> TransactionRecord:
        """
        Persist a new transaction.

        Raises TransactionStoreError if the transaction ID or another
        unique transaction identifier already exists.
        """

        self._validate_transaction(transaction)

        items_json = self._serialize_items(transaction)
        authorization_snapshot_json = (
            self._serialize_authorization_snapshot(transaction)
        )

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO transactions (
                        transaction_id,
                        intent_id,
                        user_id,
                        agent_id,
                        merchant_id,
                        amount_paise,
                        currency,
                        items_json,
                        authorization_snapshot_json,
                        intent_hash,
                        idempotency_key,
                        razorpay_order_id,
                        razorpay_payment_id,
                        state,
                        created_at,
                        updated_at
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        transaction.transaction_id,
                        transaction.intent_id,
                        transaction.user_id,
                        transaction.agent_id,
                        transaction.merchant_id,
                        transaction.amount_paise,
                        transaction.currency,
                        items_json,
                        authorization_snapshot_json,
                        transaction.intent_hash,
                        transaction.idempotency_key,
                        transaction.razorpay_order_id,
                        transaction.razorpay_payment_id,
                        transaction.state.value,
                        self._to_utc_iso(
                            transaction.created_at
                        ),
                        self._to_utc_iso(
                            transaction.updated_at
                        ),
                    ),
                )

                connection.commit()

            return transaction

        except sqlite3.IntegrityError as exc:
            raise TransactionStoreError(
                "Transaction already exists or violates a unique constraint"
            ) from exc

        except TransactionStoreError:
            raise

        except Exception as exc:
            raise TransactionStoreError(
                "Failed to create transaction"
            ) from exc

    def get(
        self,
        transaction_id: str,
    ) -> TransactionRecord | None:
        """
        Retrieve a transaction by transaction ID.
        """

        self._require_non_empty(
            transaction_id,
            "transaction_id",
        )

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT *
                FROM transactions
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_transaction(row)

        finally:
            connection.close()

    def get_by_idempotency_key(
        self,
        idempotency_key: str,
    ) -> TransactionRecord | None:
        """
        Retrieve a transaction by its idempotency key.
        """
        self._require_non_empty(
            idempotency_key,
            "idempotency_key",
        )

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT *
                FROM transactions
                WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_transaction(row)

        finally:
            connection.close()

    def get_by_order_id(
        self,
        order_id: str,
    ) -> TransactionRecord | None:
        """
        Retrieve a transaction by its Razorpay order ID.
        """

        self._require_non_empty(
            order_id,
            "order_id",
        )

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT *
                FROM transactions
                WHERE razorpay_order_id = ?
                """,
                (order_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_transaction(row)

        finally:
            connection.close()

    def get_by_payment_id(
        self,
        payment_id: str,
    ) -> TransactionRecord | None:
        """
        Retrieve a transaction by its Razorpay payment ID.
        """

        self._require_non_empty(
            payment_id,
            "payment_id",
        )

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT *
                FROM transactions
                WHERE razorpay_payment_id = ?
                """,
                (payment_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_transaction(row)

        finally:
            connection.close()

    def update(
        self,
        transaction: TransactionRecord,
    ) -> TransactionRecord:
        """
        Replace the persisted current snapshot of a transaction.

        The transaction ID is immutable and identifies the row being
        updated.
        """

        self._validate_transaction(transaction)

        items_json = self._serialize_items(transaction)
        authorization_snapshot_json = (
            self._serialize_authorization_snapshot(transaction)
        )

        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    """
                    UPDATE transactions
                    SET
                        intent_id = ?,
                        user_id = ?,
                        agent_id = ?,
                        merchant_id = ?,
                        amount_paise = ?,
                        currency = ?,
                        items_json = ?,
                        authorization_snapshot_json = ?,
                        intent_hash = ?,
                        idempotency_key = ?,
                        razorpay_order_id = ?,
                        razorpay_payment_id = ?,
                        state = ?,
                        created_at = ?,
                        updated_at = ?
                    WHERE transaction_id = ?
                    """,
                    (
                        transaction.intent_id,
                        transaction.user_id,
                        transaction.agent_id,
                        transaction.merchant_id,
                        transaction.amount_paise,
                        transaction.currency,
                        items_json,
                        authorization_snapshot_json,
                        transaction.intent_hash,
                        transaction.idempotency_key,
                        transaction.razorpay_order_id,
                        transaction.razorpay_payment_id,
                        transaction.state.value,
                        self._to_utc_iso(
                            transaction.created_at
                        ),
                        self._to_utc_iso(
                            transaction.updated_at
                        ),
                        transaction.transaction_id,
                    ),
                )

                if cursor.rowcount != 1:
                    raise TransactionStoreError(
                        "Transaction does not exist"
                    )

                connection.commit()

            return transaction

        except TransactionStoreError:
            raise

        except sqlite3.IntegrityError as exc:
            raise TransactionStoreError(
                "Transaction update violates a unique constraint"
            ) from exc

        except Exception as exc:
            raise TransactionStoreError(
                "Failed to update transaction"
            ) from exc

    @staticmethod
    def _serialize_items(
        transaction: TransactionRecord,
    ) -> str:
        try:
            items = [
                item.model_dump(mode="json")
                for item in transaction.items
            ]

            return json.dumps(
                items,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )

        except (TypeError, ValueError) as exc:
            raise TransactionStoreError(
                "Transaction items are not JSON serializable"
            ) from exc

    @staticmethod
    def _serialize_authorization_snapshot(
        transaction: TransactionRecord,
    ) -> str | None:
        try:
            if transaction.authorization_snapshot is None:
                return None

            return json.dumps(
                transaction.authorization_snapshot.model_dump(
                    mode="json"
                ),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )

        except (TypeError, ValueError) as exc:
            raise TransactionStoreError(
                "Authorization snapshot is not JSON serializable"
            ) from exc

    @staticmethod
    def _row_to_transaction(
        row: sqlite3.Row,
    ) -> TransactionRecord:
        """
        Convert one SQLite row into a strict TransactionRecord.

        SQLite stores primitive database values, so enum, timestamp,
        JSON, and nullable fields are normalized before strict Pydantic
        validation.
        """

        try:
            items_raw = json.loads(
                str(row["items_json"])
            )

            if not isinstance(items_raw, list):
                raise TransactionStoreError(
                    "Stored transaction items must be a list"
                )

            authorization_snapshot = None

            if row["authorization_snapshot_json"] is not None:
                authorization_snapshot_raw = json.loads(
                    str(row["authorization_snapshot_json"])
                )

                if not isinstance(
                    authorization_snapshot_raw,
                    dict,
                ):
                    raise TransactionStoreError(
                        "Stored authorization snapshot must be an object"
                    )

                created_at_raw = authorization_snapshot_raw.get(
                    "created_at"
                )

                if not isinstance(created_at_raw, str):
                    raise TransactionStoreError(
                        "Stored authorization snapshot created_at is invalid"
                    )

                authorization_snapshot_raw["created_at"] = (
                    datetime.fromisoformat(created_at_raw)
                )

                expires_at_raw = authorization_snapshot_raw.get(
                    "expires_at"
                )

                if expires_at_raw is not None:
                    if not isinstance(expires_at_raw, str):
                        raise TransactionStoreError(
                            "Stored authorization snapshot expires_at is invalid"
                        )

                    authorization_snapshot_raw["expires_at"] = (
                        datetime.fromisoformat(expires_at_raw)
                    )

                authorization_snapshot = (
                    AgentAuthorization.model_validate(
                        authorization_snapshot_raw
                    )
                )
            created_at = datetime.fromisoformat(
                str(row["created_at"])
            )

            updated_at = datetime.fromisoformat(
                str(row["updated_at"])
            )

            payload = {
                "transaction_id": str(
                    row["transaction_id"]
                ),
                "intent_id": str(
                    row["intent_id"]
                ),
                "user_id": str(
                    row["user_id"]
                ),
                "agent_id": str(
                    row["agent_id"]
                ),
                "merchant_id": str(
                    row["merchant_id"]
                ),
                "amount_paise": int(
                    row["amount_paise"]
                ),
                "currency": str(
                    row["currency"]
                ),
                "items": items_raw,
                "authorization_snapshot": (
                    authorization_snapshot
                ),
                "intent_hash": str(
                    row["intent_hash"]
                ),
                "idempotency_key": str(
                    row["idempotency_key"]
                ),
                "razorpay_order_id": (
                    str(row["razorpay_order_id"])
                    if row["razorpay_order_id"] is not None
                    else None
                ),
                "razorpay_payment_id": (
                    str(row["razorpay_payment_id"])
                    if row["razorpay_payment_id"] is not None
                    else None
                ),
                "state": TransactionState(
                    str(row["state"])
                ),
                "created_at": created_at,
                "updated_at": updated_at,
            }

            return TransactionRecord.model_validate(
                payload
            )

        except TransactionStoreError:
            raise

        except ValidationError as exc:
            raise TransactionStoreError(
                f"Stored transaction data is invalid: {exc}"
            ) from exc

        except (
            json.JSONDecodeError,
            TypeError,
            ValueError,
            KeyError,
        ) as exc:
            raise TransactionStoreError(
                "Stored transaction data is invalid"
            ) from exc

    @staticmethod
    def _validate_transaction(
        transaction: TransactionRecord,
    ) -> None:
        if not isinstance(
            transaction,
            TransactionRecord,
        ):
            raise TransactionStoreError(
                "transaction must be a TransactionRecord"
            )

        if not transaction.transaction_id.strip():
            raise TransactionStoreError(
                "transaction_id cannot be empty"
            )

        if transaction.created_at.tzinfo is None:
            raise TransactionStoreError(
                "Transaction created_at must be timezone-aware"
            )

        if transaction.updated_at.tzinfo is None:
            raise TransactionStoreError(
                "Transaction updated_at must be timezone-aware"
            )

    @staticmethod
    def _require_non_empty(
        value: str,
        field_name: str,
    ) -> None:
        if not isinstance(value, str):
            raise ValueError(
                f"{field_name} must be a string"
            )

        if not value.strip():
            raise ValueError(
                f"{field_name} cannot be empty"
            )

    @staticmethod
    def _to_utc_iso(
        value: datetime,
    ) -> str:
        if value.tzinfo is None:
            raise TransactionStoreError(
                "Transaction timestamps must be timezone-aware"
            )

        return value.astimezone(
            timezone.utc
        ).isoformat()