from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from models.approval import ApprovalRecord, ApprovalStatus


class ApprovalStoreError(Exception):
    """Raised when an approval record cannot be safely persisted, queried, or updated."""


class SQLiteApprovalStore:
    """
    SQLite-backed persistence for human approval workflows.
    Ensures transactional atomicity, concurrency safety via WAL and BEGIN IMMEDIATE.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=30.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    transaction_id TEXT PRIMARY KEY,
                    intent_hash TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    amount_paise INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    merchant_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    decision_reason TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_approvals_status
                ON approvals(status)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_approvals_user
                ON approvals(user_id)
                """
            )
        finally:
            connection.close()

    def create(self, record: ApprovalRecord) -> ApprovalRecord:
        """Persist a new pending approval record."""
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO approvals (
                    transaction_id,
                    intent_hash,
                    user_id,
                    agent_id,
                    amount_paise,
                    currency,
                    merchant_name,
                    status,
                    expires_at,
                    created_at,
                    decided_at,
                    decided_by,
                    decision_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.transaction_id,
                    record.intent_hash,
                    record.user_id,
                    record.agent_id,
                    record.amount_paise,
                    record.currency,
                    record.merchant_name,
                    record.status.value,
                    record.expires_at.astimezone(timezone.utc).isoformat(),
                    record.created_at.astimezone(timezone.utc).isoformat(),
                    (
                        record.decided_at.astimezone(timezone.utc).isoformat()
                        if record.decided_at is not None
                        else None
                    ),
                    record.decided_by,
                    record.decision_reason,
                ),
            )
            connection.execute("COMMIT")
            return record
        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise ApprovalStoreError(
                f"Approval record for transaction {record.transaction_id} already exists"
            ) from exc
        except Exception as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise ApprovalStoreError(
                f"Failed to create approval record: {exc}"
            ) from exc
        finally:
            connection.close()

    def get(self, transaction_id: str) -> ApprovalRecord | None:
        """Retrieve an approval record by transaction_id."""
        if not transaction_id.strip():
            raise ValueError("transaction_id cannot be blank")

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT *
                FROM approvals
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            if row is None:
                return None

            record = self._row_to_model(row)
            # Check for passive TTL expiration
            if record.status == ApprovalStatus.PENDING:
                now = datetime.now(timezone.utc)
                if now >= record.expires_at:
                    # Mark expired in database
                    self._mark_expired(connection, transaction_id)
                    record = record.model_copy(
                        update={
                            "status": ApprovalStatus.EXPIRED,
                            "decided_at": now,
                            "decision_reason": "TTL expired",
                        }
                    )
            return record
        finally:
            connection.close()

    def _mark_expired(
        self, connection: sqlite3.Connection, transaction_id: str
    ) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            now_iso = datetime.now(timezone.utc).isoformat()
            connection.execute(
                """
                UPDATE approvals
                SET status = ?,
                    decided_at = ?,
                    decision_reason = ?
                WHERE transaction_id = ?
                  AND status = ?
                """,
                (
                    ApprovalStatus.EXPIRED.value,
                    now_iso,
                    "TTL expired",
                    transaction_id,
                    ApprovalStatus.PENDING.value,
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

    def list(
        self,
        status: ApprovalStatus | None = None,
        user_id: str | None = None,
    ) -> list[ApprovalRecord]:
        """List approval records matching status and optional user_id."""
        connection = self._connect()
        try:
            # First, expire any outdated pending records
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE approvals
                    SET status = ?,
                        decided_at = ?,
                        decision_reason = ?
                    WHERE status = ?
                      AND expires_at <= ?
                    """,
                    (
                        ApprovalStatus.EXPIRED.value,
                        now_iso,
                        "TTL expired",
                        ApprovalStatus.PENDING.value,
                        now_iso,
                    ),
                )
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

            query = "SELECT * FROM approvals WHERE 1=1"
            params: list[object] = []

            if status is not None:
                query += " AND status = ?"
                params.append(status.value)

            if user_id is not None:
                query += " AND user_id = ?"
                params.append(user_id)

            query += " ORDER BY created_at DESC"

            rows = connection.execute(query, tuple(params)).fetchall()
            return [self._row_to_model(row) for row in rows]
        finally:
            connection.close()

    def decide(
        self,
        *,
        transaction_id: str,
        status: ApprovalStatus,
        decided_by: str,
        reason: str | None = None,
    ) -> ApprovalRecord:
        """
        Record an approval decision (APPROVED or REJECTED).
        Fails if the approval is not in PENDING state or has expired.
        """
        if status not in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED):
            raise ValueError(f"Invalid decision status: {status}")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT *
                FROM approvals
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            if row is None:
                connection.execute("ROLLBACK")
                raise ApprovalStoreError(
                    f"Approval request for transaction {transaction_id} not found"
                )

            current = self._row_to_model(row)
            now = datetime.now(timezone.utc)

            if current.status == ApprovalStatus.EXPIRED or now >= current.expires_at:
                now_iso = now.isoformat()
                connection.execute(
                    """
                    UPDATE approvals
                    SET status = ?, decided_at = ?, decision_reason = ?
                    WHERE transaction_id = ?
                    """,
                    (
                        ApprovalStatus.EXPIRED.value,
                        now_iso,
                        "TTL expired",
                        transaction_id,
                    ),
                )
                connection.execute("COMMIT")
                raise ApprovalStoreError(
                    f"Approval request for transaction {transaction_id} has expired"
                )

            if current.status != ApprovalStatus.PENDING:
                connection.execute("ROLLBACK")
                raise ApprovalStoreError(
                    f"Approval request for transaction {transaction_id} is already {current.status.value}"
                )

            now_iso = now.isoformat()
            connection.execute(
                """
                UPDATE approvals
                SET status = ?,
                    decided_at = ?,
                    decided_by = ?,
                    decision_reason = ?
                WHERE transaction_id = ?
                  AND status = ?
                """,
                (
                    status.value,
                    now_iso,
                    decided_by,
                    reason,
                    transaction_id,
                    ApprovalStatus.PENDING.value,
                ),
            )
            connection.execute("COMMIT")

            return current.model_copy(
                update={
                    "status": status,
                    "decided_at": now,
                    "decided_by": decided_by,
                    "decision_reason": reason,
                }
            )
        except ApprovalStoreError:
            raise
        except Exception as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise ApprovalStoreError(
                f"Failed to record approval decision: {exc}"
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> ApprovalRecord:
        created_at = datetime.fromisoformat(str(row["created_at"]))
        expires_at = datetime.fromisoformat(str(row["expires_at"]))
        decided_at = (
            datetime.fromisoformat(str(row["decided_at"]))
            if row["decided_at"] is not None
            else None
        )

        return ApprovalRecord(
            transaction_id=str(row["transaction_id"]),
            intent_hash=str(row["intent_hash"]),
            user_id=str(row["user_id"]),
            agent_id=str(row["agent_id"]),
            amount_paise=int(row["amount_paise"]),
            currency=str(row["currency"]),
            merchant_name=str(row["merchant_name"]),
            status=ApprovalStatus(str(row["status"])),
            expires_at=expires_at,
            created_at=created_at,
            decided_at=decided_at,
            decided_by=(
                str(row["decided_by"])
                if row["decided_by"] is not None
                else None
            ),
            decision_reason=(
                str(row["decision_reason"])
                if row["decision_reason"] is not None
                else None
            ),
        )
