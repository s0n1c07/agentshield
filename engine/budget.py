from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from models.authorization import AgentAuthorization


class SpendLedgerStatus(str, Enum):
    """
    Lifecycle states for an entry in the spend ledger.
    """

    RESERVED = "RESERVED"
    CONSUMED = "CONSUMED"
    RELEASED = "RELEASED"


class SpendReservationRecord(BaseModel):
    """
    Persistent record representing a reserved or settled cumulative spend.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    transaction_id: StrictStr
    authorization_id: StrictStr
    amount_paise: StrictInt = Field(gt=0)
    status: SpendLedgerStatus
    window_date: StrictStr
    window_month: StrictStr
    created_at: datetime


def resolve_tz(tz_name: str | None) -> timezone:
    """
    Resolve a timezone name into a tzinfo object without mandatory third-party dependencies.
    """
    if not tz_name or tz_name.upper() in ("UTC", "GMT", "Z"):
        return timezone.utc

    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(tz_name)
    except Exception:
        known_offsets = {
            "Asia/Kolkata": timezone(timedelta(hours=5, minutes=30)),
            "Asia/Calcutta": timezone(timedelta(hours=5, minutes=30)),
            "IST": timezone(timedelta(hours=5, minutes=30)),
        }
        return known_offsets.get(tz_name, timezone(timedelta(hours=5, minutes=30)))


class SQLiteSpendLedger:
    """
    Thread-safe, atomic cumulative budget ledger backed by SQLite with WAL mode.

    Guarantees:
    - Atomicity: Reservations check aggregate window spend and reserve within a single
      BEGIN IMMEDIATE transaction.
    - Idempotency: Keyed by transaction_id with PRIMARY KEY / UNIQUE constraints.
    - Zero Race Conditions: Database concurrency authority prevents over-reservation.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=15.0,
            isolation_level=None,  # Autocommit mode for explicit BEGIN IMMEDIATE
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
                CREATE TABLE IF NOT EXISTS spend_ledger (
                    transaction_id TEXT PRIMARY KEY,
                    authorization_id TEXT NOT NULL,
                    amount_paise INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    window_date TEXT NOT NULL,
                    window_month TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_spend_day
                ON spend_ledger(authorization_id, status, window_date)
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_spend_month
                ON spend_ledger(authorization_id, status, window_month)
                """
            )
        finally:
            connection.close()

    @staticmethod
    def get_windows(
        tz_name: str | None,
        now: datetime | None = None,
    ) -> tuple[str, str]:
        tz = resolve_tz(tz_name)
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        local_dt = now.astimezone(tz)
        window_date = local_dt.strftime("%Y-%m-%d")
        window_month = local_dt.strftime("%Y-%m")
        return window_date, window_month

    def reserve(
        self,
        *,
        transaction_id: str,
        authorization: AgentAuthorization,
        amount_paise: int,
        now: datetime | None = None,
    ) -> tuple[bool, str]:
        """
        Atomically reserve amount_paise against daily and monthly cumulative budgets.

        Returns:
            (True, "BUDGET_RESERVED" | "ALREADY_RESERVED")
            (False, "DAILY_LIMIT_EXCEEDED: ..." | "MONTHLY_LIMIT_EXCEEDED: ...")
        """
        if not transaction_id.strip():
            raise ValueError("transaction_id cannot be empty")
        if amount_paise <= 0:
            raise ValueError("amount_paise must be positive")

        window_date, window_month = self.get_windows(
            authorization.timezone,
            now=now,
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            # Check if this transaction already has a reservation
            row = connection.execute(
                "SELECT status, amount_paise FROM spend_ledger WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()

            if row is not None:
                existing_status = row["status"]
                if existing_status in (
                    SpendLedgerStatus.RESERVED.value,
                    SpendLedgerStatus.CONSUMED.value,
                ):
                    connection.execute("COMMIT")
                    return True, "ALREADY_RESERVED"

            # Check daily limit if set
            if authorization.daily_limit_paise is not None:
                daily_row = connection.execute(
                    """
                    SELECT COALESCE(SUM(amount_paise), 0) AS total
                    FROM spend_ledger
                    WHERE authorization_id = ?
                      AND status IN ('RESERVED', 'CONSUMED')
                      AND window_date = ?
                    """,
                    (authorization.authorization_id, window_date),
                ).fetchone()
                current_daily = int(daily_row["total"])
                if current_daily + amount_paise > authorization.daily_limit_paise:
                    connection.execute("ROLLBACK")
                    return False, (
                        f"DAILY_LIMIT_EXCEEDED: current={current_daily}, "
                        f"requested={amount_paise}, limit={authorization.daily_limit_paise}"
                    )

            # Check monthly limit if set
            if authorization.monthly_limit_paise is not None:
                monthly_row = connection.execute(
                    """
                    SELECT COALESCE(SUM(amount_paise), 0) AS total
                    FROM spend_ledger
                    WHERE authorization_id = ?
                      AND status IN ('RESERVED', 'CONSUMED')
                      AND window_month = ?
                    """,
                    (authorization.authorization_id, window_month),
                ).fetchone()
                current_monthly = int(monthly_row["total"])
                if current_monthly + amount_paise > authorization.monthly_limit_paise:
                    connection.execute("ROLLBACK")
                    return False, (
                        f"MONTHLY_LIMIT_EXCEEDED: current={current_monthly}, "
                        f"requested={amount_paise}, limit={authorization.monthly_limit_paise}"
                    )

            created_at = (
                (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
            )

            # Insert or replace released row with RESERVED
            connection.execute(
                """
                INSERT INTO spend_ledger (
                    transaction_id,
                    authorization_id,
                    amount_paise,
                    status,
                    window_date,
                    window_month,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(transaction_id) DO UPDATE SET
                    status = excluded.status,
                    amount_paise = excluded.amount_paise,
                    window_date = excluded.window_date,
                    window_month = excluded.window_month,
                    created_at = excluded.created_at
                """,
                (
                    transaction_id,
                    authorization.authorization_id,
                    amount_paise,
                    SpendLedgerStatus.RESERVED.value,
                    window_date,
                    window_month,
                    created_at,
                ),
            )

            connection.execute("COMMIT")
            return True, "BUDGET_RESERVED"

        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def consume(self, transaction_id: str) -> bool:
        """
        Transition a RESERVED reservation to CONSUMED (upon confirmed payment success).
        """
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE spend_ledger
                SET status = ?
                WHERE transaction_id = ?
                  AND status = ?
                """,
                (
                    SpendLedgerStatus.CONSUMED.value,
                    transaction_id,
                    SpendLedgerStatus.RESERVED.value,
                ),
            )
            updated = cursor.rowcount > 0
            connection.execute("COMMIT")
            return updated
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def release(self, transaction_id: str) -> bool:
        """
        Compensating release: transition a RESERVED reservation to RELEASED.
        Called on pre-dispatch failure, definitive payment failure, or refund.
        """
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE spend_ledger
                SET status = ?
                WHERE transaction_id = ?
                  AND status = ?
                """,
                (
                    SpendLedgerStatus.RELEASED.value,
                    transaction_id,
                    SpendLedgerStatus.RESERVED.value,
                ),
            )
            updated = cursor.rowcount > 0
            connection.execute("COMMIT")
            return updated
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def get(self, transaction_id: str) -> SpendReservationRecord | None:
        """
        Fetch reservation record for transaction_id.
        """
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    transaction_id,
                    authorization_id,
                    amount_paise,
                    status,
                    window_date,
                    window_month,
                    created_at
                FROM spend_ledger
                WHERE transaction_id = ?
                """,
                (transaction_id,),
            ).fetchone()

            if row is None:
                return None

            return SpendReservationRecord(
                transaction_id=str(row["transaction_id"]),
                authorization_id=str(row["authorization_id"]),
                amount_paise=int(row["amount_paise"]),
                status=SpendLedgerStatus(row["status"]),
                window_date=str(row["window_date"]),
                window_month=str(row["window_month"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
            )
        finally:
            connection.close()

    def get_aggregate_spend(
        self,
        *,
        authorization_id: str,
        window_date: str,
        window_month: str,
    ) -> tuple[int, int]:
        """
        Return (daily_spend, monthly_spend) in paise for active (RESERVED + CONSUMED) entries.
        """
        connection = self._connect()
        try:
            d_row = connection.execute(
                """
                SELECT COALESCE(SUM(amount_paise), 0) as total
                FROM spend_ledger
                WHERE authorization_id = ?
                  AND status IN ('RESERVED', 'CONSUMED')
                  AND window_date = ?
                """,
                (authorization_id, window_date),
            ).fetchone()
            daily = int(d_row["total"])

            m_row = connection.execute(
                """
                SELECT COALESCE(SUM(amount_paise), 0) as total
                FROM spend_ledger
                WHERE authorization_id = ?
                  AND status IN ('RESERVED', 'CONSUMED')
                  AND window_month = ?
                """,
                (authorization_id, window_month),
            ).fetchone()
            monthly = int(m_row["total"])

            return daily, monthly
        finally:
            connection.close()
