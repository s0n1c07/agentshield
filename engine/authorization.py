from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from models.authorization import (
    AgentAuthorization,
    AuthorizationDecision,
    AuthorizationEvaluation,
)
from models.intent import IntentProposal


class AuthorizationError(Exception):
    """Raised when authorization state cannot be safely accessed."""


class AuthorizationEngine:
    """
    Deterministic verifier for a stored agent authorization.

    The authorization record is server-owned and defines the bounded
    authority granted to the agent for a single execution.
    """

    def verify(
        self,
        proposal: IntentProposal,
        authorization: AgentAuthorization,
    ) -> AuthorizationDecision:
        """
        Verify identity, lifecycle state, currency, amount, merchant,
        SKU, and quantity against the stored authorization bounds.
        """

        if authorization.revoked:
            return AuthorizationDecision(
                allowed=False,
                reason="AUTHORIZATION_REVOKED",
                authorization_id=authorization.authorization_id,
            )

        if not authorization.active:
            return AuthorizationDecision(
                allowed=False,
                reason="AUTHORIZATION_INACTIVE",
                authorization_id=authorization.authorization_id,
            )

        now = datetime.now(timezone.utc)

        if (
            authorization.expires_at is not None
            and now >= authorization.expires_at
        ):
            return AuthorizationDecision(
                allowed=False,
                reason="AUTHORIZATION_EXPIRED",
                authorization_id=authorization.authorization_id,
            )

        if proposal.user_id != authorization.user_id:
            return AuthorizationDecision(
                allowed=False,
                reason="USER_MISMATCH",
                authorization_id=authorization.authorization_id,
            )

        if proposal.agent_id != authorization.agent_id:
            return AuthorizationDecision(
                allowed=False,
                reason="AGENT_MISMATCH",
                authorization_id=authorization.authorization_id,
            )

        if proposal.currency != authorization.currency:
            return AuthorizationDecision(
                allowed=False,
                reason="CURRENCY_NOT_AUTHORIZED",
                authorization_id=authorization.authorization_id,
            )

        if proposal.amount_paise > authorization.max_amount_paise:
            return AuthorizationDecision(
                allowed=False,
                reason="AMOUNT_EXCEEDS_AUTHORIZATION_LIMIT",
                authorization_id=authorization.authorization_id,
            )

        if (
            authorization.allowed_merchants
            and proposal.merchant_id
            not in authorization.allowed_merchants
        ):
            return AuthorizationDecision(
                allowed=False,
                reason="MERCHANT_NOT_AUTHORIZED",
                authorization_id=authorization.authorization_id,
            )

        if authorization.allowed_skus:
            for item in proposal.items:
                if item.sku not in authorization.allowed_skus:
                    return AuthorizationDecision(
                        allowed=False,
                        reason="SKU_NOT_AUTHORIZED",
                        authorization_id=authorization.authorization_id,
                    )

        total_quantity = sum(
            item.quantity
            for item in proposal.items
        )

        if total_quantity > authorization.max_quantity:
            return AuthorizationDecision(
                allowed=False,
                reason="QUANTITY_EXCEEDS_AUTHORIZATION_LIMIT",
                authorization_id=authorization.authorization_id,
            )

        return AuthorizationDecision(
            allowed=True,
            reason="AUTHORIZATION_APPROVED",
            authorization_id=authorization.authorization_id,
        )


class SQLiteAuthorizationAuthority:
    """
    Server-owned persistent authorization authority.

    Authorization records are stored in SQLite using WAL mode.
    The authority owns creation, lookup, revocation, and deactivation.
    """

    def __init__(self, db_path: str) -> None:
        if not db_path or not db_path.strip():
            raise ValueError("db_path cannot be empty")

        self._db_path = db_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._db_path,
            timeout=30,
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
                CREATE TABLE IF NOT EXISTS authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    revoked INTEGER NOT NULL,
                    max_amount_paise INTEGER NOT NULL,
                    allowed_merchants TEXT NOT NULL,
                    allowed_categories TEXT NOT NULL,
                    allowed_skus TEXT NOT NULL,
                    max_quantity INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    daily_limit_paise INTEGER,
                    monthly_limit_paise INTEGER,
                    timezone TEXT
                )
                """
            )

            for col_def in [
                "daily_limit_paise INTEGER",
                "monthly_limit_paise INTEGER",
                "timezone TEXT",
            ]:
                try:
                    connection.execute(
                        f"ALTER TABLE authorizations ADD COLUMN {col_def}"
                    )
                except sqlite3.OperationalError:
                    pass

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_authorizations_user_agent
                ON authorizations(user_id, agent_id)
                """
            )
        finally:
            connection.close()

    def create(
        self,
        authorization: AgentAuthorization,
    ) -> AgentAuthorization:
        """
        Persist a new authorization record.

        Authorization IDs are unique and cannot be silently overwritten.
        """

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            connection.execute(
                """
                INSERT INTO authorizations (
                    authorization_id,
                    user_id,
                    agent_id,
                    active,
                    revoked,
                    max_amount_paise,
                    allowed_merchants,
                    allowed_categories,
                    allowed_skus,
                    max_quantity,
                    currency,
                    created_at,
                    expires_at,
                    daily_limit_paise,
                    monthly_limit_paise,
                    timezone
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authorization.authorization_id,
                    authorization.user_id,
                    authorization.agent_id,
                    int(authorization.active),
                    int(authorization.revoked),
                    authorization.max_amount_paise,
                    self._encode_string_list(
                        authorization.allowed_merchants
                    ),
                    self._encode_string_list(
                        authorization.allowed_categories
                    ),
                    self._encode_string_list(
                        authorization.allowed_skus
                    ),
                    authorization.max_quantity,
                    authorization.currency,
                    authorization.created_at.astimezone(
                        timezone.utc
                    ).isoformat(),
                    (
                        authorization.expires_at.astimezone(
                            timezone.utc
                        ).isoformat()
                        if authorization.expires_at is not None
                        else None
                    ),
                    authorization.daily_limit_paise,
                    authorization.monthly_limit_paise,
                    authorization.timezone,
                ),
            )

            connection.execute("COMMIT")
            return authorization

        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise AuthorizationError(
                "Authorization already exists"
            ) from exc

        except Exception as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise AuthorizationError(
                "Failed to create authorization"
            ) from exc

        finally:
            connection.close()

    def get(
        self,
        authorization_id: str,
    ) -> AgentAuthorization | None:
        """
        Return one authorization by its server-owned ID.
        """

        if not authorization_id:
            raise ValueError(
                "authorization_id cannot be empty"
            )

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT
                    authorization_id,
                    user_id,
                    agent_id,
                    active,
                    revoked,
                    max_amount_paise,
                    allowed_merchants,
                    allowed_categories,
                    allowed_skus,
                    max_quantity,
                    currency,
                    created_at,
                    expires_at,
                    daily_limit_paise,
                    monthly_limit_paise,
                    timezone
                FROM authorizations
                WHERE authorization_id = ?
                """,
                (authorization_id,),
            ).fetchone()

            if row is None:
                return None

            return self._row_to_model(row)

        except Exception as exc:
            raise AuthorizationError(
                "Failed to read authorization"
            ) from exc

        finally:
            connection.close()

    def find_for_agent(
        self,
        *,
        user_id: str,
        agent_id: str,
    ) -> list[AgentAuthorization]:
        """
        Return all authorizations for a user/agent pair.

        Revoked, inactive, and expired records remain available
        for audit/history.
        """

        if not user_id:
            raise ValueError("user_id cannot be empty")

        if not agent_id:
            raise ValueError("agent_id cannot be empty")

        connection = self._connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    authorization_id,
                    user_id,
                    agent_id,
                    active,
                    revoked,
                    max_amount_paise,
                    allowed_merchants,
                    allowed_categories,
                    allowed_skus,
                    max_quantity,
                    currency,
                    created_at,
                    expires_at,
                    daily_limit_paise,
                    monthly_limit_paise,
                    timezone
                FROM authorizations
                WHERE user_id = ?
                  AND agent_id = ?
                ORDER BY created_at DESC
                """,
                (user_id, agent_id),
            ).fetchall()

            return [
                self._row_to_model(row)
                for row in rows
            ]

        except Exception as exc:
            raise AuthorizationError(
                "Failed to find authorizations"
            ) from exc

        finally:
            connection.close()

    def revoke(
        self,
        authorization_id: str,
    ) -> AgentAuthorization:
        """
        Explicitly revoke an authorization.

        Revocation is persistent and cannot be interpreted as approval.
        """

        if not authorization_id:
            raise ValueError(
                "authorization_id cannot be empty"
            )

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            result = connection.execute(
                """
                UPDATE authorizations
                SET revoked = 1,
                    active = 0
                WHERE authorization_id = ?
                """,
                (authorization_id,),
            )

            if result.rowcount == 0:
                connection.execute("ROLLBACK")
                raise AuthorizationError(
                    "Authorization not found"
                )

            connection.execute("COMMIT")

            authorization = self.get(authorization_id)

            if authorization is None:
                raise AuthorizationError(
                    "Authorization disappeared after revocation"
                )

            return authorization

        except AuthorizationError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

        except Exception as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise AuthorizationError(
                "Failed to revoke authorization"
            ) from exc

        finally:
            connection.close()

    def deactivate(
        self,
        authorization_id: str,
    ) -> AgentAuthorization:
        """
        Deactivate an authorization without marking it as revoked.
        """

        if not authorization_id:
            raise ValueError(
                "authorization_id cannot be empty"
            )

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            result = connection.execute(
                """
                UPDATE authorizations
                SET active = 0
                WHERE authorization_id = ?
                """,
                (authorization_id,),
            )

            if result.rowcount == 0:
                connection.execute("ROLLBACK")
                raise AuthorizationError(
                    "Authorization not found"
                )

            connection.execute("COMMIT")

            authorization = self.get(authorization_id)

            if authorization is None:
                raise AuthorizationError(
                    "Authorization disappeared after deactivation"
                )

            return authorization

        except AuthorizationError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

        except Exception as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise AuthorizationError(
                "Failed to deactivate authorization"
            ) from exc

        finally:
            connection.close()

    def check(
        self,
        proposal: IntentProposal,
    ) -> AuthorizationEvaluation:
        """
        Evaluate a proposal against server-owned authorization records
        and return the decision together with the exact authorization
        record that was evaluated.
        """

        authorizations = self.find_for_agent(
            user_id=proposal.user_id,
            agent_id=proposal.agent_id,
        )

        if not authorizations:
            return AuthorizationEvaluation(
                decision=AuthorizationDecision(
                    allowed=False,
                    reason="AUTHORIZATION_NOT_FOUND",
                    authorization_id=None,
                ),
                authorization=None,
            )

        engine = AuthorizationEngine()

        first_failure: tuple[
            AuthorizationDecision,
            AgentAuthorization,
        ] | None = None

        for authorization in authorizations:
            decision = engine.verify(
                proposal,
                authorization,
            )

            if decision.allowed:
                return AuthorizationEvaluation(
                    decision=decision,
                    authorization=authorization,
                )

            if first_failure is None:
                first_failure = (
                    decision,
                    authorization,
                )

        if first_failure is not None:
            decision, authorization = first_failure

            return AuthorizationEvaluation(
                decision=decision,
                authorization=authorization,
            )

        authorization = authorizations[0]

        decision = AuthorizationDecision(
            allowed=False,
            reason="AUTHORIZATION_REJECTED",
            authorization_id=authorization.authorization_id,
        )

        return AuthorizationEvaluation(
            decision=decision,
            authorization=authorization,
        )

    @staticmethod
    def _encode_string_list(
        values: list[str],
    ) -> str:
        """
        Store string lists as a deterministic JSON array.
        """
        import json

        return json.dumps(
            values,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @staticmethod
    def _decode_string_list(
        value: str,
    ) -> list[str]:
        """
        Decode a persisted JSON string list.
        """
        import json

        decoded = json.loads(value)

        if not isinstance(decoded, list):
            raise ValueError(
                "Persisted authorization list is invalid"
            )

        if not all(isinstance(item, str) for item in decoded):
            raise ValueError(
                "Persisted authorization list contains non-string values"
            )

        return decoded

    @classmethod
    def _row_to_model(
        cls,
        row: sqlite3.Row,
    ) -> AgentAuthorization:
        created_at = datetime.fromisoformat(
            str(row["created_at"])
        )

        expires_at_value = row["expires_at"]

        expires_at = (
            datetime.fromisoformat(str(expires_at_value))
            if expires_at_value is not None
            else None
        )

        return AgentAuthorization(
            user_id=str(row["user_id"]),
            agent_id=str(row["agent_id"]),
            authorization_id=str(
                row["authorization_id"]
            ),
            active=bool(row["active"]),
            revoked=bool(row["revoked"]),
            max_amount_paise=int(
                row["max_amount_paise"]
            ),
            allowed_merchants=cls._decode_string_list(
                str(row["allowed_merchants"])
            ),
            allowed_categories=cls._decode_string_list(
                str(row["allowed_categories"])
            ),
            allowed_skus=cls._decode_string_list(
                str(row["allowed_skus"])
            ),
            max_quantity=int(
                row["max_quantity"]
            ),
            currency=str(row["currency"]),
            created_at=created_at,
            expires_at=expires_at,
            daily_limit_paise=(
                int(row["daily_limit_paise"])
                if "daily_limit_paise" in row.keys() and row["daily_limit_paise"] is not None
                else None
            ),
            monthly_limit_paise=(
                int(row["monthly_limit_paise"])
                if "monthly_limit_paise" in row.keys() and row["monthly_limit_paise"] is not None
                else None
            ),
            timezone=(
                str(row["timezone"])
                if "timezone" in row.keys() and row["timezone"] is not None
                else "Asia/Kolkata"
            ),
        )