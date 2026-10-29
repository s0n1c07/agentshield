from __future__ import annotations

from collections.abc import Callable

from groq import Groq

from application.orchestrator import AgentShieldOrchestrator
from config import Settings
from engine.audit import SQLiteAuditTrail
from engine.authorization import SQLiteAuthorizationAuthority
from engine.budget import SQLiteSpendLedger
from engine.catalog import SQLiteCatalog
from engine.hashing import IntentHasher
from engine.idempotency import WALIdempotencyStore
from engine.mandate import AP2AlignedMandateEngine
from engine.policy import DeterministicPolicyEngine
from engine.reconciliation import (
    ReconciliationEngine,
    WebhookEventStore,
)
from engine.telemetry import WebhookTelemetryStore
from engine.transaction_store import SQLiteTransactionStore
from integrations.groq import GroqIntentParser
from integrations.razorpay import RazorpayClient
from models.authorization import (
    AgentAuthorization,
    AuthorizationDecision,
    AuthorizationEvaluation,
)
from models.intent import AgentRequestAnalysis
from models.policy import TransactionPolicy
from webhooks.razorpay import RazorpayWebhookHandler


class FailClosedAuthorizationProvider:
    """
    Temporary fail-closed authorization provider.

    Kept for compatibility with existing tests and for explicitly
    unconfigured application scenarios.
    """

    def __call__(
        self,
        analysis: AgentRequestAnalysis | None,
    ) -> AuthorizationEvaluation:
        authorization = AgentAuthorization(
            user_id="unknown",
            agent_id="unknown",
            authorization_id="unconfigured",
            active=False,
            revoked=False,
            max_amount_paise=1,
            allowed_merchants=[],
            allowed_categories=[],
            allowed_skus=[],
            max_quantity=1,
            currency="INR",
        )

        return AuthorizationEvaluation(
            decision=AuthorizationDecision(
                allowed=False,
                reason="AUTHORIZATION_AUTHORITY_NOT_CONFIGURED",
                authorization_id=authorization.authorization_id,
            ),
            authorization=authorization,
        )


class UnconfiguredPolicyProvider:
    """
    Fail-closed policy provider.
    """

    def __call__(
        self,
        analysis: AgentRequestAnalysis,
    ) -> TransactionPolicy:
        return TransactionPolicy(
            user_id=analysis.intent_proposal.user_id,
            agent_id=analysis.intent_proposal.agent_id,
            max_amount_paise=0,
            min_amount_paise=0,
            allowed_merchants=[],
            allowed_categories=[],
            allowed_skus=[],
            max_quantity=0,
            currency=analysis.intent_proposal.currency,
            bank_rail_available=False,
        )


class ApplicationContainer:
    """
    Runtime dependency container.

    This is intentionally a regular Python class rather than a Pydantic
    model because it owns live clients, stores, and services.
    """

    __slots__ = (
        "settings",
        "orchestrator",
        "transaction_store",
        "audit_trail",
        "authorization_authority",
        "razorpay",
        "catalog",
        "webhook_event_store",
        "webhook_telemetry_store",
        "webhook_handler",
        "reconciliation_engine",
        "spend_ledger",
    )

    def __init__(
        self,
        *,
        settings: Settings,
        orchestrator: AgentShieldOrchestrator,
        transaction_store: SQLiteTransactionStore,
        audit_trail: SQLiteAuditTrail,
        authorization_authority: SQLiteAuthorizationAuthority,
        razorpay: RazorpayClient,
        catalog: SQLiteCatalog,
        webhook_event_store: WebhookEventStore,
        webhook_telemetry_store: WebhookTelemetryStore,
        webhook_handler: RazorpayWebhookHandler,
        reconciliation_engine: ReconciliationEngine,
        spend_ledger: SQLiteSpendLedger | None = None,
    ) -> None:
        self.settings = settings
        self.orchestrator = orchestrator
        self.transaction_store = transaction_store
        self.audit_trail = audit_trail
        self.authorization_authority = authorization_authority
        self.razorpay = razorpay
        self.catalog = catalog
        self.webhook_event_store = webhook_event_store
        self.webhook_telemetry_store = webhook_telemetry_store
        self.webhook_handler = webhook_handler
        self.reconciliation_engine = reconciliation_engine
        self.spend_ledger = spend_ledger

    @classmethod
    def from_environment(
        cls,
        *,
        settings: Settings | None = None,
        authorization_check: Callable[
            [AgentRequestAnalysis],
            AuthorizationEvaluation,
        ] | None = None,
        policy_provider: Callable[
            [AgentRequestAnalysis],
            TransactionPolicy,
        ] | None = None,
    ) -> "ApplicationContainer":
        resolved_settings = (
            settings
            if settings is not None
            else Settings.from_environment()
        )

        transaction_store = SQLiteTransactionStore(
            f"{resolved_settings.database_path}.transactions",
        )

        audit_trail = SQLiteAuditTrail(
            f"{resolved_settings.database_path}.audit",
        )

        idempotency_store = WALIdempotencyStore(
            f"{resolved_settings.database_path}.idempotency",
        )

        authorization_authority = SQLiteAuthorizationAuthority(
            f"{resolved_settings.database_path}.authorization",
        )

        catalog = SQLiteCatalog(
            f"{resolved_settings.database_path}.catalog",
        )

        webhook_event_store = WebhookEventStore(
            f"{resolved_settings.database_path}.webhooks",
        )

        webhook_telemetry_store = WebhookTelemetryStore(
            f"{resolved_settings.database_path}.webhook-telemetry",
        )

        webhook_handler = RazorpayWebhookHandler(
            resolved_settings.webhook_secret,
        )

        if authorization_check is not None:
            resolved_authorization_check = authorization_check
        else:

            def resolved_authorization_check(
                analysis: AgentRequestAnalysis,
            ) -> AuthorizationEvaluation:
                return authorization_authority.check(
                    analysis.intent_proposal,
                )

        resolved_policy_provider = (
            policy_provider
            if policy_provider is not None
            else UnconfiguredPolicyProvider()
        )

        groq_client = Groq(
            api_key=resolved_settings.groq_api_key,
        )

        claude = GroqIntentParser(
            client=groq_client,
            model=resolved_settings.groq_model,
        )

        razorpay = RazorpayClient(
            key_id=resolved_settings.razorpay_key_id,
            key_secret=resolved_settings.razorpay_key_secret,
            timeout_seconds=resolved_settings.request_timeout_seconds,
        )

        intent_hasher = IntentHasher()

        import json
        keyring = json.loads(resolved_settings.mandate_verifying_keyring_json)
        mandate_engine = AP2AlignedMandateEngine(
            signing_private_key=resolved_settings.mandate_signing_private_key_hex,
            signing_kid=resolved_settings.mandate_signing_kid,
            keyring=keyring,
            hasher=intent_hasher,
        )

        policy_engine = DeterministicPolicyEngine()

        spend_ledger = SQLiteSpendLedger(
            f"{resolved_settings.database_path}.budget",
        )

        reconciliation_engine = ReconciliationEngine(
            webhook_store=webhook_event_store,
            transaction_store=transaction_store,
            audit_trail=audit_trail,
            telemetry_store=webhook_telemetry_store,
            spend_ledger=spend_ledger,
        )

        orchestrator = AgentShieldOrchestrator(
            claude=claude,
            authorization_check=resolved_authorization_check,
            policy_engine=policy_engine,
            intent_hasher=intent_hasher,
            mandate_engine=mandate_engine,
            idempotency_store=idempotency_store,
            razorpay=razorpay,
            policy_provider=resolved_policy_provider,
            audit_trail=audit_trail,
            transaction_store=transaction_store,
            catalog=catalog,
            spend_ledger=spend_ledger,
        )

        return cls(
            settings=resolved_settings,
            orchestrator=orchestrator,
            transaction_store=transaction_store,
            audit_trail=audit_trail,
            authorization_authority=authorization_authority,
            razorpay=razorpay,
            catalog=catalog,
            webhook_event_store=webhook_event_store,
            webhook_telemetry_store=webhook_telemetry_store,
            webhook_handler=webhook_handler,
            reconciliation_engine=reconciliation_engine,
            spend_ledger=spend_ledger,
        )


__all__ = [
    "ApplicationContainer",
    "FailClosedAuthorizationProvider",
    "UnconfiguredPolicyProvider",
]