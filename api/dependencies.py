from __future__ import annotations

import hmac

from fastapi import FastAPI, HTTPException, Request, status

from application.orchestrator import AgentShieldOrchestrator
from engine.approval import SQLiteApprovalStore
from engine.audit import SQLiteAuditTrail
from engine.reconciliation import ReconciliationEngine
from engine.telemetry import WebhookTelemetryStore
from engine.transaction_store import SQLiteTransactionStore
from models.principal import AuthenticatedPrincipal
from webhooks.razorpay import RazorpayWebhookHandler


def configure_app(
    app: FastAPI,
    *,
    orchestrator: AgentShieldOrchestrator,
    transaction_store: SQLiteTransactionStore,
    audit_trail: SQLiteAuditTrail,
    webhook_handler: RazorpayWebhookHandler | None = None,
    reconciliation_engine: ReconciliationEngine | None = None,
    webhook_telemetry_store: WebhookTelemetryStore | None = None,
    approval_store: SQLiteApprovalStore | None = None,
    api_token: str | None = None,
    api_user_id: str | None = None,
    api_agent_id: str | None = None,
    approver_token: str | None = None,
) -> None:
    """
    Attach application-scoped governance dependencies.
    """
    app.state.orchestrator = orchestrator
    app.state.transaction_store = transaction_store
    app.state.audit_trail = audit_trail

    if webhook_handler is not None:
        app.state.webhook_handler = webhook_handler

    if reconciliation_engine is not None:
        app.state.reconciliation_engine = reconciliation_engine

    if webhook_telemetry_store is not None:
        app.state.webhook_telemetry_store = webhook_telemetry_store

    if approval_store is not None:
        app.state.approval_store = approval_store

    if api_token is not None:
        app.state.api_token = api_token

    if api_user_id is not None:
        app.state.api_user_id = api_user_id

    if api_agent_id is not None:
        app.state.api_agent_id = api_agent_id

    if approver_token is not None:
        app.state.approver_token = approver_token


def get_orchestrator(
    request: Request,
) -> AgentShieldOrchestrator:
    orchestrator = getattr(
        request.app.state,
        "orchestrator",
        None,
    )

    if orchestrator is None:
        raise HTTPException(
            status_code=503,
            detail="AgentShield orchestrator is not configured",
        )

    return orchestrator


def get_transaction_store(
    request: Request,
) -> SQLiteTransactionStore:
    store = getattr(
        request.app.state,
        "transaction_store",
        None,
    )

    if store is None:
        raise HTTPException(
            status_code=503,
            detail="Transaction store is not configured",
        )

    return store


def get_audit_trail(
    request: Request,
) -> SQLiteAuditTrail:
    audit_trail = getattr(
        request.app.state,
        "audit_trail",
        None,
    )

    if audit_trail is None:
        raise HTTPException(
            status_code=503,
            detail="Audit trail is not configured",
        )

    return audit_trail


def get_webhook_handler(
    request: Request,
) -> RazorpayWebhookHandler:
    handler = getattr(
        request.app.state,
        "webhook_handler",
        None,
    )

    if handler is None:
        raise HTTPException(
            status_code=503,
            detail="Razorpay webhook handler is not configured",
        )

    return handler


def get_reconciliation_engine(
    request: Request,
) -> ReconciliationEngine:
    engine = getattr(
        request.app.state,
        "reconciliation_engine",
        None,
    )

    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="Reconciliation engine is not configured",
        )

    return engine


def get_webhook_telemetry_store(
    request: Request,
) -> WebhookTelemetryStore | None:
    """
    Telemetry is optional observability.

    Financial webhook verification and reconciliation must not depend
    on telemetry being configured, especially for isolated tests and
    minimal application configurations.
    """
    return getattr(
        request.app.state,
        "webhook_telemetry_store",
        None,
    )


def get_authenticated_principal(
    request: Request,
) -> AuthenticatedPrincipal:
    authorization = request.headers.get("Authorization")

    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    scheme, separator, token = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token.strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    expected_token = getattr(
        request.app.state,
        "api_token",
        None,
    )

    user_id = getattr(
        request.app.state,
        "api_user_id",
        None,
    )

    agent_id = getattr(
        request.app.state,
        "api_agent_id",
        None,
    )

    if (
        not isinstance(expected_token, str)
        or not expected_token
        or not isinstance(user_id, str)
        or not user_id
        or not isinstance(agent_id, str)
        or not agent_id
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AgentShield authentication is not configured",
        )

    if not hmac.compare_digest(
        token.strip(),
        expected_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    return AuthenticatedPrincipal(
        user_id=user_id,
        agent_id=agent_id,
    )


def get_approval_store(
    request: Request,
) -> SQLiteApprovalStore:
    store = getattr(
        request.app.state,
        "approval_store",
        None,
    )

    if store is None:
        raise HTTPException(
            status_code=503,
            detail="Approval store is not configured",
        )

    return store


def get_authenticated_approver(
    request: Request,
) -> AuthenticatedPrincipal:
    authorization = request.headers.get("Authorization")

    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    scheme, separator, token = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not token.strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

    token = token.strip()
    agent_token = getattr(request.app.state, "api_token", None)
    approver_token = getattr(request.app.state, "approver_token", None)

    # Security requirement: An agent CANNOT approve its own transaction.
    # The approval endpoints MUST reject requests that present the agent token (403 Forbidden).
    if agent_token and hmac.compare_digest(token, agent_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent token cannot approve transactions; approver token required",
        )

    if (
        not isinstance(approver_token, str)
        or not approver_token
        or not hmac.compare_digest(token, approver_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid approver credentials",
        )

    user_id = getattr(request.app.state, "api_user_id", "admin")
    return AuthenticatedPrincipal(
        user_id=user_id,
        agent_id="human_approver",
    )


__all__ = [
    "AuthenticatedPrincipal",
    "configure_app",
    "get_approval_store",
    "get_audit_trail",
    "get_authenticated_approver",
    "get_authenticated_principal",
    "get_orchestrator",
    "get_reconciliation_engine",
    "get_transaction_store",
    "get_webhook_handler",
    "get_webhook_telemetry_store",
]

