from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Path,
    Request,
    Response,
    status,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
)

from application.orchestrator import (
    AgentShieldOrchestrator,
    OrchestrationError,
)
from engine.approval import SQLiteApprovalStore
from engine.audit import SQLiteAuditTrail
from integrations.groq import GroqRateLimitError
from engine.reconciliation import (
    ReconciliationError,
    ReconciliationEngine,
)
from engine.telemetry import (
    WebhookTelemetryEvent,
    WebhookTelemetryEventType,
    WebhookTelemetryStore,
)
from engine.transaction_store import SQLiteTransactionStore
from models.approval import (
    ApprovalDecisionRequest,
    ApprovalRecord,
    ApprovalStatus,
)
from models.audit import AuditEvent
from models.orchestration import OrchestrationResult
from models.transaction import (
    TransactionRecord,
    TransactionState,
)
from webhooks.razorpay import RazorpayWebhookHandler

from .dependencies import (
    AuthenticatedPrincipal,
    configure_app,
    get_approval_store,
    get_authenticated_approver,
    get_authenticated_principal,
    get_audit_trail,
    get_orchestrator,
    get_reconciliation_engine,
    get_transaction_store,
    get_webhook_handler,
    get_webhook_telemetry_store,
)

if TYPE_CHECKING:
    from application.container import ApplicationContainer


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )


class AgentExecuteRequest(StrictRequestModel):
    user_message: StrictStr = Field(min_length=1)
    merchant_context: dict[str, object] | None = None

    @field_validator("user_message")
    @classmethod
    def reject_blank_user_message(
        cls,
        value: str,
    ) -> str:
        if not value.strip():
            raise ValueError("value cannot be blank")

        return value


class HealthResponse(StrictRequestModel):
    status: StrictStr


class WebhookResponse(StrictRequestModel):
    status: StrictStr
    event_id: StrictStr
    transaction_id: StrictStr
    transaction_state: TransactionState


class AgentShieldAPI:
    """Thin HTTP transport for the AgentShield application layer."""

    def __init__(
        self,
        container: ApplicationContainer | None = None,
    ) -> None:
        self.app = FastAPI(
            title="AgentShield",
            version="0.1.0",
            description=(
                "Deterministic governance/control plane for AI-initiated "
                "financial actions."
            ),
        )

        if container is not None:
            configure_app(
                self.app,
                orchestrator=container.orchestrator,
                transaction_store=container.transaction_store,
                audit_trail=container.audit_trail,
                webhook_handler=container.webhook_handler,
                reconciliation_engine=container.reconciliation_engine,
                approval_store=container.approval_store,
                api_token=container.settings.api_token,
                api_user_id=container.settings.api_user_id,
                api_agent_id=container.settings.api_agent_id,
                approver_token=container.settings.approver_token,
            )

        self._register_routes()

    def _register_routes(self) -> None:
        @self.app.get(
            "/healthz",
            response_model=HealthResponse,
            status_code=status.HTTP_200_OK,
        )
        async def healthz() -> HealthResponse:
            return HealthResponse(status="ok")

        @self.app.post(
            "/v1/agent/execute",
            response_model=OrchestrationResult,
            status_code=status.HTTP_200_OK,
        )
        async def execute_agent(
            payload: AgentExecuteRequest,
            response: Response,
            idempotency_key: str = Header(
                alias="Idempotency-Key",
                min_length=1,
            ),
            principal: AuthenticatedPrincipal = Depends(
                get_authenticated_principal
            ),
            orchestrator: AgentShieldOrchestrator = Depends(
                get_orchestrator
            ),
        ) -> OrchestrationResult:
            if not idempotency_key.strip():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Idempotency-Key cannot be blank",
                )

            intent_id = f"intent_{uuid4().hex}"
            transaction_id = f"txn_{uuid4().hex}"

            try:
                result = await orchestrator.execute(
                    user_message=payload.user_message,
                    user_id=principal.user_id,
                    agent_id=principal.agent_id,
                    intent_id=intent_id,
                    transaction_id=transaction_id,
                    idempotency_key=idempotency_key,
                    merchant_context=payload.merchant_context,
                )
                if result.transaction.state == TransactionState.PENDING_APPROVAL:
                    response.status_code = status.HTTP_202_ACCEPTED
                return result
            except OrchestrationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(exc),
                ) from exc
            except GroqRateLimitError as exc:
                # Groq quota/rate limit reached: no intent was
                # produced, so nothing was governed or executed.
                # 429 tells the caller this is safe to retry later.
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=str(exc),
                ) from exc
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=str(exc),
                ) from exc

        @self.app.post(
            "/webhooks/razorpay",
            response_model=WebhookResponse,
            status_code=status.HTTP_200_OK,
        )
        async def razorpay_webhook(
            request: Request,
            signature: str = Header(
                alias="X-Razorpay-Signature",
                min_length=1,
            ),
            event_id: str = Header(
                alias="X-Razorpay-Event-Id",
                min_length=1,
            ),
            webhook_handler: RazorpayWebhookHandler = Depends(
                get_webhook_handler
            ),
            reconciliation_engine: ReconciliationEngine = Depends(
                get_reconciliation_engine
            ),
            telemetry_store: WebhookTelemetryStore | None = Depends(
                get_webhook_telemetry_store
            ),
        ) -> WebhookResponse:
            raw_body = await request.body()

            def emit_telemetry(
                event_type: WebhookTelemetryEventType,
                *,
                transaction_id: str | None = None,
                payment_id: str | None = None,
                order_id: str | None = None,
                details: dict[str, object] | None = None,
            ) -> None:
                if telemetry_store is None:
                    return

                telemetry_store.append(
                    WebhookTelemetryEvent(
                        telemetry_id=f"telemetry_{uuid4().hex}",
                        event_type=event_type,
                        webhook_event_id=event_id,
                        transaction_id=transaction_id,
                        payment_id=payment_id,
                        order_id=order_id,
                        details=details or {},
                    )
                )

            emit_telemetry(
                WebhookTelemetryEventType.WEBHOOK_RECEIVED,
            )

            if not webhook_handler.verify_signature(
                raw_body=raw_body,
                signature=signature,
            ):
                emit_telemetry(
                    WebhookTelemetryEventType.WEBHOOK_SIGNATURE_REJECTED,
                    details={
                        "reason": "INVALID_SIGNATURE",
                    },
                )

                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid webhook signature",
                )

            emit_telemetry(
                WebhookTelemetryEventType.WEBHOOK_SIGNATURE_VERIFIED,
            )

            try:
                event = webhook_handler.parse_event(
                    raw_body=raw_body,
                    event_id=event_id,
                )
            except ValueError as exc:
                emit_telemetry(
                    WebhookTelemetryEventType.WEBHOOK_REJECTED,
                    details={
                        "reason": str(exc),
                    },
                )

                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(exc),
                ) from exc

            try:
                transaction = reconciliation_engine.reconcile_event(
                    event=event,
                )
            except ReconciliationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(exc),
                ) from exc

            return WebhookResponse(
                status="PROCESSED",
                event_id=event.event_id,
                transaction_id=transaction.transaction_id,
                transaction_state=transaction.state,
            )

        @self.app.get(
            "/v1/transactions/{transaction_id}",
            response_model=TransactionRecord,
            status_code=status.HTTP_200_OK,
        )
        async def get_transaction(
            transaction_id: str = Path(min_length=1),
            principal: AuthenticatedPrincipal = Depends(
                get_authenticated_principal
            ),
            transaction_store: SQLiteTransactionStore = Depends(
                get_transaction_store
            ),
        ) -> TransactionRecord:
            transaction = transaction_store.get(transaction_id)

            if transaction is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Transaction not found",
                )

            if (
                transaction.user_id != principal.user_id
                or transaction.agent_id != principal.agent_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Transaction access denied",
                )

            return transaction

        @self.app.get(
            "/v1/transactions/{transaction_id}/audit",
            response_model=list[AuditEvent],
            status_code=status.HTTP_200_OK,
        )
        async def get_transaction_audit(
            transaction_id: str = Path(min_length=1),
            principal: AuthenticatedPrincipal = Depends(
                get_authenticated_principal
            ),
            transaction_store: SQLiteTransactionStore = Depends(
                get_transaction_store
            ),
            audit_trail: SQLiteAuditTrail = Depends(
                get_audit_trail
            ),
        ) -> list[AuditEvent]:
            transaction = transaction_store.get(transaction_id)

            if transaction is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Transaction not found",
                )

            if (
                transaction.user_id != principal.user_id
                or transaction.agent_id != principal.agent_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Transaction access denied",
                )

            return audit_trail.list_events(
                transaction_id=transaction_id
            )

        @self.app.get(
            "/v1/approvals",
            response_model=list[ApprovalRecord],
            status_code=status.HTTP_200_OK,
        )
        async def list_approvals(
            status_filter: str | None = None,
            status: str | None = None,
            approver: AuthenticatedPrincipal = Depends(
                get_authenticated_approver
            ),
            approval_store: SQLiteApprovalStore = Depends(
                get_approval_store
            ),
        ) -> list[ApprovalRecord]:
            filter_val = status or status_filter
            parsed_status = None
            if filter_val and filter_val.strip():
                try:
                    parsed_status = ApprovalStatus(filter_val.strip().upper())
                except ValueError:
                    pass
            return approval_store.list(status=parsed_status)

        @self.app.post(
            "/v1/transactions/{transaction_id}/approve",
            response_model=TransactionRecord,
            status_code=status.HTTP_200_OK,
        )
        async def approve_transaction(
            transaction_id: str = Path(min_length=1),
            payload: ApprovalDecisionRequest | None = None,
            approver: AuthenticatedPrincipal = Depends(
                get_authenticated_approver
            ),
            orchestrator: AgentShieldOrchestrator = Depends(
                get_orchestrator
            ),
        ) -> TransactionRecord:
            reason = payload.reason if payload else None
            try:
                return await orchestrator.approve_transaction(
                    transaction_id=transaction_id,
                    approver_principal=approver.user_id,
                    reason=reason,
                )
            except OrchestrationError as exc:
                err_msg = str(exc)
                if "not found" in err_msg.lower():
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=err_msg,
                    ) from exc
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=err_msg,
                ) from exc

        @self.app.post(
            "/v1/transactions/{transaction_id}/reject",
            response_model=TransactionRecord,
            status_code=status.HTTP_200_OK,
        )
        async def reject_transaction(
            transaction_id: str = Path(min_length=1),
            payload: ApprovalDecisionRequest | None = None,
            approver: AuthenticatedPrincipal = Depends(
                get_authenticated_approver
            ),
            orchestrator: AgentShieldOrchestrator = Depends(
                get_orchestrator
            ),
        ) -> TransactionRecord:
            reason = payload.reason if payload else None
            try:
                return orchestrator.reject_transaction(
                    transaction_id=transaction_id,
                    approver_principal=approver.user_id,
                    reason=reason,
                )
            except OrchestrationError as exc:
                err_msg = str(exc)
                if "not found" in err_msg.lower():
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=err_msg,
                    ) from exc
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=err_msg,
                ) from exc

def create_app(
    container: ApplicationContainer | None = None,
) -> FastAPI:
    return AgentShieldAPI(
        container=container,
    ).app