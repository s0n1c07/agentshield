from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from models.transaction import TransactionState


class AuditEventType(str, Enum):
    INTENT_RECEIVED = "INTENT_RECEIVED"
    INTENT_VALIDATED = "INTENT_VALIDATED"
    AUTHORIZATION_APPROVED = "AUTHORIZATION_APPROVED"
    AUTHORIZATION_REJECTED = "AUTHORIZATION_REJECTED"
    POLICY_APPROVED = "POLICY_APPROVED"
    POLICY_REJECTED = "POLICY_REJECTED"
    MANDATE_CREATED = "MANDATE_CREATED"
    MANDATE_VERIFIED = "MANDATE_VERIFIED"
    IDEMPOTENCY_ACQUIRED = "IDEMPOTENCY_ACQUIRED"
    IDEMPOTENCY_REJECTED = "IDEMPOTENCY_REJECTED"
    RAZORPAY_DISPATCHED = "RAZORPAY_DISPATCHED"
    RAZORPAY_UNKNOWN = "RAZORPAY_UNKNOWN"
    ORDER_RECORDED = "ORDER_RECORDED"
    WEBHOOK_RECEIVED = "WEBHOOK_RECEIVED"
    PAYMENT_RECONCILED = "PAYMENT_RECONCILED"
    REFUND_STARTED = "REFUND_STARTED"
    REFUND_COMPLETED = "REFUND_COMPLETED"
    BUDGET_RESERVED = "BUDGET_RESERVED"
    BUDGET_REJECTED = "BUDGET_REJECTED"
    BUDGET_CONSUMED = "BUDGET_CONSUMED"
    BUDGET_RELEASED = "BUDGET_RELEASED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    RECOVERY_STARTED = "RECOVERY_STARTED"
    RECOVERY_COMPLETED = "RECOVERY_COMPLETED"


class AuditEvent(BaseModel):
    """Immutable representation of one AgentShield audit record."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    sequence: int = Field(ge=1)
    event_id: StrictStr = Field(min_length=1)
    event_type: AuditEventType
    transaction_id: StrictStr = Field(min_length=1)
    intent_id: StrictStr = Field(min_length=1)
    user_id: StrictStr = Field(min_length=1)
    agent_id: StrictStr = Field(min_length=1)
    state: TransactionState
    intent_hash: StrictStr | None = Field(default=None)
    occurred_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: StrictStr = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
    event_hash: StrictStr = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )
