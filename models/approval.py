from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr


class ApprovalStatus(str, Enum):
    """Lifecycle status of a human approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalRecord(BaseModel):
    """
    Persistent record representing a high-value transaction awaiting
    explicit human-in-the-loop review and approval.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    transaction_id: StrictStr = Field(
        min_length=1,
        description="Unique identifier of the paused transaction.",
    )

    intent_hash: StrictStr = Field(
        min_length=64,
        max_length=64,
        description="SHA-256 hash of the exact governed intent proposal.",
    )

    user_id: StrictStr = Field(
        min_length=1,
        description="User who owns the financial authority.",
    )

    agent_id: StrictStr = Field(
        min_length=1,
        description="AI agent that initiated the proposal.",
    )

    amount_paise: StrictInt = Field(
        gt=0,
        description="Total transaction amount in paise.",
    )

    currency: StrictStr = Field(
        min_length=3,
        max_length=3,
        description="Transaction currency code.",
    )

    merchant_name: StrictStr = Field(
        min_length=1,
        description="Target merchant name or ID.",
    )

    status: ApprovalStatus = Field(
        default=ApprovalStatus.PENDING,
        description="Current approval decision state.",
    )

    expires_at: datetime = Field(
        description="UTC timestamp after which this approval request expires.",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the approval request was created.",
    )

    decided_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the human decision was recorded.",
    )

    decided_by: StrictStr | None = Field(
        default=None,
        description="Identifier of the human principal who approved or rejected.",
    )

    decision_reason: StrictStr | None = Field(
        default=None,
        description="Optional human-provided rationale for approval or rejection.",
    )


class ApprovalDecisionRequest(BaseModel):
    """Payload submitted when approving or rejecting a pending transaction."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    reason: StrictStr | None = Field(
        default=None,
        description="Optional reason for the human decision.",
    )
