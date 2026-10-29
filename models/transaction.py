from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr
from models.intent import IntentItem
from models.authorization import AgentAuthorization
from models.authorization import AgentAuthorization
class IdempotencyStatus(str, Enum):
    """
    Lifecycle of an idempotency record.

    These values describe the execution claim
    """

    ACQUIRED = "ACQUIRED"
    COMPLETED = "COMPLETED"
    FAILED_SAFE_TO_RETRY = "FAILED_SAFE_TO_RETRY"


class IdempotencyRecord(BaseModel):
    """
    Persistent record representing ownership of an execution key.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    idempotency_key: StrictStr = Field(
        min_length=1,
        description="Unique key identifying one logical execution.",
    )

    transaction_id: StrictStr = Field(
        min_length=1,
        description="Transaction associated with the execution.",
    )

    status: IdempotencyStatus = Field(
        description="Current idempotency execution status.",
    )

    created_at: datetime = Field(
        description="UTC timestamp when the idempotency record was created.",
    )


class TransactionState(str, Enum):
    """
    Deterministic lifecycle states for an AgentShield transaction.
    """

    CREATED = "CREATED"

    INTENT_VALIDATED = "INTENT_VALIDATED"
    POLICY_APPROVED = "POLICY_APPROVED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    MANDATE_VALID = "MANDATE_VALID"
    LOCK_ACQUIRED = "LOCK_ACQUIRED"

    DISPATCHED = "DISPATCHED"

    UNKNOWN = "UNKNOWN"
    RECONCILE_PENDING = "RECONCILE_PENDING"

    SUCCESS = "SUCCESS"
    FAILED_SAFE_TO_RETRY = "FAILED_SAFE_TO_RETRY"

    STOCKOUT_DETECTED = "STOCKOUT_DETECTED"
    REFUNDING = "REFUNDING"
    REFUNDED = "REFUNDED"
    REROUTING = "REROUTING"
    RECOVERED = "RECOVERED"

    COMPLETED = "COMPLETED"


class TransactionRecord(BaseModel):
    """
    Server-owned record representing the lifecycle of one
    logical financial transaction.

    The transaction state is controlled by the state machine.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    # Identity

    transaction_id: StrictStr = Field(
        min_length=1,
        description="Unique identifier for the transaction.",
    )

    intent_id: StrictStr = Field(
        min_length=1,
        description="Intent associated with this transaction.",
    )

    user_id: StrictStr = Field(
        min_length=1,
        description="User on whose behalf the transaction is executed.",
    )

    agent_id: StrictStr = Field(
        min_length=1,
        description="AI agent proposing the transaction.",
    )

    # Financial transaction

    merchant_id: StrictStr = Field(
        min_length=1,
        description="Merchant receiving the transaction.",
    )

    amount_paise: StrictInt = Field(
        gt=0,
        description="Exact transaction amount in paise.",
    )

    currency: StrictStr = Field(
        min_length=3,
        max_length=3,
        description="Transaction currency.",
    )

    items: list[IntentItem] = Field(
        min_length=1,
        description="Exact line items governed by this transaction.",
    )


    # Governance 

    intent_hash: StrictStr = Field(
        min_length=64,
        max_length=64,
        description="64-character hexadecimal SHA-256 hash of the governed intent.",
    )

    authorization_snapshot: AgentAuthorization | None = Field(
        default=None,
        description=(
            "Exact server-owned authorization record used for "
            "this transaction execution."
        ),
    )

    idempotency_key: StrictStr = Field(
        min_length=1,
        description="Unique execution identity used for duplicate prevention.",
    )



    # External payment references

    razorpay_order_id: StrictStr | None = Field(
        default=None,
        description="Razorpay order identifier, once created.",
    )

    razorpay_payment_id: StrictStr | None = Field(
        default=None,
        description="Razorpay payment identifier, once known.",
    )

    # Lifecycle

    state: TransactionState = Field(
        default=TransactionState.CREATED,
        description="Current transaction lifecycle state.",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the transaction was created.",
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the latest transaction update.",
    )