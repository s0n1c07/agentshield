from __future__ import annotations

from datetime import datetime, timezone

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)
class AgentAuthorization(BaseModel):
    """
    Trusted, server-owned authorization record representing the bounded
    authority delegated by a user to a specific AI agent.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    user_id: StrictStr = Field(
        min_length=1,
        description="User who owns the financial authority.",
    )

    agent_id: StrictStr = Field(
        min_length=1,
        description="AI agent delegated authority by the user.",
    )

    authorization_id: StrictStr = Field(
        min_length=1,
        description="Unique identifier for this delegation.",
    )

    active: StrictBool = Field(
        default=True,
        description="Whether this authorization is currently active.",
    )

    revoked: StrictBool = Field(
        default=False,
        description="Whether the user has explicitly revoked the authorization.",
    )

    max_amount_paise: StrictInt = Field(
        gt=0,
        description="Maximum transaction amount authorized in paise.",
    )

    allowed_merchants: list[StrictStr] = Field(
        default_factory=list,
        description="Merchants this authorization permits.",
    )

    allowed_categories: list[StrictStr] = Field(
        default_factory=list,
        description="Product categories this authorization permits.",
    )

    allowed_skus: list[StrictStr] = Field(
        default_factory=list,
        description="Product SKUs this authorization permits.",
    )

    max_quantity: StrictInt = Field(
        default=1,
        ge=1,
        description="Maximum total quantity authorized for one execution.",
    )

    currency: StrictStr = Field(
        min_length=3,
        max_length=3,
        description="Currency authorized for transactions.",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time at which the authorization was created.",
    )

    expires_at: datetime | None = Field(
        default=None,
        description="Time after which the authorization is no longer valid.",
    )

    daily_limit_paise: StrictInt | None = Field(
        default=None,
        gt=0,
        description="Optional maximum cumulative spending permitted per calendar day in paise.",
    )

    monthly_limit_paise: StrictInt | None = Field(
        default=None,
        gt=0,
        description="Optional maximum cumulative spending permitted per calendar month in paise.",
    )

    timezone: StrictStr = Field(
        default="Asia/Kolkata",
        description="Configurable timezone for calendar day and month spend windows.",
    )

    approval_threshold_paise: StrictInt | None = Field(
        default=None,
        gt=0,
        description="Optional transaction amount threshold requiring human approval.",
    )


class AuthorizationDecision(BaseModel):
    """
    Deterministic result produced by the authorization engine.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    allowed: StrictBool = Field(
        description="Whether the agent is authorized to act for the user.",
    )

    reason: StrictStr = Field(
        min_length=1,
        description="Machine-readable reason for the decision.",
    )

    authorization_id: StrictStr | None = Field(
        default=None,
        description="Authorization responsible for the decision.",
    )

class AuthorizationEvaluation(BaseModel):
    """
    Server-owned authorization evaluation.

    Contains the deterministic decision and, when available,
    the exact server-owned authorization record that produced it.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    decision: AuthorizationDecision = Field(
        description="Deterministic authorization decision.",
    )

    authorization: AgentAuthorization | None = Field(
        default=None,
        description="Exact server-owned authorization record evaluated, "
        "when one exists.",
    )

    @model_validator(mode="after")
    def validate_authorization_binding(self) -> "AuthorizationEvaluation":
        """
        Enforce consistency between the decision and the
        server-owned authorization record.
        """

        decision_authorization_id = self.decision.authorization_id
        authorization = self.authorization

        if self.decision.allowed and authorization is None:
            raise ValueError(
                "Allowed authorization evaluation requires an authorization record"
            )

        if decision_authorization_id is None:
            if authorization is not None:
                raise ValueError(
                    "Authorization record cannot be present when "
                    "decision has no authorization ID"
                )

            return self

        if authorization is None:
            raise ValueError(
                "Authorization record is required when decision "
                "contains an authorization ID"
            )

        if decision_authorization_id != authorization.authorization_id:
            raise ValueError(
                "Authorization decision is bound to a different "
                "authorization record"
            )

        return self