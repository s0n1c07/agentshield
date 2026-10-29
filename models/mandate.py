from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator
from datetime import datetime, timedelta, timezone


class Mandate(BaseModel):
    """
    Cryptographically signed mandate.

    This is an AP2-aligned MVP representation.

    The mandate binds:
    - user identity
    - agent identity
    - merchant
    - transaction amount
    - intent hash
    - nonce
    - validity window
    - cryptographic signature
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    user_id: StrictStr = Field(
        min_length=1,
        description="User whose authorization is being represented.",
    )

    agent_id: StrictStr = Field(
        min_length=1,
        description="AI agent acting on behalf of the user.",
    )

    merchant_id: StrictStr = Field(
        min_length=1,
        description="Merchant for the governed transaction.",
    )

    amount_paise: StrictInt = Field(
        gt=0,
        description="Transaction amount in paise.",
    )

    intent_hash: StrictStr = Field(
        min_length=1,
        description="SHA-256 hash of the canonical governed intent.",
    )

    nonce: StrictStr = Field(
        min_length=1,
        description="Unique value used for replay/freshness protection.",
    )

    issued_at: datetime = Field(
        description="Time at which the mandate was issued.",
    )

    expires_at: datetime = Field(
        description="Time at which the mandate expires.",
    )

    kid: StrictStr = Field(
        min_length=1,
        description="Key identifier for the public key used to verify the mandate.",
    )

    alg: StrictStr = Field(
        default="EdDSA",
        min_length=1,
        description="Cryptographic algorithm used to sign the mandate.",
    )

    signature: StrictStr = Field(
        min_length=1,
        description="Hexadecimal Ed25519 signature over the mandate payload.",
    )

    @classmethod
    def create_times(
        cls,
        *,
        issued_at: datetime,
        ttl_seconds: int,
    ) -> tuple[datetime, datetime]:
        """
        Calculate a mandate validity window.
        """

        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")

        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)

        expires_at = issued_at + timedelta(seconds=ttl_seconds)

        return issued_at, expires_at

    @model_validator(mode="after")
    def validate_time_window(self) -> "Mandate":
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("issued_at and expires_at must be timezone-aware")

        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")

        return self