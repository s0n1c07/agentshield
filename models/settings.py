from __future__ import annotations

import os

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)


class ConfigurationError(ValueError):
    """Raised when required application configuration is missing or invalid."""


def _required(name: str) -> str:
    value = os.getenv(name)

    if value is None or not value.strip():
        raise ConfigurationError(f"{name} is required")

    return value.strip()


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigurationError(
            f"{name} must be a positive number"
        ) from exc

    if value <= 0:
        raise ConfigurationError(
            f"{name} must be greater than 0"
        )

    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)

    if raw is None or not raw.strip():
        return default

    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(
            f"{name} must be a positive integer"
        ) from exc

    if value <= 0:
        raise ConfigurationError(
            f"{name} must be greater than 0"
        )

    return value


class Settings(BaseModel):
    """
    Validated, immutable application configuration.

    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    # LLM configuration
    llm_provider: StrictStr
    groq_api_key: StrictStr
    groq_model: StrictStr

    # Razorpay credentials
    razorpay_key_id: StrictStr
    razorpay_key_secret: StrictStr

    # Mandate Ed25519 configuration
    mandate_signing_kid: StrictStr = Field(default="kid-default")
    mandate_signing_private_key_hex: StrictStr = Field(default="")
    mandate_verifying_keyring_json: StrictStr = Field(default="{}")
    mandate_secret_key: bytes | None = None  # Deprecated and unused
    database_path: StrictStr
    mandate_ttl_seconds: StrictInt = Field(gt=0)
    max_retries: StrictInt = Field(gt=0)
    request_timeout_seconds: StrictFloat = Field(gt=0)
    webhook_secret: StrictStr

    # AgentShield credentials
    api_token: StrictStr
    api_user_id: StrictStr
    api_agent_id: StrictStr
    approver_token: StrictStr = Field(default="agentshield-approver-token-secret-fallback-32chars")
    approval_ttl_seconds: StrictInt = Field(default=900, gt=0)

    @model_validator(mode="before")
    @classmethod
    def populate_mandate_keys(cls, data: Any) -> Any:
        if isinstance(data, dict):
            mandate_secret = data.get("mandate_secret_key")
            priv_hex = data.get("mandate_signing_private_key_hex")
            if mandate_secret and not priv_hex:
                import hashlib
                import json
                from cryptography.hazmat.primitives.asymmetric import ed25519

                if isinstance(mandate_secret, str):
                    mandate_secret = mandate_secret.encode("utf-8")
                seed = hashlib.sha256(mandate_secret).digest()
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
                pub = priv.public_key()
                data["mandate_signing_kid"] = data.get("mandate_signing_kid") or "kid-default"
                data["mandate_signing_private_key_hex"] = seed.hex()
                data["mandate_verifying_keyring_json"] = json.dumps(
                    {"kid-default": pub.public_bytes_raw().hex()}
                )
        return data

    @classmethod
    def from_environment(cls) -> "Settings":
        provider = os.getenv(
            "LLM_PROVIDER",
            "groq",
        ).strip().lower()

        if provider != "groq":
            raise ConfigurationError(
                "LLM_PROVIDER must be 'groq'"
            )

        groq_api_key = _required("GROQ_API_KEY")
        groq_model = _required("GROQ_MODEL")

        razorpay_key_id = _required("RAZORPAY_KEY_ID")
        razorpay_key_secret = _required("RAZORPAY_KEY_SECRET")

        webhook_secret = _required("RAZORPAY_WEBHOOK_SECRET")

        api_token = _required("AGENTSHIELD_API_TOKEN")
        api_user_id = _required("AGENTSHIELD_API_USER_ID")
        api_agent_id = _required("AGENTSHIELD_API_AGENT_ID")

        # Validate legacy secret if present in environment
        mandate_secret_raw = os.getenv("MANDATE_SECRET_KEY")
        mandate_secret_key = None
        if mandate_secret_raw is not None and mandate_secret_raw.strip():
            raw_secret = mandate_secret_raw.strip().encode("utf-8")
            if len(raw_secret) < 32:
                raise ConfigurationError(
                    "MANDATE_SECRET_KEY must be at least 32 bytes"
                )
            mandate_secret_key = raw_secret

        # Ed25519 keypair and keyring validation
        mandate_signing_kid = os.getenv("MANDATE_SIGNING_KID")
        mandate_signing_private_key_hex = os.getenv("MANDATE_SIGNING_PRIVATE_KEY_HEX")
        mandate_verifying_keyring_json = os.getenv("MANDATE_VERIFYING_KEYRING_JSON")

        if mandate_signing_private_key_hex and mandate_signing_kid and mandate_verifying_keyring_json:
            mandate_signing_kid = mandate_signing_kid.strip()
            mandate_signing_private_key_hex = mandate_signing_private_key_hex.strip()
            mandate_verifying_keyring_json = mandate_verifying_keyring_json.strip()

            try:
                priv_bytes = bytes.fromhex(mandate_signing_private_key_hex)
                if len(priv_bytes) != 32:
                    raise ConfigurationError(
                        "MANDATE_SIGNING_PRIVATE_KEY_HEX must represent exactly 32 bytes (64 hex characters)"
                    )
            except ValueError as exc:
                raise ConfigurationError(
                    f"MANDATE_SIGNING_PRIVATE_KEY_HEX must be valid hex: {exc}"
                ) from exc

            import json
            try:
                keyring_dict = json.loads(mandate_verifying_keyring_json)
                if not isinstance(keyring_dict, dict) or not keyring_dict:
                    raise ConfigurationError(
                        "MANDATE_VERIFYING_KEYRING_JSON must be a non-empty JSON object"
                    )
                for k, pub_hex in keyring_dict.items():
                    pub_bytes = bytes.fromhex(pub_hex)
                    if len(pub_bytes) != 32:
                        raise ConfigurationError(
                            f"Keyring entry for '{k}' must represent 32 bytes (64 hex characters)"
                        )
            except (json.JSONDecodeError, ValueError) as exc:
                raise ConfigurationError(
                    f"MANDATE_VERIFYING_KEYRING_JSON is invalid: {exc}"
                ) from exc

            if mandate_signing_kid not in keyring_dict:
                raise ConfigurationError(
                    f"Active signing kid '{mandate_signing_kid}' not found in MANDATE_VERIFYING_KEYRING_JSON"
                )

        elif mandate_secret_key is not None:
            # Deprecated fallback path: deterministically derive Ed25519 keys from legacy secret
            import hashlib
            from cryptography.hazmat.primitives.asymmetric import ed25519
            import json

            seed = hashlib.sha256(mandate_secret_key).digest()
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            pub = priv.public_key()
            mandate_signing_kid = "kid-default"
            mandate_signing_private_key_hex = seed.hex()
            mandate_verifying_keyring_json = json.dumps(
                {"kid-default": pub.public_bytes_raw().hex()}
            )
        else:
            raise ConfigurationError(
                "MANDATE_SIGNING_PRIVATE_KEY_HEX, MANDATE_SIGNING_KID, and MANDATE_VERIFYING_KEYRING_JSON are required"
            )

        if len(api_token) < 32:
            raise ConfigurationError(
                "AGENTSHIELD_API_TOKEN must be at least 32 characters"
            )

        database_path = os.getenv(
            "DATABASE_PATH",
            "state.db",
        ).strip()

        if not database_path:
            raise ConfigurationError(
                "DATABASE_PATH cannot be empty"
            )

        return cls(
            llm_provider=provider,
            groq_api_key=groq_api_key,
            groq_model=groq_model,
            razorpay_key_id=razorpay_key_id,
            razorpay_key_secret=razorpay_key_secret,
            mandate_signing_kid=mandate_signing_kid,
            mandate_signing_private_key_hex=mandate_signing_private_key_hex,
            mandate_verifying_keyring_json=mandate_verifying_keyring_json,
            mandate_secret_key=mandate_secret_key,
            database_path=database_path,
            mandate_ttl_seconds=_positive_int(
                "MANDATE_TTL_SECONDS",
                300,
            ),
            max_retries=_positive_int(
                "MAX_RETRIES",
                3,
            ),
            request_timeout_seconds=_positive_float(
                "REQUEST_TIMEOUT_SECONDS",
                10.0,
            ),
            webhook_secret=webhook_secret,
            api_token=api_token,
            api_user_id=api_user_id,
            api_agent_id=api_agent_id,
            approver_token=os.getenv(
                "AGENTSHIELD_APPROVER_TOKEN",
                "agentshield-approver-token-secret-fallback-32chars",
            ).strip(),
            approval_ttl_seconds=_positive_int(
                "AGENTSHIELD_APPROVAL_TTL_SECONDS",
                900,
            ),
        )
