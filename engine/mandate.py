from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from engine.hashing import IntentHasher
from models.authorization import AgentAuthorization
from models.intent import IntentProposal
from models.mandate import Mandate

DOMAIN_SEPARATOR = "agentshield-mandate-v1"
SUPPORTED_ALGORITHM = "EdDSA"


class Ed25519MandateEngine:
    """
    AP2-aligned asymmetric mandate engine powered by Ed25519 (EdDSA).

    Responsibilities:
    - Create cryptographically signed mandates with an Ed25519 private key.
    - Embed domain separation prefix ("agentshield-mandate-v1"), kid, and alg in payload.
    - Verify mandate authenticity using a public keyring (supporting key rotation).
    - Pin verification strictly to Ed25519 / EdDSA (prevents algorithm downgrade/confusion).
    - Verify freshness and bound intent hash.
    """

    def __init__(
        self,
        signing_private_key: ed25519.Ed25519PrivateKey | bytes | str | None = None,
        *,
        signing_kid: str | None = None,
        keyring: dict[str, ed25519.Ed25519PublicKey | bytes | str] | None = None,
        hasher: IntentHasher | None = None,
        secret_key: bytes | None = None,  # Deprecated legacy compatibility parameter
    ) -> None:
        self._hasher = hasher or IntentHasher()
        self._keyring: dict[str, ed25519.Ed25519PublicKey] = {}
        self._signing_key: ed25519.Ed25519PrivateKey | None = None
        self._signing_kid: str | None = signing_kid

        # Handle legacy secret_key fallback for backwards compatibility with tests
        if secret_key is not None and signing_private_key is None and not keyring:
            seed = hashlib.sha256(secret_key).digest()
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            self._signing_key = priv
            self._signing_kid = signing_kid or "kid-default"
            self._keyring[self._signing_kid] = priv.public_key()
            return

        if isinstance(signing_private_key, bytes) and len(signing_private_key) != 32 and not keyring:
            seed = hashlib.sha256(signing_private_key).digest()
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
            self._signing_key = priv
            self._signing_kid = signing_kid or "kid-default"
            self._keyring[self._signing_kid] = priv.public_key()
            return

        # Parse keyring
        if keyring:
            for kid, pub_key in keyring.items():
                self._keyring[kid] = self._parse_public_key(pub_key)

        # Parse signing key
        if signing_private_key is not None:
            self._signing_key = self._parse_private_key(signing_private_key)
            if not self._signing_kid:
                raise ValueError("signing_kid is required when signing_private_key is provided")
            
            # Automatically add signing key's public key to keyring if not already present
            pub = self._signing_key.public_key()
            if self._signing_kid not in self._keyring:
                self._keyring[self._signing_kid] = pub

    @staticmethod
    def _parse_private_key(
        key: ed25519.Ed25519PrivateKey | bytes | str,
    ) -> ed25519.Ed25519PrivateKey:
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key
        if isinstance(key, str):
            key = bytes.fromhex(key.strip())
        if not isinstance(key, bytes):
            raise TypeError("Private key must be Ed25519PrivateKey, bytes, or hex str")
        if len(key) != 32:
            raise ValueError(f"Ed25519 private key must be exactly 32 bytes, got {len(key)}")
        return ed25519.Ed25519PrivateKey.from_private_bytes(key)

    @staticmethod
    def _parse_public_key(
        key: ed25519.Ed25519PublicKey | bytes | str,
    ) -> ed25519.Ed25519PublicKey:
        if isinstance(key, ed25519.Ed25519PublicKey):
            return key
        if isinstance(key, str):
            key = bytes.fromhex(key.strip())
        if not isinstance(key, bytes):
            raise TypeError("Public key must be Ed25519PublicKey, bytes, or hex str")
        if len(key) != 32:
            raise ValueError(f"Ed25519 public key must be exactly 32 bytes, got {len(key)}")
        return ed25519.Ed25519PublicKey.from_public_bytes(key)

    def create(
        self,
        *,
        authorization: AgentAuthorization,
        proposal: IntentProposal,
        issued_at: datetime | None = None,
    ) -> Mandate:
        """
        Create an Ed25519-signed mandate for an already-governed proposal.
        """
        if self._signing_key is None or not self._signing_kid:
            raise ValueError("Signing key and signing_kid must be configured to create mandates")

        if issued_at is None:
            issued_at = datetime.now(timezone.utc)

        if issued_at.tzinfo is None:
            issued_at = issued_at.replace(tzinfo=timezone.utc)

        intent_hash = self._hasher.hash(
            authorization,
            proposal,
        )

        issued_at, expires_at = Mandate.create_times(
            issued_at=issued_at,
            ttl_seconds=proposal.ttl_seconds,
        )

        payload = self._signature_payload(
            kid=self._signing_kid,
            alg=SUPPORTED_ALGORITHM,
            user_id=proposal.user_id,
            agent_id=proposal.agent_id,
            merchant_id=proposal.merchant_id,
            amount_paise=proposal.amount_paise,
            intent_hash=intent_hash,
            nonce=proposal.nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )

        signature_bytes = self._signing_key.sign(payload)
        signature = signature_bytes.hex()

        return Mandate(
            user_id=proposal.user_id,
            agent_id=proposal.agent_id,
            merchant_id=proposal.merchant_id,
            amount_paise=proposal.amount_paise,
            intent_hash=intent_hash,
            nonce=proposal.nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            kid=self._signing_kid,
            alg=SUPPORTED_ALGORITHM,
            signature=signature,
        )

    def verify(
        self,
        *,
        mandate: Mandate,
        authorization: AgentAuthorization,
        proposal: IntentProposal,
        now: datetime | None = None,
    ) -> bool:
        """
        Verify an Ed25519 mandate.

        Checks:
        1. Algorithm must be pinned strictly to EdDSA.
        2. Mandate Key ID (kid) must exist in the verifying keyring.
        3. Identity binding: user_id, agent_id, merchant_id match.
        4. Amount and nonce binding match.
        5. Time validity (issued_at <= now < expires_at).
        6. Recomputed intent hash matches.
        7. Cryptographic Ed25519 signature is authentic over the domain-separated payload.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        # 1. Algorithm pinning (reject algorithm confusion or downgrade)
        if mandate.alg != SUPPORTED_ALGORITHM:
            return False

        # 2. Key ID existence in active keyring
        public_key = self._keyring.get(mandate.kid)
        if public_key is None:
            return False

        # 3. Identity binding
        if proposal.user_id != mandate.user_id:
            return False

        if proposal.agent_id != mandate.agent_id:
            return False

        if proposal.merchant_id != mandate.merchant_id:
            return False

        # 4. Amount binding
        if proposal.amount_paise != mandate.amount_paise:
            return False

        # 5. Nonce binding
        if proposal.nonce != mandate.nonce:
            return False

        # 6. Time validity
        if now < mandate.issued_at:
            return False

        if now >= mandate.expires_at:
            return False

        # 7. Recomputed intent hash
        current_intent_hash = self._hasher.hash(
            authorization,
            proposal,
        )

        if not hmac.compare_digest(
            current_intent_hash,
            mandate.intent_hash,
        ):
            return False

        # 8. Cryptographic verification with pinned algorithm
        payload = self._signature_payload(
            kid=mandate.kid,
            alg=SUPPORTED_ALGORITHM,  # Always use pinned alg, never untrusted input
            user_id=mandate.user_id,
            agent_id=mandate.agent_id,
            merchant_id=mandate.merchant_id,
            amount_paise=mandate.amount_paise,
            intent_hash=mandate.intent_hash,
            nonce=mandate.nonce,
            issued_at=mandate.issued_at,
            expires_at=mandate.expires_at,
        )

        try:
            signature_bytes = bytes.fromhex(mandate.signature)
            public_key.verify(signature_bytes, payload)
            return True
        except (ValueError, InvalidSignature):
            return False

    @staticmethod
    def _signature_payload(
        *,
        kid: str,
        alg: str,
        user_id: str,
        agent_id: str,
        merchant_id: str,
        amount_paise: int,
        intent_hash: str,
        nonce: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> bytes:
        payload_str = "|".join(
            [
                DOMAIN_SEPARATOR,
                kid,
                alg,
                user_id,
                agent_id,
                merchant_id,
                str(amount_paise),
                intent_hash,
                nonce,
                issued_at.isoformat(),
                expires_at.isoformat(),
            ]
        )
        return payload_str.encode("utf-8")


# Alias for backward compatibility across existing references
AP2AlignedMandateEngine = Ed25519MandateEngine