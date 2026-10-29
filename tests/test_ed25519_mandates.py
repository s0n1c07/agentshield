from __future__ import annotations

import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest

from engine.mandate import Ed25519MandateEngine, SUPPORTED_ALGORITHM
from models.authorization import AgentAuthorization
from models.intent import IntentItem, IntentProposal
from models.mandate import Mandate


def make_authorization(**overrides) -> AgentAuthorization:
    payload = {
        "user_id": "user_123",
        "agent_id": "agent_001",
        "authorization_id": "auth_001",
        "active": True,
        "revoked": False,
        "max_amount_paise": 500000,
        "allowed_merchants": ["merchant_001"],
        "allowed_categories": ["footwear"],
        "allowed_skus": ["shoe_001"],
        "max_quantity": 2,
        "currency": "INR",
        "created_at": datetime.now(timezone.utc),
        "expires_at": None,
    }
    payload.update(overrides)
    return AgentAuthorization.model_validate(payload)


def make_proposal(**overrides) -> IntentProposal:
    payload = {
        "user_id": "user_123",
        "agent_id": "agent_001",
        "intent_id": "intent_001",
        "raw_user_prompt": "Buy running shoes under ₹5000.",
        "merchant_id": "merchant_001",
        "amount_paise": 450000,
        "currency": "INR",
        "items": [
            {
                "sku": "shoe_001",
                "quantity": 1,
            }
        ],
        "action_type": "CREATE_ORDER",
        "nonce": "nonce_001",
        "created_at": datetime.now(timezone.utc),
        "ttl_seconds": 300,
    }
    payload.update(overrides)
    return IntentProposal.model_validate(payload)


def test_ed25519_mandate_creation_and_verification():
    key_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = key_a.public_key()
    kid_a = "key-a"

    engine = Ed25519MandateEngine(
        signing_private_key=key_a,
        signing_kid=kid_a,
        keyring={kid_a: pub_a},
    )

    auth = make_authorization()
    prop = make_proposal()

    mandate = engine.create(authorization=auth, proposal=prop)

    assert mandate.kid == "key-a"
    assert mandate.alg == "EdDSA"
    assert len(mandate.signature) == 128  # 64 bytes in hex
    assert engine.verify(mandate=mandate, authorization=auth, proposal=prop) is True


def test_ed25519_key_rotation():
    """
    Sign with kid A.
    Add kid B to keyring: both A and B can verify.
    Remove kid A from keyring: mandate signed by A is rejected.
    """
    key_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = key_a.public_key()
    kid_a = "key-a"

    key_b = ed25519.Ed25519PrivateKey.generate()
    pub_b = key_b.public_key()
    kid_b = "key-b"

    # Engine with both A and B in keyring
    engine_both = Ed25519MandateEngine(
        signing_private_key=key_a,
        signing_kid=kid_a,
        keyring={kid_a: pub_a, kid_b: pub_b},
    )

    auth = make_authorization()
    prop = make_proposal()

    mandate_a = engine_both.create(authorization=auth, proposal=prop)
    assert engine_both.verify(mandate=mandate_a, authorization=auth, proposal=prop) is True

    # Engine rotated: only key B in keyring
    engine_rotated = Ed25519MandateEngine(
        signing_private_key=key_b,
        signing_kid=kid_b,
        keyring={kid_b: pub_b},
    )

    # Mandate signed by old key A is now rejected
    assert engine_rotated.verify(mandate=mandate_a, authorization=auth, proposal=prop) is False

    # New mandate signed by key B is accepted
    mandate_b = engine_rotated.create(authorization=auth, proposal=prop)
    assert engine_rotated.verify(mandate=mandate_b, authorization=auth, proposal=prop) is True


def test_unknown_kid_rejected():
    key_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = key_a.public_key()
    kid_a = "key-a"

    engine = Ed25519MandateEngine(
        signing_private_key=key_a,
        signing_kid=kid_a,
        keyring={kid_a: pub_a},
    )

    auth = make_authorization()
    prop = make_proposal()
    mandate = engine.create(authorization=auth, proposal=prop)

    # Change kid to unknown
    tampered_mandate = mandate.model_copy(update={"kid": "unknown-key-id"})
    assert engine.verify(mandate=tampered_mandate, authorization=auth, proposal=prop) is False


def test_algorithm_downgrade_rejected():
    key_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = key_a.public_key()
    kid_a = "key-a"

    engine = Ed25519MandateEngine(
        signing_private_key=key_a,
        signing_kid=kid_a,
        keyring={kid_a: pub_a},
    )

    auth = make_authorization()
    prop = make_proposal()
    mandate = engine.create(authorization=auth, proposal=prop)

    # Attempt algorithm confusion / downgrade
    for invalid_alg in ["HS256", "RS256", "none", "Ed25519"]:
        tampered_mandate = mandate.model_copy(update={"alg": invalid_alg})
        assert engine.verify(mandate=tampered_mandate, authorization=auth, proposal=prop) is False


def test_hmac_style_forged_mandate_rejected():
    key_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = key_a.public_key()
    kid_a = "key-a"

    engine = Ed25519MandateEngine(
        signing_private_key=key_a,
        signing_kid=kid_a,
        keyring={kid_a: pub_a},
    )

    auth = make_authorization()
    prop = make_proposal()

    # Forge an HMAC signature
    fake_hmac = hmac.new(b"secret", b"payload", hashlib.sha256).hexdigest()

    forged_mandate = Mandate(
        user_id=prop.user_id,
        agent_id=prop.agent_id,
        merchant_id=prop.merchant_id,
        amount_paise=prop.amount_paise,
        intent_hash="a" * 64,
        nonce=prop.nonce,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=300),
        kid=kid_a,
        alg="EdDSA",
        signature=fake_hmac,  # 32 bytes hex, not valid 64 bytes Ed25519 sig
    )

    assert engine.verify(mandate=forged_mandate, authorization=auth, proposal=prop) is False


def test_field_tampering_rejected():
    key_a = ed25519.Ed25519PrivateKey.generate()
    pub_a = key_a.public_key()
    kid_a = "key-a"

    engine = Ed25519MandateEngine(
        signing_private_key=key_a,
        signing_kid=kid_a,
        keyring={kid_a: pub_a},
    )

    auth = make_authorization()
    prop = make_proposal()
    mandate = engine.create(authorization=auth, proposal=prop)

    # Tamper amount
    tampered_amount = mandate.model_copy(update={"amount_paise": 999999})
    assert engine.verify(mandate=tampered_amount, authorization=auth, proposal=prop) is False

    # Tamper user_id
    tampered_user = mandate.model_copy(update={"user_id": "user_evil"})
    assert engine.verify(mandate=tampered_user, authorization=auth, proposal=prop) is False

    # Tamper agent_id
    tampered_agent = mandate.model_copy(update={"agent_id": "agent_evil"})
    assert engine.verify(mandate=tampered_agent, authorization=auth, proposal=prop) is False

    # Tamper merchant_id
    tampered_merchant = mandate.model_copy(update={"merchant_id": "merchant_evil"})
    assert engine.verify(mandate=tampered_merchant, authorization=auth, proposal=prop) is False

    # Tamper nonce
    tampered_nonce = mandate.model_copy(update={"nonce": "nonce_tampered"})
    assert engine.verify(mandate=tampered_nonce, authorization=auth, proposal=prop) is False

    # Tamper intent hash
    tampered_hash = mandate.model_copy(update={"intent_hash": "b" * 64})
    assert engine.verify(mandate=tampered_hash, authorization=auth, proposal=prop) is False
