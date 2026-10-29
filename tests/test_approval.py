from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from api.dependencies import configure_app
from api.main import create_app
from application.orchestrator import (
    AgentShieldOrchestrator,
    OrchestrationError,
)
from engine.approval import SQLiteApprovalStore
from engine.audit import SQLiteAuditTrail
from engine.authorization import SQLiteAuthorizationAuthority
from engine.budget import SQLiteSpendLedger
from engine.catalog import SQLiteCatalog
from engine.hashing import IntentHasher
from engine.idempotency import WALIdempotencyStore
from engine.mandate import AP2AlignedMandateEngine
from engine.policy import DeterministicPolicyEngine
from engine.transaction_store import SQLiteTransactionStore
from models.approval import ApprovalRecord, ApprovalStatus
from models.audit import AuditEventType
from models.authorization import (
    AgentAuthorization,
    AuthorizationDecision,
    AuthorizationEvaluation,
)
from models.catalog import CatalogProduct
from models.intent import (
    AgentRequestAnalysis,
    AuthorizationInterpretation,
    IntentItem,
    IntentProposal,
)
from models.policy import TransactionPolicy
from models.transaction import TransactionRecord, TransactionState


def make_keypair() -> tuple[str, str, dict[str, str]]:
    kid = "key-test-01"
    priv = ed25519.Ed25519PrivateKey.generate()
    seed_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    keyring = {kid: pub_hex}
    return kid, seed_hex, keyring


def make_test_analysis(amount_paise: int = 450000, intent_id: str = "intent_001") -> AgentRequestAnalysis:
    now = datetime.now(timezone.utc)
    proposal = IntentProposal(
        user_id="user_123",
        agent_id="agent_001",
        intent_id=intent_id,
        raw_user_prompt="Buy running shoes under ₹5000.",
        merchant_id="merchant_001",
        amount_paise=amount_paise,
        currency="INR",
        items=[IntentItem(sku="shoe_001", quantity=1)],
        action_type="CREATE_ORDER",
        nonce="nonce_001",
        created_at=now,
        ttl_seconds=300,
    )
    auth_interp = AuthorizationInterpretation(
        max_amount_paise=500000,
        currency="INR",
        product_constraints=["running shoes"],
        allowed_merchants=[],
        max_quantity=1,
        constraints=["running shoes", "maximum ₹5000"],
    )
    return AgentRequestAnalysis(
        raw_user_prompt="Buy running shoes under ₹5000.",
        authorization=auth_interp,
        intent_proposal=proposal,
    )


class FakeIntentParser:
    def __init__(self, amount_paise: int = 450000):
        self.amount_paise = amount_paise

    def parse(self, user_message, *, user_id, agent_id, intent_id, merchant_context=None):
        return make_test_analysis(self.amount_paise, intent_id=intent_id)


class FakeRazorpayOrder:
    def __init__(self, amount_paise: int):
        self.order_id = "order_test_123"
        self.amount_paise = amount_paise
        self.currency = "INR"
        self.status = "created"


class FakeRazorpayClient:
    def __init__(self):
        self.calls: list[dict[str, object]] = []

    async def create_order(self, *, amount_paise, currency, receipt, notes):
        self.calls.append({
            "amount_paise": amount_paise,
            "currency": currency,
            "receipt": receipt,
            "notes": notes,
        })
        return FakeRazorpayOrder(amount_paise)


def setup_orchestrator(
    tmp_path: Path,
    approval_threshold_paise: int | None = 400000,
    amount_paise: int = 450000,
    active_auth: bool = True,
    revoked_auth: bool = False,
    approval_ttl_seconds: int = 900,
):
    kid, priv_hex, keyring = make_keypair()
    hasher = IntentHasher()
    mandate_engine = AP2AlignedMandateEngine(
        signing_private_key=priv_hex,
        signing_kid=kid,
        keyring=keyring,
        hasher=hasher,
    )

    auth_store = SQLiteAuthorizationAuthority(str(tmp_path / "auth.db"))
    auth = AgentAuthorization(
        user_id="user_123",
        agent_id="agent_001",
        authorization_id="auth_001",
        active=active_auth,
        revoked=revoked_auth,
        max_amount_paise=500000,
        allowed_merchants=["merchant_001"],
        allowed_categories=["footwear"],
        allowed_skus=["shoe_001"],
        max_quantity=2,
        currency="INR",
        approval_threshold_paise=approval_threshold_paise,
    )
    auth_store.create(auth)

    catalog = SQLiteCatalog(str(tmp_path / "catalog.db"))
    catalog.create(
        CatalogProduct(
            merchant_id="merchant_001",
            sku="shoe_001",
            name="Running Shoes",
            category="footwear",
            price_paise=amount_paise,
            currency="INR",
            stock=10,
        )
    )

    def auth_check(analysis: AgentRequestAnalysis) -> AuthorizationEvaluation:
        return auth_store.check(analysis.intent_proposal)

    def policy_provider(analysis: AgentRequestAnalysis) -> TransactionPolicy:
        return TransactionPolicy(
            user_id="user_123",
            agent_id="agent_001",
            max_amount_paise=500000,
            min_amount_paise=1000,
            allowed_merchants=["merchant_001"],
            allowed_categories=[],
            allowed_skus=["shoe_001"],
            max_quantity=2,
            currency="INR",
        )

    audit_trail = SQLiteAuditTrail(str(tmp_path / "audit.db"))
    transaction_store = SQLiteTransactionStore(str(tmp_path / "txn.db"))
    idempotency_store = WALIdempotencyStore(str(tmp_path / "idemp.db"))
    spend_ledger = SQLiteSpendLedger(str(tmp_path / "budget.db"))
    approval_store = SQLiteApprovalStore(str(tmp_path / "approval.db"))
    razorpay = FakeRazorpayClient()

    orchestrator = AgentShieldOrchestrator(
        intent_parser=FakeIntentParser(amount_paise=amount_paise),
        authorization_check=auth_check,
        policy_engine=DeterministicPolicyEngine(),
        intent_hasher=hasher,
        mandate_engine=mandate_engine,
        idempotency_store=idempotency_store,
        razorpay=razorpay,
        policy_provider=policy_provider,
        audit_trail=audit_trail,
        transaction_store=transaction_store,
        catalog=catalog,
        spend_ledger=spend_ledger,
        approval_store=approval_store,
        approval_ttl_seconds=approval_ttl_seconds,
    )

    return {
        "orchestrator": orchestrator,
        "auth_store": auth_store,
        "transaction_store": transaction_store,
        "approval_store": approval_store,
        "audit_trail": audit_trail,
        "razorpay": razorpay,
        "auth": auth,
    }


@pytest.mark.asyncio
async def test_transaction_below_threshold_proceeds_without_approval(tmp_path: Path):
    """
    1. Transaction below threshold proceeds directly without approval.
    """
    # Amount 450000 is below 500000 threshold
    env = setup_orchestrator(tmp_path, approval_threshold_paise=500000, amount_paise=450000)
    orchestrator = env["orchestrator"]
    razorpay = env["razorpay"]
    approval_store = env["approval_store"]

    res = await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_below_01",
        idempotency_key="idemp_below_01",
    )

    assert res.status == "DISPATCHED"
    assert res.transaction.state == TransactionState.DISPATCHED
    assert res.mandate is not None
    assert len(razorpay.calls) == 1
    assert approval_store.get("txn_below_01") is None


@pytest.mark.asyncio
async def test_transaction_at_or_above_threshold_enters_pending_approval(tmp_path: Path):
    """
    2. Transaction at or above threshold enters PENDING_APPROVAL with no mandate or Razorpay call.
    Also verifies idempotent polling returns the pending transaction.
    """
    # Amount 450000 is >= 400000 threshold
    env = setup_orchestrator(tmp_path, approval_threshold_paise=400000, amount_paise=450000)
    orchestrator = env["orchestrator"]
    razorpay = env["razorpay"]
    approval_store = env["approval_store"]

    res = await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_above_01",
        idempotency_key="idemp_above_01",
    )

    assert res.status == "PENDING_APPROVAL"
    assert res.transaction.state == TransactionState.PENDING_APPROVAL
    assert res.mandate is None  # Mandate NOT created yet
    assert len(razorpay.calls) == 0  # No payment call made

    record = approval_store.get("txn_above_01")
    assert record is not None
    assert record.status == ApprovalStatus.PENDING
    assert record.amount_paise == 450000
    assert record.intent_hash == res.transaction.intent_hash

    # Calling execute again with same idempotency key while pending returns the pending transaction (idempotent poll)
    poll_res = await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_002",
        transaction_id="txn_above_02",
        idempotency_key="idemp_above_01",
    )
    assert poll_res.transaction.transaction_id == "txn_above_01"
    assert poll_res.transaction.state == TransactionState.PENDING_APPROVAL


@pytest.mark.asyncio
async def test_approved_transaction_completes_execution_and_creates_razorpay_order(tmp_path: Path):
    """
    3. Approved transaction completes execution, generates Ed25519 mandate, and creates Razorpay order.
    """
    env = setup_orchestrator(tmp_path, approval_threshold_paise=400000, amount_paise=450000)
    orchestrator = env["orchestrator"]
    razorpay = env["razorpay"]
    approval_store = env["approval_store"]
    audit_trail = env["audit_trail"]

    await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_approve_01",
        idempotency_key="idemp_approve_01",
    )

    assert len(razorpay.calls) == 0

    approved_tx = await orchestrator.approve_transaction(
        transaction_id="txn_approve_01",
        approver_principal="human_admin_01",
        reason="Verified purchase request",
    )

    assert approved_tx.state == TransactionState.DISPATCHED
    assert approved_tx.razorpay_order_id == "order_test_123"
    assert len(razorpay.calls) == 1

    app_record = approval_store.get("txn_approve_01")
    assert app_record.status == ApprovalStatus.APPROVED
    assert app_record.decided_by == "human_admin_01"

    events = [e.event_type for e in audit_trail.list_events(transaction_id="txn_approve_01")]
    assert AuditEventType.APPROVAL_REQUESTED in events
    assert AuditEventType.APPROVAL_APPROVED in events
    assert AuditEventType.MANDATE_CREATED in events
    assert AuditEventType.MANDATE_VERIFIED in events
    assert AuditEventType.RAZORPAY_DISPATCHED in events


@pytest.mark.asyncio
async def test_rejected_transaction_enters_approval_rejected_and_creates_no_order(tmp_path: Path):
    """
    4. Rejected transaction enters APPROVAL_REJECTED and creates NO Razorpay order.
    """
    env = setup_orchestrator(tmp_path, approval_threshold_paise=400000, amount_paise=450000)
    orchestrator = env["orchestrator"]
    razorpay = env["razorpay"]
    approval_store = env["approval_store"]
    audit_trail = env["audit_trail"]

    await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_reject_01",
        idempotency_key="idemp_reject_01",
    )

    rejected_tx = orchestrator.reject_transaction(
        transaction_id="txn_reject_01",
        approver_principal="human_admin_01",
        reason="Exceeds personal budget limit",
    )

    assert rejected_tx.state == TransactionState.APPROVAL_REJECTED
    assert len(razorpay.calls) == 0

    app_record = approval_store.get("txn_reject_01")
    assert app_record.status == ApprovalStatus.REJECTED
    assert app_record.decision_reason == "Exceeds personal budget limit"

    events = [e.event_type for e in audit_trail.list_events(transaction_id="txn_reject_01")]
    assert AuditEventType.APPROVAL_REQUESTED in events
    assert AuditEventType.APPROVAL_REJECTED in events
    assert AuditEventType.RAZORPAY_DISPATCHED not in events


@pytest.mark.asyncio
async def test_expired_approval_cannot_be_approved(tmp_path: Path):
    """
    5. Expired approval cannot be approved (returns error and transitions to APPROVAL_EXPIRED).
    """
    # Negative TTL guarantees immediate expiration
    env = setup_orchestrator(
        tmp_path,
        approval_threshold_paise=400000,
        amount_paise=450000,
        approval_ttl_seconds=-10,
    )
    orchestrator = env["orchestrator"]
    transaction_store = env["transaction_store"]

    await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_expired_01",
        idempotency_key="idemp_expired_01",
    )

    with pytest.raises(OrchestrationError, match="expired"):
        await orchestrator.approve_transaction(
            transaction_id="txn_expired_01",
            approver_principal="human_admin_01",
        )

    tx = transaction_store.get("txn_expired_01")
    assert tx.state == TransactionState.APPROVAL_EXPIRED


def test_agent_token_cannot_call_approve_or_reject_returns_403(tmp_path: Path):
    """
    6. Agent token cannot call /approve or /reject (403 Forbidden). Token separation invariant.
    """
    app = create_app()
    agent_token = "agent-secret-token-32-chars-long-abc"
    approver_token = "approver-secret-token-32-chars-long-xyz"

    env = setup_orchestrator(tmp_path)
    configure_app(
        app,
        orchestrator=env["orchestrator"],
        transaction_store=env["transaction_store"],
        audit_trail=env["audit_trail"],
        approval_store=env["approval_store"],
        api_token=agent_token,
        api_user_id="user_123",
        api_agent_id="agent_001",
        approver_token=approver_token,
    )

    client = TestClient(app)

    # 1. Calling /approve with agent token returns 403 Forbidden
    resp = client.post(
        "/v1/transactions/txn_test/approve",
        headers={"Authorization": f"Bearer {agent_token}"},
        json={"reason": "Self-approval attempt"},
    )
    assert resp.status_code == 403
    assert "Agent token cannot approve" in resp.json()["detail"]

    # 2. Calling /reject with agent token returns 403 Forbidden
    resp = client.post(
        "/v1/transactions/txn_test/reject",
        headers={"Authorization": f"Bearer {agent_token}"},
        json={"reason": "Self-rejection attempt"},
    )
    assert resp.status_code == 403
    assert "Agent token cannot approve" in resp.json()["detail"]

    # 3. Calling /approve without token returns 401 Unauthorized
    resp = client.post("/v1/transactions/txn_test/approve")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_revoking_authorization_while_approval_pending_causes_approve_to_fail(tmp_path: Path):
    """
    7. Revoking authorization while approval is pending causes /approve to fail (re-check catches it).
    """
    env = setup_orchestrator(tmp_path, approval_threshold_paise=400000, amount_paise=450000)
    orchestrator = env["orchestrator"]
    auth_store = env["auth_store"]
    razorpay = env["razorpay"]

    await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_revoke_01",
        idempotency_key="idemp_revoke_01",
    )

    # User revokes the authorization while transaction was pending approval
    auth_store.revoke("auth_001")

    # Approver now attempts to approve
    with pytest.raises(OrchestrationError, match="Authorization revalidation failed"):
        await orchestrator.approve_transaction(
            transaction_id="txn_revoke_01",
            approver_principal="human_admin_01",
        )

    # Zero payment orders created
    assert len(razorpay.calls) == 0


@pytest.mark.asyncio
async def test_tampered_intent_hash_causes_approve_to_fail(tmp_path: Path):
    """
    8. Tampered intent hash causes /approve to fail. Cryptographic intent binding invariant.
    """
    env = setup_orchestrator(tmp_path, approval_threshold_paise=400000, amount_paise=450000)
    orchestrator = env["orchestrator"]
    approval_store = env["approval_store"]
    razorpay = env["razorpay"]

    await orchestrator.execute(
        user_message="Buy running shoes",
        user_id="user_123",
        agent_id="agent_001",
        intent_id="intent_001",
        transaction_id="txn_tamper_01",
        idempotency_key="idemp_tamper_01",
    )

    # Attacker tampers with the intent hash in the approval store
    connection = approval_store._connect()
    try:
        connection.execute(
            "UPDATE approvals SET intent_hash = ? WHERE transaction_id = ?",
            ("f" * 64, "txn_tamper_01"),
        )
    finally:
        connection.close()

    with pytest.raises(OrchestrationError, match="intent hash"):
        await orchestrator.approve_transaction(
            transaction_id="txn_tamper_01",
            approver_principal="human_admin_01",
        )

    assert len(razorpay.calls) == 0
