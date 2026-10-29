from __future__ import annotations

import concurrent.futures
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from engine.budget import SQLiteSpendLedger, SpendLedgerStatus
from models.authorization import AgentAuthorization


def make_authorization(**overrides) -> AgentAuthorization:
    payload = {
        "user_id": "user_123",
        "agent_id": "agent_001",
        "authorization_id": "auth_budget_001",
        "active": True,
        "revoked": False,
        "max_amount_paise": 500000,  # ₹5,000 per txn
        "daily_limit_paise": 1000000,  # ₹10,000 per day
        "monthly_limit_paise": 3000000,  # ₹30,000 per month
        "timezone": "Asia/Kolkata",
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


def test_concurrency_budget_reservation_limits_burst(tmp_path: Path):
    """
    20 concurrent threads attempt to reserve ₹2,000 each against a ₹10,000 daily limit.
    Total requested: ₹40,000.
    At most 5 threads must succeed (5 x ₹2,000 = ₹10,000).
    The remaining 15 must be rejected.
    Total reserved in the database must never exceed ₹10,000.
    """
    db_path = tmp_path / "budget_concurrent.db"
    ledger = SQLiteSpendLedger(db_path)
    auth = make_authorization(daily_limit_paise=1000000)

    num_threads = 20
    amount_per_thread = 200000  # ₹2,000

    results = []

    def attempt_reservation(index: int):
        txn_id = f"txn-burst-{index}"
        # Use separate ledger instances across threads to test DB-level concurrency
        thread_ledger = SQLiteSpendLedger(db_path)
        return thread_ledger.reserve(
            transaction_id=txn_id,
            authorization=auth,
            amount_paise=amount_per_thread,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attempt_reservation, i) for i in range(num_threads)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r[0] is True]
    failures = [r for r in results if r[0] is False]

    assert len(successes) == 5, f"Expected exactly 5 successes, got {len(successes)}"
    assert len(failures) == 15, f"Expected 15 failures, got {len(failures)}"

    for fail in failures:
        assert "DAILY_LIMIT_EXCEEDED" in fail[1]

    # Verify database aggregate
    window_date, window_month = SQLiteSpendLedger.get_windows(auth.timezone)
    daily, monthly = ledger.get_aggregate_spend(
        authorization_id=auth.authorization_id,
        window_date=window_date,
        window_month=window_month,
    )
    assert daily == 1000000
    assert daily <= auth.daily_limit_paise


def test_idempotent_retry_does_not_double_reserve(tmp_path: Path):
    db_path = tmp_path / "budget_idempotent.db"
    ledger = SQLiteSpendLedger(db_path)
    auth = make_authorization(daily_limit_paise=1000000)

    txn_id = "txn-idem-001"
    amount = 400000  # ₹4,000

    # First reservation
    res1, msg1 = ledger.reserve(
        transaction_id=txn_id,
        authorization=auth,
        amount_paise=amount,
    )
    assert res1 is True
    assert msg1 == "BUDGET_RESERVED"

    # Retry same transaction
    res2, msg2 = ledger.reserve(
        transaction_id=txn_id,
        authorization=auth,
        amount_paise=amount,
    )
    assert res2 is True
    assert msg2 == "ALREADY_RESERVED"

    # Total spend should only be 400000, not 800000
    window_date, window_month = SQLiteSpendLedger.get_windows(auth.timezone)
    daily, _ = ledger.get_aggregate_spend(
        authorization_id=auth.authorization_id,
        window_date=window_date,
        window_month=window_month,
    )
    assert daily == 400000


def test_calendar_window_rollover(tmp_path: Path):
    db_path = tmp_path / "budget_rollover.db"
    ledger = SQLiteSpendLedger(db_path)
    auth = make_authorization(
        daily_limit_paise=500000,  # ₹5,000 / day
        monthly_limit_paise=2000000,  # ₹20,000 / month
    )

    day1 = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
    day2 = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)

    # Exhaust day 1 budget
    res1, _ = ledger.reserve(
        transaction_id="txn-day1",
        authorization=auth,
        amount_paise=500000,
        now=day1,
    )
    assert res1 is True

    # Attempting more on day 1 is blocked
    res_block, msg_block = ledger.reserve(
        transaction_id="txn-day1-overflow",
        authorization=auth,
        amount_paise=100000,
        now=day1,
    )
    assert res_block is False
    assert "DAILY_LIMIT_EXCEEDED" in msg_block

    # On day 2, daily budget resets and succeeds
    res_day2, msg_day2 = ledger.reserve(
        transaction_id="txn-day2",
        authorization=auth,
        amount_paise=500000,
        now=day2,
    )
    assert res_day2 is True
    assert msg_day2 == "BUDGET_RESERVED"

    # Monthly total tracks across both days (1000000 total)
    _, window_month = SQLiteSpendLedger.get_windows(auth.timezone, now=day2)
    _, monthly = ledger.get_aggregate_spend(
        authorization_id=auth.authorization_id,
        window_date="2026-10-16",
        window_month=window_month,
    )
    assert monthly == 1000000


def test_release_on_failure_frees_budget(tmp_path: Path):
    db_path = tmp_path / "budget_release.db"
    ledger = SQLiteSpendLedger(db_path)
    auth = make_authorization(daily_limit_paise=500000)

    # Reserve ₹5,000 (exhausts daily limit)
    res1, _ = ledger.reserve(
        transaction_id="txn-fail-001",
        authorization=auth,
        amount_paise=500000,
    )
    assert res1 is True

    # Next attempt blocked
    res2, _ = ledger.reserve(
        transaction_id="txn-next-001",
        authorization=auth,
        amount_paise=200000,
    )
    assert res2 is False

    # Simulate definitive pre-dispatch failure: compensating release
    released = ledger.release("txn-fail-001")
    assert released is True

    record = ledger.get("txn-fail-001")
    assert record.status == SpendLedgerStatus.RELEASED

    # Now the next attempt can reserve successfully
    res3, msg3 = ledger.reserve(
        transaction_id="txn-next-001",
        authorization=auth,
        amount_paise=200000,
    )
    assert res3 is True
    assert msg3 == "BUDGET_RESERVED"


def test_unknown_outcome_retains_reservation(tmp_path: Path):
    db_path = tmp_path / "budget_unknown.db"
    ledger = SQLiteSpendLedger(db_path)
    auth = make_authorization(daily_limit_paise=500000)

    # Reserve ₹5,000
    res1, _ = ledger.reserve(
        transaction_id="txn-unknown-001",
        authorization=auth,
        amount_paise=500000,
    )
    assert res1 is True

    # On unknown state, release is NOT called (funds may have moved).
    # Status remains RESERVED:
    rec = ledger.get("txn-unknown-001")
    assert rec.status == SpendLedgerStatus.RESERVED

    # Another transaction must still be blocked to protect conservative financial limit
    res2, msg2 = ledger.reserve(
        transaction_id="txn-unknown-002",
        authorization=auth,
        amount_paise=100000,
    )
    assert res2 is False
    assert "DAILY_LIMIT_EXCEEDED" in msg2
