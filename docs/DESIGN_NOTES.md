# AgentShield Architectural Design Notes & Interview Preparation

## Baseline System Measurements

Before any code changes were introduced, the existing baseline test suites were executed on Python 3.12:
- **Pytest Suite**: `352 passed, 0 failed, 1 warning in 17.19s`
- **Evaluation Benchmark (`scripts.run_evaluation`)**: `71 cases, 71 passed, 0 failed, 0.0000 bypass/unsafe rate`
- **Adversarial Benchmark (`scripts.run_adversarial`)**: `20 cases, 20 passed, 0 failed, 0.0000 bypass/unsafe rate`

*(Note: On Windows environments, `TemporaryDirectory` cleanup requires `ignore_cleanup_errors=True` due to open SQLite file descriptors. This was configured in `evaluation/adversarial_runner.py` without altering any security or business logic).*

---

## Extension Implementation Plan & File Touch Map

### Extension 3: Ed25519 Mandate Signatures (Replace Shared-Secret HMAC)
**Goal**: Transition mandate signing and verification from shared-secret HMAC-SHA256 to asymmetric Ed25519 (EdDSA). Mandates become verifiable by third-party rails or downstream auditors without distributing private signing keys.

#### Files Touched:
- `models/mandate.py`:
  - Add `kid: StrictStr` (Key Identifier).
  - Add `alg: StrictStr = Field(default="EdDSA")`.
- `engine/mandate.py`:
  - Implement `Ed25519MandateEngine` (and deprecate/replace `AP2AlignedMandateEngine`).
  - Domain separation prefix: `"agentshield-mandate-v1"`.
  - Signature payload: `f"agentshield-mandate-v1|{kid}|{alg}|{user_id}|{agent_id}|{merchant_id}|{amount_paise}|{intent_hash}|{nonce}|{issued_at.isoformat()}|{expires_at.isoformat()}"`.
  - Verification: Algorithm pinned strictly to `"EdDSA"`. Caller cannot select or downgrade algorithm. Verifies against a Keyring (`dict[str, Ed25519PublicKey]`).
- `config.py` / `models/settings.py`:
  - Replace/deprecate `MANDATE_SECRET_KEY`.
  - Add `MANDATE_SIGNING_PRIVATE_KEY_HEX` (or base64/PEM) and `MANDATE_SIGNING_KID`.
  - Add `MANDATE_VERIFYING_KEYRING_JSON` (mapping of kid -> public key hex).
  - Validate at startup; fail-fast if active kid not in keyring or invalid key format.
- `application/container.py`:
  - Wire `Ed25519MandateEngine` with configured signing key and public keyring.
- `application/orchestrator.py`:
  - Update any direct references to mandate engine.
- `scripts/generate_signing_key.py`:
  - New utility script to generate fresh Ed25519 keypair, format hex strings, and output environment variables.
- `scripts/seed_demo_data.py`:
  - Update seed data and demo setup with Ed25519 keys.
- `.env.example`:
  - Document `MANDATE_SIGNING_PRIVATE_KEY_HEX`, `MANDATE_SIGNING_KID`, and `MANDATE_VERIFYING_KEYRING_JSON`.
- `tests/test_mandate.py` (and new test files):
  - Key rotation (kid A + kid B, sign A, verify both; remove A, verify fails).
  - Tamper tests (alter each field: amount, user, nonce, timestamps).
  - Alg downgrade attacks (attempt HMAC, none, RSA).
  - Unknown kid rejection.
- `evaluation/adversarial_scenarios.py` & `evaluation/adversarial_runner.py`:
  - Add adversarial test scenarios for algorithm downgrade and key spoofing.

#### Ambiguities & Conservative Decisions:
1. **Key Format**: Hex vs PEM vs Base64?
   - *Conservative Choice*: Raw 32-byte Ed25519 seed/private key in hexadecimal (64 hex characters) and public key in hexadecimal (64 hex characters). Standard RFC 8032 format, concise in environment variables and JSON strings, no multi-line newline formatting issues.
2. **Algorithm Pinning**: If a mandate header specifies `alg="HS256"`, should it be evaluated via HMAC?
   - *Conservative Choice*: Absolutely not. The verifier strictly pins `expected_alg="EdDSA"`. If `mandate.alg != "EdDSA"`, verification immediately returns `False` and audits an invalid algorithm attempt.
3. **Key Rotation Lifecycle**: What happens when an active signing key is rotated out?
   - *Conservative Choice*: Mandates signed by the old key can still be verified as long as the old key's `kid` remains in `MANDATE_VERIFYING_KEYRING_JSON`. Once removed from the keyring, verification immediately fails.

#### What Ed25519 Asymmetric Mandates Do and Do Not Buy:
- **What it buys**:
  - **Separation of Signing vs Verification Capabilities**: Verification now strictly requires only the public key. Any downstream service, audit worker, or payment rail adapter can independently verify mandate authenticity without possessing the private signing key.
  - **Key Rotation without Secrets Exposure**: Public keyrings allow seamless key rotation (`kid`) without distributing shared secrets across components.
  - **Future Architectural Decoupling**: The signer can later be extracted into an isolated Hardware Security Module (HSM), KMS, or standalone signing enclave without changing the verifier interface.
- **What it does NOT buy**:
  - In the current single-process architecture, both the orchestrator (which signs) and the verifier execute in the same Python process. A process-level memory compromise could still compromise the private key in memory. True defense-in-depth requires isolating the signing key into a KMS or sidecar service.

---

### Extension 1: Cumulative Spending Limits (Daily & Monthly)
**Goal**: Enforce calendar-based aggregate limits (e.g., maximum ₹50,000 per day, ₹200,000 per month) in addition to the per-transaction cap (`max_amount_paise`). Protects against "split-purchase" attacks where an agent fragments a large transaction into dozens of sub-threshold transactions.

#### Files Touched:
- `models/authorization.py`:
  - Add optional `daily_limit_paise: StrictInt | None = None`.
  - Add optional `monthly_limit_paise: StrictInt | None = None`.
  - Add optional `timezone: StrictStr = "Asia/Kolkata"`.
- `models/transaction.py`:
  - Define `SpendLedgerStatus(str, Enum)`: `RESERVED`, `CONSUMED`, `RELEASED`.
  - Define `SpendReservationRecord`.
- `engine/budget.py`:
  - New `SQLiteSpendLedger` managing `spend_ledger` table with schema:
    - `transaction_id TEXT PRIMARY KEY`
    - `authorization_id TEXT NOT NULL`
    - `amount_paise INTEGER NOT NULL`
    - `status TEXT NOT NULL`
    - `window_date TEXT NOT NULL` (e.g. "2026-10-29")
    - `window_month TEXT NOT NULL` (e.g. "2026-10")
    - `created_at TEXT NOT NULL`
  - Atomic reservation under `BEGIN IMMEDIATE`:
    - Compute calendar day and month start/end in target timezone.
    - `SELECT SUM(amount_paise) FROM spend_ledger WHERE authorization_id = ? AND status IN ('RESERVED', 'CONSUMED') AND window_date = ?`
    - Check against `daily_limit_paise` and `monthly_limit_paise`.
    - If sum + new amount > limit, reject deterministically.
    - If within limit, insert with status `RESERVED`.
    - Idempotent: `INSERT OR IGNORE` or checking existing `transaction_id`.
- `application/container.py`:
  - Wire `SQLiteSpendLedger` pointing to `{DATABASE_PATH}.budget`.
- `application/orchestrator.py`:
  - Place reservation immediately after authorization revalidation and before/at idempotency acquisition.
  - Implement explicit **Compensating Release**: If payment dispatch errors or idempotency fails, mark reservation `RELEASED`.
  - On `SUCCESS`: Transition reservation to `CONSUMED`.
  - On definitive failure (`FAILED_SAFE_TO_RETRY`, `REFUNDED`): Transition to `RELEASED`.
  - On `UNKNOWN` and `RECONCILE_PENDING`: Hold `RESERVED` status (conservative: rail may have debited funds).
- `engine/reconciliation.py`:
  - Update spend ledger state on webhook resolution (`CONSUMED` on success, `RELEASED` on failure/refund).
- `tests/test_budget.py`:
  - 20 concurrent threads attempting to exceed daily limit simultaneously; prove aggregate never exceeds cap.
  - Calendar window rollover test.
  - Idempotent retry without double-reservation.
  - Release on failure, hold on unknown.
- `evaluation/adversarial_scenarios.py`:
  - Add adversarial cases: "Split-purchase limit evasion" and "Concurrent limit burst".

#### Ambiguities & Conservative Decisions:
1. **Timezone Anchor**:
   - *Conservative Choice*: Default to `"Asia/Kolkata"` (Razorpay's native domestic clearing timezone). The calendar day resets at 00:00:00 IST. Documented clearly in config.
2. **Handling `UNKNOWN` Dispatches**:
   - *Conservative Choice*: Retain reservation as `RESERVED`. If the rail actually captured the payment, releasing the budget would enable an attacker to spend beyond the user's intended monthly cap. Reconcile handles release if payment definitively failed.
3. **Database Isolation & Compensating Action**:
   - *Conservative Choice*: Since `state.db.budget` is a separate SQLite file from `state.db.transactions` and `state.db.idempotency`, cross-file transactions cannot be locked in a single atomic commit without ATTACH. Therefore, the orchestrator reserves budget first, executes idempotency next, and if any subsequent step fails before dispatch, executes an immediate compensating `release_reservation()`.

---

### Extension 2: Human-in-the-Loop Approval for High-Value Transactions
**Goal**: Transactions exceeding an `approval_threshold_paise` must pause in a `PENDING_APPROVAL` state, requiring a cryptographically isolated human approver to review and approve the exact intent before the mandate is generated and payment is dispatched.

#### Files Touched:
- `models/authorization.py`:
  - Add optional `approval_threshold_paise: StrictInt | None = None`.
- `models/transaction.py`:
  - Add states to `TransactionState`:
    - `PENDING_APPROVAL = "PENDING_APPROVAL"`
    - `APPROVAL_REJECTED = "APPROVAL_REJECTED"`
    - `APPROVAL_EXPIRED = "APPROVAL_EXPIRED"`
- `engine/state_machine.py`:
  - Transitions:
    - `POLICY_APPROVED` -> `PENDING_APPROVAL` (when amount >= threshold)
    - `POLICY_APPROVED` -> `MANDATE_VALID` (when amount < threshold or threshold is None)
    - `PENDING_APPROVAL` -> `MANDATE_VALID`
    - `PENDING_APPROVAL` -> `APPROVAL_REJECTED`
    - `PENDING_APPROVAL` -> `APPROVAL_EXPIRED`
- `models/approval.py` & `engine/approval.py`:
  - Approval storage model (`transaction_id`, `intent_hash`, `user_id`, `amount_paise`, `status`, `expires_at`, `created_at`).
  - Table: `approvals`.
- `application/orchestrator.py`:
  - After `POLICY_APPROVED`:
    - If `amount_paise >= threshold`:
      - Compute and persist `intent_hash`.
      - Store approval record with TTL (default 15 minutes).
      - Transition transaction to `PENDING_APPROVAL`.
      - Write audit event `APPROVAL_REQUESTED`.
      - Return HTTP 202 `PENDING_APPROVAL`.
      - Do **NOT** create mandate yet (mandate TTL must not burn while waiting for human).
  - New methods: `approve_transaction(transaction_id, intent_hash, approver_principal)` and `reject_transaction(...)`.
  - On approve:
    - Re-verify approver credentials (must have approver role, distinct from agent).
    - Match supplied `intent_hash` against stored `intent_hash`.
    - Check expiration; move to `APPROVAL_EXPIRED` if expired.
    - Re-resolve and re-verify authorization, re-evaluate policy and catalog (fresh state).
    - Create and verify Ed25519 mandate.
    - Transition to `MANDATE_VALID`, reserve budget, acquire idempotency, dispatch to Razorpay.
- `api/main.py`:
  - `GET /v1/approvals?status=pending`: List pending transactions for approver.
  - `POST /v1/transactions/{id}/approve`: Submit approval with `{intent_hash}` in payload.
  - `POST /v1/transactions/{id}/reject`: Submit rejection with `{reason}`.
  - Enforce `AGENTSHIELD_APPROVER_TOKEN` authentication dependency.
- `frontend/src`:
  - Update Flight Recorder to display `PENDING_APPROVAL` status with badge.
  - Add "Approve" and "Reject" action buttons when viewing a pending transaction.
- `tests/test_approval.py`:
  - Agent token cannot approve its own transaction (403/Forbidden).
  - Intent hash mismatch rejected.
  - Expired approval rejected.
  - Authorization revoked while waiting; subsequent approval fails.
  - Idempotent re-execution while pending returns same pending transaction.

#### Ambiguities & Conservative Decisions:
1. **Mandate Creation Timing**:
   - *Conservative Choice*: Mandate is created **after** human approval is granted. If created before, the mandate's short TTL (e.g. 5 minutes) would expire while the human reads the prompt, or an approved transaction would carry a stale cryptographic mandate.
2. **Re-Validation on Approval**:
   - *Conservative Choice*: Approval does NOT skip security checks. When approval is submitted, the orchestrator re-validates that the authorization is still active (hasn't been revoked in the interim) and catalog stock/pricing is still valid.
3. **Approver Credential Separation**:
   - *Conservative Choice*: Approvals require a distinct secret token `AGENTSHIELD_APPROVER_TOKEN` mapped to `Role.APPROVER`. If an agent bearer token calls `/v1/transactions/{id}/approve`, it is rejected with `403 Forbidden`.

---

### Extension 4: Packaging, CI/CD, and Verification Documentation
**Goal**: Package AgentShield into production-ready containers, establish automated CI regression testing with zero test skips, and author clear architectural documentation.

#### Files Touched:
- `Dockerfile`:
  - Multi-stage build with Python 3.11 slim base image.
  - Non-root user `agentshield`.
  - Built-in container healthcheck on `/healthz`.
- `docker-compose.yml`:
  - Orchestrates API service and React Vite frontend.
  - Mounts persistent volume for SQLite database storage.
  - Runs with `.env` configuration.
  - Includes automated seed data step.
- `.dockerignore`:
  - Exclude `.git`, `__pycache__`, `.venv`, `tests`, `node_modules`.
- `.github/workflows/ci.yml`:
  - Matrix / Python 3.11 job with pip dependency caching.
  - Runs `pytest -q`, `python -m scripts.run_evaluation`, `python -m scripts.run_adversarial`.
  - Runs `python -m scripts.check_reports` (fails if any bypass or failure occurs).
  - Frontend job: `npm ci`, `npm run lint`, `npm run build`.
- `scripts/check_reports.py`:
  - Verifies `reports/evaluation.json` and `reports/adversarial.json` have 0 failures and 0.0000 bypass rates.
- `README.md`:
  - CI badge.
  - 5-line Docker quickstart.
  - Updated crypto (Ed25519), cumulative budgets, and approval workflows.
  - Regenerated test and evaluation counts.
  - "Design Decisions and Tradeoffs" section.

---

## Interview Questions & Architectural Tradeoffs

### Q1: Why Ed25519 instead of HMAC or RSA?
- **HMAC Tradeoff**: HMAC is symmetric. In order to verify an HMAC mandate, the verifier must hold the secret signing key. If we ever externalize verification to a bank rail or distributed edge worker, distributing the HMAC key compromises the signing authority.
- **RSA Tradeoff**: RSA-2048 keys and signatures are massive (256-byte signatures) and slow to generate/verify compared to elliptic curves.
- **Ed25519 Advantage**: 32-byte keys, 64-byte deterministic signatures, immune to side-channel timing attacks, constant-time verification, and AP2/W3C alignment. The private key remains exclusively in the signing boundary, while public keys can be distributed safely across keyrings.

### Q2: Why use database-level concurrency (BEGIN IMMEDIATE / PRIMARY KEY) instead of Redis or in-memory distributed locks?
- **Tradeoff**: In-memory distributed locks (like Redlock) suffer from clock drift, GC pauses, and network partition split-brains, potentially granting the lock to two concurrent transactions.
- **Decision**: SQLite in WAL mode with `BEGIN IMMEDIATE` provides transactional serialization at the storage layer. By relying on `PRIMARY KEY(idempotency_key)` and `UNIQUE(transaction_id)`, the operating system kernel and filesystem ensure that only one thread can commit the reservation. No check-then-insert race condition is possible.

### Q3: Why re-run authorization and catalog checks when a human approves?
- **Tradeoff**: Re-running checks adds a few milliseconds of compute overhead.
- **Decision**: Time-of-Check to Time-of-Use (TOCTOU) vulnerability. Between the time a transaction enters `PENDING_APPROVAL` and the human clicks "Approve" (which could be hours later):
  1. The user might have revoked the agent's authorization.
  2. The merchant's catalog price might have changed.
  3. The daily budget might have been exhausted by other transactions.
  Treating earlier validation as permanently valid would create a severe security vulnerability.

### Q4: What is the failure window in SQLite database splitting?
- **Tradeoff**: Keeping transactions, audit, budget, and idempotency in separate SQLite files eliminates lock contention across high-throughput subsystems, but loses multi-table atomic ACID commits.
- **Mitigation**: The explicit Compensating Release Pattern. If budget reservation succeeds on `state.db.budget` but idempotency fails on `state.db.idempotency`, the orchestrator immediately compensates by releasing the reservation. If the machine loses power in between, the conservative reservation remains held until the daily window rolls over or reconciliation sweeps it.
