import { useMemo, useState } from 'react'
import './App.css'

type StepState = 'passed' | 'blocked' | 'pending' | 'unknown'

type PipelineStep = {
  key: string
  name: string
  description: string
  evidence: string
  state: StepState
  label: string
}

type IntentItem = {
  sku: string
  quantity: number
}

type AuthorizationSnapshot = {
  authorization_id: string
  max_amount_paise: number
  allowed_merchants: string[]
  allowed_categories: string[]
  allowed_skus: string[]
  max_quantity: number
  currency: string
  active: boolean
  revoked: boolean
}

type TransactionRecord = {
  transaction_id: string
  intent_id: string
  user_id: string
  agent_id: string
  merchant_id: string
  amount_paise: number
  currency: string
  items: IntentItem[]
  intent_hash: string
  authorization_snapshot?: AuthorizationSnapshot | null
  idempotency_key: string
  razorpay_order_id?: string | null
  razorpay_payment_id?: string | null
  state: string
  created_at: string
  updated_at: string
}

type OrchestrationResult = {
  transaction: TransactionRecord
  mandate: {
    user_id: string
    agent_id: string
    merchant_id: string
    amount_paise: number
    intent_hash: string
    nonce: string
    issued_at: string
    expires_at: string
    signature: string
  }
  status: string
}

type AuditEvent = {
  sequence: number
  event_id: string
  event_type: string
  transaction_id: string
  intent_id: string
  user_id: string
  agent_id: string
  state: string
  intent_hash?: string | null
  occurred_at: string
  details: Record<string, unknown>
  previous_event_hash: string
  event_hash: string
}

const USER_ID = 'user_123'
const AGENT_ID = 'agent_001'
const MERCHANT_ID = 'merchant_001'

const APPROVED_AMOUNT = 450000
const BLOCKED_AMOUNT = 900000

const approvedMessage =
  'Buy exactly one shoe_001 from merchant_001 for ₹4500.'

const blockedMessage =
  'Buy shoe_001 from merchant_001 for ₹9000.'

function formatRupees(amountPaise: number): string {
  return `₹${(amountPaise / 100).toLocaleString('en-IN')}`
}

function shortHash(value: string): string {
  if (value.length <= 20) {
    return value
  }

  return `${value.slice(0, 10)}…${value.slice(-8)}`
}

function formatTime(value: string): string {
  return new Date(value).toLocaleTimeString('en-IN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function stateLabel(state: StepState): string {
  switch (state) {
    case 'passed':
      return 'PASSED'
    case 'blocked':
      return 'BLOCKED'
    case 'unknown':
      return 'UNKNOWN'
    default:
      return 'NOT REACHED'
  }
}

function StepIcon({ state }: { state: StepState }) {
  if (state === 'passed') {
    return <span className="step-icon passed">✓</span>
  }

  if (state === 'blocked') {
    return <span className="step-icon blocked">!</span>
  }

  if (state === 'unknown') {
    return <span className="step-icon unknown">?</span>
  }

  return <span className="step-icon pending">—</span>
}

function classifyPipelineState(
  state: string,
  successStates: string[],
  pendingStates: string[],
): StepState {
  if (successStates.includes(state)) {
    return 'passed'
  }

  if (pendingStates.includes(state)) {
    return 'pending'
  }

  return 'blocked'
}

function buildLifecyclePipeline(
  transaction: TransactionRecord,
  result: OrchestrationResult | null,
  auditEvents: AuditEvent[],
): PipelineStep[] {
  const state = transaction.state
  const hasAudit = (type: string) =>
    auditEvents.some((event) => event.event_type === type)

  const authorizationState: StepState = hasAudit(
    'AUTHORIZATION_APPROVED',
  )
    ? 'passed'
    : hasAudit('AUTHORIZATION_REJECTED')
      ? 'blocked'
      : classifyPipelineState(
          state,
          [
            'POLICY_APPROVED',
            'MANDATE_VALID',
            'LOCK_ACQUIRED',
            'DISPATCHED',
            'SUCCESS',
            'COMPLETED',
          ],
          ['CREATED', 'INTENT_VALIDATED'],
        )

  const policyState: StepState = hasAudit('POLICY_APPROVED')
    ? 'passed'
    : hasAudit('POLICY_REJECTED')
      ? 'blocked'
      : classifyPipelineState(
          state,
          [
            'MANDATE_VALID',
            'LOCK_ACQUIRED',
            'DISPATCHED',
            'SUCCESS',
            'COMPLETED',
          ],
          ['INTENT_VALIDATED'],
        )

  const mandateState: StepState = hasAudit('MANDATE_VERIFIED')
    || hasAudit('MANDATE_CREATED')
    ? 'passed'
    : classifyPipelineState(
        state,
        [
          'LOCK_ACQUIRED',
          'DISPATCHED',
          'SUCCESS',
          'COMPLETED',
        ],
        ['POLICY_APPROVED'],
      )

  const idempotencyState: StepState = hasAudit(
    'IDEMPOTENCY_ACQUIRED',
  )
    ? 'passed'
    : classifyPipelineState(
        state,
        [
          'DISPATCHED',
          'SUCCESS',
          'COMPLETED',
        ],
        ['MANDATE_VALID'],
      )

  let razorpayState: StepState = 'blocked'
  let razorpayDescription = 'No payment API call made.'
  let razorpayEvidence = 'Execution boundary not crossed.'

  if (
    state === 'UNKNOWN' ||
    state === 'RECONCILE_PENDING'
  ) {
    razorpayState = 'unknown'
    razorpayDescription =
      'Dispatch outcome requires reconciliation.'
    razorpayEvidence =
      'Control plane refuses to blindly retry.'
  } else if (
    state === 'DISPATCHED' ||
    state === 'SUCCESS' ||
    state === 'COMPLETED'
  ) {
    razorpayState = 'passed'
    razorpayDescription = transaction.razorpay_order_id
      ? `Order created · ${transaction.razorpay_order_id}`
      : 'Execution reached Razorpay.'
    razorpayEvidence =
      transaction.razorpay_payment_id
        ? `Payment · ${transaction.razorpay_payment_id}`
        : 'Order recorded.'
  } else if (state === 'LOCK_ACQUIRED') {
    razorpayState = 'pending'
    razorpayDescription = 'Execution claim acquired.'
    razorpayEvidence = 'Ready for Razorpay dispatch.'
  }

  const webhookState: StepState = hasAudit('WEBHOOK_RECEIVED')
    ? 'passed'
    : ['SUCCESS', 'COMPLETED'].includes(state)
      ? 'passed'
      : state === 'UNKNOWN' || state === 'RECONCILE_PENDING'
        ? 'unknown'
        : 'pending'

  const reconciliationState: StepState =
    hasAudit('PAYMENT_RECONCILED') ||
    ['SUCCESS', 'COMPLETED'].includes(state)
      ? 'passed'
      : state === 'UNKNOWN' ||
          state === 'RECONCILE_PENDING'
        ? 'pending'
        : 'pending'

  return [
    {
      key: 'authorization',
      name: 'Authorization',
      description:
        'Server-owned authority defines the financial ceiling.',
      evidence: transaction.authorization_snapshot
        ? `${transaction.authorization_snapshot.authorization_id} · max ${formatRupees(
            transaction.authorization_snapshot.max_amount_paise,
          )}`
        : 'Authoritative authorization record not attached.',
      state: authorizationState,
      label: stateLabel(authorizationState),
    },
    {
      key: 'policy',
      name: 'Policy',
      description:
        'Deterministic merchant, SKU, amount, currency and quantity checks.',
      evidence:
        `${transaction.merchant_id} · ${transaction.currency} · ` +
        `${transaction.items[0]?.sku ?? '—'} · qty ${
          transaction.items[0]?.quantity ?? '—'
        }`,
      state: policyState,
      label: stateLabel(policyState),
    },
    {
      key: 'mandate',
      name: 'Mandate',
      description:
        'Bound to the validated intent and authorization.',
      evidence: result
        ? `nonce ${shortHash(result.mandate.nonce)}`
        : 'Mandate evidence not available.',
      state: mandateState,
      label: stateLabel(mandateState),
    },
    {
      key: 'idempotency',
      name: 'Idempotency',
      description:
        'Execution claim prevents duplicate payment dispatch.',
      evidence: shortHash(transaction.idempotency_key),
      state: idempotencyState,
      label: stateLabel(idempotencyState),
    },
    {
      key: 'razorpay',
      name: 'Razorpay',
      description: razorpayDescription,
      evidence: razorpayEvidence,
      state: razorpayState,
      label: stateLabel(razorpayState),
    },
    {
      key: 'webhook',
      name: 'Webhook',
      description:
        'Signed payment event enters the reconciliation boundary.',
      evidence: hasAudit('WEBHOOK_RECEIVED')
        ? 'Webhook received and processed by control plane.'
        : 'Waiting for provider event.',
      state: webhookState,
      label: stateLabel(webhookState),
    },
    {
      key: 'reconciliation',
      name: 'Reconciliation',
      description:
        'Provider outcome is correlated before lifecycle completion.',
      evidence: hasAudit('PAYMENT_RECONCILED')
        ? 'Payment outcome reconciled.'
        : state === 'UNKNOWN' ||
            state === 'RECONCILE_PENDING'
          ? 'Reconciliation pending.'
          : 'Awaiting payment outcome.',
      state: reconciliationState,
      label: stateLabel(reconciliationState),
    },
  ]
}

function buildBlockedPipeline(reason: string): PipelineStep[] {
  return [
    {
      key: 'authorization',
      name: 'Authorization',
      description: reason,
      evidence: 'Server-owned financial authority rejected the request.',
      state: 'blocked',
      label: 'BLOCKED',
    },
    {
      key: 'policy',
      name: 'Policy',
      description: 'Not reached because authorization failed first.',
      evidence: 'No downstream execution allowed.',
      state: 'pending',
      label: 'NOT REACHED',
    },
    {
      key: 'mandate',
      name: 'Mandate',
      description: 'Not reached.',
      evidence: 'No mandate issued.',
      state: 'pending',
      label: 'NOT REACHED',
    },
    {
      key: 'idempotency',
      name: 'Idempotency',
      description: 'Payment execution was never claimed.',
      evidence: 'No execution lock created.',
      state: 'pending',
      label: 'NOT REACHED',
    },
    {
      key: 'razorpay',
      name: 'Razorpay',
      description: 'No API call made.',
      evidence: 'Money movement boundary was never crossed.',
      state: 'blocked',
      label: 'BLOCKED',
    },
    {
      key: 'webhook',
      name: 'Webhook',
      description: 'No provider event expected.',
      evidence: 'No order was created.',
      state: 'blocked',
      label: 'BLOCKED',
    },
    {
      key: 'reconciliation',
      name: 'Reconciliation',
      description: 'No payment outcome to reconcile.',
      evidence: 'Execution stopped upstream.',
      state: 'blocked',
      label: 'BLOCKED',
    },
  ]
}

async function executeScenario(
  userMessage: string,
): Promise<OrchestrationResult> {
  const token = import.meta.env.VITE_AGENTSHIELD_API_TOKEN

  if (!token) {
    throw new Error(
      'VITE_AGENTSHIELD_API_TOKEN is not configured.',
    )
  }

  const response = await fetch('/v1/agent/execute', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': `frontend-${crypto.randomUUID()}`,
    },
    body: JSON.stringify({
      user_message: userMessage,
      merchant_context: {
        merchant_id: MERCHANT_ID,
        category: 'footwear',
        sku: 'shoe_001',
      },
    }),
  })

  const body = await response.json().catch(() => null)

  if (!response.ok) {
    const detail =
      body &&
      typeof body === 'object' &&
      'detail' in body &&
      typeof body.detail === 'string'
        ? body.detail
        : `AgentShield request failed with HTTP ${response.status}.`

    throw new Error(detail)
  }

  return body as OrchestrationResult
}

async function fetchAuditTrail(
  transactionId: string,
): Promise<AuditEvent[]> {
  const token = import.meta.env.VITE_AGENTSHIELD_API_TOKEN

  if (!token) {
    throw new Error(
      'VITE_AGENTSHIELD_API_TOKEN is not configured.',
    )
  }

  const response = await fetch(
    `/v1/transactions/${encodeURIComponent(transactionId)}/audit`,
    {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  )

  const body = await response.json().catch(() => null)

  if (!response.ok) {
    const detail =
      body &&
      typeof body === 'object' &&
      'detail' in body &&
      typeof body.detail === 'string'
        ? body.detail
        : `Audit request failed with HTTP ${response.status}.`

    throw new Error(detail)
  }

  return body as AuditEvent[]
}

async function approvePendingTransaction(
  transactionId: string,
): Promise<TransactionRecord> {
  const token =
    import.meta.env.VITE_AGENTSHIELD_APPROVER_TOKEN ||
    import.meta.env.VITE_AGENTSHIELD_API_TOKEN

  if (!token) {
    throw new Error('Approver token is not configured.')
  }

  const response = await fetch(
    `/v1/transactions/${encodeURIComponent(transactionId)}/approve`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason: 'Approved via dashboard' }),
    },
  )

  const body = await response.json().catch(() => null)

  if (!response.ok) {
    const detail =
      body &&
      typeof body === 'object' &&
      'detail' in body &&
      typeof body.detail === 'string'
        ? body.detail
        : `Approval failed with HTTP ${response.status}.`
    throw new Error(detail)
  }

  return body as TransactionRecord
}

async function rejectPendingTransaction(
  transactionId: string,
): Promise<TransactionRecord> {
  const token =
    import.meta.env.VITE_AGENTSHIELD_APPROVER_TOKEN ||
    import.meta.env.VITE_AGENTSHIELD_API_TOKEN

  if (!token) {
    throw new Error('Approver token is not configured.')
  }

  const response = await fetch(
    `/v1/transactions/${encodeURIComponent(transactionId)}/reject`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ reason: 'Rejected via dashboard' }),
    },
  )

  const body = await response.json().catch(() => null)

  if (!response.ok) {
    const detail =
      body &&
      typeof body === 'object' &&
      'detail' in body &&
      typeof body.detail === 'string'
        ? body.detail
        : `Rejection failed with HTTP ${response.status}.`
    throw new Error(detail)
  }

  return body as TransactionRecord
}

function App() {
  const [blocked, setBlocked] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] =
    useState<OrchestrationResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [auditEvents, setAuditEvents] =
    useState<AuditEvent[]>([])

  const selectedMessage = blocked
    ? blockedMessage
    : approvedMessage

  const selectedAmount = blocked
    ? BLOCKED_AMOUNT
    : APPROVED_AMOUNT

  const transaction = result?.transaction ?? null
  const transactionState = transaction?.state ?? null
  const authorization =
    transaction?.authorization_snapshot ?? null

  const pipeline = useMemo(() => {
    if (error) {
      return buildBlockedPipeline(error)
    }

    if (!transaction) {
      return []
    }

    return buildLifecyclePipeline(
      transaction,
      result,
      auditEvents,
    )
  }, [error, result, transaction, auditEvents])

  const passedCount = pipeline.filter(
    (step) => step.state === 'passed',
  ).length

  const attentionCount = pipeline.filter(
    (step) =>
      step.state === 'blocked' ||
      step.state === 'unknown',
  ).length

  const decision = error
    ? 'BLOCKED'
    : result
      ? transaction?.state === 'PENDING_APPROVAL'
        ? 'PENDING APPROVAL'
        : transaction?.state === 'APPROVAL_REJECTED'
          ? 'REJECTED'
          : transaction?.state === 'APPROVAL_EXPIRED'
            ? 'EXPIRED'
            : result.status === 'SUCCESS' ||
              result.status === 'COMPLETED'
              ? 'COMPLETED'
              : 'APPROVED'
      : 'READY'

  const runScenario = async () => {
    setLoading(true)
    setError(null)
    setResult(null)
    setAuditEvents([])

    try {
      const response = await executeScenario(
        selectedMessage,
      )

      setResult(response)

      try {
        const events = await fetchAuditTrail(
          response.transaction.transaction_id,
        )
        setAuditEvents(events)
      } catch (auditError) {
        console.warn(
          'Audit trail could not be loaded:',
          auditError,
        )
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'AgentShield execution failed.',
      )
    } finally {
      setLoading(false)
    }
  }

  const handleApprove = async () => {
    if (!transaction) return
    setLoading(true)
    setError(null)
    try {
      const updatedTx = await approvePendingTransaction(
        transaction.transaction_id,
      )
      setResult((prev) =>
        prev
          ? {
              ...prev,
              transaction: updatedTx,
              status: updatedTx.state,
            }
          : null,
      )
      try {
        const events = await fetchAuditTrail(
          transaction.transaction_id,
        )
        setAuditEvents(events)
      } catch (e) {
        console.warn('Audit refresh failed:', e)
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Approval failed',
      )
    } finally {
      setLoading(false)
    }
  }

  const handleReject = async () => {
    if (!transaction) return
    setLoading(true)
    setError(null)
    try {
      const updatedTx = await rejectPendingTransaction(
        transaction.transaction_id,
      )
      setResult((prev) =>
        prev
          ? {
              ...prev,
              transaction: updatedTx,
              status: updatedTx.state,
            }
          : null,
      )
      try {
        const events = await fetchAuditTrail(
          transaction.transaction_id,
        )
        setAuditEvents(events)
      } catch (e) {
        console.warn('Audit refresh failed:', e)
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : 'Rejection failed',
      )
    } finally {
      setLoading(false)
    }
  }

  const toggleScenario = () => {
    setBlocked((value) => !value)
    setResult(null)
    setError(null)
    setAuditEvents([])
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <div className="brand-mark">A</div>
            <div>
              <div className="brand-name">
                AgentShield 
              </div>
              <div className="brand-subtitle">
                PAYMENT GOVERNANCE CONTROL PLANE
              </div>
            </div>
          </div>

          <div className="topbar-meta">
            <span className="live-dot" />
            Local test environment
            <span className="principal">
              {USER_ID} / {AGENT_ID}
            </span>
          </div>
        </div>
      </header>

      <main className="page">
        <section className="hero">
          <div>
            <div className="eyebrow">FLIGHT RECORDER</div>
            <h1>Every payment decision, traceable.</h1>
            <p>
              Agent intent enters the control plane. Authority,
              policy, mandate, execution and reconciliation are
              recorded as one governed lifecycle.
            </p>
          </div>

          <div className="hero-actions">
            <button
              className="secondary-button"
              type="button"
              onClick={toggleScenario}
              disabled={loading}
            >
              {blocked
                ? 'Use approved scenario'
                : 'Test blocked scenario'}
            </button>

            <button
              className="primary-button"
              type="button"
              onClick={runScenario}
              disabled={loading}
            >
              {loading
                ? 'Recording...'
                : 'Run governance check'}
            </button>
          </div>
        </section>

        <section
          className={`decision ${error ? 'decision-danger' : ''}`}
        >
          <div>
            <div className="eyebrow">
              GOVERNANCE DECISION
            </div>
            <div className="decision-title">
              {decision}
            </div>
            <div className="decision-copy">
              {error
                ? error
                : transaction
                  ? `Transaction ${transaction.transaction_id} is in ${transaction.state}.`
                  : 'No execution recorded yet.'}
            </div>
          </div>

          <div className="decision-metric">
            <span>REQUESTED</span>
            <strong>{formatRupees(
              transaction?.amount_paise ?? selectedAmount,
            )}</strong>
          </div>
        </section>

        {transaction?.state === 'PENDING_APPROVAL' && (
          <section
            style={{
              marginTop: '1.25rem',
              padding: '1.5rem',
              borderRadius: '12px',
              border: '1px solid #f59e0b',
              background: 'rgba(245, 158, 11, 0.08)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '1rem',
              flexWrap: 'wrap',
            }}
          >
            <div>
              <div
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  letterSpacing: '0.08em',
                  color: '#f59e0b',
                  marginBottom: '0.25rem',
                }}
              >
                HUMAN APPROVAL REQUIRED
              </div>
              <div
                style={{
                  fontSize: '1rem',
                  fontWeight: 600,
                  color: '#ffffff',
                }}
              >
                Amount exceeds automatic authorization threshold
              </div>
              <div
                style={{
                  fontSize: '0.85rem',
                  color: '#94a3b8',
                  marginTop: '0.25rem',
                }}
              >
                A human approver token is required to authorize money movement and dispatch to payment rail.
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                className="secondary-button"
                style={{
                  borderColor: '#ef4444',
                  color: '#ef4444',
                }}
                disabled={loading}
                onClick={handleReject}
              >
                {loading ? 'Processing...' : 'Reject Payment'}
              </button>
              <button
                type="button"
                className="primary-button"
                style={{
                  background: '#10b981',
                  borderColor: '#10b981',
                }}
                disabled={loading}
                onClick={handleApprove}
              >
                {loading ? 'Processing...' : 'Approve Payment'}
              </button>
            </div>
          </section>
        )}

        <section className="overview-grid">
          <article className="card request-card">
            <div className="card-label">AI REQUEST</div>
            <div className="request-title">
              {selectedMessage}
            </div>

            <div className="facts-grid">
              <div>
                <span>USER</span>
                <strong>{USER_ID}</strong>
              </div>
              <div>
                <span>AGENT</span>
                <strong>{AGENT_ID}</strong>
              </div>
              <div>
                <span>MERCHANT</span>
                <strong>
                  {transaction?.merchant_id ?? MERCHANT_ID}
                </strong>
              </div>
              <div>
                <span>SKU</span>
                <strong>
                  {transaction?.items[0]?.sku ?? 'shoe_001'}
                </strong>
              </div>
            </div>
          </article>

          <article className="card payment-card">
            <div className="card-label">PAYMENT</div>
            <div className="payment-amount">
              {formatRupees(
                transaction?.amount_paise ?? selectedAmount,
              )}
            </div>
            <div className="payment-caption">
              INR · quantity {transaction?.items[0]?.quantity ?? 1}
            </div>

            <div className="limit-block">
              <div className="limit-header">
                <span>AUTHORIZED MAXIMUM</span>
                <strong>
                  {authorization
                    ? formatRupees(
                        authorization.max_amount_paise,
                      )
                    : '—'}
                </strong>
              </div>
              <div className="limit-track">
                <div
                  className={`limit-fill ${
                    error ? 'danger-fill' : ''
                  }`}
                  style={{
                    width: `${
                      authorization
                        ? Math.min(
                            100,
                            ((transaction?.amount_paise ??
                              selectedAmount) /
                              authorization.max_amount_paise) *
                              100,
                          )
                        : Math.min(
                            100,
                            (selectedAmount / APPROVED_AMOUNT) *
                              100,
                          )
                    }%`,
                  }}
                />
              </div>
            </div>
          </article>
        </section>

        <section className="card recorder-card">
          <div className="section-header">
            <div>
              <div className="card-label">
                GOVERNED LIFECYCLE
              </div>
              <h2>Flight Recorder</h2>
            </div>

            <div className="recorder-summary">
              {pipeline.length === 0
                ? 'Awaiting execution'
                : attentionCount > 0
                  ? `${passedCount} passed · ${attentionCount} attention`
                  : `${passedCount} / ${pipeline.length} passed`}
            </div>
          </div>

          <div className="recorder">
            {pipeline.length === 0 ? (
              <div className="empty-recorder">
                <div className="empty-node">•</div>
                <div>
                  <strong>Recorder is armed.</strong>
                  <p>
                    Run a scenario to capture the complete
                    decision lifecycle.
                  </p>
                </div>
              </div>
            ) : (
              pipeline.map((step, index) => (
                <div
                  className="recorder-row"
                  key={step.key}
                >
                  <div className="recorder-rail">
                    <StepIcon state={step.state} />
                    {index < pipeline.length - 1 && (
                      <span className="connector" />
                    )}
                  </div>

                  <div className="recorder-content">
                    <div className="step-header">
                      <div>
                        <div className="step-name">
                          {step.name}
                        </div>
                        <div className="step-description">
                          {step.description}
                        </div>
                      </div>

                      <span
                        className={`step-badge step-${step.state}`}
                      >
                        {step.label}
                      </span>
                    </div>

                    <div className="evidence">
                      <span className="evidence-label">
                        EVIDENCE
                      </span>
                      <span className="evidence-value">
                        {step.evidence}
                      </span>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="details-grid">
          <article className="card">
            <div className="card-label">TRANSACTION</div>
            <div className="primary-code">
              {transaction?.transaction_id ??
                'Awaiting transaction'}
            </div>

            <div className="detail-list">
              <div>
                <span>STATE</span>
                <strong>
                  {transactionState ??
                    (error ? 'BLOCKED' : 'READY')}
                </strong>
              </div>
              <div>
                <span>RAZORPAY ORDER</span>
                <strong>
                  {transaction?.razorpay_order_id ?? '—'}
                </strong>
              </div>
              <div>
                <span>AUTHORIZATION</span>
                <strong>
                  {authorization?.authorization_id ??
                    'Not resolved'}
                </strong>
              </div>
              <div>
                <span>INTENT HASH</span>
                <strong className="code">
                  {transaction?.intent_hash
                    ? shortHash(transaction.intent_hash)
                    : '—'}
                </strong>
              </div>
            </div>
          </article>

          <article className="card authority-card">
            <div className="card-label">PAYMENT AUTHORITY</div>

            <div className="authority-heading">
              <div>
                <h2>Server-owned financial bounds</h2>
                <p>
                  The model may interpret intent; it does not own
                  the payment limits.
                </p>
              </div>

              <span
                className={`authority-pill ${
                  authorization?.active &&
                  !authorization.revoked
                    ? 'active'
                    : 'inactive'
                }`}
              >
                {authorization?.active &&
                !authorization.revoked
                  ? 'ACTIVE'
                  : 'NOT RESOLVED'}
              </span>
            </div>

            <div className="authority-grid">
              <div>
                <span>MAX AMOUNT</span>
                <strong>
                  {authorization
                    ? formatRupees(
                        authorization.max_amount_paise,
                      )
                    : '—'}
                </strong>
              </div>
              <div>
                <span>ALLOWED SKU</span>
                <strong>
                  {authorization
                    ? authorization.allowed_skus.join(', ')
                    : '—'}
                </strong>
              </div>
              <div>
                <span>MAX QUANTITY</span>
                <strong>
                  {authorization?.max_quantity ?? '—'}
                </strong>
              </div>
              <div>
                <span>CURRENCY</span>
                <strong>
                  {authorization?.currency ?? '—'}
                </strong>
              </div>
            </div>
          </article>
        </section>

        {auditEvents.length > 0 && (
          <section className="card audit-card">
            <div className="section-header">
              <div>
                <div className="card-label">
                  IMMUTABLE EVIDENCE
                </div>
                <h2>Audit trail</h2>
              </div>

              <div className="recorder-summary">
                {auditEvents.length} events
              </div>
            </div>

            <div className="audit-list">
              {auditEvents.map((event) => (
                <div
                  className="audit-row"
                  key={event.event_id}
                >
                  <div className="audit-sequence">
                    #{event.sequence}
                  </div>

                  <div className="audit-main">
                    <div className="audit-top">
                      <strong>{event.event_type}</strong>
                      <span>
                        {formatTime(event.occurred_at)}
                      </span>
                    </div>

                    <div className="audit-meta">
                      <span>{event.state}</span>
                      <span className="code">
                        {shortHash(event.event_hash)}
                      </span>
                    </div>

                    {Object.keys(event.details).length > 0 && (
                      <div className="audit-details">
                        {Object.entries(event.details).map(
                          ([key, value]) => (
                            <span
                              key={key}
                              className="audit-chip"
                            >
                              <b>{key}</b>
                              {String(value)}
                            </span>
                          ),
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        <footer className="footer">
          <span>AgentShield </span>
          <span>
            Deterministic payment governance
          </span>
          <span>Razorpay execution rail</span>
        </footer>
      </main>
    </div>
  )
}

export default App
