from __future__ import annotations

from typing import ClassVar

from models.transaction import TransactionState


class InvalidTransactionTransition(Exception):
    """
    Raised when an invalid transaction state transition is requested.
    """


class TransactionStateMachine:
    """
    Deterministic finite state machine for AgentShield transactions.
    """

    TRANSITIONS: ClassVar[
        dict[TransactionState, frozenset[TransactionState]]
    ] = {
        TransactionState.CREATED: frozenset(
            {
                TransactionState.INTENT_VALIDATED,
            }
        ),

        # Policy must be approved before the intent is cryptographically
        # bound into a mandate.
        TransactionState.INTENT_VALIDATED: frozenset(
            {
                TransactionState.POLICY_APPROVED,
            }
        ),

        # Once policy is approved, the governed intent can either move directly
        # to MANDATE_VALID (if below approval threshold), or to PENDING_APPROVAL
        TransactionState.POLICY_APPROVED: frozenset(
            {
                TransactionState.MANDATE_VALID,
                TransactionState.PENDING_APPROVAL,
            }
        ),

        TransactionState.PENDING_APPROVAL: frozenset(
            {
                TransactionState.MANDATE_VALID,
                TransactionState.APPROVAL_REJECTED,
                TransactionState.APPROVAL_EXPIRED,
            }
        ),

        TransactionState.APPROVAL_REJECTED: frozenset(),
        TransactionState.APPROVAL_EXPIRED: frozenset(),

        TransactionState.MANDATE_VALID: frozenset(
            {
                TransactionState.LOCK_ACQUIRED,
            }
        ),

        TransactionState.LOCK_ACQUIRED: frozenset(
            {
                TransactionState.DISPATCHED,
            }
        ),

        TransactionState.DISPATCHED: frozenset(
            {
                TransactionState.SUCCESS,
                TransactionState.UNKNOWN,
            }
        ),

        TransactionState.UNKNOWN: frozenset(
            {
                TransactionState.RECONCILE_PENDING,
            }
        ),

        TransactionState.RECONCILE_PENDING: frozenset(
            {
                TransactionState.SUCCESS,
                TransactionState.FAILED_SAFE_TO_RETRY,
            }
        ),

        TransactionState.SUCCESS: frozenset(
            {
                TransactionState.COMPLETED,
                TransactionState.STOCKOUT_DETECTED,
            }
        ),

        TransactionState.STOCKOUT_DETECTED: frozenset(
            {
                TransactionState.REFUNDING,
            }
        ),

        TransactionState.REFUNDING: frozenset(
            {
                TransactionState.REFUNDED,
            }
        ),

        TransactionState.REFUNDED: frozenset(
            {
                TransactionState.REROUTING,
            }
        ),

        TransactionState.REROUTING: frozenset(
            {
                TransactionState.RECOVERED,
            }
        ),

        TransactionState.RECOVERED: frozenset(
            {
                TransactionState.COMPLETED,
            }
        ),

        # Recovered/retryable failures can re-enter the execution path
        # through the lock acquisition step.
        TransactionState.FAILED_SAFE_TO_RETRY: frozenset(
            {
                TransactionState.LOCK_ACQUIRED,
            }
        ),

        TransactionState.COMPLETED: frozenset(),
    }

    @classmethod
    def can_transition(
        cls,
        current: TransactionState,
        target: TransactionState,
    ) -> bool:
        """
        Return True when the requested transition is explicitly allowed.
        """

        return target in cls.TRANSITIONS.get(
            current,
            frozenset(),
        )

    @classmethod
    def transition(
        cls,
        current: TransactionState,
        target: TransactionState,
    ) -> TransactionState:
        """
        Perform one validated state transition.
        """

        if not cls.can_transition(current, target):
            raise InvalidTransactionTransition(
                f"Invalid transaction transition: "
                f"{current.value} -> {target.value}"
            )

        return target