//! Fail-closed decision types.
//!
//! This module defines the two distinct result types that the KYA model keeps
//! strictly separate:
//!
//! - [`PolicyOutcome`]: the result of **offline, static** policy evaluation
//!   (stage C). It never means "authorized"; at best its
//!   `EligibleForOnlineAuthorization` variant means "nothing in the static
//!   rules forbids this, so it may proceed to the authority".
//! - [`Decision`]: the final, **authoritative** authorization result. A
//!   `Decision` can only be produced by the online authoritative bridge in
//!   `kya-client` (stage D).
//!
//! # The deliberate missing conversion
//!
//! There is intentionally **no** `From<PolicyOutcome> for Decision`. Converting
//! a static "passed" into an "authorized" without consulting the authority
//! would be exactly the silent authorization fallback the SDK forbids. The only
//! bridge from a [`PolicyOutcome`] to a [`Decision`] is the fail-closed
//! `authorize` function in `kya-client`, which denies on any error, timeout,
//! unknown state, or approval-required signal.

use core::fmt;

/// A machine-readable reason accompanying a policy outcome or decision.
///
/// Reason codes make outcomes auditable and testable without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReasonCode {
    /// The requested action was not in the mandate scope.
    ActionNotPermitted,
    /// The transaction amount exceeded the per-transaction limit.
    AmountExceedsLimit,
    /// The acting agent did not match the mandate's agent.
    AgentMismatch,
    /// The intent's principal did not match the mandate's principal.
    PrincipalMismatch,
    /// Static policy checks found nothing to forbid (stage C only).
    StaticChecksPassed,
    /// The authoritative authority explicitly approved the request.
    AuthorityApproved,
    /// The authoritative authority explicitly denied the request.
    AuthorityDenied,
    /// The authority requires human approval before the action may proceed.
    ApprovalRequired,
    /// The authoritative check could not be completed (error/timeout/unknown).
    AuthorityUnavailable,
    /// The verified-evidence precondition was not met: the identity the
    /// evaluator was asked to treat as established did not match the mandate,
    /// so no further static check can be trusted. A hard fail.
    EvidenceInvalid,
    /// The intent was directed at a merchant the mandate does not allow.
    MerchantNotPermitted,
    /// The intent acted on a resource the mandate does not allow.
    ResourceNotPermitted,
    /// The transaction currency was outside the mandate's allowed-currency set.
    CurrencyNotPermitted,
    /// The mandate is not yet valid (its not-before time is in the future).
    MandateNotYetValid,
    /// The mandate has expired (its expiry time is at or before now).
    MandateExpired,
    /// The intent's audience did not match the mandate's required audience.
    AudienceMismatch,
    /// The transaction binding on the intent did not match the mandate's.
    BindingMismatch,
    /// A required fact could not be established offline, so the request must
    /// fail closed to a non-executing outcome (never a silent pass).
    OnlineEvidenceRequired,
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ReasonCode::ActionNotPermitted => "action not permitted by scope",
            ReasonCode::AmountExceedsLimit => "amount exceeds per-transaction limit",
            ReasonCode::AgentMismatch => "acting agent does not match mandate",
            ReasonCode::PrincipalMismatch => "intent principal does not match mandate",
            ReasonCode::StaticChecksPassed => "static policy checks passed",
            ReasonCode::AuthorityApproved => "authority approved",
            ReasonCode::AuthorityDenied => "authority denied",
            ReasonCode::ApprovalRequired => "human approval required",
            ReasonCode::AuthorityUnavailable => "authority unavailable",
            ReasonCode::EvidenceInvalid => "verified-evidence precondition not met",
            ReasonCode::MerchantNotPermitted => "merchant not permitted by scope",
            ReasonCode::ResourceNotPermitted => "resource not permitted by scope",
            ReasonCode::CurrencyNotPermitted => "currency not permitted by scope",
            ReasonCode::MandateNotYetValid => "mandate is not yet valid",
            ReasonCode::MandateExpired => "mandate has expired",
            ReasonCode::AudienceMismatch => "audience does not match mandate",
            ReasonCode::BindingMismatch => "transaction binding does not match mandate",
            ReasonCode::OnlineEvidenceRequired => "online authoritative evidence required",
        };
        f.write_str(s)
    }
}

/// The result of offline, static policy evaluation (stage C).
///
/// This enum reconciles the five distinct stage-C meanings the KYA model
/// distinguishes. **None** of them is an authorization; only
/// [`EligibleForOnlineAuthorization`](PolicyOutcome::EligibleForOnlineAuthorization)
/// may even proceed to the authoritative stage D, and even that is explicitly
/// not permission to execute a transaction.
///
/// The five meanings:
///
/// - [`InvalidEvidence`](PolicyOutcome::InvalidEvidence): the verified-evidence
///   precondition was not met (the identity the evaluator was handed as
///   established did not actually match the mandate). A hard fail.
/// - [`Denied`](PolicyOutcome::Denied): a static policy rule forbade the
///   request (action, merchant, resource, limit, currency, validity window,
///   audience, or binding).
/// - [`RequiresApproval`](PolicyOutcome::RequiresApproval): the mandate requires
///   human approval; this must never be silently upgraded to an allow.
/// - [`Indeterminate`](PolicyOutcome::Indeterminate): a required fact could not
///   be established offline. Fails closed; never a pass.
/// - [`EligibleForOnlineAuthorization`](PolicyOutcome::EligibleForOnlineAuthorization):
///   every static check passed. This is the **only** outcome the fail-closed
///   bridge forwards to the authority, and it is **not** execution permission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyOutcome {
    /// The verified-evidence precondition was not satisfied. A hard fail: the
    /// evaluator was asked to treat an identity as established that did not
    /// match the mandate, so nothing else can be trusted.
    InvalidEvidence {
        /// Why the evidence was rejected (typically
        /// [`ReasonCode::EvidenceInvalid`], or an identity-mismatch code).
        reason: ReasonCode,
    },
    /// A static policy rule forbade the request outright.
    Denied {
        /// Which static rule rejected the request.
        reason: ReasonCode,
    },
    /// The mandate requires human approval before the action may proceed. This
    /// is surfaced explicitly so it can never be rounded up to an allow.
    RequiresApproval {
        /// Always [`ReasonCode::ApprovalRequired`]; carried for auditability.
        reason: ReasonCode,
    },
    /// A required fact could not be established offline. Fails closed.
    Indeterminate {
        /// Why the outcome is indeterminate (typically
        /// [`ReasonCode::OnlineEvidenceRequired`]).
        reason: ReasonCode,
    },
    /// Every static check passed. This is NOT an authorization: it only means
    /// the request is eligible to proceed to the authoritative stage D check.
    EligibleForOnlineAuthorization {
        /// Always [`ReasonCode::StaticChecksPassed`]; carried for auditability.
        reason: ReasonCode,
    },
}

impl PolicyOutcome {
    /// Returns `true` only if the outcome is
    /// [`PolicyOutcome::EligibleForOnlineAuthorization`] — the single state that
    /// may proceed to the authoritative stage D check. This is deliberately
    /// **not** named `is_authorized`: eligibility is not authorization.
    pub fn is_eligible_for_online_authorization(&self) -> bool {
        matches!(self, PolicyOutcome::EligibleForOnlineAuthorization { .. })
    }

    /// The reason code carried by this outcome.
    pub fn reason(&self) -> ReasonCode {
        match self {
            PolicyOutcome::InvalidEvidence { reason }
            | PolicyOutcome::Denied { reason }
            | PolicyOutcome::RequiresApproval { reason }
            | PolicyOutcome::Indeterminate { reason }
            | PolicyOutcome::EligibleForOnlineAuthorization { reason } => *reason,
        }
    }
}

/// The final authoritative authorization result (stage D).
///
/// Deny-by-default: anything other than an explicit authority approval is an
/// [`Decision::Deny`]. There is no `Unknown` variant that could be mistaken for
/// a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// The request is authorized by the authority.
    Allow {
        /// Always [`ReasonCode::AuthorityApproved`]; carried for auditability.
        reason: ReasonCode,
    },
    /// The request is denied (the only safe default).
    Deny {
        /// Why the request was denied.
        reason: ReasonCode,
    },
}

impl Decision {
    /// Returns `true` only if the decision is [`Decision::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    /// The reason code carried by this decision.
    pub fn reason(&self) -> ReasonCode {
        match self {
            Decision::Allow { reason } | Decision::Deny { reason } => *reason,
        }
    }

    /// The canonical fail-closed denial for a given reason.
    pub fn deny(reason: ReasonCode) -> Self {
        Decision::Deny { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_eligible_is_not_authorization() {
        // An eligible static outcome carries no notion of "allowed"; only the
        // authoritative Decision type can express that, and only via the
        // kya-client bridge. The absence of From<PolicyOutcome> for Decision is
        // enforced by the compiler, not by this test.
        let outcome = PolicyOutcome::EligibleForOnlineAuthorization {
            reason: ReasonCode::StaticChecksPassed,
        };
        assert!(outcome.is_eligible_for_online_authorization());
        assert_eq!(outcome.reason(), ReasonCode::StaticChecksPassed);
    }

    #[test]
    fn non_eligible_outcomes_are_not_forwardable() {
        for outcome in [
            PolicyOutcome::InvalidEvidence {
                reason: ReasonCode::EvidenceInvalid,
            },
            PolicyOutcome::Denied {
                reason: ReasonCode::ActionNotPermitted,
            },
            PolicyOutcome::RequiresApproval {
                reason: ReasonCode::ApprovalRequired,
            },
            PolicyOutcome::Indeterminate {
                reason: ReasonCode::OnlineEvidenceRequired,
            },
        ] {
            assert!(
                !outcome.is_eligible_for_online_authorization(),
                "{outcome:?} must not be forwardable to stage D"
            );
        }
    }

    #[test]
    fn decision_is_deny_by_default_shape() {
        let denied = Decision::deny(ReasonCode::AuthorityUnavailable);
        assert!(!denied.is_allowed());
        assert_eq!(denied.reason(), ReasonCode::AuthorityUnavailable);
    }
}
