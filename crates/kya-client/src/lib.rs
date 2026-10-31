#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # kya-client
//!
//! The online authoritative authorization layer (**stage D**) and the
//! external-integration client seam of the FintechBear KYA SDK. This crate
//! defines traits only; it ships no concrete HTTP, database, or cloud
//! transport. Concrete transports are supplied by downstream code or, later, by
//! the commercial platform.
//!
//! ## Why a separate stage D
//!
//! Static policy evaluation (stage C, in [`kya_core::policy`]) is offline and
//! deterministic. It cannot know whether a mandate has been revoked, whether a
//! cumulative budget is exhausted, or whether a request replays a prior one.
//! Establishing that current, global state requires trustworthy authoritative
//! evidence, which is exactly what an [`OnlineAuthorizer`] provides.
//!
//! ## Fail-closed by construction
//!
//! There is deliberately no `From<PolicyOutcome> for Decision` anywhere in the
//! SDK. The only path from a stage-C [`PolicyOutcome`] to a final
//! [`Decision`] is [`authorize`], which:
//!
//! - never contacts the authority when the static outcome already rejected;
//! - denies when the authority returns an error, a timeout, an unknown state,
//!   or an approval-required signal;
//! - allows only on an explicit authority approval.

use core::future::Future;
use kya_core::decision::{Decision, PolicyOutcome, ReasonCode};

pub mod runtime;

/// The authoritative verdict returned by an [`OnlineAuthorizer`].
///
/// This is intentionally richer than [`Decision`] so that "approval required"
/// and "unknown" are explicit and cannot be silently coerced into an allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityVerdict {
    /// The authority explicitly approves the request.
    Approved,
    /// The authority explicitly denies the request.
    Denied,
    /// The request needs out-of-band human approval before proceeding.
    ApprovalRequired,
}

/// Errors from the authoritative authorization channel.
///
/// Every variant maps to a fail-closed [`Decision::Deny`] in [`authorize`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorizerError {
    /// The authority could not be reached in time.
    Timeout,
    /// A transport-level failure occurred.
    Transport,
    /// The authority returned a response the client could not interpret.
    Unknown,
}

impl core::fmt::Display for AuthorizerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            AuthorizerError::Timeout => "authority request timed out",
            AuthorizerError::Transport => "authority transport failure",
            AuthorizerError::Unknown => "authority returned an uninterpretable response",
        };
        f.write_str(s)
    }
}

impl std::error::Error for AuthorizerError {}

/// The stage D online authoritative authorization seam.
///
/// Implementors contact an authority (revocation, cumulative-budget, replay
/// state) and return a typed verdict. Implementors are runtime-agnostic: the
/// trait returns a [`Future`] but mandates no particular async runtime.
pub trait OnlineAuthorizer {
    /// The future returned by [`OnlineAuthorizer::authorize_request`].
    type Fut: Future<Output = Result<AuthorityVerdict, AuthorizerError>>;

    /// Ask the authority to rule on a request whose static checks already
    /// passed. The static [`PolicyOutcome`] is passed for context and audit.
    fn authorize_request(&self, outcome: &PolicyOutcome) -> Self::Fut;
}

/// The external-integration client abstraction (payment providers, ledgers,
/// etc.). This is a trait seam only; no concrete transport is implemented.
pub trait IntegrationClient {
    /// The future returned by [`IntegrationClient::submit`].
    type Fut: Future<Output = Result<(), AuthorizerError>>;

    /// Submit an already-authorized action to the external system.
    fn submit(&self, decision: &Decision) -> Self::Fut;
}

/// The one and only fail-closed bridge from a stage-C [`PolicyOutcome`] to a
/// final [`Decision`].
///
/// Behaviour:
///
/// - If `outcome` is not [`PolicyOutcome::EligibleForOnlineAuthorization`],
///   returns `Deny` immediately with the outcome's reason and does **not**
///   await the authorizer. This covers `InvalidEvidence`, `Denied`,
///   `RequiresApproval`, and `Indeterminate`: none of them may become an
///   `Allow` without the authority, so the bridge never even contacts it.
/// - Otherwise awaits the authorizer and maps its result fail-closed:
///   `Approved` -> `Allow`; `Denied` -> `Deny`; `ApprovalRequired` -> `Deny`;
///   any [`AuthorizerError`] -> `Deny`.
///
/// There is deliberately no silent-upgrade path: an eligible static outcome is
/// only ever a precondition for contacting the authority, never authorization
/// on its own.
pub async fn authorize<A>(authorizer: &A, outcome: &PolicyOutcome) -> Decision
where
    A: OnlineAuthorizer,
{
    if !outcome.is_eligible_for_online_authorization() {
        // Static policy did not reach the eligible state (it rejected, required
        // approval, found invalid evidence, or was indeterminate): never
        // contact the authority, and fail closed to Deny with the reason.
        return Decision::deny(outcome.reason());
    }

    match authorizer.authorize_request(outcome).await {
        Ok(AuthorityVerdict::Approved) => Decision::Allow {
            reason: ReasonCode::AuthorityApproved,
        },
        Ok(AuthorityVerdict::Denied) => Decision::deny(ReasonCode::AuthorityDenied),
        Ok(AuthorityVerdict::ApprovalRequired) => Decision::deny(ReasonCode::ApprovalRequired),
        Err(_) => Decision::deny(ReasonCode::AuthorityUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::block_on;
    use core::cell::Cell;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    /// A ready future carrying a fixed authorizer result, recording whether it
    /// was ever polled so tests can prove the authority was/was not contacted.
    struct ReadyAuth<'a> {
        result: Result<AuthorityVerdict, AuthorizerError>,
        contacted: &'a Cell<bool>,
    }

    struct ReadyFut {
        result: Result<AuthorityVerdict, AuthorizerError>,
    }

    impl Future for ReadyFut {
        type Output = Result<AuthorityVerdict, AuthorizerError>;
        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(self.result.clone())
        }
    }

    impl OnlineAuthorizer for ReadyAuth<'_> {
        type Fut = ReadyFut;
        fn authorize_request(&self, _outcome: &PolicyOutcome) -> Self::Fut {
            self.contacted.set(true);
            ReadyFut {
                result: self.result.clone(),
            }
        }
    }

    fn passed() -> PolicyOutcome {
        PolicyOutcome::EligibleForOnlineAuthorization {
            reason: ReasonCode::StaticChecksPassed,
        }
    }

    fn rejected() -> PolicyOutcome {
        PolicyOutcome::Denied {
            reason: ReasonCode::ActionNotPermitted,
        }
    }

    #[test]
    fn passed_outcome_can_be_authorized() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::Approved),
            contacted: &contacted,
        };
        let decision = block_on(authorize(&auth, &passed()));
        assert!(decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::AuthorityApproved);
        assert!(contacted.get(), "authority should be contacted when passed");
    }

    #[test]
    fn denied_outcome_never_contacts_authority() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::Approved),
            contacted: &contacted,
        };
        let decision = block_on(authorize(&auth, &rejected()));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::ActionNotPermitted);
        assert!(
            !contacted.get(),
            "authority must NOT be contacted when static policy rejected"
        );
    }

    #[test]
    fn approval_required_is_not_auto_authorized() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::ApprovalRequired),
            contacted: &contacted,
        };
        let decision = block_on(authorize(&auth, &passed()));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::ApprovalRequired);
    }

    #[test]
    fn authorizer_error_fails_closed_to_deny() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Err(AuthorizerError::Timeout),
            contacted: &contacted,
        };
        let decision = block_on(authorize(&auth, &passed()));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::AuthorityUnavailable);
    }

    #[test]
    fn explicit_denial_maps_to_deny() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::Denied),
            contacted: &contacted,
        };
        let decision = block_on(authorize(&auth, &passed()));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::AuthorityDenied);
    }

    #[test]
    fn requires_approval_outcome_never_contacts_authority() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::Approved),
            contacted: &contacted,
        };
        let outcome = PolicyOutcome::RequiresApproval {
            reason: ReasonCode::ApprovalRequired,
        };
        let decision = block_on(authorize(&auth, &outcome));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::ApprovalRequired);
        assert!(
            !contacted.get(),
            "RequiresApproval must not reach the authority as eligible"
        );
    }

    #[test]
    fn invalid_evidence_outcome_fails_closed_without_contacting_authority() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::Approved),
            contacted: &contacted,
        };
        let outcome = PolicyOutcome::InvalidEvidence {
            reason: ReasonCode::EvidenceInvalid,
        };
        let decision = block_on(authorize(&auth, &outcome));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::EvidenceInvalid);
        assert!(!contacted.get());
    }

    #[test]
    fn indeterminate_outcome_fails_closed_without_contacting_authority() {
        let contacted = Cell::new(false);
        let auth = ReadyAuth {
            result: Ok(AuthorityVerdict::Approved),
            contacted: &contacted,
        };
        let outcome = PolicyOutcome::Indeterminate {
            reason: ReasonCode::OnlineEvidenceRequired,
        };
        let decision = block_on(authorize(&auth, &outcome));
        assert!(!decision.is_allowed());
        assert_eq!(decision.reason(), ReasonCode::OnlineEvidenceRequired);
        assert!(
            !contacted.get(),
            "a missing-online-state outcome can never become Allow"
        );
    }
}
