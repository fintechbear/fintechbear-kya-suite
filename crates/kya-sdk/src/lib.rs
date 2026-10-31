#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Rule 6: production paths must not use unwrap/expect (clippy warns workspace-wide).
// Tests MAY use them for brevity, so relax the lint under `cfg(test)` only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # kya-sdk
//!
//! The ergonomic public **facade** of the FintechBear KYA ("Know Your Agent")
//! SDK. It is a thin, outermost-ring crate that re-exports a curated, stable
//! surface over the three library crates so a consumer can run the whole
//! verify + evaluate + authorize flow from **one** entry point, without having
//! to learn the internal module layout of [`kya_core`], [`kya_crypto`], and
//! [`kya_client`].
//!
//! The facade adds **no** new behaviour and **no** new trust: it never
//! implements cryptography, never performs I/O, and — crucially — never exposes
//! a constructor that mints verified evidence without real verification. Every
//! security-relevant operation it surfaces is the *same* function from the
//! underlying crates, routed through the *same* sealed, fail-closed paths.
//!
//! ## What a consumer can do through this one crate
//!
//! 1. **Configure explicit trusted issuer keys.** Build a [`TrustConfiguration`]
//!    that wraps the [`TrustAnchors`] (which `(issuer, key_ref)` pairs are
//!    trusted) and the [`TrustedKeyStore`] (the concrete public-key bytes)
//!    together, because verification requires *both* and configuring them
//!    separately is the most common first-day mistake.
//! 2. **Configure a verification context.** Build a [`RequestConditions`] value
//!    naming the expected audience, the injected current time, and the exact
//!    transaction-binding bytes the request presents.
//! 3. **Submit supported signed evidence.** Assemble a [`SignedMandate`] (the
//!    [`DelegationClaim`], the [`Mandate`], the detached Ed25519 signature, and
//!    the validity window).
//! 4. **Verify actual cryptographic signatures** with [`verify_mandate`] (or
//!    [`verify_delegation`]), which route through the *real* [`kya_crypto`]
//!    engine whose verified-evidence mint-points are owned privately inside
//!    `kya-crypto`. There is no stand-in.
//! 5. **Inspect authenticated claims** via the accessors on [`VerifiedMandate`]
//!    — including [`VerifiedMandate::proof_of_possession`], which honestly
//!    reports [`ProofOfPossession::NotEstablished`].
//! 6. **Supply a transaction intent** with [`TransactionIntent`].
//! 7. **Evaluate supported static constraints** with [`evaluate`], producing a
//!    structured [`PolicyOutcome`] (stage C).
//! 8. **Inspect structured outcomes and reason codes** via [`PolicyOutcome`],
//!    [`ReasonCode`], and the stable [`ErrorCode`] / [`AsErrorCode`] surface.
//! 9. **Identify missing authoritative online checks** with
//!    [`requires_online_authorization`] and [`online_state_is_unestablished`],
//!    which make "eligibility is not authorization" explicit in the type system
//!    and in prose.
//! 10. **Integrate into their own backend** by implementing the
//!     [`OnlineAuthorizer`] / [`IntegrationClient`] trait seams and calling the
//!     one fail-closed [`authorize`] bridge.
//!
//! ## Open-source independence (no FintechBear account required)
//!
//! Everything above runs with **only** the consumer's explicitly configured
//! trust keys. The facade requires **no** API key, subscription, hosted
//! FintechBear account, database, SaaS dashboard, cloud service, or payment
//! provider credentials. Local verification ([`verify_mandate`],
//! [`verify_delegation`]) and static evaluation ([`evaluate`]) are **synchronous**
//! and make **no** network call.
//!
//! The boundary between what is open and what is not:
//!
//! - **Open-source local verification (this crate and its dependencies):**
//!   stages A, B, and C — identity, real signature verification, and static
//!   policy. Fully usable offline with caller-configured trust.
//! - **External authoritative authorization (stage D):** revocation, cumulative
//!   budget, and global replay state. This crate re-exports only the
//!   [`OnlineAuthorizer`] / [`IntegrationClient`] **trait seams** and the
//!   fail-closed [`authorize`] bridge. It ships **no** concrete authority,
//!   payment processor, custodial wallet, managed-revocation service, budget
//!   ledger, approval server, billing, or SaaS backend. The consumer (or a
//!   future managed platform) supplies the implementation.
//! - **Future managed FintechBear infrastructure:** a hosted implementation of
//!   the stage-D seams. It is not part of this open-source SDK and is not
//!   required to use it; the same open core is reusable inside it unchanged.
//!
//! ## Protocol-adapter honesty
//!
//! The AP2 constraint adapter is **experimental and incomplete**; it is *not*
//! full AP2 support and is deliberately **not** re-exported from this facade.
//! See the [`ap2`] module documentation here and the `kya-adapter-ap2` crate
//! docs for the precise supported / unsupported / unverified boundary.
//!
//! ## What this crate is NOT
//!
//! It is not a place for new logic. If a behaviour is security-relevant it
//! belongs in the reviewed inner crate behind its existing seal, and the facade
//! only re-exports it. The facade intentionally exposes **no** boolean-only
//! authorization API, **no** `From<PolicyOutcome> for Decision`, and **no**
//! async wrapper around the synchronous local path.

pub mod ap2;
pub mod prelude;
mod trust;

pub use trust::{RequestConditions, TrustConfiguration, TrustConfigurationError};

// ---------------------------------------------------------------------------
// Curated re-exports.
//
// These are the SAME types and functions from the inner crates. Re-exporting
// them here gives consumers one import surface and a stable facade path; it
// adds no behaviour and weakens no seal.
// ---------------------------------------------------------------------------

// Stage A — identity and explicit trust.
pub use kya_core::identity::{
    AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustAnchors, TrustedKeyRef,
};

// Evidence: the raw-claim / verified-evidence distinction, and the honest
// proof-of-possession state. The raw claim and the typed errors live in
// kya-core; the verified-evidence types live in kya-crypto (the only crate that
// can mint them, bound to the reviewed verifier).
pub use kya_core::evidence::{
    DelegationClaim, EvidenceError, MandateBindingError, ProofOfPossession,
};

// Domain value types for building a mandate and a transaction intent.
pub use kya_core::mandate::{
    Audience, Mandate, TransactionBinding, TransactionIntent, ValidityError, ValidityWindow,
};
pub use kya_core::money::{CurrencyCode, CurrencyError, Money, MoneyError};
pub use kya_core::scope::{Action, Scope, ScopeError};

// Stage B — the REAL cryptographic engine entry points and verified-evidence
// types. No stand-in; the verified types are only constructible here.
pub use kya_crypto::{
    verify_delegation, verify_mandate, CryptoVerificationError, Ed25519PublicKeyBytes, JwsEdDsa,
    SignedClaim, SignedMandate, TrustedKeyStore, VerificationOutcome, VerificationProof,
    VerifiedDelegation, VerifiedMandate, ACCEPTED_ALGORITHM,
};

// Stage C — the static policy evaluator and its structured results.
pub use kya_core::decision::{Decision, PolicyOutcome, ReasonCode};
pub use kya_core::policy::evaluate;

// Stable, machine-readable error-code surface (DX): every public typed error
// maps to a stable kebab-case code.
pub use kya_core::error::{AsErrorCode, ErrorCode};

// Stage D — the fail-closed bridge and the integration trait seams ONLY. No
// concrete authority or transport is provided.
pub use kya_client::{
    authorize, runtime, AuthorityVerdict, AuthorizerError, IntegrationClient, OnlineAuthorizer,
};

/// Returns `true` only when `outcome` is eligible to proceed to the stage-D
/// online authority — i.e. when an authoritative online check is **required
/// and still outstanding**.
///
/// This is the facade's explicit statement of a core safety fact: a passing
/// static evaluation is **eligibility, not authorization**. When this returns
/// `true`, the consumer must still call [`authorize`] with an
/// [`OnlineAuthorizer`]; the request is **not** authorized yet. When it returns
/// `false`, the static outcome already rejected (invalid evidence, denied,
/// approval required, or indeterminate) and must fail closed — it can never
/// become an `Allow` without the authority.
///
/// It is a thin, non-panicking wrapper over
/// [`PolicyOutcome::is_eligible_for_online_authorization`], named from the
/// consumer's perspective ("do I still owe an online check?").
pub fn requires_online_authorization(outcome: &PolicyOutcome) -> bool {
    outcome.is_eligible_for_online_authorization()
}

/// Returns `true` whenever the authoritative online state (revocation,
/// cumulative budget, global replay) has **not** been established by this
/// local, offline flow.
///
/// This is always `true` for any [`PolicyOutcome`] produced by [`evaluate`]:
/// static evaluation is offline and *cannot* know current revocation, budget,
/// or replay state. The helper exists so a consumer can assert, in code, that
/// the online state is unestablished after local verification and evaluation,
/// and must be resolved by the stage-D [`authorize`] bridge before any
/// execution. It never looks at the variant precisely because the answer does
/// not depend on it: offline evaluation establishes none of the online facts.
pub fn online_state_is_unestablished(_outcome: &PolicyOutcome) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligible_outcome_requires_online_authorization() {
        let eligible = PolicyOutcome::EligibleForOnlineAuthorization {
            reason: ReasonCode::StaticChecksPassed,
        };
        assert!(requires_online_authorization(&eligible));
        // Even an eligible outcome leaves the online state unestablished.
        assert!(online_state_is_unestablished(&eligible));
    }

    #[test]
    fn rejecting_outcomes_do_not_require_online_authorization() {
        for outcome in [
            PolicyOutcome::Denied {
                reason: ReasonCode::ActionNotPermitted,
            },
            PolicyOutcome::InvalidEvidence {
                reason: ReasonCode::EvidenceInvalid,
            },
            PolicyOutcome::RequiresApproval {
                reason: ReasonCode::ApprovalRequired,
            },
            PolicyOutcome::Indeterminate {
                reason: ReasonCode::OnlineEvidenceRequired,
            },
        ] {
            assert!(
                !requires_online_authorization(&outcome),
                "{outcome:?} rejected statically and must not be eligible"
            );
            // The online state is unestablished regardless of the outcome: the
            // offline flow never learns revocation/budget/replay state.
            assert!(online_state_is_unestablished(&outcome));
        }
    }
}
