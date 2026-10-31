//! End-to-end integration tests across all five stages.
//!
//! These wire the real `kya-core` domain types (stages A, B, C) through the
//! real `kya_client::authorize` bridge (stage D) and assert the security
//! invariants hold across crate boundaries (AGENTS.md Rule 14): a verified
//! delegation plus a passing static policy is still not an authorization until
//! the authority approves, and every non-approval path fails closed to `Deny`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use kya_client::runtime::block_on;
use kya_client::{authorize, AuthorityVerdict, AuthorizerError, OnlineAuthorizer};
use kya_core::decision::{PolicyOutcome, ReasonCode};
use kya_core::evidence::DelegationClaim;
use kya_core::identity::{
    AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustAnchors, TrustedKeyRef,
};
use kya_core::mandate::{Mandate, TransactionIntent, ValidityWindow};
use kya_core::money::Money;
use kya_core::scope::{Action, Scope};
use kya_crypto::{
    verify_mandate, CryptoVerificationError, SignedMandate, TrustedKeyStore, VerifiedMandate,
};

use ed25519_dalek::{Signer, SigningKey};

// --- a minimal fixed-result authorizer so tests exercise the real bridge ---

struct FixedAuth {
    result: Result<AuthorityVerdict, AuthorizerError>,
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

impl OnlineAuthorizer for FixedAuth {
    type Fut = ReadyFut;
    fn authorize_request(&self, _outcome: &PolicyOutcome) -> Self::Fut {
        ReadyFut {
            result: self.result.clone(),
        }
    }
}

// --- shared fixtures spanning stage A identities ---

fn issuer() -> IssuerId {
    IssuerId::new("issuer:acme-bank").expect("valid")
}
fn principal() -> PrincipalId {
    PrincipalId::new("principal:acme-treasury").expect("valid")
}
fn agent() -> AgentId {
    AgentId::new("agent:treasury-bot").expect("valid")
}
fn key() -> TrustedKeyRef {
    TrustedKeyRef::new("kid:acme-2026").expect("valid")
}

fn anchors() -> TrustAnchors {
    let mut a = TrustAnchors::new();
    a.trust_key(issuer(), key());
    a
}

/// Deterministic issuer signing key for the test (public key is anchored and
/// registered in the key store so the real engine can verify a genuine
/// signature).
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

const AUDIENCE: &str = "aud:acme-payments";
const BINDING: &[u8] = b"txn-binding:invoice-2026-0042";

fn mandate() -> Mandate {
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid"))
        .with_per_transaction_limit(Money::from_code(10_000, "USD").expect("valid"));
    Mandate::new(
        issuer(),
        principal(),
        agent(),
        scope,
        ValidityWindow::new(0, 2_000).expect("valid window"),
    )
}

/// Produce a GENUINE authenticated [`VerifiedMandate`] through the sanctioned
/// `kya-crypto` engine over a real Ed25519 signature that covers the mandate's
/// **canonical encoding**. The verified-mandate seal forbids pairing a
/// signature with a mandate it does not cover, so even the tests must sign the
/// exact mandate they evaluate. This is the mandate-bound fix for Security
/// Check B: the evaluated mandate is provably the signed one.
fn verified_mandate(anchors: &TrustAnchors) -> Result<VerifiedMandate, CryptoVerificationError> {
    let m = mandate();
    let sk = signing_key();
    let signature = sk.sign(&m.canonical_encoding()).to_bytes().to_vec();
    let claim = DelegationClaim::new(issuer(), agent(), key());

    let mut store = TrustedKeyStore::new();
    store.insert(issuer(), key(), *sk.verifying_key().as_bytes());

    let signed = SignedMandate {
        claim: &claim,
        mandate: &m,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 2_000,
        binding: BINDING,
    };
    verify_mandate(&signed, &store, anchors, 1_000, AUDIENCE, BINDING)
}

/// The injected current time used for stage-C evaluation in these tests; it
/// lies within the mandate's validity window.
const NOW: u64 = 1_000;

fn intent(action: &str, minor: i128) -> TransactionIntent {
    TransactionIntent::new(
        agent(),
        MerchantId::new("merchant:supplier-co").expect("valid"),
        ResourceId::new("invoice:2026-0042").expect("valid"),
        Action::new(action).expect("valid"),
        Money::from_code(minor, "USD").expect("valid"),
    )
    .with_principal(principal())
}

// --- tests ---

#[test]
fn full_happy_path_requires_authority_approval_for_allow() {
    // Stage A/B: establish the authenticated verified mandate through the real
    // engine (signature over the mandate's canonical encoding).
    let verified = verified_mandate(&anchors()).expect("mandate should verify");
    assert_eq!(verified.agent(), &agent());

    // Stage C: static policy passes.
    let outcome = kya_core::policy::evaluate(&verified, &intent("transfer", 5_000), NOW);
    assert!(
        outcome.is_eligible_for_online_authorization(),
        "static checks should pass"
    );

    // Stage D: only an authority Approved yields Allow.
    let auth = FixedAuth {
        result: Ok(AuthorityVerdict::Approved),
    };
    let decision = block_on(authorize(&auth, &outcome));
    assert!(decision.is_allowed());
    assert_eq!(decision.reason(), ReasonCode::AuthorityApproved);
}

#[test]
fn verified_mandate_plus_passed_policy_is_not_authorization() {
    // Even with a verified mandate and a passing policy, an authority that
    // denies (or errors, or needs approval) must produce Deny. This is the
    // central security distinction tested end to end.
    let verified = verified_mandate(&anchors()).expect("mandate should verify");
    let outcome = kya_core::policy::evaluate(&verified, &intent("transfer", 5_000), NOW);
    assert!(outcome.is_eligible_for_online_authorization());

    for (result, expected) in [
        (Ok(AuthorityVerdict::Denied), ReasonCode::AuthorityDenied),
        (
            Ok(AuthorityVerdict::ApprovalRequired),
            ReasonCode::ApprovalRequired,
        ),
        (
            Err(AuthorizerError::Timeout),
            ReasonCode::AuthorityUnavailable,
        ),
        (
            Err(AuthorizerError::Transport),
            ReasonCode::AuthorityUnavailable,
        ),
        (
            Err(AuthorizerError::Unknown),
            ReasonCode::AuthorityUnavailable,
        ),
    ] {
        let auth = FixedAuth { result };
        let decision = block_on(authorize(&auth, &outcome));
        assert!(!decision.is_allowed(), "must not allow for {expected:?}");
        assert_eq!(decision.reason(), expected);
    }
}

#[test]
fn static_rejection_short_circuits_to_deny() {
    // An out-of-scope action rejects at stage C; the bridge must deny and must
    // not need the authority at all.
    let verified = verified_mandate(&anchors()).expect("mandate should verify");
    let outcome = kya_core::policy::evaluate(&verified, &intent("wire-to-unknown", 5_000), NOW);
    assert_eq!(outcome.reason(), ReasonCode::ActionNotPermitted);

    let auth = FixedAuth {
        result: Ok(AuthorityVerdict::Approved), // would allow if contacted
    };
    let decision = block_on(authorize(&auth, &outcome));
    assert!(!decision.is_allowed());
    assert_eq!(decision.reason(), ReasonCode::ActionNotPermitted);
}

#[test]
fn untrusted_issuer_cannot_produce_verified_mandate() {
    // Trust anchors are empty: even a genuine signature does not yield a
    // verified mandate through the sanctioned engine. There is no path to
    // fabricate a verified identity, and an unanchored key fails closed.
    let empty = TrustAnchors::new();
    assert!(matches!(
        verified_mandate(&empty),
        Err(CryptoVerificationError::UntrustedKey)
    ));
}

#[test]
fn over_limit_amount_is_denied_end_to_end() {
    let verified = verified_mandate(&anchors()).expect("mandate should verify");
    let outcome = kya_core::policy::evaluate(&verified, &intent("transfer", 10_001), NOW);
    assert_eq!(outcome.reason(), ReasonCode::AmountExceedsLimit);
    let auth = FixedAuth {
        result: Ok(AuthorityVerdict::Approved),
    };
    let decision = block_on(authorize(&auth, &outcome));
    assert!(!decision.is_allowed());
    assert_eq!(decision.reason(), ReasonCode::AmountExceedsLimit);
}

#[test]
fn no_negative_stage_c_outcome_can_become_allow() {
    // STEP 6 critical assertion: enumerate every non-eligible stage-C outcome
    // and prove that routing it through the fail-closed bridge NEVER yields an
    // Allow, even when the (stubbed) authority would have approved. The bridge
    // must also never contact the authority for any of these.
    let non_eligible = [
        (
            PolicyOutcome::InvalidEvidence {
                reason: ReasonCode::EvidenceInvalid,
            },
            ReasonCode::EvidenceInvalid,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::ActionNotPermitted,
            },
            ReasonCode::ActionNotPermitted,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::MerchantNotPermitted,
            },
            ReasonCode::MerchantNotPermitted,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::ResourceNotPermitted,
            },
            ReasonCode::ResourceNotPermitted,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::CurrencyNotPermitted,
            },
            ReasonCode::CurrencyNotPermitted,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::AmountExceedsLimit,
            },
            ReasonCode::AmountExceedsLimit,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::MandateExpired,
            },
            ReasonCode::MandateExpired,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::MandateNotYetValid,
            },
            ReasonCode::MandateNotYetValid,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::AudienceMismatch,
            },
            ReasonCode::AudienceMismatch,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::BindingMismatch,
            },
            ReasonCode::BindingMismatch,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::AgentMismatch,
            },
            ReasonCode::AgentMismatch,
        ),
        (
            PolicyOutcome::Denied {
                reason: ReasonCode::PrincipalMismatch,
            },
            ReasonCode::PrincipalMismatch,
        ),
        (
            PolicyOutcome::RequiresApproval {
                reason: ReasonCode::ApprovalRequired,
            },
            ReasonCode::ApprovalRequired,
        ),
        (
            PolicyOutcome::Indeterminate {
                reason: ReasonCode::OnlineEvidenceRequired,
            },
            ReasonCode::OnlineEvidenceRequired,
        ),
    ];

    for (outcome, expected) in non_eligible {
        let auth = FixedAuth {
            // The authority WOULD approve; the bridge must still deny because
            // the static outcome is not eligible.
            result: Ok(AuthorityVerdict::Approved),
        };
        let decision = block_on(authorize(&auth, &outcome));
        assert!(!decision.is_allowed(), "{outcome:?} must never yield Allow");
        assert_eq!(
            decision.reason(),
            expected,
            "{outcome:?} must deny with its own reason"
        );
    }
}

#[test]
fn missing_online_state_always_fails_closed_to_deny() {
    // "Missing online state": the request passed every static check (eligible),
    // but the authority cannot establish revocation / replay / budget / online
    // approval. Every such path - explicit denial, approval-required, timeout,
    // transport failure, or an uninterpretable response - must fail closed to
    // Deny. This is the end-to-end proof that offline eligibility is never
    // execution permission.
    let verified = verified_mandate(&anchors()).expect("mandate should verify");
    let eligible = kya_core::policy::evaluate(&verified, &intent("transfer", 5_000), NOW);
    assert!(eligible.is_eligible_for_online_authorization());

    for (result, expected) in [
        (Ok(AuthorityVerdict::Denied), ReasonCode::AuthorityDenied),
        (
            Ok(AuthorityVerdict::ApprovalRequired),
            ReasonCode::ApprovalRequired,
        ),
        (
            Err(AuthorizerError::Timeout),
            ReasonCode::AuthorityUnavailable,
        ),
        (
            Err(AuthorizerError::Transport),
            ReasonCode::AuthorityUnavailable,
        ),
        (
            Err(AuthorizerError::Unknown),
            ReasonCode::AuthorityUnavailable,
        ),
    ] {
        let auth = FixedAuth { result };
        let decision = block_on(authorize(&auth, &eligible));
        assert!(
            !decision.is_allowed(),
            "missing online state must never allow ({expected:?})"
        );
        assert_eq!(decision.reason(), expected);
    }
}

#[test]
fn only_an_eligible_outcome_with_authority_approval_yields_allow() {
    // The single positive control: the ONLY way to reach Allow is an eligible
    // static outcome AND an explicit authority approval. This pins down that
    // Allow is not reachable by any other combination exercised above.
    let verified = verified_mandate(&anchors()).expect("mandate should verify");
    let eligible = kya_core::policy::evaluate(&verified, &intent("transfer", 5_000), NOW);
    let auth = FixedAuth {
        result: Ok(AuthorityVerdict::Approved),
    };
    let decision = block_on(authorize(&auth, &eligible));
    assert!(decision.is_allowed());
    assert_eq!(decision.reason(), ReasonCode::AuthorityApproved);
}
