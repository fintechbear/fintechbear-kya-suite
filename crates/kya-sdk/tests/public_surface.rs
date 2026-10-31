//! Integration test exercising the facade **only** through its public surface.
//!
//! This test imports nothing from `kya-core`, `kya-crypto`, or `kya-client`
//! directly (apart from the test-only `ed25519-dalek` used to produce a genuine
//! signature, exactly as the rest of the workspace does). It plays the role of
//! an external crate consuming `kya-sdk`, and walks the ten developer tasks the
//! facade promises:
//!
//! 1. configure explicit trusted issuer keys,
//! 2. configure a verification context,
//! 3. submit supported signed evidence,
//! 4. verify actual cryptographic signatures,
//! 5. inspect authenticated claims,
//! 6. supply a transaction intent,
//! 7. evaluate supported static constraints,
//! 8. inspect structured outcomes and reason codes,
//! 9. identify missing authoritative online checks,
//! 10. integrate into a backend via the fail-closed bridge.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;
use kya_sdk::runtime::block_on;

/// A trivial in-test authority that returns a fixed verdict. A consumer would
/// implement `OnlineAuthorizer` against their own backend; this stands in for
/// stage D so the test can reach a final `Decision`.
struct FixedAuthority(AuthorityVerdict);

struct Ready(Result<AuthorityVerdict, AuthorizerError>);

impl Future for Ready {
    type Output = Result<AuthorityVerdict, AuthorizerError>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.0.clone())
    }
}

impl OnlineAuthorizer for FixedAuthority {
    type Fut = Ready;
    fn authorize_request(&self, _outcome: &PolicyOutcome) -> Self::Fut {
        Ready(Ok(self.0))
    }
}

/// Build a mandate, trust configuration, and a genuine signature over the
/// mandate's canonical encoding, all through the facade surface.
fn build() -> (TrustConfiguration, Mandate, DelegationClaim, Vec<u8>) {
    // Task 1: configure explicit trusted issuer keys. A deterministic key is
    // used only to produce a real signature for the test; the consumer only
    // needs the PUBLIC key to be trusted.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme").unwrap();
    let principal = PrincipalId::new("principal:alice").unwrap();
    let agent = AgentId::new("agent:treasury").unwrap();
    let key_ref = TrustedKeyRef::new("kid:2026").unwrap();

    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");
    assert!(trust.trusts_issuer_key(&issuer, &key_ref));

    // Task 6 (building the mandate the intent is checked against): a mandate the
    // agent may 'transfer' up to 100.00 USD, valid within [0, 2000).
    let limit = Money::from_code(10_000, "USD").unwrap();
    let scope = Scope::new()
        .allow(Action::new("transfer").unwrap())
        .with_per_transaction_limit(limit);
    let mandate = Mandate::new(
        issuer.clone(),
        principal,
        agent.clone(),
        scope,
        ValidityWindow::new(0, 2_000).unwrap(),
    );

    // Task 3: the raw delegation claim and a genuine signature over the
    // mandate's canonical encoding (the exact bytes the verified-mandate path
    // binds to).
    let claim = DelegationClaim::new(issuer, agent, key_ref);
    let signature = signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();

    (trust, mandate, claim, signature)
}

#[test]
fn full_flow_through_public_facade_only() {
    let (trust, mandate, claim, signature) = build();

    // Task 2: configure the verification context (injected time, audience,
    // binding).
    let now: u64 = 1_000;
    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-42";
    let conditions = RequestConditions::new(now, audience, binding);

    // Task 3 + 4: submit signed evidence and verify the REAL signature through
    // the facade's re-export of the kya-crypto engine.
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };
    let verified: VerifiedMandate = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        conditions.now,
        conditions.expected_audience,
        conditions.expected_binding,
    )
    .expect("genuine signature over the canonical encoding must verify");

    // Task 5: inspect authenticated claims, including the honest PoP state.
    assert_eq!(verified.issuer().as_str(), "issuer:acme");
    assert_eq!(verified.agent().as_str(), "agent:treasury");
    assert_eq!(
        verified.proof_of_possession(),
        ProofOfPossession::NotEstablished,
        "issuer-signed binding is not agent proof-of-possession"
    );

    // Task 6: supply a transaction intent.
    let intent = TransactionIntent::new(
        AgentId::new("agent:treasury").unwrap(),
        MerchantId::new("merchant:supplier").unwrap(),
        ResourceId::new("invoice:42").unwrap(),
        Action::new("transfer").unwrap(),
        Money::from_code(5_000, "USD").unwrap(),
    );

    // Task 7: evaluate static constraints (synchronous, offline, no network).
    let outcome = evaluate(&verified, &intent, now);

    // Task 8: inspect structured outcomes and reason codes.
    assert_eq!(outcome.reason(), ReasonCode::StaticChecksPassed);

    // Task 9: identify the missing authoritative online check. Eligibility is
    // NOT authorization; the online state is still unestablished.
    assert!(requires_online_authorization(&outcome));
    assert!(kya_sdk::online_state_is_unestablished(&outcome));

    // Task 10: integrate into a backend via the fail-closed bridge. Only an
    // explicit authority approval yields Allow.
    let approved = block_on(authorize(
        &FixedAuthority(AuthorityVerdict::Approved),
        &outcome,
    ));
    assert!(approved.is_allowed());
    assert_eq!(approved.reason(), ReasonCode::AuthorityApproved);

    // And the bridge fails closed on an authority denial.
    let denied = block_on(authorize(
        &FixedAuthority(AuthorityVerdict::Denied),
        &outcome,
    ));
    assert!(!denied.is_allowed());
    assert_eq!(denied.reason(), ReasonCode::AuthorityDenied);
}

#[test]
fn denied_and_indeterminate_are_distinguishable_and_never_eligible() {
    // A consumer must be able to tell a static denial apart from an
    // indeterminate (missing-online-state) outcome, and neither is eligible.
    let denied = PolicyOutcome::Denied {
        reason: ReasonCode::ActionNotPermitted,
    };
    let indeterminate = PolicyOutcome::Indeterminate {
        reason: ReasonCode::OnlineEvidenceRequired,
    };

    assert_ne!(denied.reason(), indeterminate.reason());
    assert!(!requires_online_authorization(&denied));
    assert!(!requires_online_authorization(&indeterminate));

    // The fail-closed bridge never contacts an authority for either and denies
    // with the carried reason.
    let d = block_on(authorize(
        &FixedAuthority(AuthorityVerdict::Approved),
        &denied,
    ));
    assert_eq!(d.reason(), ReasonCode::ActionNotPermitted);
    let i = block_on(authorize(
        &FixedAuthority(AuthorityVerdict::Approved),
        &indeterminate,
    ));
    assert_eq!(i.reason(), ReasonCode::OnlineEvidenceRequired);
}

#[test]
fn trust_misconfiguration_surfaces_a_clear_error_and_stable_code() {
    // Submitting a mandate whose issuer key is not trusted fails closed with a
    // structured error that maps to a stable code — no secrets in the message.
    let (_trust, mandate, claim, signature) = build();
    let empty_trust = TrustConfiguration::new();
    let now: u64 = 1_000;
    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-42";

    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };
    let err = verify_mandate(
        &signed,
        empty_trust.key_store(),
        empty_trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect_err("an unconfigured trust store must fail closed");

    // The error exposes a stable, machine-readable code (unknown issuer) and a
    // non-sensitive message.
    assert_eq!(err.error_code(), ErrorCode::VerificationUnknownIssuer);
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn malformed_trust_key_is_rejected_up_front() {
    let issuer = IssuerId::new("issuer:acme").unwrap();
    let key_ref = TrustedKeyRef::new("kid:2026").unwrap();
    let mut trust = TrustConfiguration::new();
    let err = trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), &[0u8; 16])
        .expect_err("a 16-byte key must be rejected");
    assert_eq!(err, TrustConfigurationError::MalformedPublicKey { got: 16 });
    // Predictable initialization: nothing was registered.
    assert!(!trust.trusts_issuer_key(&issuer, &key_ref));
}
