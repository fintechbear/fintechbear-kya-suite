//! Cross-context / cross-protocol signature-reuse regression suite
//! (AGENTS.md Rules 15, 17), Security audit Section 3.
//!
//! The `mandate_binding.rs` suite proves that substituting one *field* of a
//! mandate between sign time and verify time fails closed. This file proves the
//! complementary, higher-level property: a genuine signature minted in **one
//! context** cannot be replayed to authenticate a **different context's**
//! object. Concretely:
//!
//! 1. A signature over a raw delegation payload (the `verify_delegation` path,
//!    where the signer commits to opaque caller bytes) must NOT authenticate a
//!    `VerifiedMandate` via `verify_mandate` (whose bytes-to-verify are the
//!    mandate's canonical encoding). The magic-tagged canonical encoding differs
//!    from any raw payload, so the genuine signature does not cover it.
//! 2. A signature over mandate A's canonical encoding must NOT verify as a raw
//!    delegation over different presented bytes, nor authenticate a different
//!    mandate B (the classic substitution, re-proven here at the context
//!    boundary).
//! 3. Two DIFFERENT mandates presented with the SAME claimed verified signature
//!    cannot both authenticate: at most the one whose canonical encoding the
//!    signature actually covers verifies; the other fails closed. This is the
//!    "same claimed verified bytes" binding-mismatch case.
//! 4. An AP2-style framed payload signature does not authenticate a mandate.
//!
//! Every negative path asserts a specific fail-closed
//! [`CryptoVerificationError`] and that no `VerifiedMandate` / `VerifiedDelegation`
//! is ever produced.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_core::evidence::DelegationClaim;
use kya_core::identity::{AgentId, IssuerId, MerchantId, PrincipalId, TrustAnchors, TrustedKeyRef};
use kya_core::mandate::{Audience, Mandate, TransactionBinding, ValidityWindow};
use kya_core::money::Money;
use kya_core::scope::{Action, Scope};
use kya_crypto::{
    verify_delegation, verify_mandate, CryptoVerificationError, SignedClaim, SignedMandate,
    TrustedKeyStore,
};

const NOW: u64 = 1_500;
const AUDIENCE: &str = "aud:processor";
const BINDING: &[u8] = b"txn-binding:invoice-42";

fn issuer() -> IssuerId {
    IssuerId::new("issuer:acme").expect("valid")
}
fn agent() -> AgentId {
    AgentId::new("agent:1").expect("valid")
}
fn key() -> TrustedKeyRef {
    TrustedKeyRef::new("kid:1").expect("valid")
}
fn usd(minor: i128) -> Money {
    Money::from_code(minor, "USD").expect("valid USD")
}
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn store() -> TrustedKeyStore {
    let mut s = TrustedKeyStore::new();
    s.insert(issuer(), key(), *signing_key().verifying_key().as_bytes());
    s
}
fn anchors() -> TrustAnchors {
    let mut a = TrustAnchors::new();
    a.trust_key(issuer(), key());
    a
}
fn claim() -> DelegationClaim {
    DelegationClaim::new(issuer(), agent(), key())
}

fn mandate_a() -> Mandate {
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid"))
        .with_per_transaction_limit(usd(10_000))
        .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")]);
    Mandate::new(
        issuer(),
        PrincipalId::new("principal:alice").expect("valid"),
        agent(),
        scope,
        ValidityWindow::new(0, 3_000).expect("valid"),
    )
    .with_required_audience(Audience::new(AUDIENCE).expect("valid"))
    .bound_to(TransactionBinding::new("mandate:A").expect("valid"))
}

fn mandate_b() -> Mandate {
    // Same shape as A but a raised limit: a different logical mandate.
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid"))
        .with_per_transaction_limit(usd(100_000_000))
        .with_allowed_merchants(vec![MerchantId::new("merchant:store").expect("valid")]);
    Mandate::new(
        issuer(),
        PrincipalId::new("principal:alice").expect("valid"),
        agent(),
        scope,
        ValidityWindow::new(0, 3_000).expect("valid"),
    )
    .with_required_audience(Audience::new(AUDIENCE).expect("valid"))
    .bound_to(TransactionBinding::new("mandate:A").expect("valid"))
}

fn assert_mandate_fails_closed(
    result: Result<kya_crypto::VerifiedMandate, CryptoVerificationError>,
) {
    match result {
        Ok(_) => panic!("cross-context reuse must never yield a VerifiedMandate"),
        Err(CryptoVerificationError::BindingMismatch)
        | Err(CryptoVerificationError::SignatureInvalid)
        | Err(CryptoVerificationError::UntrustedKey)
        | Err(CryptoVerificationError::UnknownIssuer) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

// ---- (1) raw-delegation signature cannot authenticate a mandate -----------

#[test]
fn raw_delegation_signature_does_not_authenticate_a_mandate() {
    // The signer commits to an OPAQUE raw payload (as in the delegation path).
    let raw_payload = b"raw-delegation-payload-the-signer-committed-to".to_vec();
    let signature = signing_key().sign(&raw_payload).to_bytes().to_vec();

    // That same signature is presented to the MANDATE path, whose bytes-to-
    // verify are the mandate's magic-tagged canonical encoding (which differs
    // from the raw payload). It must fail closed.
    let m = mandate_a();
    let c = claim();
    let signed = SignedMandate {
        claim: &c,
        mandate: &m,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    assert_mandate_fails_closed(verify_mandate(
        &signed,
        &store(),
        &anchors(),
        NOW,
        AUDIENCE,
        BINDING,
    ));
}

#[test]
fn mandate_signature_still_authenticates_its_own_raw_payload_path_only_for_those_bytes() {
    // Positive control: a signature over mandate A's canonical encoding DOES
    // verify when the delegation path is handed exactly those bytes as the
    // signed payload (the signature is genuine over them). This shows the two
    // paths agree only when the bytes match — there is no magic difference in
    // the verifier, the difference is WHICH bytes each path commits to.
    let m = mandate_a();
    let canonical = m.canonical_encoding();
    let signature = signing_key().sign(&canonical).to_bytes().to_vec();
    let c = claim();

    let signed = SignedClaim {
        claim: &c,
        signed_bytes: &canonical,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    let evidence = verify_delegation(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING)
        .expect("genuine signature over these exact bytes verifies as a delegation");
    assert_eq!(evidence.issuer(), &issuer());
}

#[test]
fn raw_delegation_over_wrong_bytes_fails_even_with_genuine_mandate_signature() {
    // A signature over mandate A's canonical encoding presented to the
    // delegation path over DIFFERENT raw bytes must fail closed: the signature
    // does not cover the presented bytes.
    let m = mandate_a();
    let signature = signing_key()
        .sign(&m.canonical_encoding())
        .to_bytes()
        .to_vec();
    let c = claim();
    let wrong_bytes = b"these-are-not-the-canonical-encoding".to_vec();
    let signed = SignedClaim {
        claim: &c,
        signed_bytes: &wrong_bytes,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    assert_eq!(
        verify_delegation(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING),
        Err(CryptoVerificationError::SignatureInvalid)
    );
}

// ---- (3) two mandates, one claimed signature ------------------------------

#[test]
fn two_mandates_one_signature_only_the_signed_one_authenticates() {
    // The signature genuinely covers mandate A's canonical encoding.
    let a = mandate_a();
    let b = mandate_b();
    let signature = signing_key()
        .sign(&a.canonical_encoding())
        .to_bytes()
        .to_vec();
    let c = claim();

    // Presenting A with the signature: verifies (positive control).
    let signed_a = SignedMandate {
        claim: &c,
        mandate: &a,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    let verified_a = verify_mandate(&signed_a, &store(), &anchors(), NOW, AUDIENCE, BINDING)
        .expect("the mandate the signature actually covers verifies");
    assert_eq!(verified_a.issuer(), &issuer());

    // Presenting B with the SAME claimed signature: fails closed. Both cannot
    // be authenticated by one signature.
    let signed_b = SignedMandate {
        claim: &c,
        mandate: &b,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    assert_mandate_fails_closed(verify_mandate(
        &signed_b,
        &store(),
        &anchors(),
        NOW,
        AUDIENCE,
        BINDING,
    ));
}

// ---- (4) AP2-style framed payload does not authenticate a mandate ---------

#[test]
fn ap2_style_framed_signature_does_not_authenticate_a_mandate() {
    // A signature over a payload framed as if for a different protocol envelope
    // (an "AP2-style" blob) must not authenticate a KYA mandate: the mandate
    // path verifies over the magic-tagged canonical encoding, which no foreign
    // frame equals.
    let mut ap2_like = b"AP2-ENVELOPE\x01".to_vec();
    ap2_like.extend_from_slice(&mandate_a().canonical_encoding());
    let signature = signing_key().sign(&ap2_like).to_bytes().to_vec();

    let m = mandate_a();
    let c = claim();
    let signed = SignedMandate {
        claim: &c,
        mandate: &m,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    assert_mandate_fails_closed(verify_mandate(
        &signed,
        &store(),
        &anchors(),
        NOW,
        AUDIENCE,
        BINDING,
    ));
}
