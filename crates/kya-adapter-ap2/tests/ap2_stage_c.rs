//! Integration tests for the AP2 constraint adapter across stages A/B and C.
//!
//! These wire the adapter's independently-verifiable surface end to end: map
//! AP2-style constraints onto a `kya-core` [`Mandate`], verify a genuine
//! Ed25519 signature over the mandate's canonical encoding through `kya-crypto`
//! (so the evaluated mandate is provably the signed one), and run the UNCHANGED
//! stage-C evaluator ([`kya_core::policy::evaluate`]) on the resulting
//! authenticated [`kya_crypto::VerifiedMandate`]. They assert specific
//! outcome and error variants (AGENTS.md Rule 14), both on the happy path and
//! on fail-closed negatives (wrong currency, out-of-scope action, tampered
//! signature, substituted mandate).
//!
//! What these tests deliberately do NOT do: they do not assert compatibility
//! with any real AP2 token, schema, or published test vector. The exact AP2
//! signature envelope and any standalone vectors are `[UNVERIFIED]` per
//! ADR-0001 and therefore BLOCKED; asserting against them would be an
//! unverifiable claim (AGENTS.md Rule 20). The signed bytes here are
//! `kya-core`'s internal canonical mandate encoding, not an AP2 serialization.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_adapter_ap2::{
    verify_ap2_mandate, Ap2Identities, Ap2MandateConstraints, Ap2SignedMandateBinding,
    Ap2SpendingLimit,
};
use kya_core::decision::ReasonCode;
use kya_core::evidence::DelegationClaim;
use kya_core::identity::{
    AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustAnchors, TrustedKeyRef,
};
use kya_core::mandate::{Mandate, TransactionIntent};
use kya_core::money::Money;
use kya_core::policy::evaluate;
use kya_core::scope::Action;
use kya_crypto::{CryptoVerificationError, TrustedKeyStore};

const NOW: u64 = 1_000;
const AUDIENCE: &str = "aud:ap2-payments";
const BINDING: &[u8] = b"txn-binding:ap2-invoice-7";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn constraints() -> Ap2MandateConstraints {
    Ap2MandateConstraints {
        identities: Ap2Identities {
            issuer: "issuer:ap2-authority".to_owned(),
            principal: "principal:alice".to_owned(),
            agent: "agent:shopper".to_owned(),
            allowed_merchants: Some(vec!["merchant:store".to_owned()]),
            allowed_resources: Some(vec!["cart:7".to_owned()]),
        },
        permitted_action: "purchase".to_owned(),
        spending_limit: Ap2SpendingLimit {
            max_minor_units: 10_000,
            currency: "USD".to_owned(),
        },
        not_before: 0,
        not_after: 2_000,
        required_audience: None,
        requires_human_approval: false,
        transaction_binding: None,
    }
}

fn anchors() -> TrustAnchors {
    let mut a = TrustAnchors::new();
    a.trust_key(
        IssuerId::new("issuer:ap2-authority").unwrap(),
        TrustedKeyRef::new("kid:ap2-1").unwrap(),
    );
    a
}

fn store() -> TrustedKeyStore {
    let mut s = TrustedKeyStore::new();
    s.insert(
        IssuerId::new("issuer:ap2-authority").unwrap(),
        TrustedKeyRef::new("kid:ap2-1").unwrap(),
        *signing_key().verifying_key().as_bytes(),
    );
    s
}

fn claim() -> DelegationClaim {
    DelegationClaim::new(
        IssuerId::new("issuer:ap2-authority").unwrap(),
        AgentId::new("agent:shopper").unwrap(),
        TrustedKeyRef::new("kid:ap2-1").unwrap(),
    )
}

/// Sign the mandate's canonical encoding with the trusted issuer key.
fn sign_mandate(mandate: &Mandate) -> Vec<u8> {
    signing_key()
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec()
}

fn intent(action: &str, minor: i128, currency: &str) -> TransactionIntent {
    TransactionIntent::new(
        AgentId::new("agent:shopper").unwrap(),
        MerchantId::new("merchant:store").unwrap(),
        ResourceId::new("cart:7").unwrap(),
        Action::new(action).unwrap(),
        Money::from_code(minor, currency).unwrap(),
    )
    .with_principal(PrincipalId::new("principal:alice").unwrap())
}

#[test]
fn mapped_constraints_and_verified_mandate_are_eligible_for_stage_d() {
    // Stage C input: map AP2 constraints onto a kya-core Mandate.
    let mandate = constraints().to_mandate().expect("maps cleanly");

    // Stages A/B: verify a genuine signature over the mandate's canonical
    // encoding. The verified mandate IS the signed one, by construction.
    let claim = claim();
    let sig = sign_mandate(&mandate);
    let signed = Ap2SignedMandateBinding {
        claim: &claim,
        mandate: &mandate,
        signature: &sig,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 2_000,
        binding: BINDING,
    };
    let verified = verify_ap2_mandate(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING)
        .expect("genuine signature verifies");

    // Stage C runs UNCHANGED on the authenticated mandate.
    let outcome = evaluate(&verified, &intent("purchase", 5_000, "USD"), NOW);
    assert!(
        outcome.is_eligible_for_online_authorization(),
        "eligibility is NOT authorization; stage D still required"
    );
    assert_eq!(outcome.reason(), ReasonCode::StaticChecksPassed);
}

#[test]
fn out_of_scope_action_is_denied_by_stage_c() {
    let mandate = constraints().to_mandate().expect("maps cleanly");
    let claim = claim();
    let sig = sign_mandate(&mandate);
    let signed = Ap2SignedMandateBinding {
        claim: &claim,
        mandate: &mandate,
        signature: &sig,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 2_000,
        binding: BINDING,
    };
    let verified =
        verify_ap2_mandate(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING).unwrap();

    // "refund" is not the permitted "purchase" action.
    let outcome = evaluate(&verified, &intent("refund", 5_000, "USD"), NOW);
    assert_eq!(outcome.reason(), ReasonCode::ActionNotPermitted);
    assert!(!outcome.is_eligible_for_online_authorization());
}

#[test]
fn wrong_currency_is_denied_by_stage_c() {
    let mandate = constraints().to_mandate().expect("maps cleanly");
    let claim = claim();
    let sig = sign_mandate(&mandate);
    let signed = Ap2SignedMandateBinding {
        claim: &claim,
        mandate: &mandate,
        signature: &sig,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 2_000,
        binding: BINDING,
    };
    let verified =
        verify_ap2_mandate(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING).unwrap();

    // EUR is outside the mandate's allowed-currency set (narrowed to USD).
    let outcome = evaluate(&verified, &intent("purchase", 5_000, "EUR"), NOW);
    assert_eq!(outcome.reason(), ReasonCode::CurrencyNotPermitted);
    assert!(!outcome.is_eligible_for_online_authorization());
}

#[test]
fn tampered_signature_never_yields_verified_mandate() {
    let mandate = constraints().to_mandate().expect("maps cleanly");
    let claim = claim();
    let mut sig = sign_mandate(&mandate);
    sig[0] ^= 0xFF;
    let signed = Ap2SignedMandateBinding {
        claim: &claim,
        mandate: &mandate,
        signature: &sig,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 2_000,
        binding: BINDING,
    };
    // No verified mandate can be produced, so stage C is never reached with a
    // forged signature. Fail closed with the specific variant.
    let err = verify_ap2_mandate(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING)
        .expect_err("tampered signature must fail");
    assert_eq!(
        err,
        kya_adapter_ap2::Ap2AdapterError::Verification(CryptoVerificationError::SignatureInvalid)
    );
}

#[test]
fn substituted_mandate_never_yields_verified_mandate() {
    // Sign the canonical encoding of the base (10_000 USD) mandate...
    let signed_mandate = constraints().to_mandate().expect("maps cleanly");
    let sig = sign_mandate(&signed_mandate);
    // ...but present a mandate whose spending limit was raised. The signature
    // was never computed over the presented mandate's canonical encoding.
    let mut raised = constraints();
    raised.spending_limit.max_minor_units = 100_000_000;
    let presented = raised.to_mandate().expect("maps cleanly");
    let claim = claim();
    let signed = Ap2SignedMandateBinding {
        claim: &claim,
        mandate: &presented,
        signature: &sig,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 2_000,
        binding: BINDING,
    };
    let err = verify_ap2_mandate(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING)
        .expect_err("substituted mandate must fail closed");
    // The engine verifies over the PRESENTED mandate's canonical encoding, so a
    // signature computed over a different mandate fails closed as SignatureInvalid
    // (it does not cover the substituted mandate). Both SignatureInvalid and
    // BindingMismatch are fail-closed, non-authorizing rejections.
    assert!(
        matches!(
            err,
            kya_adapter_ap2::Ap2AdapterError::Verification(
                CryptoVerificationError::SignatureInvalid
            ) | kya_adapter_ap2::Ap2AdapterError::Verification(
                CryptoVerificationError::BindingMismatch
            )
        ),
        "substituted mandate must fail closed, got {err:?}"
    );
}
