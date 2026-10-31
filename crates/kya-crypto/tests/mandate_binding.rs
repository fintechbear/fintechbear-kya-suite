//! Security regression suite for **signed-mandate binding** (Security Check B).
//!
//! These tests prove, over **real Ed25519 signatures**, that a signature
//! computed over mandate `A`'s canonical encoding can never be paired with a
//! different mandate `B` that was substituted at verify/evaluate time. For each
//! of the eleven security-relevant fields — agent, principal, issuer, audience,
//! merchant, resource, allowed action, spending limit, currency, validity
//! period, and approval requirement — we sign `A`, present `B` (differing only
//! in that one field) to [`kya_crypto::verify_mandate`], and assert the mint
//! FAILS closed with a typed error and never yields a `VerifiedMandate` nor an
//! eligible stage-C outcome.
//!
//! A positive control proves the genuine, unmodified mandate still verifies and
//! evaluates exactly as before.
//!
//! Each negative test would PASS (incorrectly) if the canonical-encoding
//! binding check in `VerifiedMandate::establish` were removed, so they lock in
//! the secure behavior against regression (AGENTS.md Rule 17).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_core::decision::ReasonCode;
use kya_core::evidence::DelegationClaim;
use kya_core::identity::{
    AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustAnchors, TrustedKeyRef,
};
use kya_core::mandate::{Audience, Mandate, TransactionBinding, TransactionIntent, ValidityWindow};
use kya_core::money::{CurrencyCode, Money};
use kya_core::policy::evaluate;
use kya_core::scope::{Action, Scope};
use kya_crypto::{verify_mandate, CryptoVerificationError, SignedMandate, TrustedKeyStore};

const NOW: u64 = 1_500;
const AUDIENCE: &str = "aud:processor";
const BINDING: &[u8] = b"txn-binding:invoice-42";

fn issuer() -> IssuerId {
    IssuerId::new("issuer:acme").expect("valid")
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

/// A fully-featured baseline mandate touching every security-relevant field.
fn base_mandate() -> Mandate {
    build_mandate(MandateFields::default())
}

/// The mutable fields a test can vary to substitute exactly one dimension.
struct MandateFields {
    issuer: &'static str,
    principal: &'static str,
    agent: &'static str,
    action: &'static str,
    limit_minor: i128,
    currency: &'static str,
    merchant: &'static str,
    resource: &'static str,
    not_before: u64,
    not_after: u64,
    audience: &'static str,
    requires_approval: bool,
    binding: &'static str,
}

impl Default for MandateFields {
    fn default() -> Self {
        MandateFields {
            issuer: "issuer:acme",
            principal: "principal:alice",
            agent: "agent:1",
            action: "transfer",
            limit_minor: 10_000,
            currency: "USD",
            merchant: "merchant:store",
            resource: "order:42",
            not_before: 1_000,
            not_after: 2_000,
            audience: "aud:processor",
            requires_approval: false,
            binding: "mandate-binding:A",
        }
    }
}

fn build_mandate(f: MandateFields) -> Mandate {
    let scope = Scope::new()
        .allow(Action::new(f.action).expect("valid"))
        .with_per_transaction_limit(Money::from_code(f.limit_minor, f.currency).expect("valid"))
        .with_allowed_merchants(vec![MerchantId::new(f.merchant).expect("valid")])
        .with_allowed_resources(vec![ResourceId::new(f.resource).expect("valid")])
        .with_allowed_currencies(vec![CurrencyCode::new(f.currency).expect("valid")]);
    let mut m = Mandate::new(
        IssuerId::new(f.issuer).expect("valid"),
        PrincipalId::new(f.principal).expect("valid"),
        AgentId::new(f.agent).expect("valid"),
        scope,
        ValidityWindow::new(f.not_before, f.not_after).expect("valid"),
    )
    .with_required_audience(Audience::new(f.audience).expect("valid"))
    .bound_to(TransactionBinding::new(f.binding).expect("valid"));
    if f.requires_approval {
        m = m.requiring_human_approval();
    }
    m
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

/// Sign `signed_mandate`'s canonical encoding, then attempt to verify
/// `presented_mandate`. Returns the engine result.
fn verify_with_substitution(
    signed_mandate: &Mandate,
    presented_mandate: &Mandate,
) -> Result<kya_crypto::VerifiedMandate, CryptoVerificationError> {
    let sk = signing_key();
    // The signature is GENUINE over the SIGNED mandate's canonical encoding.
    let signature = sk
        .sign(&signed_mandate.canonical_encoding())
        .to_bytes()
        .to_vec();
    // But we present a DIFFERENT mandate to the engine. The engine derives the
    // bytes-to-verify from the PRESENTED mandate, so the genuine signature will
    // not match unless the two mandates are byte-identical.
    let claim = DelegationClaim::new(
        presented_mandate.issuer().clone(),
        agent_of(presented_mandate),
        key(),
    );
    let signed = SignedMandate {
        claim: &claim,
        mandate: presented_mandate,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    verify_mandate(&signed, &store(), &anchors(), NOW, AUDIENCE, BINDING)
}

fn agent_of(m: &Mandate) -> AgentId {
    AgentId::new(m.agent().as_str()).expect("valid")
}

fn intent() -> TransactionIntent {
    TransactionIntent::new(
        AgentId::new("agent:1").expect("valid"),
        MerchantId::new("merchant:store").expect("valid"),
        ResourceId::new("order:42").expect("valid"),
        Action::new("transfer").expect("valid"),
        usd(5_000),
    )
    .with_principal(PrincipalId::new("principal:alice").expect("valid"))
    .with_audience(Audience::new(AUDIENCE).expect("valid"))
    .with_binding(TransactionBinding::new("mandate-binding:A").expect("valid"))
}

// ---- positive control ------------------------------------------------------

#[test]
fn genuine_unmodified_mandate_verifies_and_evaluates() {
    let m = base_mandate();
    let verified = verify_with_substitution(&m, &m).expect("genuine mandate should verify");
    assert_eq!(verified.issuer(), &issuer());
    assert_eq!(verified.agent().as_str(), "agent:1");

    // And stage C evaluates it to eligible (nothing static forbids it).
    let outcome = evaluate(&verified, &intent(), NOW);
    assert!(
        outcome.is_eligible_for_online_authorization(),
        "genuine mandate must still be eligible: {outcome:?}"
    );
    assert_eq!(outcome.reason(), ReasonCode::StaticChecksPassed);
}

// ---- eleven field substitutions, each must fail closed --------------------

/// Assert a substitution mint failed closed and never produced a verified
/// mandate. The error is either a binding mismatch (the usual case: the
/// canonical bytes differ) or, for the issuer case, an untrusted-key/issuer
/// failure — both are fail-closed and non-authorizing.
fn assert_fails_closed(result: Result<kya_crypto::VerifiedMandate, CryptoVerificationError>) {
    match result {
        Ok(_) => panic!("substitution must never yield a VerifiedMandate"),
        Err(CryptoVerificationError::BindingMismatch)
        | Err(CryptoVerificationError::SignatureInvalid)
        | Err(CryptoVerificationError::UntrustedKey)
        | Err(CryptoVerificationError::UnknownIssuer) => {}
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn substitute_agent_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        agent: "agent:evil",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_principal_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        principal: "principal:mallory",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_issuer_fails_closed() {
    // Anchor and register the substituted issuer too, so the ONLY thing that can
    // reject it is the canonical-bytes binding / issuer-match, not a missing key.
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        issuer: "issuer:evil",
        ..MandateFields::default()
    });
    let sk = signing_key();
    let signature = sk.sign(&signed.canonical_encoding()).to_bytes().to_vec();
    let evil_issuer = IssuerId::new("issuer:evil").expect("valid");
    let claim = DelegationClaim::new(evil_issuer.clone(), agent_of(&presented), key());

    let mut store = store();
    store.insert(evil_issuer.clone(), key(), *sk.verifying_key().as_bytes());
    let mut anchors = anchors();
    anchors.trust_key(evil_issuer, key());

    let signed_mandate = SignedMandate {
        claim: &claim,
        mandate: &presented,
        signature: &signature,
        audience: AUDIENCE,
        not_before: 0,
        expires_at: 3_000,
        binding: BINDING,
    };
    let result = verify_mandate(&signed_mandate, &store, &anchors, NOW, AUDIENCE, BINDING);
    assert_fails_closed(result);
}

#[test]
fn substitute_audience_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        audience: "aud:attacker",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_merchant_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        merchant: "merchant:evil",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_resource_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        resource: "order:evil",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_action_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        action: "drain-account",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_spending_limit_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        limit_minor: 100_000_000,
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_currency_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        currency: "EUR",
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_validity_period_fails_closed() {
    let signed = base_mandate();
    let presented = build_mandate(MandateFields {
        not_after: 9_999,
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}

#[test]
fn substitute_approval_requirement_fails_closed() {
    let signed = base_mandate(); // does not require approval
    let presented = build_mandate(MandateFields {
        requires_approval: true,
        ..MandateFields::default()
    });
    assert_fails_closed(verify_with_substitution(&signed, &presented));
}
