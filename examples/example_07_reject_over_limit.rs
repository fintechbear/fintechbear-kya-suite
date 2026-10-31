//! EXAMPLE 7 - Reject a transaction exceeding a spending limit.
//!
//! Verifies a genuine mandate (per-transaction limit 100.00 USD) through the
//! real engine, then runs the static stage-C evaluator [`evaluate`] against an
//! intent for MORE than the limit. The result is [`PolicyOutcome::Denied`] with
//! reason [`ReasonCode::AmountExceedsLimit`]. The denial is a terminal offline
//! rejection: it can never become an `Allow`.
//!
//! What this example does NOT verify: the denial is purely a static,
//! offline-computable fact (amount vs. the signed limit). It establishes NO
//! online state (revocation / cumulative budget / global replay); those stay
//! unknown because a statically-denied request never reaches the online
//! authority.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;

fn main() {
    // TEST-ONLY synthetic issuer key, deterministic. NEVER a production secret.
    let test_only_signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");

    // Per-transaction limit: 100.00 USD (10_000 minor units).
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(Money::from_code(10_000, "USD").expect("valid limit"));
    let mandate = Mandate::new(
        issuer.clone(),
        principal.clone(),
        agent.clone(),
        scope,
        ValidityWindow::new(0, 2_000).expect("valid window"),
    );

    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-2026-0042";
    let now: u64 = 1_000;

    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();
    let claim = DelegationClaim::new(issuer, agent.clone(), key_ref);
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };
    let verified = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect("genuine mandate must verify");

    // An OVER-LIMIT intent: 100.01 USD against a 100.00 USD limit.
    let intent = TransactionIntent::new(
        agent,
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(10_001, "USD").expect("valid amount"),
    )
    .with_principal(principal);

    let outcome = evaluate(&verified, &intent, now);
    println!("static evaluation reason: {:?}", outcome.reason());
    assert!(
        !requires_online_authorization(&outcome),
        "an over-limit intent must not be eligible"
    );
    assert_eq!(outcome.reason(), ReasonCode::AmountExceedsLimit);
    println!("outcome: Denied {{ AmountExceedsLimit }} (terminal, fail-closed).");

    println!();
    println!("Does NOT verify: the denial is a static amount-vs-limit fact only.");
    println!("No online state (revocation / budget / replay) was checked, because");
    println!("a statically-denied request never reaches the online authority.");
}
