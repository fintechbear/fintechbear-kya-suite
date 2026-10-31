//! EXAMPLE 8 - Reject a currency mismatch (cross-currency fail-closed).
//!
//! Verifies a genuine mandate whose scope permits ONLY USD, then runs the
//! static stage-C evaluator [`evaluate`] against an intent denominated in EUR.
//! The evaluator denies with [`ReasonCode::CurrencyNotPermitted`]: money is
//! never silently converted across currencies (AGENTS.md Rule 8), so a
//! cross-currency request fails closed.
//!
//! What this example does NOT verify: the denial is a static,
//! offline-computable fact (the intent's currency is outside the signed
//! allow-list). It establishes NO online state (revocation / cumulative budget
//! / global replay); a statically-denied request never reaches the online
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

    // The scope permits ONLY USD. An EUR intent must be denied, not converted.
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(Money::from_code(10_000, "USD").expect("valid limit"))
        .with_allowed_currencies(vec![CurrencyCode::new("USD").expect("valid currency")]);
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

    // An intent in a DIFFERENT currency (EUR) than the mandate permits (USD).
    let intent = TransactionIntent::new(
        agent,
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(5_000, "EUR").expect("valid amount"),
    )
    .with_principal(principal);

    let outcome = evaluate(&verified, &intent, now);
    println!("static evaluation reason: {:?}", outcome.reason());
    assert!(
        !requires_online_authorization(&outcome),
        "a cross-currency intent must not be eligible"
    );
    assert_eq!(outcome.reason(), ReasonCode::CurrencyNotPermitted);
    println!("outcome: Denied {{ CurrencyNotPermitted }} (no silent conversion).");

    println!();
    println!("Does NOT verify: the denial is a static currency-allow-list fact.");
    println!("No online state (revocation / budget / replay) was checked, because");
    println!("a statically-denied request never reaches the online authority.");
}
