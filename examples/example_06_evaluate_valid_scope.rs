//! EXAMPLE 6 - Evaluate a valid merchant / action / amount scope.
//!
//! Verifies a genuine mandate through the real engine, then runs the static
//! stage-C evaluator [`evaluate`] against a transaction intent that is within
//! scope: an allowed action, an allowed merchant and resource, and an amount
//! under the per-transaction limit. The result is
//! [`PolicyOutcome::EligibleForOnlineAuthorization`] with reason
//! [`ReasonCode::StaticChecksPassed`].
//!
//! What this example does NOT verify: ELIGIBILITY IS NOT AUTHORIZATION. A
//! passing static evaluation means only that nothing offline forbids the
//! request. No online authority (stage D) was consulted, so revocation,
//! cumulative budget, and global replay state are all unknown and the request
//! remains unauthorized.
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

    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(Money::from_code(10_000, "USD").expect("valid limit"))
        .with_allowed_merchants(vec![
            MerchantId::new("merchant:supplier-co").expect("valid merchant")
        ]);
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

    // An in-scope intent: allowed action and merchant, amount under the limit.
    let intent = TransactionIntent::new(
        agent,
        MerchantId::new("merchant:supplier-co").expect("valid merchant"),
        ResourceId::new("invoice:2026-0042").expect("valid resource"),
        Action::new("transfer").expect("valid action"),
        Money::from_code(5_000, "USD").expect("valid amount"),
    )
    .with_principal(principal);

    let outcome = evaluate(&verified, &intent, now);
    println!("static evaluation reason: {:?}", outcome.reason());
    assert!(
        requires_online_authorization(&outcome),
        "an in-scope intent should be eligible for online authorization"
    );
    assert_eq!(outcome.reason(), ReasonCode::StaticChecksPassed);
    println!("outcome: EligibleForOnlineAuthorization (stage C passed).");

    println!();
    println!("Does NOT verify: ELIGIBILITY IS NOT AUTHORIZATION. No online");
    println!("authority (stage D) was consulted, so revocation / cumulative");
    println!("budget / global replay are unknown. The request is NOT authorized.");
    println!(
        "online state unestablished: {}",
        kya_sdk::online_state_is_unestablished(&outcome)
    );
}
