//! EXAMPLE 2 - Verify correctly signed Ed25519 evidence.
//!
//! Produces a genuine Ed25519 signature over a mandate's canonical encoding and
//! routes it through the REAL `kya-crypto` engine via the facade's
//! [`verify_mandate`]. A successful call mints an authenticated
//! [`VerifiedMandate`]: the signature is authentic, the `(issuer, key_ref)` pair
//! is trust-anchored, and the audience / validity / binding all checked out.
//! There is no stand-in verifier anywhere; only the reviewed
//! `Ed25519SignatureVerifier` inside `kya-crypto` can reach the crate-private
//! verified-evidence mint-point, which lives privately in `kya-crypto`.
//!
//! What this example does NOT verify: a verified signature is NOT an
//! authorization. No online authority (stage D) was consulted, so revocation,
//! cumulative budget, and global replay state are all unknown. Agent
//! proof-of-possession is also NOT established (only the ISSUER signed).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;

fn main() {
    // TEST-ONLY synthetic issuer key. Deterministic from a fixed seed so the
    // example is reproducible. NEVER a production secret.
    let test_only_signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    // Explicit trust: anchor the pair and register its public-key bytes.
    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");

    // The mandate the issuer signs over (via its canonical encoding).
    let limit = Money::from_code(10_000, "USD").expect("valid limit");
    let scope = Scope::new()
        .allow(Action::new("transfer").expect("valid action"))
        .with_per_transaction_limit(limit);
    let mandate = Mandate::new(
        issuer.clone(),
        principal,
        agent.clone(),
        scope,
        ValidityWindow::new(0, 2_000).expect("valid window"),
    );

    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-2026-0042";
    let now: u64 = 1_000;

    // A GENUINE signature over the mandate's canonical encoding.
    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();

    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref);
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };

    // Run the real engine through the facade.
    let verified: VerifiedMandate = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect("genuine signature over the canonical encoding must verify");

    println!(
        "verified mandate: issuer={} agent={} key_ref={}",
        verified.issuer(),
        verified.agent(),
        verified.key_ref()
    );
    println!("signature authentic and trust-anchored (stages A + B).");

    println!();
    println!("Does NOT verify: a verified signature is NOT authorization. No");
    println!("online authority (stage D) was consulted, so revocation / budget /");
    println!("replay are unknown. Agent proof-of-possession is NOT established:");
    println!("  {}", verified.proof_of_possession());
}
