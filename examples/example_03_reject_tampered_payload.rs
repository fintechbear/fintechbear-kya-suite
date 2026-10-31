//! EXAMPLE 3 - Reject a modified signed payload.
//!
//! Produces a genuine Ed25519 signature, flips a single byte of it, and submits
//! the tampered evidence to the real `kya-crypto` engine through the facade's
//! [`verify_mandate`]. The engine fails closed with
//! [`CryptoVerificationError::SignatureInvalid`]: no [`VerifiedMandate`] is
//! minted, so there is no evidence to evaluate.
//!
//! What this example does NOT verify: because verification fails, nothing
//! downstream runs. Even if it had succeeded, a verified signature would NOT be
//! an authorization: online state (revocation / budget / replay) and agent
//! proof-of-possession would still be unestablished.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;
use kya_sdk::CryptoVerificationError;

fn main() {
    // TEST-ONLY synthetic issuer key, deterministic from a fixed seed. NEVER a
    // production secret.
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
        .with_per_transaction_limit(Money::from_code(10_000, "USD").expect("valid limit"));
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

    // Genuine signature, then TAMPER: flip one byte so it no longer verifies.
    let mut signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();
    signature[0] ^= 0xFF;
    println!("flipped one byte of the signature to simulate tampering.");

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

    match verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    ) {
        Ok(_) => {
            // Unreachable for a tampered signature; treat as a hard failure
            // rather than silently continuing.
            panic!("SECURITY DEFECT: a tampered signature must never verify");
        }
        Err(e) => {
            println!("rejected as expected: {e}");
            assert_eq!(
                e,
                CryptoVerificationError::SignatureInvalid,
                "a flipped signature byte must fail closed with SignatureInvalid"
            );
            println!("error code: {:?}", e.error_code());
        }
    }

    println!();
    println!("Does NOT verify: verification failed, so no mandate was minted and");
    println!("no evaluation ran. Rejection is fail-closed; nothing was authorized.");
}
