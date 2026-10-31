//! EXAMPLE 4 - Reject an unknown or unauthorized issuer.
//!
//! Produces a genuine Ed25519 signature but presents it under a trust
//! configuration that does NOT anchor the issuer key. The real `kya-crypto`
//! engine (via the facade's [`verify_mandate`]) fails closed: an unconfigured
//! issuer yields [`CryptoVerificationError::UnknownIssuer`], and an issuer whose
//! key is known but not anchored yields
//! [`CryptoVerificationError::UntrustedKey`]. Trust is explicit and
//! allow-listed (AGENTS.md Rule 11): a genuine signature from an untrusted
//! issuer is not evidence.
//!
//! What this example does NOT verify: verification fails, so nothing downstream
//! runs. The example makes no claim about online state (revocation / budget /
//! replay) because it never reaches that stage, and a signature alone is never
//! an authorization regardless of trust.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_sdk::prelude::*;
use kya_sdk::CryptoVerificationError;

fn main() {
    // TEST-ONLY synthetic issuer key, deterministic from a fixed seed. NEVER a
    // production secret.
    let test_only_signing_key = SigningKey::from_bytes(&[7u8; 32]);

    let issuer = IssuerId::new("issuer:unknown-bank").expect("valid issuer id");
    let principal = PrincipalId::new("principal:acme-treasury").expect("valid principal id");
    let agent = AgentId::new("agent:treasury-bot").expect("valid agent id");
    let key_ref = TrustedKeyRef::new("kid:unknown-2026").expect("valid key ref");

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

    let signature = test_only_signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();
    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };

    // Case 1: the issuer is entirely unconfigured -> UnknownIssuer.
    let empty_trust = TrustConfiguration::new();
    match verify_mandate(
        &signed,
        empty_trust.key_store(),
        empty_trust.anchors(),
        now,
        audience,
        binding,
    ) {
        Ok(_) => panic!("SECURITY DEFECT: an unconfigured issuer must never verify"),
        Err(e) => {
            println!("unconfigured issuer rejected: {e} ({:?})", e.error_code());
            assert_eq!(e, CryptoVerificationError::UnknownIssuer);
        }
    }

    // Case 2: a DIFFERENT, genuinely-trusted issuer key exists, but it is not
    // this claim's key. The presented key is not anchored -> UntrustedKey. We
    // register the issuer under a different key_ref with unrelated bytes.
    let other_key_ref = TrustedKeyRef::new("kid:acme-rotated").expect("valid key ref");
    let mut partial_trust = TrustConfiguration::new();
    partial_trust
        .trust_issuer_key(issuer.clone(), other_key_ref, &[9u8; 32])
        .expect("32-byte Ed25519 public key");
    match verify_mandate(
        &signed,
        partial_trust.key_store(),
        partial_trust.anchors(),
        now,
        audience,
        binding,
    ) {
        Ok(_) => panic!("SECURITY DEFECT: an unanchored key must never verify"),
        Err(e) => {
            println!("unanchored key rejected: {e} ({:?})", e.error_code());
            assert_eq!(e, CryptoVerificationError::UntrustedKey);
        }
    }

    println!();
    println!("Does NOT verify: trust is explicit and allow-listed; a genuine");
    println!("signature from an untrusted issuer is not evidence. Verification");
    println!("failed, so no online state was checked and nothing was authorized.");
}
