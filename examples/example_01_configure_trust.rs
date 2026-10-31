//! EXAMPLE 1 - Configure a trusted issuer / key store.
//!
//! Builds a [`kya_sdk::TrustConfiguration`], the facade bundle that wires the
//! [`TrustAnchors`] (which `(issuer, key_ref)` pairs are trusted) and the
//! [`TrustedKeyStore`] (the concrete Ed25519 public-key bytes) together. Both
//! are required by the verification engine, and configuring only one is the
//! most common first-day mistake, so the facade updates both in a single
//! explicit, allow-listed act of trust.
//!
//! What this example does NOT verify: nothing is signed or verified here. A
//! trust configuration is only a deny-by-default allow-list of public keys. It
//! establishes no authenticity, no scope eligibility, and no online state
//! (revocation / cumulative budget / global replay are all unknown). Trusting a
//! key is not authorizing a transaction.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;

use kya_sdk::prelude::*;

fn main() {
    // TEST-ONLY synthetic key material. A deterministic signing key stands in
    // for an issuer's key pair ONLY so the example has a real 32-byte public key
    // to anchor. NEVER do this in production: real issuer private keys live in
    // an HSM/KMS and never appear in source. We only use the PUBLIC key here.
    let test_only_signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = test_only_signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").expect("valid issuer id");
    let key_ref = TrustedKeyRef::new("kid:acme-2026").expect("valid key ref");

    // Start from an empty configuration: deny-by-default, nothing is trusted.
    let mut trust = TrustConfiguration::new();
    println!(
        "before: issuer+key trusted = {}",
        trust.trusts_issuer_key(&issuer, &key_ref)
    );

    // The single explicit act of trust: anchor the pair AND register its
    // public-key bytes together. A wrong-length key is rejected up front.
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .expect("32-byte Ed25519 public key");

    println!(
        "after:  issuer+key trusted = {}",
        trust.trusts_issuer_key(&issuer, &key_ref)
    );
    println!("configured 1 trusted issuer key (explicit, allow-listed).");

    println!();
    println!("Does NOT verify: trusting a key establishes no authenticity, no");
    println!("scope eligibility, and NO online state (revocation / budget /");
    println!("replay unknown). Configuring trust is not authorization.");
}
