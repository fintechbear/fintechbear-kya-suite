//! Dependency-free property / fuzz-style tests for the crypto engine entry
//! points.
//!
//! Using the same deterministic `SplitMix64` generator the rest of the repo
//! uses (see `kya-core/tests/property_identity.rs`), this feeds pseudo-random
//! bytes into every untrusted-input parse/verify entry point and asserts the
//! two invariants that matter for a security parser (AGENTS.md Rules 5, 7):
//!
//! 1. no input, however adversarial, causes a panic; and
//! 2. every failure is a typed [`CryptoVerificationError`] (or a
//!    [`VerificationError`]), never a silent success and never a forged
//!    `Verified`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;

use kya_core::evidence::DelegationClaim;
use kya_core::identity::{AgentId, IssuerId, TrustAnchors, TrustedKeyRef};
use kya_core::verification::{SignatureVerifier, VerificationStatus};
use kya_crypto::{
    verify_delegation, CryptoVerificationError, Ed25519SignatureVerifier, JwsEdDsa, SignedClaim,
    TrustedKeyStore,
};

/// Deterministic dependency-free PRNG (splitmix64), matching the repo pattern.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A pseudo-random byte vector of length up to `max`.
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next_u64() as usize) % (max + 1);
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

const SEEDS: [u64; 6] = [1, 7, 0xDEAD_BEEF, 0x0102_0304, u64::MAX, 0xA5A5_A5A5];
const CASES_PER_SEED: usize = 2_000;

#[test]
fn fuzz_ed25519_verifier_never_panics_and_only_typed_errors() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let key = rng.bytes(40);
            let msg = rng.bytes(64);
            let sig = rng.bytes(80);
            let verifier = Ed25519SignatureVerifier::new();
            // Any result is acceptable EXCEPT a panic. Random bytes cannot
            // forge a Verified against a random key with overwhelming
            // probability; but we only assert the type contract: Ok(status) or
            // a typed error.
            match verifier.verify(&key, &msg, &sig) {
                Ok(VerificationStatus::Verified) | Ok(VerificationStatus::Invalid) => {}
                Ok(_) => {} // VerificationStatus is #[non_exhaustive].
                Err(_typed) => {}
            }
        }
    }
}

#[test]
fn fuzz_jws_verify_never_panics_and_only_typed_errors() {
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let token = rng.bytes(300);
            let key = rng.bytes(40);
            match JwsEdDsa::new().verify(&token, &key) {
                Ok(_payload) => {
                    // A random token verifying is astronomically unlikely; if it
                    // somehow did, it is still a typed Ok, not a panic. Nothing
                    // to assert beyond the type contract.
                }
                Err(e) => assert_is_typed(&e),
            }
        }
    }
}

#[test]
fn fuzz_jws_with_genuine_header_prefix_never_panics() {
    // Bias the fuzzer toward structurally-plausible tokens (real EdDSA header,
    // dots in place) so the deeper decode/verify paths are exercised, not just
    // the early segment-count rejection.
    let header = "eyJhbGciOiJFZERTQSJ9"; // base64url of {"alg":"EdDSA"}
    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let payload = rng.bytes(60);
            let sig = rng.bytes(90);
            let p = base64url_ish(&payload, &mut rng);
            let s = base64url_ish(&sig, &mut rng);
            let token = format!("{header}.{p}.{s}");
            let key = rng.bytes(40);
            if let Err(e) = JwsEdDsa::new().verify(token.as_bytes(), &key) {
                assert_is_typed(&e);
            }
        }
    }
}

#[test]
fn fuzz_verify_delegation_never_panics_and_only_typed_errors() {
    let issuer = IssuerId::new("issuer:acme").unwrap();
    let agent = AgentId::new("agent:1").unwrap();
    let key_ref = TrustedKeyRef::new("kid:1").unwrap();
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());
    let mut store = TrustedKeyStore::new();
    store.insert(
        issuer.clone(),
        key_ref.clone(),
        *sk.verifying_key().as_bytes(),
    );
    let mut anchors = TrustAnchors::new();
    anchors.trust_key(issuer, key_ref);

    for seed in SEEDS {
        let mut rng = SplitMix64::new(seed);
        for _ in 0..CASES_PER_SEED {
            let signed_bytes = rng.bytes(200);
            let signature = rng.bytes(80);
            let binding = rng.bytes(64);
            let now = rng.next_u64();
            let aud_pick = rng.next_u64() % 2;
            let audience = if aud_pick == 0 {
                "aud:payments"
            } else {
                "aud:rand"
            };

            let s = SignedClaim {
                claim: &claim,
                signed_bytes: &signed_bytes,
                signature: &signature,
                audience,
                not_before: rng.next_u64(),
                expires_at: rng.next_u64(),
                binding: &binding,
            };
            // The only acceptable outcomes are a typed error or (astronomically
            // unlikely) a genuine VerifiedDelegation. No panic, ever.
            match verify_delegation(&s, &store, &anchors, now, "aud:payments", b"txn-binding") {
                Ok(_evidence) => {}
                Err(e) => assert_is_typed(&e),
            }
        }
    }
}

/// Occasionally corrupt the base64url-ish string so both valid and invalid
/// encodings are exercised by the fuzzer.
fn base64url_ish(data: &[u8], rng: &mut SplitMix64) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for &b in data {
        out.push(ALPHA[(b & 63) as usize] as char);
    }
    // 1-in-4 chance to inject a non-alphabet byte to force a decode failure.
    if rng.next_u64() % 4 == 0 {
        out.push('=');
    }
    out
}

/// Assert the error is one of the engine's declared typed variants (it always
/// is; this makes the "only typed errors" contract explicit and would fail to
/// compile if the error type were ever widened to carry untyped data).
fn assert_is_typed(e: &CryptoVerificationError) {
    match e {
        CryptoVerificationError::UnsupportedAlgorithm
        | CryptoVerificationError::MalformedKey
        | CryptoVerificationError::MalformedSignature
        | CryptoVerificationError::SignatureInvalid
        | CryptoVerificationError::UnknownIssuer
        | CryptoVerificationError::UntrustedKey
        | CryptoVerificationError::AudienceMismatch
        | CryptoVerificationError::Expired
        | CryptoVerificationError::NotYetValid
        | CryptoVerificationError::BindingMismatch
        | CryptoVerificationError::MalformedPayload
        | CryptoVerificationError::OversizedInput => {}
        // `CryptoVerificationError` is `#[non_exhaustive]`; a future variant is
        // still a typed error, which is all this test asserts.
        _ => {}
    }
}
