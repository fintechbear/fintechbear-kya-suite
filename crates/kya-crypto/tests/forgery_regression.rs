//! External-crate forgery regression tests for the verified-evidence seal.
//!
//! Integration tests compile as a **separate crate**, so this file sees exactly
//! the public surface an untrusted external consumer sees. It proves two
//! things:
//!
//! 1. A malicious, always-`Ok(Verified)` [`SignatureVerifier`] implemented here
//!    CANNOT mint a [`VerifiedDelegation`], even when the correct key is
//!    trust-anchored. The mint-point for a verified outcome / verified evidence
//!    lives in `kya-crypto` itself (`crate::evidence`): `VerificationProof::new`,
//!    `VerificationOutcome::verified`, `run_verifier`, and the `establish`
//!    constructors are all `pub(crate)` and bound to the concrete reviewed
//!    [`Ed25519SignatureVerifier`]. There is no generic registration seam in
//!    `kya-core` and no exported blessing macro, so a fake verifier has no path
//!    to verified evidence. The compile-time proof lives as `compile_fail`
//!    doc-tests in `engine_security.rs` (collected by `cargo test`); this file
//!    asserts the runtime corollary: the ONLY route to a `VerifiedDelegation`
//!    is the genuine `kya_crypto::verify_delegation` over a real signature.
//! 2. That genuine route still works for a real, signed, anchored, in-window,
//!    correctly-bound claim, and fails closed for a bad signature.
//!
//! The specific [`CryptoVerificationError`] variant is asserted in every
//! negative case, never a bare `is_err()`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_core::evidence::DelegationClaim;
use kya_core::identity::{AgentId, IssuerId, TrustAnchors, TrustedKeyRef};
use kya_core::verification::{SignatureVerifier, VerificationError, VerificationStatus};
use kya_crypto::{verify_delegation, CryptoVerificationError, SignedClaim, TrustedKeyStore};

/// A malicious verifier an attacker might write: it ignores its inputs and
/// always claims the signature verified. It implements the PUBLIC
/// `SignatureVerifier` trait (which anyone may implement), but that is not
/// enough to mint evidence.
struct AlwaysVerified;

impl SignatureVerifier for AlwaysVerified {
    fn verify(
        &self,
        _public_key: &[u8],
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<VerificationStatus, VerificationError> {
        Ok(VerificationStatus::Verified)
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The malicious verifier compiles and can be *called directly* — it just
/// reports `Verified`. The point of the seal is that this direct call gets the
/// attacker nothing: there is no public API that turns this boolean-like answer
/// into a `VerificationProof`, a verified `VerificationOutcome`, or a
/// `VerifiedDelegation`. The mint-point is crate-private to `kya-crypto` and
/// bound to the concrete `Ed25519SignatureVerifier` (compile-time, proven by
/// the doc-tests in `engine_security.rs`), and it cannot construct the sealed
/// types.
#[test]
fn malicious_verifier_answer_is_inert() {
    let status = AlwaysVerified
        .verify(b"anything", b"anything", b"anything")
        .expect("the fake verifier returns Ok");
    // It happily says "Verified"...
    assert_eq!(status, VerificationStatus::Verified);
    // ...but `VerificationStatus` is a plain enum with no bridge to a proof or
    // to verified evidence. There is nothing further an attacker can do with it
    // through the public API. The authority to mint a verified outcome / proof
    // lives in `kya-crypto`'s own `evidence` module, reachable only
    // crate-internally: `VerificationProof::new`, `VerificationOutcome::verified`,
    // `run_verifier`, `VerifiedDelegation::establish`, and
    // `VerifiedMandate::establish` are all `pub(crate)` and `run_verifier` is
    // bound to the concrete `Ed25519SignatureVerifier`, so this external
    // always-`Verified` verifier cannot even be passed to it. There is no
    // `kya-core` `VerifierSanction`, no `verify_signature`, and no
    // `verification::internal::register` seam to abuse — all removed. See the
    // `compile_fail` doc-tests in `engine_security.rs`.
}

/// The genuine, sanctioned path still produces verified evidence for a real,
/// anchored, in-window, correctly-bound, genuinely-signed claim.
#[test]
fn genuine_sanctioned_path_still_establishes_evidence() {
    let issuer = IssuerId::new("issuer:acme").unwrap();
    let agent = AgentId::new("agent:robo-1").unwrap();
    let key_ref = TrustedKeyRef::new("kid:2026").unwrap();
    let sk = signing_key(42);
    let vk = sk.verifying_key();

    let signed_bytes = b"exact-protocol-signing-input".to_vec();
    let signature = sk.sign(&signed_bytes).to_bytes().to_vec();

    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());
    let mut store = TrustedKeyStore::new();
    store.insert(issuer.clone(), key_ref.clone(), *vk.as_bytes());
    let mut anchors = TrustAnchors::new();
    anchors.trust_key(issuer, key_ref);

    let signed = SignedClaim {
        claim: &claim,
        signed_bytes: &signed_bytes,
        signature: &signature,
        audience: "aud:payments",
        not_before: 0,
        expires_at: 2_000,
        binding: b"txn-binding",
    };

    let evidence = verify_delegation(
        &signed,
        &store,
        &anchors,
        1_000,
        "aud:payments",
        b"txn-binding",
    )
    .expect("genuine, sanctioned, anchored, in-window, bound claim verifies");
    assert_eq!(evidence.issuer().as_str(), "issuer:acme");
    assert_eq!(evidence.agent().as_str(), "agent:robo-1");
    assert_eq!(evidence.key_ref().as_str(), "kid:2026");
}

/// Even with the correct key trust-anchored AND resolvable, a signature that
/// does not actually verify fails closed. There is no way for the attacker's
/// always-`Verified` verifier to substitute its answer for the real Ed25519
/// check that `verify_delegation` performs internally.
#[test]
fn anchored_key_with_bad_signature_still_fails_closed() {
    let issuer = IssuerId::new("issuer:acme").unwrap();
    let agent = AgentId::new("agent:robo-1").unwrap();
    let key_ref = TrustedKeyRef::new("kid:2026").unwrap();
    let sk = signing_key(42);
    let vk = sk.verifying_key();

    let signed_bytes = b"genuine-bytes".to_vec();
    // A signature over DIFFERENT bytes: real Ed25519 verification must reject.
    let wrong_signature = sk.sign(b"other-bytes").to_bytes().to_vec();

    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());
    let mut store = TrustedKeyStore::new();
    store.insert(issuer.clone(), key_ref.clone(), *vk.as_bytes());
    let mut anchors = TrustAnchors::new();
    anchors.trust_key(issuer, key_ref);

    let signed = SignedClaim {
        claim: &claim,
        signed_bytes: &signed_bytes,
        signature: &wrong_signature,
        audience: "aud:payments",
        not_before: 0,
        expires_at: 2_000,
        binding: b"txn-binding",
    };

    assert_eq!(
        verify_delegation(
            &signed,
            &store,
            &anchors,
            1_000,
            "aud:payments",
            b"txn-binding"
        ),
        Err(CryptoVerificationError::SignatureInvalid)
    );
}
