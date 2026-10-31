//! The concrete Ed25519 signature verifier.
//!
//! [`Ed25519SignatureVerifier`] implements the core
//! [`kya_core::verification::SignatureVerifier`] trait seam using the reviewed
//! `ed25519-dalek` implementation of RFC 8032. It parses a 32-byte public key
//! and a 64-byte signature, returns a typed error (never a panic) on malformed
//! input, and returns `Ok(Verified)` / `Ok(Invalid)` for a genuine match /
//! non-match.
//!
//! Verification uses `ed25519-dalek`'s **strict** path
//! ([`VerifyingKey::verify_strict`]) rather than the permissive
//! [`Verifier::verify`]. Strict verification rejects signatures with a
//! non-canonical `S` component (signature malleability) and rejects small-order
//! / non-canonical public keys. For a financial-authorization SDK a
//! trust-anchored key must not be able to present a malleable or non-canonical
//! signature, so the stricter check is mandatory; genuine canonical signatures
//! from honest signers still verify.

use ed25519_dalek::{Signature, VerifyingKey};

use kya_core::verification::{SignatureVerifier, VerificationError, VerificationStatus};

/// The single accepted algorithm name for this engine.
///
/// Only Ed25519, spelled `EdDSA` to match the JWS/JWT `alg` header value for
/// the Ed25519 instantiation (RFC 8037). Any other name (including `alg: none`)
/// is rejected as unsupported.
pub const ACCEPTED_ALGORITHM: &str = "EdDSA";

/// Length in bytes of a raw Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of a raw Ed25519 signature.
const SIGNATURE_LEN: usize = 64;

/// A concrete Ed25519 detached-signature verifier.
///
/// It holds no state and no key material: the key and signature bytes are
/// supplied per call, consistent with `kya-core` holding no secrets. It is a
/// unit struct so callers construct it with [`Ed25519SignatureVerifier::new`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed25519SignatureVerifier;

impl Ed25519SignatureVerifier {
    /// Construct the verifier.
    pub fn new() -> Self {
        Ed25519SignatureVerifier
    }
}

impl SignatureVerifier for Ed25519SignatureVerifier {
    /// Verify a detached Ed25519 signature over `payload` using `public_key`.
    ///
    /// # Errors
    ///
    /// - [`VerificationError::MalformedKey`] if `public_key` is not exactly 32
    ///   bytes or is not a valid Ed25519 verifying key.
    /// - [`VerificationError::MalformedSignature`] if `signature` is not exactly
    ///   64 bytes.
    ///
    /// A genuine non-match returns `Ok(VerificationStatus::Invalid)`; a match
    /// returns `Ok(VerificationStatus::Verified)`. Verification is **strict**
    /// ([`VerifyingKey::verify_strict`]): a signature with a non-canonical `S`
    /// component (malleability) or a small-order / non-canonical public key is
    /// rejected as `Invalid`. This function never panics on any input.
    fn verify(
        &self,
        public_key: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<VerificationStatus, VerificationError> {
        let key_bytes: [u8; PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| VerificationError::MalformedKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerificationError::MalformedKey)?;

        let sig_bytes: [u8; SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| VerificationError::MalformedSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);

        // Strict verification: reject non-canonical `S` (malleability) and
        // small-order / non-canonical public keys. A genuine, canonical
        // signature from an honest signer still verifies.
        match verifying_key.verify_strict(payload, &sig) {
            Ok(()) => Ok(VerificationStatus::Verified),
            Err(_) => Ok(VerificationStatus::Invalid),
        }
    }
}

// `Ed25519SignatureVerifier` is the single reviewed verifier the KYA SDK uses
// to mint a `VerificationProof`. The authority to mint a verified outcome / proof
// does NOT live in `kya-core` behind any seam; it lives in this crate, in
// `crates/kya-crypto/src/evidence.rs`, through the crate-private `run_verifier`
// (which constructs a `VerificationProof` only when this concrete verifier
// returns `Ok(Verified)`). `run_verifier` takes `&Ed25519SignatureVerifier`
// by concrete type and is `pub(crate)`, so it is reachable only from inside
// `kya-crypto` and cannot be invoked with any other verifier.
//
// This replaces the former, bypassable design where a `#[doc(hidden)] pub`
// `kya_core::verification::internal::register::<V>()` seam (and before it a
// `#[macro_export] sanction_verifier!` macro) could mint a sanction for ANY
// external `V: SignatureVerifier`. Those are gone: `kya-core` no longer has
// `internal::register`, `verify_signature`, `VerifierSanction`, or any verified
// type. Using this type as the sole verifier is the explicit, code-reviewed
// assertion that it performs genuine, standard RFC 8032 verification via
// `ed25519-dalek` (AGENTS.md Rules 10, 11, 17). No other verifier can reach the
// proof-minting path, so an always-`Verified` stand-in defined in another crate
// can never produce verified evidence.

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministically build a signing key from a fixed 32-byte seed so tests
    /// need no RNG dependency.
    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn verifies_a_genuine_signature() {
        let sk = signing_key(7);
        let vk = sk.verifying_key();
        let msg = b"exact protocol bytes";
        let sig = sk.sign(msg);

        let verifier = Ed25519SignatureVerifier::new();
        let status = verifier
            .verify(vk.as_bytes(), msg, &sig.to_bytes())
            .expect("well-formed inputs");
        assert_eq!(status, VerificationStatus::Verified);
    }

    #[test]
    fn rejects_tampered_message_as_invalid() {
        let sk = signing_key(9);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"original");

        let verifier = Ed25519SignatureVerifier::new();
        let status = verifier
            .verify(vk.as_bytes(), b"tampered", &sig.to_bytes())
            .expect("well-formed inputs");
        assert_eq!(status, VerificationStatus::Invalid);
    }

    #[test]
    fn rejects_wrong_key_as_invalid() {
        let sk = signing_key(1);
        let other = signing_key(2).verifying_key();
        let msg = b"bytes";
        let sig = sk.sign(msg);

        let verifier = Ed25519SignatureVerifier::new();
        let status = verifier
            .verify(other.as_bytes(), msg, &sig.to_bytes())
            .expect("well-formed inputs");
        assert_eq!(status, VerificationStatus::Invalid);
    }

    #[test]
    fn wrong_length_key_is_malformed_key() {
        let verifier = Ed25519SignatureVerifier::new();
        assert_eq!(
            verifier.verify(&[0u8; 31], b"m", &[0u8; 64]),
            Err(VerificationError::MalformedKey)
        );
        assert_eq!(
            verifier.verify(&[0u8; 33], b"m", &[0u8; 64]),
            Err(VerificationError::MalformedKey)
        );
    }

    #[test]
    fn wrong_length_signature_is_malformed_signature() {
        let vk = signing_key(3).verifying_key();
        let verifier = Ed25519SignatureVerifier::new();
        assert_eq!(
            verifier.verify(vk.as_bytes(), b"m", &[0u8; 63]),
            Err(VerificationError::MalformedSignature)
        );
        assert_eq!(
            verifier.verify(vk.as_bytes(), b"m", &[0u8; 65]),
            Err(VerificationError::MalformedSignature)
        );
    }

    /// Strict verification must reject a small-order public key. The identity
    /// point (all-zero encoding) is a valid Edwards point of order 1; strict
    /// verification rejects such small-order / non-canonical public keys, so
    /// no `(message, signature)` can ever verify under it. Under the permissive
    /// `verify()` path some signatures would be accepted against a small-order
    /// key, which is exactly the latitude a financial-authorization SDK must
    /// not grant. The key is well-formed (parses as a `VerifyingKey`), so the
    /// rejection is `Invalid`, not `MalformedKey`.
    #[test]
    fn strict_verification_rejects_small_order_public_key() {
        // All-zero encoding is the identity (order-1) point: a small-order key.
        let small_order_key = [0u8; PUBLIC_KEY_LEN];
        // It must still parse as a verifying key (well-formed encoding) so this
        // exercises the strict *verification* reject, not a parse reject.
        assert!(
            VerifyingKey::from_bytes(&small_order_key).is_ok(),
            "identity-point encoding must parse as a well-formed verifying key"
        );

        let verifier = Ed25519SignatureVerifier::new();
        // Exercise a spread of signatures: the all-zero signature and a handful
        // of structured ones. Under verify_strict a small-order key never
        // yields Verified.
        for sig in [
            [0u8; SIGNATURE_LEN],
            [1u8; SIGNATURE_LEN],
            [0xFFu8; SIGNATURE_LEN],
        ] {
            let status = verifier
                .verify(&small_order_key, b"small-order payload", &sig)
                .expect("well-formed length inputs");
            assert_eq!(
                status,
                VerificationStatus::Invalid,
                "strict verification must reject a small-order public key"
            );
        }
    }

    /// Strict verification must reject a signature whose `S` scalar is not
    /// canonically reduced modulo the group order (signature malleability). We
    /// take a genuine signature and replace its upper 32 bytes (the `S`
    /// component) with `0xFF..FF`, which is far larger than the group order L
    /// and therefore non-canonical. `verify_strict` rejects it; the permissive
    /// `verify()` path does not enforce this. The signature is still 64 bytes,
    /// so this is an `Invalid` verdict, not `MalformedSignature`.
    #[test]
    fn strict_verification_rejects_non_canonical_signature_scalar() {
        let sk = signing_key(11);
        let vk = sk.verifying_key();
        let msg = b"canonical signer bytes";
        let genuine = sk.sign(msg);

        let mut tampered = genuine.to_bytes();
        // Overwrite the S component (upper 32 bytes) with a non-canonical scalar
        // (0xFF.. is >= L), leaving R (lower 32 bytes) intact.
        for b in tampered.iter_mut().skip(32) {
            *b = 0xFF;
        }

        let verifier = Ed25519SignatureVerifier::new();
        let status = verifier
            .verify(vk.as_bytes(), msg, &tampered)
            .expect("64-byte signature, 32-byte key");
        assert_eq!(
            status,
            VerificationStatus::Invalid,
            "strict verification must reject a non-canonical S component"
        );
    }

    #[test]
    fn does_not_panic_on_arbitrary_inputs() {
        let verifier = Ed25519SignatureVerifier::new();
        // Empty, short, and junk inputs all resolve to typed errors, no panic.
        let _ = verifier.verify(&[], &[], &[]);
        let _ = verifier.verify(&[0xFF; 32], b"x", &[0xFF; 64]);
    }

    /// Genuine strict-vs-permissive boundary vector (Rule 17 regression guard).
    ///
    /// The two tests above assert `Invalid`, but their vectors are rejected by
    /// *both* `ed25519-dalek`'s permissive `Verifier::verify` and the strict
    /// `VerifyingKey::verify_strict` (in dalek 2.x the `S < L` canonicality
    /// check runs on both paths, and an all-zero identity key with arbitrary
    /// bytes fails the verification equation on both). They therefore do NOT
    /// lock in the strict path: a regression from `verify_strict` to `verify`
    /// would leave them green.
    ///
    /// This test uses a vector that `verify` ACCEPTS but `verify_strict`
    /// REJECTS, so it fails if the engine ever regresses to permissive
    /// verification. The genuine difference in dalek 2.x is cofactored
    /// (`verify`) vs cofactorless (`verify_strict`) handling of a small-order /
    /// torsion public key: `verify_strict` rejects a small-order public key,
    /// `verify` does not.
    ///
    /// The vector was constructed by reproducing `ed25519-dalek`'s own
    /// `repudiation` test construction (ed25519-dalek 2.2.0 `tests/ed25519.rs`):
    /// `A` is the order-2 torsion point `(0, -1)` (compressed `ec ff .. 7f`),
    /// `s = 1`, and `R = s*B - A`, chosen so the challenge `H(R || A || M)` is
    /// odd and the cofactored verification equation `s*B = R + H*A` holds while
    /// the public key stays small order. The concrete bytes below were captured
    /// from that construction (curve25519-dalek was used only to FIND the
    /// vector; it is not a dependency of this crate). The test is
    /// self-validating: it first asserts the dalek permissive/strict
    /// preconditions, so if a future dalek version moves the boundary the
    /// preconditions fail loudly rather than silently giving false protection.
    #[test]
    fn strict_path_rejects_a_vector_permissive_verify_accepts() {
        use ed25519_dalek::Verifier;

        // Order-2 torsion public key A = (0, -1): small order, but well-formed.
        let public_key: [u8; PUBLIC_KEY_LEN] = [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        let message = b"KYA strict/permissive boundary vector";
        // Signature = R (compressed s*B - A) || s (scalar 1, little-endian).
        // S = scalar 1 is canonical (< L), so any rejection is from the
        // small-order public key, not from the S<L malleability check.
        let signature: [u8; SIGNATURE_LEN] = [
            // R = s*B - A
            0x95, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
            0x99, 0x99, 0x99, 0x99, // S = scalar 1
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        // Self-validating precondition: prove, against THIS dalek version, that
        // the vector genuinely lies on the strict/permissive boundary.
        let vk =
            VerifyingKey::from_bytes(&public_key).expect("torsion key is a well-formed encoding");
        let sig = Signature::from_bytes(&signature);
        assert!(
            vk.is_weak(),
            "precondition: the public key must be small order"
        );
        assert!(
            vk.verify(message, &sig).is_ok(),
            "precondition: permissive verify() must ACCEPT this vector; \
             if this fails, the vector no longer exercises the boundary"
        );
        assert!(
            vk.verify_strict(message, &sig).is_err(),
            "precondition: strict verify_strict() must REJECT this vector; \
             if this fails, the vector no longer exercises the boundary"
        );

        // The actual regression assertion: our engine uses verify_strict, so it
        // must report Invalid. If the production code ever regressed to the
        // permissive verify(), the vector would verify and this would be
        // Verified -> the test fails, which is the point of Rule 17.
        let verifier = Ed25519SignatureVerifier::new();
        let status = verifier
            .verify(&public_key, message, &signature)
            .expect("well-formed length inputs");
        assert_eq!(
            status,
            VerificationStatus::Invalid,
            "engine must reject a small-order-key vector that permissive verify accepts"
        );
    }
}
