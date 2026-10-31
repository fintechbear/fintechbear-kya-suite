//! Stage B cryptographic-verification **trait seam** and value types.
//!
//! This module defines *where* signature verification plugs in and the
//! auditable value types that describe *what* was verified. It does **not**
//! implement any cryptographic algorithm, and — crucially — it does **not**
//! contain the authority to mint a *verified* outcome or verified evidence.
//! That authority lives in the reviewed concrete crypto crate (`kya-crypto`),
//! which is the only crate that performs real signature verification.
//!
//! A successful verification (stage B) proves **authenticity and integrity** of
//! signed bytes. It is emphatically **not** an authorization: it says nothing
//! about revocation, cumulative budget, or global replay state. Those are
//! established only by the online authoritative check (stage D).
//!
//! It also says nothing about **agent proof-of-possession**. Verifying a
//! signature over some bytes proves whoever holds the signing key produced
//! them; in this SDK that signer is the *issuer*, not the *agent* the
//! delegation is about. No agent key check is performed anywhere, so a verified
//! outcome must never be read as the agent having demonstrated it holds its own
//! key. That gap is represented explicitly on the verified evidence by
//! [`crate::evidence::ProofOfPossession`].
//!
//! The module defines a [`VerificationContext`] (what is being verified and
//! under which key/algorithm) so callers can carry an auditable record of a
//! verification attempt without ever holding secret key material in the core.
//!
//! # Where the verified types live, and why (the forgery-vector fix)
//!
//! A verified *outcome* ([`kya_crypto::VerificationOutcome`]) and verified
//! *evidence* ([`kya_crypto::VerifiedDelegation`],
//! [`kya_crypto::VerifiedMandate`]) are deliberately **not** defined in this
//! crate. They, and their only constructors, live in `kya-crypto`, bound to the
//! single reviewed concrete verifier (`kya_crypto::Ed25519SignatureVerifier`).
//!
//! This is the root-cause fix for the confirmed verifier-sanction bypass. The
//! previous design mint-pointed a verified outcome inside `kya-core` behind a
//! `#[doc(hidden)] pub` registration seam that was generic over *any*
//! `V: SignatureVerifier`. Because `kya-core` must not depend on `kya-crypto`
//! (AGENTS.md Rule 2) and cannot name the concrete Ed25519 type, no
//! pure-visibility rule in `kya-core` could admit exactly `kya-crypto` while
//! rejecting every other external crate — both saw the same public surface. A
//! hostile downstream crate could therefore implement an always-`Verified`
//! verifier, call the hidden seam to mint a token, route attacker-chosen bytes
//! through the mint-point, and forge trusted evidence with **no** cryptography.
//!
//! Relocating the verified-outcome and verified-evidence constructors into
//! `kya-crypto` closes this as a true Rust visibility wall: the constructors are
//! private to `kya-crypto` and reachable only through
//! [`kya_crypto::verify_delegation`] / [`kya_crypto::verify_mandate`], which run
//! the reviewed `Ed25519SignatureVerifier` over real bytes. An external crate
//! has no path — public or `#[doc(hidden)]` — to build a verified outcome or
//! verified evidence for a verifier of its own. `kya-core` stays crypto-free and
//! depends on nothing in-repo.
//!
//! [`kya_crypto::VerificationOutcome`]: https://docs.rs/kya-crypto
//! [`kya_crypto::VerifiedDelegation`]: https://docs.rs/kya-crypto
//! [`kya_crypto::VerifiedMandate`]: https://docs.rs/kya-crypto
//! [`kya_crypto::Ed25519SignatureVerifier`]: https://docs.rs/kya-crypto
//! [`kya_crypto::verify_delegation`]: https://docs.rs/kya-crypto
//! [`kya_crypto::verify_mandate`]: https://docs.rs/kya-crypto

use core::fmt;

use crate::identity::{IssuerId, TrustedKeyRef};

/// A named signature algorithm a verifier may be asked to use.
///
/// Expressed as a validated newtype rather than a raw string so that an
/// algorithm name cannot be confused with other strings and so that the
/// "unsupported algorithm" path is explicit. The core does not implement any of
/// these; it only names them for the seam.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AlgorithmId(String);

impl AlgorithmId {
    /// Construct an algorithm identifier.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError::UnsupportedAlgorithm`] if the name is empty.
    /// (An empty algorithm name is treated as a request the verifier cannot
    /// satisfy, never as a silent "no algorithm" pass — cf. the `alg: none`
    /// downgrade attack.)
    pub fn new(raw: &str) -> Result<Self, VerificationError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(VerificationError::UnsupportedAlgorithm);
        }
        Ok(AlgorithmId(trimmed.to_owned()))
    }

    /// The algorithm name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of a signature verification attempt.
///
/// Note the deliberate absence of a "maybe": verification is binary, and any
/// error maps to [`VerificationError`] rather than a silent pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationStatus {
    /// The signature is authentic for the given bytes and key.
    Verified,
    /// The signature did not match.
    Invalid,
}

impl VerificationStatus {
    /// Returns `true` only for [`VerificationStatus::Verified`].
    pub fn is_verified(self) -> bool {
        matches!(self, VerificationStatus::Verified)
    }
}

/// Errors that can occur during signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationError {
    /// The key material was malformed or of an unsupported type.
    MalformedKey,
    /// The signature bytes were malformed.
    MalformedSignature,
    /// The algorithm requested is not supported by this verifier.
    UnsupportedAlgorithm,
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::MalformedKey => f.write_str("malformed verification key"),
            VerificationError::MalformedSignature => f.write_str("malformed signature"),
            VerificationError::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
        }
    }
}

impl std::error::Error for VerificationError {}

/// What is being verified, and under which issuer key and algorithm.
///
/// A verification context binds the attributed issuer, the specific trusted key
/// reference, and the algorithm together so that an outcome can be audited and
/// so that a signature cannot be silently re-attributed to a different key. It
/// carries **no secret material**: the key is referenced by [`TrustedKeyRef`],
/// not held as bytes (AGENTS.md Rule 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationContext {
    issuer: IssuerId,
    key_ref: TrustedKeyRef,
    algorithm: AlgorithmId,
}

impl VerificationContext {
    /// Construct a verification context.
    pub fn new(issuer: IssuerId, key_ref: TrustedKeyRef, algorithm: AlgorithmId) -> Self {
        VerificationContext {
            issuer,
            key_ref,
            algorithm,
        }
    }

    /// The issuer the signature is attributed to.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The trusted key reference the signature is checked against.
    pub fn key_ref(&self) -> &TrustedKeyRef {
        &self.key_ref
    }

    /// The algorithm the verifier was asked to use.
    pub fn algorithm(&self) -> &AlgorithmId {
        &self.algorithm
    }
}

/// A verifier of detached signatures over a byte payload.
///
/// Implementors MUST rely on standard, reviewed cryptographic primitives and
/// MUST NOT invent algorithms. Implementors MUST NOT panic on malformed,
/// attacker-controlled input; they return [`VerificationError`] instead.
///
/// Implementing this trait is **not sufficient** to mint verified evidence.
/// `kya-core` holds no constructor for a *verified* outcome or verified
/// evidence; those live exclusively in the reviewed `kya-crypto` crate, bound to
/// its one concrete verifier. An external always-`Verified` implementor of this
/// trait can describe a result but can never cause trusted evidence to be
/// minted — there is no path in `kya-core` or `kya-crypto` that will run an
/// arbitrary external verifier to produce verified evidence. See the module
/// docs for the forgery vector this prevents.
pub trait SignatureVerifier {
    /// Verify `signature` over `payload` using `public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError`] if the inputs are malformed or the
    /// algorithm is unsupported. A genuine non-match returns
    /// `Ok(VerificationStatus::Invalid)`, not an error.
    fn verify(
        &self,
        public_key: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<VerificationStatus, VerificationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_algorithm_is_unsupported_not_silent() {
        assert_eq!(
            AlgorithmId::new("  "),
            Err(VerificationError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn algorithm_id_trims_and_preserves_name() {
        let alg = AlgorithmId::new("  EdDSA ").expect("valid");
        assert_eq!(alg.as_str(), "EdDSA");
        assert_eq!(alg.to_string(), "EdDSA");
    }

    #[test]
    fn status_is_binary() {
        assert!(VerificationStatus::Verified.is_verified());
        assert!(!VerificationStatus::Invalid.is_verified());
    }

    #[test]
    fn verification_error_display_is_non_sensitive() {
        assert_eq!(
            VerificationError::MalformedKey.to_string(),
            "malformed verification key"
        );
        assert_eq!(
            VerificationError::MalformedSignature.to_string(),
            "malformed signature"
        );
        assert_eq!(
            VerificationError::UnsupportedAlgorithm.to_string(),
            "unsupported algorithm"
        );
    }

    #[test]
    fn context_carries_no_secret_only_references() {
        let ctx = VerificationContext::new(
            IssuerId::new("issuer:acme").expect("valid"),
            TrustedKeyRef::new("kid:1").expect("valid"),
            AlgorithmId::new("ed25519").expect("valid"),
        );
        assert_eq!(ctx.issuer().as_str(), "issuer:acme");
        assert_eq!(ctx.key_ref().as_str(), "kid:1");
        assert_eq!(ctx.algorithm().as_str(), "ed25519");
    }

    /// An external-shaped verifier can be implemented, but there is no longer
    /// any `kya-core` function that turns it into a verified outcome or verified
    /// evidence: the mint-point left this crate entirely. This test documents
    /// that `SignatureVerifier` is a pure description seam.
    #[test]
    fn signature_verifier_is_only_a_description_seam() {
        struct AlwaysVerified;
        impl SignatureVerifier for AlwaysVerified {
            fn verify(
                &self,
                _pk: &[u8],
                _m: &[u8],
                _s: &[u8],
            ) -> Result<VerificationStatus, VerificationError> {
                Ok(VerificationStatus::Verified)
            }
        }
        let status = AlwaysVerified
            .verify(b"pk", b"m", b"s")
            .expect("in-crate verifier returns Ok");
        // It can report Verified, but this crate exposes no way to promote that
        // report into a verified outcome or verified evidence. That authority
        // lives only in kya-crypto, bound to the reviewed concrete verifier.
        assert_eq!(status, VerificationStatus::Verified);
    }
}
