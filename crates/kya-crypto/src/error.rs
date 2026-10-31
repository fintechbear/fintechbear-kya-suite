//! Structured, typed verification errors for the concrete crypto engine.
//!
//! Every failure path in this crate returns a [`CryptoVerificationError`]: a
//! `#[non_exhaustive]` enum implementing [`Display`](core::fmt::Display) and
//! [`std::error::Error`]. No code path panics on untrusted input, and no error
//! variant ever carries secrets, key bytes, signatures, or raw attacker payload
//! (AGENTS.md Rule 18) — only a flat description of *what class* of failure
//! occurred. Each variant maps to a stable [`kya_core::error::ErrorCode`] via
//! [`kya_core::error::AsErrorCode`].

use core::fmt;

use kya_core::error::{AsErrorCode, ErrorCode};
use kya_core::evidence::EvidenceError;
use kya_core::verification::VerificationError;

/// A structured reason a cryptographic verification failed.
///
/// Variants are deliberately distinct so a caller (and an audit log) can tell
/// *why* verification failed without the engine ever rounding a near-miss up to
/// "verified". The enum is `#[non_exhaustive]` so new variants are an additive,
/// semver-compatible change (AGENTS.md Rule 21).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoVerificationError {
    /// The requested or presented algorithm is not on the allowlist. Only
    /// `EdDSA`/Ed25519 is accepted; `alg: none`, HMAC, RSA, ECDSA, the empty
    /// string, and any other identifier land here (downgrade/confusion
    /// defense).
    UnsupportedAlgorithm,
    /// The public key material was not a valid 32-byte Ed25519 key.
    MalformedKey,
    /// The signature was not a valid 64-byte Ed25519 signature.
    MalformedSignature,
    /// The signature was well-formed but did not verify against the key/bytes.
    SignatureInvalid,
    /// The issuer named by the claim has no entry in the trusted key store.
    UnknownIssuer,
    /// The `(issuer, key_ref)` pair is not an anchored trust (either absent
    /// from the key store for that issuer, or absent from the `TrustAnchors`).
    UntrustedKey,
    /// The claim's audience did not exactly match the expected audience.
    AudienceMismatch,
    /// The claim's expiration (`exp`) is at or before the supplied current
    /// time.
    Expired,
    /// The claim's not-before (`nbf`) is strictly after the supplied current
    /// time.
    NotYetValid,
    /// The claim's signed-over transaction binding did not exactly match the
    /// presented request binding.
    BindingMismatch,
    /// An untrusted payload could not be decoded or parsed (bad base64url,
    /// UTF-8, JSON shape, or structural form).
    MalformedPayload,
    /// An untrusted input exceeded the configured maximum size bound.
    OversizedInput,
}

impl fmt::Display for CryptoVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CryptoVerificationError::UnsupportedAlgorithm => {
                "unsupported or disallowed signature algorithm"
            }
            CryptoVerificationError::MalformedKey => "malformed Ed25519 public key",
            CryptoVerificationError::MalformedSignature => "malformed Ed25519 signature",
            CryptoVerificationError::SignatureInvalid => "signature did not verify",
            CryptoVerificationError::UnknownIssuer => "issuer is not configured",
            CryptoVerificationError::UntrustedKey => "key is not an anchored trust for its issuer",
            CryptoVerificationError::AudienceMismatch => "audience did not match",
            CryptoVerificationError::Expired => "claim has expired",
            CryptoVerificationError::NotYetValid => "claim is not yet valid",
            CryptoVerificationError::BindingMismatch => "transaction binding did not match",
            CryptoVerificationError::MalformedPayload => "payload could not be parsed",
            CryptoVerificationError::OversizedInput => "input exceeded the permitted size bound",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CryptoVerificationError {}

impl AsErrorCode for CryptoVerificationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            CryptoVerificationError::UnsupportedAlgorithm => {
                ErrorCode::VerificationUnsupportedAlgorithm
            }
            CryptoVerificationError::MalformedKey => ErrorCode::VerificationMalformedKey,
            CryptoVerificationError::MalformedSignature => {
                ErrorCode::VerificationMalformedSignature
            }
            CryptoVerificationError::SignatureInvalid => ErrorCode::VerificationSignatureInvalid,
            CryptoVerificationError::UnknownIssuer => ErrorCode::VerificationUnknownIssuer,
            CryptoVerificationError::UntrustedKey => ErrorCode::VerificationUntrustedKey,
            CryptoVerificationError::AudienceMismatch => ErrorCode::VerificationAudienceMismatch,
            CryptoVerificationError::Expired => ErrorCode::VerificationExpired,
            CryptoVerificationError::NotYetValid => ErrorCode::VerificationNotYetValid,
            CryptoVerificationError::BindingMismatch => ErrorCode::VerificationBindingMismatch,
            CryptoVerificationError::MalformedPayload => ErrorCode::VerificationMalformedPayload,
            CryptoVerificationError::OversizedInput => ErrorCode::VerificationOversizedInput,
        }
    }
}

impl From<VerificationError> for CryptoVerificationError {
    /// Lift a core seam error into the crypto engine's error type without
    /// losing the distinction between malformed key, malformed signature, and
    /// unsupported algorithm.
    fn from(e: VerificationError) -> Self {
        match e {
            VerificationError::MalformedKey => CryptoVerificationError::MalformedKey,
            VerificationError::MalformedSignature => CryptoVerificationError::MalformedSignature,
            VerificationError::UnsupportedAlgorithm => {
                CryptoVerificationError::UnsupportedAlgorithm
            }
            // `VerificationError` is `#[non_exhaustive]`; any future variant
            // maps fail-closed to an unsupported-algorithm failure rather than
            // panicking.
            _ => CryptoVerificationError::UnsupportedAlgorithm,
        }
    }
}

impl From<EvidenceError> for CryptoVerificationError {
    /// Lift an evidence-establishment failure into the engine's error type.
    ///
    /// `SignatureNotVerified` should be unreachable on the sealed path (we only
    /// call `establish` with a `Verified` outcome), but it maps to
    /// [`CryptoVerificationError::SignatureInvalid`] to stay fail-closed rather
    /// than panic. `IssuerMismatch` and `UntrustedKey` both reduce to an
    /// untrusted-key failure from the engine's perspective.
    fn from(e: EvidenceError) -> Self {
        match e {
            EvidenceError::SignatureNotVerified => CryptoVerificationError::SignatureInvalid,
            EvidenceError::IssuerMismatch => CryptoVerificationError::UntrustedKey,
            EvidenceError::UntrustedKey => CryptoVerificationError::UntrustedKey,
            // `EvidenceError` is `#[non_exhaustive]`; a future variant maps
            // fail-closed to an untrusted-key failure rather than panicking.
            _ => CryptoVerificationError::UntrustedKey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_to_stable_codes() {
        assert_eq!(
            CryptoVerificationError::SignatureInvalid.error_code(),
            ErrorCode::VerificationSignatureInvalid
        );
        assert_eq!(
            CryptoVerificationError::AudienceMismatch.error_code(),
            ErrorCode::VerificationAudienceMismatch
        );
        assert_eq!(
            CryptoVerificationError::OversizedInput.error_code(),
            ErrorCode::VerificationOversizedInput
        );
    }

    #[test]
    fn display_is_non_sensitive() {
        // Display strings must never leak payload/keys; they are fixed phrases.
        assert_eq!(
            CryptoVerificationError::MalformedKey.to_string(),
            "malformed Ed25519 public key"
        );
    }

    #[test]
    fn core_verification_error_lifts() {
        assert_eq!(
            CryptoVerificationError::from(VerificationError::MalformedSignature),
            CryptoVerificationError::MalformedSignature
        );
    }

    #[test]
    fn evidence_error_lifts_to_fail_closed() {
        assert_eq!(
            CryptoVerificationError::from(EvidenceError::UntrustedKey),
            CryptoVerificationError::UntrustedKey
        );
        assert_eq!(
            CryptoVerificationError::from(EvidenceError::IssuerMismatch),
            CryptoVerificationError::UntrustedKey
        );
        assert_eq!(
            CryptoVerificationError::from(EvidenceError::SignatureNotVerified),
            CryptoVerificationError::SignatureInvalid
        );
    }
}
