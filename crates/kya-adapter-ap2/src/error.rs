//! Typed errors for the AP2 constraint adapter.
//!
//! Every fallible operation in this crate returns an [`Ap2AdapterError`]: a
//! `#[non_exhaustive]` enum implementing [`Display`](core::fmt::Display) and
//! [`std::error::Error`] (AGENTS.md Rule 7). No variant carries secrets, key
//! bytes, signatures, or raw attacker payload (Rule 18); each is a flat
//! description of *what class* of failure occurred. Where a failure originates
//! in `kya-core` construction or in the `kya-crypto` engine, the underlying
//! typed error is preserved as the [`std::error::Error::source`] so callers
//! lose no fidelity.

use core::fmt;

use kya_core::error::{AsErrorCode, ErrorCode};
use kya_core::identity::IdentityError;
use kya_core::mandate::ValidityError;
use kya_core::money::MoneyError;
use kya_core::scope::ScopeError;
use kya_crypto::CryptoVerificationError;

/// A structured reason an AP2 constraint mapping or verification failed.
///
/// The enum is `#[non_exhaustive]` so new variants are an additive,
/// semver-compatible change (AGENTS.md Rule 21).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ap2AdapterError {
    /// An identity value (issuer, agent, principal, merchant, resource, or
    /// audience) was empty, too long, or carried a disallowed/control
    /// character.
    Identity(IdentityError),
    /// A monetary amount or currency was invalid (negative amount, bad currency
    /// code, or a currency mismatch).
    Money(MoneyError),
    /// A permitted-action name was empty.
    Scope(ScopeError),
    /// The constraint set declared an inverted validity window
    /// (`not_before > not_after`).
    Validity(ValidityError),
    /// The caller-supplied signed bytes failed cryptographic verification or an
    /// associated fail-closed check in the `kya-crypto` engine (bad signature,
    /// untrusted key, unknown issuer, audience/validity/binding mismatch,
    /// malformed or oversized input, unsupported algorithm).
    Verification(CryptoVerificationError),
}

impl fmt::Display for Ap2AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ap2AdapterError::Identity(_) => f.write_str("invalid AP2 identity value"),
            Ap2AdapterError::Money(_) => f.write_str("invalid AP2 monetary constraint"),
            Ap2AdapterError::Scope(_) => f.write_str("invalid AP2 action constraint"),
            Ap2AdapterError::Validity(_) => f.write_str("invalid AP2 validity window"),
            Ap2AdapterError::Verification(_) => f.write_str("AP2 delegation did not verify"),
        }
    }
}

impl std::error::Error for Ap2AdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Ap2AdapterError::Identity(e) => Some(e),
            Ap2AdapterError::Money(e) => Some(e),
            Ap2AdapterError::Scope(e) => Some(e),
            Ap2AdapterError::Validity(e) => Some(e),
            Ap2AdapterError::Verification(e) => Some(e),
        }
    }
}

impl From<IdentityError> for Ap2AdapterError {
    fn from(e: IdentityError) -> Self {
        Ap2AdapterError::Identity(e)
    }
}

impl From<MoneyError> for Ap2AdapterError {
    fn from(e: MoneyError) -> Self {
        Ap2AdapterError::Money(e)
    }
}

impl From<ScopeError> for Ap2AdapterError {
    fn from(e: ScopeError) -> Self {
        Ap2AdapterError::Scope(e)
    }
}

impl From<ValidityError> for Ap2AdapterError {
    fn from(e: ValidityError) -> Self {
        Ap2AdapterError::Validity(e)
    }
}

impl From<CryptoVerificationError> for Ap2AdapterError {
    fn from(e: CryptoVerificationError) -> Self {
        Ap2AdapterError::Verification(e)
    }
}

impl AsErrorCode for Ap2AdapterError {
    /// Map to the stable, kebab-case [`ErrorCode`] machinery already used across
    /// the workspace. Mapping delegates to the underlying typed error's code so
    /// the adapter does not invent new codes for failures that already have one.
    fn error_code(&self) -> ErrorCode {
        match self {
            // Identity/money/scope errors already have precise codes in the
            // shared taxonomy; delegate rather than invent a new one.
            Ap2AdapterError::Identity(e) => e.error_code(),
            Ap2AdapterError::Money(e) => e.error_code(),
            Ap2AdapterError::Scope(e) => e.error_code(),
            // ValidityError has no dedicated shared code (it is adapter-level
            // input the caller supplied outside the supported range); the
            // closest stable code is the "present but outside allowed set"
            // class.
            Ap2AdapterError::Validity(_) => ErrorCode::UnsupportedValue,
            Ap2AdapterError::Verification(e) => e.error_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_error_wraps_and_preserves_source() {
        let err = Ap2AdapterError::from(IdentityError::Empty);
        assert_eq!(err, Ap2AdapterError::Identity(IdentityError::Empty));
        // Display is non-sensitive and the source is preserved.
        assert_eq!(err.to_string(), "invalid AP2 identity value");
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn verification_error_maps_to_underlying_code() {
        let err = Ap2AdapterError::from(CryptoVerificationError::SignatureInvalid);
        assert_eq!(
            err.error_code(),
            CryptoVerificationError::SignatureInvalid.error_code()
        );
    }

    #[test]
    fn construction_errors_map_to_underlying_codes() {
        assert_eq!(
            Ap2AdapterError::from(MoneyError::Negative).error_code(),
            ErrorCode::MoneyNegative
        );
        assert_eq!(
            Ap2AdapterError::from(ScopeError::EmptyAction).error_code(),
            ErrorCode::ScopeEmptyAction
        );
        assert_eq!(
            Ap2AdapterError::from(ValidityError::Inverted {
                not_before: 2,
                not_after: 1
            })
            .error_code(),
            ErrorCode::UnsupportedValue
        );
    }
}
