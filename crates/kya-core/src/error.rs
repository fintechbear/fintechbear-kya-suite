//! Structured, stable error codes for the KYA domain.
//!
//! Every typed error enum in this crate (`IdentityError`, `MoneyError`,
//! `CurrencyError`, `ScopeError`, `VerificationError`, …) describes a *class* of
//! failure in rich, module-local terms. Those enums are the right thing to
//! `match` on in Rust code.
//!
//! [`ErrorCode`] is a second, flatter view of the same failures: a single
//! `#[non_exhaustive]` enum of **stable, machine-readable codes** suitable for
//! logging, metrics, audit records, and protocol responses, where a compact
//! code is more useful than a nested enum. Mapping into [`ErrorCode`] is total
//! and lossless at the level of "what went wrong"; it deliberately drops the
//! sensitive or verbose payload (byte lengths, key material, raw strings) so a
//! code is always safe to emit (AGENTS.md Rule 18).
//!
//! The codes are part of the public API and follow semantic versioning
//! (AGENTS.md Rule 21); the enum is `#[non_exhaustive]` so new codes are an
//! additive change.

use core::fmt;

use crate::identity::IdentityError;
use crate::money::{CurrencyError, MoneyError};
use crate::scope::ScopeError;
use crate::verification::VerificationError;

/// A stable, machine-readable code describing a class of KYA failure.
///
/// Each code has a stable kebab-case string form ([`ErrorCode::as_str`]) that
/// is safe to log and to place on the wire. Codes never carry secrets, keys,
/// signatures, or raw attacker-controlled strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// An identifier was empty or whitespace-only.
    IdentifierEmpty,
    /// An identifier exceeded the maximum permitted length.
    IdentifierTooLong,
    /// An identifier contained characters outside the permitted set.
    IdentifierMalformed,
    /// A currency code was not exactly three characters.
    CurrencyWrongLength,
    /// A currency code contained a non-uppercase-ASCII character.
    CurrencyNotUppercaseAscii,
    /// A monetary amount was negative.
    MoneyNegative,
    /// A monetary arithmetic operation overflowed.
    MoneyOverflow,
    /// Two amounts in different currencies were combined or compared.
    MoneyCurrencyMismatch,
    /// A scope action name was empty.
    ScopeEmptyAction,
    /// Verification was given malformed key material.
    VerificationMalformedKey,
    /// Verification was given a malformed signature.
    VerificationMalformedSignature,
    /// Verification was asked for an unsupported algorithm.
    VerificationUnsupportedAlgorithm,
    /// A cryptographic signature was well-formed but did not match.
    VerificationSignatureInvalid,
    /// A signature was attributed to an issuer that is not known/configured.
    VerificationUnknownIssuer,
    /// A signing key is not an anchored trust for its issuer.
    VerificationUntrustedKey,
    /// A verified claim's audience did not match the expected audience.
    VerificationAudienceMismatch,
    /// A verified claim's validity window has elapsed (exp in the past).
    VerificationExpired,
    /// A verified claim is not yet valid (nbf in the future).
    VerificationNotYetValid,
    /// A verified claim's transaction binding did not match the request.
    VerificationBindingMismatch,
    /// An untrusted payload could not be parsed/decoded.
    VerificationMalformedPayload,
    /// An untrusted input exceeded the permitted size bound.
    VerificationOversizedInput,
    /// A required field was absent from an external/untrusted input.
    MissingField,
    /// An external value was present but outside the supported/allowed set.
    UnsupportedValue,
}

impl ErrorCode {
    /// The stable kebab-case string form of this code.
    ///
    /// This string is part of the public API: it is safe to log, to persist in
    /// audit records, and to place on the wire. It never changes for a given
    /// variant within a major version.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::IdentifierEmpty => "identifier-empty",
            ErrorCode::IdentifierTooLong => "identifier-too-long",
            ErrorCode::IdentifierMalformed => "identifier-malformed",
            ErrorCode::CurrencyWrongLength => "currency-wrong-length",
            ErrorCode::CurrencyNotUppercaseAscii => "currency-not-uppercase-ascii",
            ErrorCode::MoneyNegative => "money-negative",
            ErrorCode::MoneyOverflow => "money-overflow",
            ErrorCode::MoneyCurrencyMismatch => "money-currency-mismatch",
            ErrorCode::ScopeEmptyAction => "scope-empty-action",
            ErrorCode::VerificationMalformedKey => "verification-malformed-key",
            ErrorCode::VerificationMalformedSignature => "verification-malformed-signature",
            ErrorCode::VerificationUnsupportedAlgorithm => "verification-unsupported-algorithm",
            ErrorCode::VerificationSignatureInvalid => "verification-signature-invalid",
            ErrorCode::VerificationUnknownIssuer => "verification-unknown-issuer",
            ErrorCode::VerificationUntrustedKey => "verification-untrusted-key",
            ErrorCode::VerificationAudienceMismatch => "verification-audience-mismatch",
            ErrorCode::VerificationExpired => "verification-expired",
            ErrorCode::VerificationNotYetValid => "verification-not-yet-valid",
            ErrorCode::VerificationBindingMismatch => "verification-binding-mismatch",
            ErrorCode::VerificationMalformedPayload => "verification-malformed-payload",
            ErrorCode::VerificationOversizedInput => "verification-oversized-input",
            ErrorCode::MissingField => "missing-field",
            ErrorCode::UnsupportedValue => "unsupported-value",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Anything that can be reduced to a stable [`ErrorCode`].
///
/// Implemented for every public typed error in the crate so that callers can
/// obtain a safe, flat code from any domain error without matching on its full
/// structure.
pub trait AsErrorCode {
    /// The stable code for this error.
    fn error_code(&self) -> ErrorCode;
}

impl AsErrorCode for IdentityError {
    fn error_code(&self) -> ErrorCode {
        match self {
            IdentityError::Empty => ErrorCode::IdentifierEmpty,
            IdentityError::TooLong { .. } => ErrorCode::IdentifierTooLong,
            IdentityError::Malformed => ErrorCode::IdentifierMalformed,
        }
    }
}

impl AsErrorCode for CurrencyError {
    fn error_code(&self) -> ErrorCode {
        match self {
            CurrencyError::WrongLength { .. } => ErrorCode::CurrencyWrongLength,
            CurrencyError::NotUppercaseAscii => ErrorCode::CurrencyNotUppercaseAscii,
        }
    }
}

impl AsErrorCode for MoneyError {
    fn error_code(&self) -> ErrorCode {
        match self {
            MoneyError::Negative => ErrorCode::MoneyNegative,
            MoneyError::Overflow => ErrorCode::MoneyOverflow,
            MoneyError::CurrencyMismatch { .. } => ErrorCode::MoneyCurrencyMismatch,
            MoneyError::Currency(e) => e.error_code(),
        }
    }
}

impl AsErrorCode for ScopeError {
    fn error_code(&self) -> ErrorCode {
        match self {
            ScopeError::EmptyAction => ErrorCode::ScopeEmptyAction,
        }
    }
}

impl AsErrorCode for VerificationError {
    fn error_code(&self) -> ErrorCode {
        match self {
            VerificationError::MalformedKey => ErrorCode::VerificationMalformedKey,
            VerificationError::MalformedSignature => ErrorCode::VerificationMalformedSignature,
            VerificationError::UnsupportedAlgorithm => ErrorCode::VerificationUnsupportedAlgorithm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_strings() {
        assert_eq!(ErrorCode::MoneyOverflow.as_str(), "money-overflow");
        assert_eq!(ErrorCode::MoneyOverflow.to_string(), "money-overflow");
        assert_eq!(ErrorCode::MissingField.as_str(), "missing-field");
    }

    #[test]
    fn identity_errors_map_to_codes() {
        assert_eq!(
            IdentityError::Empty.error_code(),
            ErrorCode::IdentifierEmpty
        );
        assert_eq!(
            IdentityError::TooLong {
                got: 9_000,
                max: 512
            }
            .error_code(),
            ErrorCode::IdentifierTooLong
        );
        assert_eq!(
            IdentityError::Malformed.error_code(),
            ErrorCode::IdentifierMalformed
        );
    }

    #[test]
    fn money_currency_error_delegates_to_currency_code() {
        let e = MoneyError::Currency(CurrencyError::WrongLength { got: 2 });
        assert_eq!(e.error_code(), ErrorCode::CurrencyWrongLength);
    }

    #[test]
    fn verification_errors_map_to_codes() {
        assert_eq!(
            VerificationError::UnsupportedAlgorithm.error_code(),
            ErrorCode::VerificationUnsupportedAlgorithm
        );
    }

    #[test]
    fn no_two_variants_share_a_string() {
        let codes = [
            ErrorCode::IdentifierEmpty,
            ErrorCode::IdentifierTooLong,
            ErrorCode::IdentifierMalformed,
            ErrorCode::CurrencyWrongLength,
            ErrorCode::CurrencyNotUppercaseAscii,
            ErrorCode::MoneyNegative,
            ErrorCode::MoneyOverflow,
            ErrorCode::MoneyCurrencyMismatch,
            ErrorCode::ScopeEmptyAction,
            ErrorCode::VerificationMalformedKey,
            ErrorCode::VerificationMalformedSignature,
            ErrorCode::VerificationUnsupportedAlgorithm,
            ErrorCode::VerificationSignatureInvalid,
            ErrorCode::VerificationUnknownIssuer,
            ErrorCode::VerificationUntrustedKey,
            ErrorCode::VerificationAudienceMismatch,
            ErrorCode::VerificationExpired,
            ErrorCode::VerificationNotYetValid,
            ErrorCode::VerificationBindingMismatch,
            ErrorCode::VerificationMalformedPayload,
            ErrorCode::VerificationOversizedInput,
            ErrorCode::MissingField,
            ErrorCode::UnsupportedValue,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in codes {
            assert!(seen.insert(c.as_str()), "duplicate string for {c:?}");
        }
    }
}
