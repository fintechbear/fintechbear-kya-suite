#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # kya-protocol
//!
//! The language-independent **protocol surface** of the FintechBear KYA SDK.
//! This crate defines the version marker and the wire-level shapes that
//! describe mandates and transaction intents on the wire. The shapes reference
//! the domain types in [`kya_core`]; the dependency points toward the domain
//! core, never the other way.
//!
//! In v0.1 this crate carries only a minimal, **fail-closed** decode/encode
//! boundary: it declares the protocol's semantic version, the placeholder wire
//! shapes, and a tiny `std`-only field-map representation ([`WireFields`]) for
//! turning untrusted external input into validated domain types. It still
//! contains no external-protocol codec: there is no JSON, no `serde`, and no
//! claim of byte-for-byte compatibility with any external wire protocol. The
//! field-map form exists so that the untrusted-input boundary (and the typed
//! errors it produces) can be exercised and tested.
//!
//! ## The decode/encode boundary
//!
//! [`WireFields`] is an **internal v0.1 field-map**: an ordered list of
//! `(key, value)` string pairs. It is deliberately simple and self-describing
//! so the decode boundary can be tested without a dependency; it is **not** a
//! wire-compatible external protocol format and makes no compatibility claim.
//!
//! Each wire shape provides:
//!
//! - `encode(&self) -> WireFields` — serialize the (already-validated) domain
//!   value into the field-map form; and
//! - `decode(&WireFields) -> Result<Self, WireError>` — reconstruct the value
//!   from untrusted input, failing closed.
//!
//! Decoding **never panics** on malformed input (AGENTS.md Rule 5) and is
//! fail-closed (Rule 9): a missing required field yields
//! [`WireError::MissingField`]; a present-but-invalid value yields
//! [`WireError::InvalidField`] carrying a stable [`kya_core::error::ErrorCode`]
//! and the field *name* only — never the raw attacker-controlled value
//! (Rule 18). The monetary amount is parsed as an [`i128`] from a
//! decimal-integer string with no floating point anywhere (Rule 8), and the
//! transaction amount stays a `(minor_units, currency)` pair on the wire so no
//! implicit conversion or rounding can occur.
//!
//! Encoding followed by decoding round-trips: for any valid value,
//! `decode(&value.encode()) == Ok(value)`.
//!
//! ## Raw wire input is a claim, not evidence
//!
//! A [`WireMandate`] or [`WireTransactionIntent`] is **untrusted input**. It
//! carries a [`WireDelegationClaim`]'s worth of assertion and nothing more:
//! decoding it establishes neither authenticity nor trust. Decoding a
//! [`WireDelegationClaim`] yields only a raw [`WireDelegationClaim`] (mirroring
//! [`kya_core::evidence::DelegationClaim`]); it can never yield a verified
//! delegation (`kya_crypto::VerifiedDelegation`), whose only constructor runs
//! real cryptographic verification inside the reviewed crypto crate. Promotion
//! to verified evidence happens only through stage B verification against
//! configured trust anchors, exactly as in the core. The wire types preserve
//! the claim/evidence distinction rather than erasing it.
//!
//! ## Honest compatibility
//!
//! The protocol version follows semantic-versioning intent. Any
//! wire-incompatible change MUST bump the major component. The SDK makes no
//! claim of compatibility with external protocols it has not been tested
//! against.

use core::fmt;

use kya_core::error::{AsErrorCode, ErrorCode};
use kya_core::identity::{AgentId, IssuerId, MerchantId, PrincipalId, ResourceId, TrustedKeyRef};
use kya_core::money::{CurrencyCode, Money};

/// The protocol major version. Incompatible wire changes bump this.
pub const PROTOCOL_VERSION_MAJOR: u16 = 0;

/// The protocol minor version. Backwards-compatible additions bump this.
pub const PROTOCOL_VERSION_MINOR: u16 = 1;

/// The protocol version as a `"major.minor"` string.
pub const PROTOCOL_VERSION: &str = "0.1";

/// A parsed protocol version expressed as a `(major, minor)` pair.
///
/// A peer announces the protocol version it speaks; before any wire value is
/// acted upon, that announced version MUST be checked against what this build
/// of the SDK supports. The version is a security-relevant input: processing a
/// payload under an unsupported protocol version could mean interpreting fields
/// with semantics this build does not implement, so compatibility is decided
/// **fail-closed** (AGENTS.md Rule 9) by [`check_supported_version`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    /// The major component. Incompatible wire changes bump this.
    pub major: u16,
    /// The minor component. Backwards-compatible additions bump this.
    pub minor: u16,
}

impl ProtocolVersion {
    /// The protocol version this build of the SDK implements.
    pub const CURRENT: ProtocolVersion = ProtocolVersion {
        major: PROTOCOL_VERSION_MAJOR,
        minor: PROTOCOL_VERSION_MINOR,
    };

    /// Parse a `"major.minor"` string into a [`ProtocolVersion`], failing closed
    /// on anything that is not exactly two base-10 `u16` components separated by
    /// a single `.`.
    ///
    /// This never panics on untrusted input (AGENTS.md Rule 5): a missing
    /// component, extra components, a non-numeric component, leading/trailing
    /// whitespace, a sign, or an out-of-range value all yield
    /// [`VersionError::Malformed`].
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Malformed`] when `raw` is not a well-formed
    /// `"major.minor"` version string.
    pub fn parse(raw: &str) -> Result<ProtocolVersion, VersionError> {
        let mut parts = raw.split('.');
        let major_raw = parts.next().ok_or(VersionError::Malformed)?;
        let minor_raw = parts.next().ok_or(VersionError::Malformed)?;
        if parts.next().is_some() {
            // More than two components: not a "major.minor" version.
            return Err(VersionError::Malformed);
        }
        // `str::parse::<u16>` rejects empty strings, signs, whitespace, and
        // out-of-range values; it never uses floating point.
        let major = major_raw
            .parse::<u16>()
            .map_err(|_| VersionError::Malformed)?;
        let minor = minor_raw
            .parse::<u16>()
            .map_err(|_| VersionError::Malformed)?;
        Ok(ProtocolVersion { major, minor })
    }

    /// Whether this version is compatible with [`ProtocolVersion::CURRENT`].
    ///
    /// Compatibility follows semantic-versioning intent: the **major** version
    /// must match exactly (a different major is a wire-incompatible change,
    /// Rule 21), and the announced **minor** must not exceed the supported
    /// minor (a newer minor may carry additive fields this build does not
    /// understand, so it is refused rather than partially interpreted). An older
    /// or equal minor within the same major is accepted.
    pub fn is_supported(&self) -> bool {
        self.major == ProtocolVersion::CURRENT.major && self.minor <= ProtocolVersion::CURRENT.minor
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A typed error produced while checking a peer-announced protocol version.
///
/// It is `#[non_exhaustive]` so new failure kinds are an additive change
/// (Rule 21). It carries no attacker-controlled free text (Rule 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionError {
    /// The announced version string was not a well-formed `"major.minor"`
    /// value (missing or extra components, non-numeric, signed, whitespace, or
    /// out of range).
    Malformed,
    /// The announced version was well-formed but is not supported by this build
    /// of the SDK. The request fails closed rather than being processed under
    /// semantics this build does not implement.
    Unsupported {
        /// The well-formed but unsupported version that was announced.
        announced: ProtocolVersion,
    },
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionError::Malformed => f.write_str("malformed protocol version"),
            VersionError::Unsupported { announced } => write!(
                f,
                "unsupported protocol version {announced}; this build supports {}",
                ProtocolVersion::CURRENT
            ),
        }
    }
}

impl std::error::Error for VersionError {}

impl AsErrorCode for VersionError {
    fn error_code(&self) -> ErrorCode {
        match self {
            // A malformed version string is a malformed-input condition; an
            // unsupported-but-well-formed version is an unsupported value.
            VersionError::Malformed => ErrorCode::UnsupportedValue,
            VersionError::Unsupported { .. } => ErrorCode::UnsupportedValue,
        }
    }
}

/// Check a peer-announced protocol version string and accept it only if this
/// build supports it, failing closed otherwise.
///
/// This is the single entry point a decoder or adapter SHOULD call before
/// acting on any wire value: it parses `announced` and then applies
/// [`ProtocolVersion::is_supported`]. An unsupported or malformed version is
/// **rejected** (AGENTS.md Rule 9) rather than processed, because interpreting a
/// payload under a version whose semantics this build does not implement is a
/// defect, not a convenience.
///
/// # Errors
///
/// Returns [`VersionError::Malformed`] when `announced` is not a well-formed
/// `"major.minor"` string, and [`VersionError::Unsupported`] when it is
/// well-formed but outside the supported set. On success returns the parsed,
/// supported [`ProtocolVersion`].
pub fn check_supported_version(announced: &str) -> Result<ProtocolVersion, VersionError> {
    let version = ProtocolVersion::parse(announced)?;
    if version.is_supported() {
        Ok(version)
    } else {
        Err(VersionError::Unsupported { announced: version })
    }
}

/// A typed error produced while decoding untrusted wire input into a domain
/// value.
///
/// The error is deliberately low on detail: it names the offending field and
/// carries a stable, machine-readable [`ErrorCode`], but it never embeds the
/// raw attacker-controlled field *value* (AGENTS.md Rule 18). This keeps the
/// error safe to log and audit.
///
/// It is `#[non_exhaustive]` so new failure kinds are an additive change
/// (Rule 21).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// A required field was absent from the input field-map.
    MissingField {
        /// The stable name of the missing field.
        field: &'static str,
    },
    /// A required field was present but its value failed domain validation.
    ///
    /// The carried [`ErrorCode`] is the underlying domain code (for example
    /// [`ErrorCode::IdentifierMalformed`] or [`ErrorCode::MoneyNegative`]) when
    /// one is available, or [`ErrorCode::UnsupportedValue`] when the value is
    /// well-formed-looking but outside the supported set (for example a
    /// non-integer amount string).
    InvalidField {
        /// The stable name of the invalid field.
        field: &'static str,
        /// The stable code describing why the value was rejected.
        code: ErrorCode,
    },
}

impl WireError {
    /// Build an [`WireError::InvalidField`] from any domain error that can be
    /// reduced to an [`ErrorCode`] via [`AsErrorCode`].
    fn invalid<E: AsErrorCode>(field: &'static str, err: &E) -> Self {
        WireError::InvalidField {
            field,
            code: err.error_code(),
        }
    }

    /// Build an [`WireError::InvalidField`] carrying
    /// [`ErrorCode::UnsupportedValue`] for a value that is syntactically
    /// present but outside the supported set (for example a non-integer amount
    /// string).
    fn unsupported(field: &'static str) -> Self {
        WireError::InvalidField {
            field,
            code: ErrorCode::UnsupportedValue,
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Field names are compile-time constants, never attacker-controlled.
            WireError::MissingField { field } => {
                write!(f, "missing required field: {field}")
            }
            WireError::InvalidField { field, code } => {
                write!(f, "invalid field {field}: {code}")
            }
        }
    }
}

impl std::error::Error for WireError {}

impl AsErrorCode for WireError {
    fn error_code(&self) -> ErrorCode {
        match self {
            WireError::MissingField { .. } => ErrorCode::MissingField,
            // Carry the precise underlying domain code when available.
            WireError::InvalidField { code, .. } => *code,
        }
    }
}

/// An internal v0.1 **field-map** representation of a wire value.
///
/// This is an ordered list of `(key, value)` string pairs. It is a small,
/// `std`-only, self-describing form used purely as the untrusted-input boundary
/// for decoding and as the target for encoding. It is **not** a
/// wire-compatible external protocol format (no JSON, no `serde`) and makes no
/// claim of compatibility with any external protocol (AGENTS.md Rule 20). The
/// field key names are part of the v0.1 surface and are documented on each
/// wire shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireFields {
    fields: Vec<(String, String)>,
}

impl WireFields {
    /// Create an empty field-map.
    pub fn new() -> Self {
        WireFields { fields: Vec::new() }
    }

    /// Append a `(key, value)` pair. Used by encoders; later keys do not
    /// overwrite earlier ones, so encoders must not emit duplicates.
    pub fn push(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.push((key.into(), value.into()));
    }

    /// Look up the first value for `key`, if present.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Look up a required field, returning [`WireError::MissingField`] when it
    /// is absent.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::MissingField`] if `field` is not present.
    pub fn require(&self, field: &'static str) -> Result<&str, WireError> {
        self.get(field).ok_or(WireError::MissingField { field })
    }

    /// The field pairs in insertion order.
    pub fn as_pairs(&self) -> &[(String, String)] {
        &self.fields
    }
}

/// Parse a `(minor_units, currency)` amount from untrusted strings, with no
/// floating point anywhere (AGENTS.md Rule 8).
///
/// Validation follows a **deterministic order**: the currency code is validated
/// **before** the amount is parsed. When both fields are invalid, the error is
/// therefore reported against the currency field. This makes the failure
/// reported for a given malformed input stable and predictable.
///
/// Anything that is not a plain base-10 integer (a decimal point, exponent,
/// whitespace, sign noise, or overflow of [`i128`]) is rejected as
/// [`ErrorCode::UnsupportedValue`]; a negative value is left to [`Money`] to
/// reject as [`ErrorCode::MoneyNegative`].
fn decode_money(
    minor_field: &'static str,
    currency_field: &'static str,
    fields: &WireFields,
) -> Result<Money, WireError> {
    let minor_raw = fields.require(minor_field)?;
    let currency_raw = fields.require(currency_field)?;

    // Deterministic order: validate the currency code FIRST so a bad currency
    // is reported against the currency field even when the amount is also
    // invalid.
    let currency =
        CurrencyCode::new(currency_raw).map_err(|e| WireError::invalid(currency_field, &e))?;

    // Then parse the amount strictly as a base-10 i128. `str::parse` rejects
    // decimals, exponents, and out-of-range values; it never uses floating
    // point.
    let minor_units: i128 = minor_raw
        .parse::<i128>()
        .map_err(|_| WireError::unsupported(minor_field))?;

    Money::new(minor_units, currency).map_err(|e| WireError::invalid(minor_field, &e))
}

/// A wire-level representation of a delegated mandate.
///
/// This references core identity types so the wire shape and the domain cannot
/// drift apart. It is a **claim** until verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMandate {
    /// The issuer that granted the mandate.
    pub issuer: IssuerId,
    /// The principal on whose behalf authority is delegated.
    pub principal: PrincipalId,
    /// The agent the mandate was granted to.
    pub agent: AgentId,
}

impl WireMandate {
    /// Field key for the issuer identifier.
    pub const FIELD_ISSUER: &'static str = "issuer";
    /// Field key for the principal identifier.
    pub const FIELD_PRINCIPAL: &'static str = "principal";
    /// Field key for the agent identifier.
    pub const FIELD_AGENT: &'static str = "agent";

    /// Serialize this mandate into the internal v0.1 field-map form.
    pub fn encode(&self) -> WireFields {
        let mut fields = WireFields::new();
        fields.push(Self::FIELD_ISSUER, self.issuer.as_str());
        fields.push(Self::FIELD_PRINCIPAL, self.principal.as_str());
        fields.push(Self::FIELD_AGENT, self.agent.as_str());
        fields
    }

    /// Decode a mandate from untrusted field-map input, failing closed.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::MissingField`] for an absent required field and
    /// [`WireError::InvalidField`] for a present-but-invalid value. Never
    /// panics.
    pub fn decode(fields: &WireFields) -> Result<Self, WireError> {
        let issuer = IssuerId::new(fields.require(Self::FIELD_ISSUER)?)
            .map_err(|e| WireError::invalid(Self::FIELD_ISSUER, &e))?;
        let principal = PrincipalId::new(fields.require(Self::FIELD_PRINCIPAL)?)
            .map_err(|e| WireError::invalid(Self::FIELD_PRINCIPAL, &e))?;
        let agent = AgentId::new(fields.require(Self::FIELD_AGENT)?)
            .map_err(|e| WireError::invalid(Self::FIELD_AGENT, &e))?;
        Ok(WireMandate {
            issuer,
            principal,
            agent,
        })
    }
}

/// A wire-level, **unverified** delegation claim carried on the protocol.
///
/// Mirrors [`kya_core::evidence::DelegationClaim`]: it names an issuer, an
/// agent, and the key reference the signature is attributed to. It proves
/// nothing on its own, and decoding it can never yield a verified delegation
/// (`kya_crypto::VerifiedDelegation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireDelegationClaim {
    /// The issuer the agent claims delegated to it.
    pub issuer: IssuerId,
    /// The agent the claim is about.
    pub agent: AgentId,
    /// The key reference the claim says the issuer signed with.
    pub claimed_key_ref: TrustedKeyRef,
}

impl WireDelegationClaim {
    /// Field key for the issuer identifier.
    pub const FIELD_ISSUER: &'static str = "issuer";
    /// Field key for the agent identifier.
    pub const FIELD_AGENT: &'static str = "agent";
    /// Field key for the claimed key reference.
    pub const FIELD_CLAIMED_KEY_REF: &'static str = "claimed_key_ref";

    /// Serialize this claim into the internal v0.1 field-map form.
    pub fn encode(&self) -> WireFields {
        let mut fields = WireFields::new();
        fields.push(Self::FIELD_ISSUER, self.issuer.as_str());
        fields.push(Self::FIELD_AGENT, self.agent.as_str());
        fields.push(Self::FIELD_CLAIMED_KEY_REF, self.claimed_key_ref.as_str());
        fields
    }

    /// Decode a **raw** delegation claim from untrusted field-map input,
    /// failing closed.
    ///
    /// This yields only a raw claim. It performs no verification and cannot, by
    /// construction, produce a verified delegation
    /// (`kya_crypto::VerifiedDelegation`).
    ///
    /// # Errors
    ///
    /// Returns [`WireError::MissingField`] for an absent required field and
    /// [`WireError::InvalidField`] for a present-but-invalid value. Never
    /// panics.
    pub fn decode(fields: &WireFields) -> Result<Self, WireError> {
        let issuer = IssuerId::new(fields.require(Self::FIELD_ISSUER)?)
            .map_err(|e| WireError::invalid(Self::FIELD_ISSUER, &e))?;
        let agent = AgentId::new(fields.require(Self::FIELD_AGENT)?)
            .map_err(|e| WireError::invalid(Self::FIELD_AGENT, &e))?;
        let claimed_key_ref = TrustedKeyRef::new(fields.require(Self::FIELD_CLAIMED_KEY_REF)?)
            .map_err(|e| WireError::invalid(Self::FIELD_CLAIMED_KEY_REF, &e))?;
        Ok(WireDelegationClaim {
            issuer,
            agent,
            claimed_key_ref,
        })
    }
}

/// A wire-level representation of a transaction intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireTransactionIntent {
    /// The agent making the request.
    pub agent: AgentId,
    /// The counterparty merchant.
    pub merchant: MerchantId,
    /// The resource acted on.
    pub resource: ResourceId,
    /// The amount involved.
    pub amount: Money,
}

impl WireTransactionIntent {
    /// Field key for the agent identifier.
    pub const FIELD_AGENT: &'static str = "agent";
    /// Field key for the merchant identifier.
    pub const FIELD_MERCHANT: &'static str = "merchant";
    /// Field key for the resource identifier.
    pub const FIELD_RESOURCE: &'static str = "resource";
    /// Field key for the amount in minor units (a decimal-integer string).
    pub const FIELD_AMOUNT_MINOR_UNITS: &'static str = "amount_minor_units";
    /// Field key for the amount's ISO 4217 currency code.
    pub const FIELD_AMOUNT_CURRENCY: &'static str = "amount_currency";

    /// Serialize this intent into the internal v0.1 field-map form.
    ///
    /// The amount is emitted as a `(minor_units, currency)` pair so there is no
    /// implicit currency conversion or rounding on the wire (AGENTS.md Rule 8).
    pub fn encode(&self) -> WireFields {
        let mut fields = WireFields::new();
        fields.push(Self::FIELD_AGENT, self.agent.as_str());
        fields.push(Self::FIELD_MERCHANT, self.merchant.as_str());
        fields.push(Self::FIELD_RESOURCE, self.resource.as_str());
        fields.push(
            Self::FIELD_AMOUNT_MINOR_UNITS,
            self.amount.minor_units().to_string(),
        );
        fields.push(Self::FIELD_AMOUNT_CURRENCY, self.amount.currency().as_str());
        fields
    }

    /// Decode a transaction intent from untrusted field-map input, failing
    /// closed.
    ///
    /// The amount is parsed as an [`i128`] from a decimal-integer string with
    /// no floating point (AGENTS.md Rule 8); a non-integer string is rejected
    /// as [`ErrorCode::UnsupportedValue`].
    ///
    /// # Errors
    ///
    /// Returns [`WireError::MissingField`] for an absent required field and
    /// [`WireError::InvalidField`] for a present-but-invalid value. Never
    /// panics.
    pub fn decode(fields: &WireFields) -> Result<Self, WireError> {
        let agent = AgentId::new(fields.require(Self::FIELD_AGENT)?)
            .map_err(|e| WireError::invalid(Self::FIELD_AGENT, &e))?;
        let merchant = MerchantId::new(fields.require(Self::FIELD_MERCHANT)?)
            .map_err(|e| WireError::invalid(Self::FIELD_MERCHANT, &e))?;
        let resource = ResourceId::new(fields.require(Self::FIELD_RESOURCE)?)
            .map_err(|e| WireError::invalid(Self::FIELD_RESOURCE, &e))?;
        let amount = decode_money(
            Self::FIELD_AMOUNT_MINOR_UNITS,
            Self::FIELD_AMOUNT_CURRENCY,
            fields,
        )?;
        Ok(WireTransactionIntent {
            agent,
            merchant,
            resource,
            amount,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_mandate() -> WireMandate {
        WireMandate {
            issuer: IssuerId::new("issuer:acme").expect("valid"),
            principal: PrincipalId::new("principal:alice").expect("valid"),
            agent: AgentId::new("agent:1").expect("valid"),
        }
    }

    fn valid_claim() -> WireDelegationClaim {
        WireDelegationClaim {
            issuer: IssuerId::new("issuer:acme").expect("valid"),
            agent: AgentId::new("agent:1").expect("valid"),
            claimed_key_ref: TrustedKeyRef::new("kid:1").expect("valid"),
        }
    }

    fn valid_intent() -> WireTransactionIntent {
        WireTransactionIntent {
            agent: AgentId::new("agent:1").expect("valid"),
            merchant: MerchantId::new("merchant:store").expect("valid"),
            resource: ResourceId::new("order:42").expect("valid"),
            amount: Money::from_code(100, "USD").expect("valid"),
        }
    }

    #[test]
    fn protocol_version_is_expected() {
        assert_eq!(PROTOCOL_VERSION_MAJOR, 0);
        assert_eq!(PROTOCOL_VERSION_MINOR, 1);
        assert_eq!(PROTOCOL_VERSION, "0.1");
    }

    // ---- (14) protocol-version compatibility, fail-closed --------------

    #[test]
    fn current_version_string_is_supported() {
        // The version this build advertises must round-trip through the check.
        let v = check_supported_version(PROTOCOL_VERSION).expect("current is supported");
        assert_eq!(v, ProtocolVersion::CURRENT);
        assert_eq!(v, ProtocolVersion { major: 0, minor: 1 });
    }

    #[test]
    fn older_minor_within_same_major_is_supported() {
        // 0.0 is an older minor within the same major: accepted.
        let v = check_supported_version("0.0").expect("older minor supported");
        assert_eq!(v, ProtocolVersion { major: 0, minor: 0 });
        assert!(v.is_supported());
    }

    #[test]
    fn unsupported_major_is_rejected_fail_closed() {
        // A different (newer) MAJOR is a wire-incompatible change and must be
        // rejected rather than processed under this build's semantics.
        let err = check_supported_version("1.0").expect_err("different major rejected");
        assert_eq!(
            err,
            VersionError::Unsupported {
                announced: ProtocolVersion { major: 1, minor: 0 }
            }
        );
        assert_eq!(err.error_code(), ErrorCode::UnsupportedValue);
    }

    #[test]
    fn newer_minor_is_rejected_fail_closed() {
        // A newer MINOR within the same major may carry additive fields this
        // build does not understand; it is refused, not partially interpreted.
        let err = check_supported_version("0.2").expect_err("newer minor rejected");
        assert_eq!(
            err,
            VersionError::Unsupported {
                announced: ProtocolVersion { major: 0, minor: 2 }
            }
        );
    }

    #[test]
    fn malformed_version_strings_fail_closed_without_panic() {
        for bad in [
            "", "0", "0.", ".1", "0.1.2", "x.y", "0.y", "-1.0", "0.-1", " 0.1", "0.1 ", "0,1",
            "00.1e0", "65536.0", "0.70000",
        ] {
            let err = check_supported_version(bad).expect_err("malformed rejected");
            assert_eq!(
                err,
                VersionError::Malformed,
                "input {bad:?} should be Malformed"
            );
            assert_eq!(err.error_code(), ErrorCode::UnsupportedValue);
        }
    }

    #[test]
    fn version_display_round_trips_through_parse() {
        let v = ProtocolVersion {
            major: 3,
            minor: 14,
        };
        assert_eq!(v.to_string(), "3.14");
        assert_eq!(ProtocolVersion::parse("3.14"), Ok(v));
    }

    #[test]
    fn wire_shapes_reference_core_types() {
        let m = valid_mandate();
        assert_eq!(m.issuer.as_str(), "issuer:acme");

        let intent = valid_intent();
        assert_eq!(intent.merchant.as_str(), "merchant:store");

        let claim = valid_claim();
        assert_eq!(claim.claimed_key_ref.as_str(), "kid:1");
    }

    // ---- (1) serialization round-trip ----------------------------------

    #[test]
    fn mandate_round_trips() {
        let m = valid_mandate();
        assert_eq!(WireMandate::decode(&m.encode()), Ok(m));
    }

    #[test]
    fn claim_round_trips() {
        let c = valid_claim();
        assert_eq!(WireDelegationClaim::decode(&c.encode()), Ok(c));
    }

    #[test]
    fn intent_round_trips() {
        let i = valid_intent();
        let decoded = WireTransactionIntent::decode(&i.encode()).expect("round-trips");
        assert_eq!(decoded, i);
        // Amount preserved exactly, as a (minor_units, currency) pair.
        assert_eq!(decoded.amount.minor_units(), 100);
        assert_eq!(decoded.amount.currency().as_str(), "USD");
    }

    #[test]
    fn intent_round_trips_at_amount_boundaries() {
        for minor in [0i128, 1, i128::MAX] {
            let i = WireTransactionIntent {
                agent: AgentId::new("agent:1").expect("valid"),
                merchant: MerchantId::new("merchant:store").expect("valid"),
                resource: ResourceId::new("order:42").expect("valid"),
                amount: Money::from_code(minor, "USD").expect("valid"),
            };
            let decoded = WireTransactionIntent::decode(&i.encode()).expect("round-trips");
            assert_eq!(decoded.amount.minor_units(), minor);
        }
    }

    // ---- (2) missing fields --------------------------------------------

    /// Drop one field from an encoded field-map and return the rest.
    fn without(fields: &WireFields, drop: &str) -> WireFields {
        let mut out = WireFields::new();
        for (k, v) in fields.as_pairs() {
            if k != drop {
                out.push(k.clone(), v.clone());
            }
        }
        out
    }

    #[test]
    fn mandate_missing_each_field() {
        let encoded = valid_mandate().encode();
        for field in [
            WireMandate::FIELD_ISSUER,
            WireMandate::FIELD_PRINCIPAL,
            WireMandate::FIELD_AGENT,
        ] {
            let err = WireMandate::decode(&without(&encoded, field)).expect_err("missing");
            assert_eq!(err, WireError::MissingField { field });
            assert_eq!(err.error_code(), ErrorCode::MissingField);
        }
    }

    #[test]
    fn claim_missing_each_field() {
        let encoded = valid_claim().encode();
        for field in [
            WireDelegationClaim::FIELD_ISSUER,
            WireDelegationClaim::FIELD_AGENT,
            WireDelegationClaim::FIELD_CLAIMED_KEY_REF,
        ] {
            let err = WireDelegationClaim::decode(&without(&encoded, field)).expect_err("missing");
            assert_eq!(err, WireError::MissingField { field });
            assert_eq!(err.error_code(), ErrorCode::MissingField);
        }
    }

    #[test]
    fn intent_missing_each_field() {
        let encoded = valid_intent().encode();
        for field in [
            WireTransactionIntent::FIELD_AGENT,
            WireTransactionIntent::FIELD_MERCHANT,
            WireTransactionIntent::FIELD_RESOURCE,
            WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
            WireTransactionIntent::FIELD_AMOUNT_CURRENCY,
        ] {
            let err =
                WireTransactionIntent::decode(&without(&encoded, field)).expect_err("missing");
            assert_eq!(err, WireError::MissingField { field });
            assert_eq!(err.error_code(), ErrorCode::MissingField);
        }
    }

    // ---- (3) invalid external input ------------------------------------

    /// Replace one field's value in an encoded field-map.
    fn with_value(fields: &WireFields, key: &str, value: &str) -> WireFields {
        let mut out = WireFields::new();
        for (k, v) in fields.as_pairs() {
            if k == key {
                out.push(k.clone(), value.to_string());
            } else {
                out.push(k.clone(), v.clone());
            }
        }
        out
    }

    #[test]
    fn invalid_identifier_control_char() {
        let fields = with_value(
            &valid_mandate().encode(),
            WireMandate::FIELD_ISSUER,
            "bad\x00id",
        );
        let err = WireMandate::decode(&fields).expect_err("malformed");
        assert_eq!(
            err,
            WireError::InvalidField {
                field: WireMandate::FIELD_ISSUER,
                code: ErrorCode::IdentifierMalformed,
            }
        );
        assert_eq!(err.error_code(), ErrorCode::IdentifierMalformed);
    }

    #[test]
    fn invalid_identifier_empty() {
        let fields = with_value(&valid_mandate().encode(), WireMandate::FIELD_AGENT, "   ");
        let err = WireMandate::decode(&fields).expect_err("empty");
        assert_eq!(err.error_code(), ErrorCode::IdentifierEmpty);
    }

    #[test]
    fn invalid_identifier_too_long() {
        let huge = "a".repeat(10_000);
        let fields = with_value(
            &valid_mandate().encode(),
            WireMandate::FIELD_PRINCIPAL,
            &huge,
        );
        let err = WireMandate::decode(&fields).expect_err("too long");
        assert_eq!(err.error_code(), ErrorCode::IdentifierTooLong);
    }

    #[test]
    fn invalid_currency_wrong_length() {
        let fields = with_value(
            &valid_intent().encode(),
            WireTransactionIntent::FIELD_AMOUNT_CURRENCY,
            "US",
        );
        let err = WireTransactionIntent::decode(&fields).expect_err("bad currency");
        assert_eq!(
            err,
            WireError::InvalidField {
                field: WireTransactionIntent::FIELD_AMOUNT_CURRENCY,
                code: ErrorCode::CurrencyWrongLength,
            }
        );
    }

    #[test]
    fn invalid_currency_lowercase() {
        let fields = with_value(
            &valid_intent().encode(),
            WireTransactionIntent::FIELD_AMOUNT_CURRENCY,
            "usd",
        );
        let err = WireTransactionIntent::decode(&fields).expect_err("lowercase");
        assert_eq!(err.error_code(), ErrorCode::CurrencyNotUppercaseAscii);
    }

    #[test]
    fn invalid_amount_negative() {
        let fields = with_value(
            &valid_intent().encode(),
            WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
            "-1",
        );
        let err = WireTransactionIntent::decode(&fields).expect_err("negative");
        assert_eq!(
            err,
            WireError::InvalidField {
                field: WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
                code: ErrorCode::MoneyNegative,
            }
        );
    }

    #[test]
    fn decode_money_validates_currency_before_amount() {
        // Deterministic order: when BOTH the currency and the amount are
        // invalid, the currency-field error is returned, proving currency is
        // validated before the amount is parsed.
        let mut fields = valid_intent().encode();
        fields = with_value(&fields, WireTransactionIntent::FIELD_AMOUNT_CURRENCY, "usd");
        fields = with_value(
            &fields,
            WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
            "not-an-integer",
        );
        let err = WireTransactionIntent::decode(&fields).expect_err("both invalid");
        assert_eq!(
            err,
            WireError::InvalidField {
                field: WireTransactionIntent::FIELD_AMOUNT_CURRENCY,
                code: ErrorCode::CurrencyNotUppercaseAscii,
            },
            "currency must be validated before amount"
        );
    }

    // ---- (4) unsupported values ----------------------------------------

    #[test]
    fn unsupported_amount_non_integer() {
        // Well-formed-looking but outside the allowed set: not a base-10 integer.
        for bad in ["12.5", "1e3", "0x10", "abc", " 10", "10 ", "1,0", ""] {
            let fields = with_value(
                &valid_intent().encode(),
                WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
                bad,
            );
            let err = WireTransactionIntent::decode(&fields).expect_err("non-integer");
            assert_eq!(
                err,
                WireError::InvalidField {
                    field: WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
                    code: ErrorCode::UnsupportedValue,
                },
                "input {bad:?} should be UnsupportedValue"
            );
            assert_eq!(err.error_code(), ErrorCode::UnsupportedValue);
        }
    }

    #[test]
    fn unsupported_amount_overflow() {
        // Larger than i128::MAX: a garbage/overflowing amount string.
        let overflow = "170141183460469231731687303715884105728"; // i128::MAX + 1
        let fields = with_value(
            &valid_intent().encode(),
            WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS,
            overflow,
        );
        let err = WireTransactionIntent::decode(&fields).expect_err("overflow");
        assert_eq!(err.error_code(), ErrorCode::UnsupportedValue);
    }

    // ---- claim/evidence distinction ------------------------------------

    #[test]
    fn claim_decode_yields_raw_claim_not_verified() {
        // Decoding yields a raw WireDelegationClaim; it can be mapped to a
        // kya_core raw DelegationClaim. There is deliberately no path from here
        // to a VerifiedDelegation: `VerifiedDelegation::establish` is the only
        // constructor and it requires a verification outcome + trust anchors.
        let c = valid_claim();
        let decoded = WireDelegationClaim::decode(&c.encode()).expect("round-trips");
        let raw: kya_core::evidence::DelegationClaim = kya_core::evidence::DelegationClaim::new(
            decoded.issuer.clone(),
            decoded.agent.clone(),
            decoded.claimed_key_ref.clone(),
        );
        assert_eq!(raw.issuer(), &decoded.issuer);
        assert_eq!(raw.agent(), &decoded.agent);
        assert_eq!(raw.claimed_key_ref(), &decoded.claimed_key_ref);
        // The following would NOT compile, proving the distinction holds:
        //   let _: kya_crypto::VerifiedDelegation = decoded.into();
    }

    // ---- (5) decode never panics over adversarial input ----------------

    #[test]
    fn decode_never_panics_on_adversarial_input() {
        let mut adversarial: Vec<String> = ["", " ", "\x00", "\n", "\t", "-", "+", "--1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        adversarial.push("9".repeat(400));

        for a in &adversarial {
            for b in &adversarial {
                for c in &adversarial {
                    let mut fields = WireFields::new();
                    fields.push(WireMandate::FIELD_ISSUER, a.clone());
                    fields.push(WireMandate::FIELD_PRINCIPAL, b.clone());
                    fields.push(WireMandate::FIELD_AGENT, c.clone());
                    // Must return a Result, never panic.
                    let _ = WireMandate::decode(&fields);

                    let mut ifields = WireFields::new();
                    ifields.push(WireTransactionIntent::FIELD_AGENT, a.clone());
                    ifields.push(WireTransactionIntent::FIELD_MERCHANT, b.clone());
                    ifields.push(WireTransactionIntent::FIELD_RESOURCE, c.clone());
                    ifields.push(WireTransactionIntent::FIELD_AMOUNT_MINOR_UNITS, a.clone());
                    ifields.push(WireTransactionIntent::FIELD_AMOUNT_CURRENCY, b.clone());
                    let _ = WireTransactionIntent::decode(&ifields);
                }
            }
        }
    }

    #[test]
    fn wire_error_display_hides_values() {
        // Display names fields and codes, never raw values.
        let e = WireError::InvalidField {
            field: "amount_minor_units",
            code: ErrorCode::UnsupportedValue,
        };
        let s = e.to_string();
        assert!(s.contains("amount_minor_units"));
        assert!(s.contains("unsupported-value"));

        let m = WireError::MissingField { field: "issuer" };
        assert!(m.to_string().contains("issuer"));
    }

    #[test]
    fn empty_fields_lookup_returns_none() {
        let empty = WireFields::new();
        assert_eq!(empty.get("anything"), None);
        assert_eq!(
            empty.require("issuer"),
            Err(WireError::MissingField { field: "issuer" })
        );
    }
}
