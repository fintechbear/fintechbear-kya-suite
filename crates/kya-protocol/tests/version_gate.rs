//! Integration tests for the fail-closed protocol-version gate (STEP 6
//! scenario 14, "unsupported protocol version").
//!
//! A peer announces the protocol version it speaks. Before any wire value is
//! interpreted, that announced version MUST be checked: a payload carried under
//! a protocol version whose semantics this build does not implement must be
//! **rejected fail-closed** (AGENTS.md Rule 9), never processed. These tests
//! exercise [`kya_protocol::check_supported_version`] as the gate a decoder or
//! adapter runs *before* decoding, from the external-crate perspective.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use kya_core::error::{AsErrorCode, ErrorCode};
use kya_core::identity::{AgentId, IssuerId, PrincipalId};
use kya_protocol::{
    check_supported_version, ProtocolVersion, VersionError, WireFields, WireMandate,
    PROTOCOL_VERSION,
};

/// A field-map that also announces the protocol version under a reserved key,
/// mirroring how a real transport would carry the version alongside the body.
fn envelope(version: &str) -> WireFields {
    let mandate = WireMandate {
        issuer: IssuerId::new("issuer:acme").expect("valid"),
        principal: PrincipalId::new("principal:alice").expect("valid"),
        agent: AgentId::new("agent:1").expect("valid"),
    };
    let mut fields = mandate.encode();
    fields.push("protocol_version", version.to_string());
    fields
}

/// Decode a mandate only after the announced version passes the gate. This is
/// the fail-closed ordering a transport integration must follow: check the
/// version first, decode second.
fn decode_if_supported(fields: &WireFields) -> Result<WireMandate, VersionError> {
    let announced = fields.get("protocol_version").unwrap_or("");
    // Gate FIRST: an unsupported/malformed version short-circuits before the
    // body is ever interpreted.
    check_supported_version(announced)?;
    // Only a supported version reaches the decode step.
    Ok(WireMandate::decode(fields).expect("body is well-formed in this fixture"))
}

#[test]
fn supported_version_is_processed() {
    let fields = envelope(PROTOCOL_VERSION);
    let mandate = decode_if_supported(&fields).expect("current version processes");
    assert_eq!(mandate.issuer.as_str(), "issuer:acme");
}

#[test]
fn unsupported_major_is_rejected_before_decoding() {
    // A payload claiming a future, wire-incompatible major is refused outright.
    let fields = envelope("1.0");
    let err = decode_if_supported(&fields).expect_err("unsupported major rejected");
    assert_eq!(
        err,
        VersionError::Unsupported {
            announced: ProtocolVersion { major: 1, minor: 0 }
        }
    );
    assert_eq!(err.error_code(), ErrorCode::UnsupportedValue);
}

#[test]
fn newer_minor_is_rejected_before_decoding() {
    let fields = envelope("0.2");
    let err = decode_if_supported(&fields).expect_err("newer minor rejected");
    assert_eq!(
        err,
        VersionError::Unsupported {
            announced: ProtocolVersion { major: 0, minor: 2 }
        }
    );
}

#[test]
fn absent_or_malformed_version_fails_closed() {
    // No version announced at all, and a garbage version, both fail closed.
    for bad in ["", "garbage", "0", "0.1.0"] {
        let fields = envelope(bad);
        let err = decode_if_supported(&fields).expect_err("malformed rejected");
        assert_eq!(err, VersionError::Malformed, "input {bad:?}");
    }
}
