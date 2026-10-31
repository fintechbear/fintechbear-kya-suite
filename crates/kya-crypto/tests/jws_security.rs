//! Algorithm-confusion and encoding security tests for the compact-JWS verifier
//! ([`kya_crypto::JwsEdDsa`]).
//!
//! These assert the SPECIFIC [`CryptoVerificationError`] variant for each
//! adversarial token: `alg: none`, swapped/symmetric algorithms, invalid
//! base64url, invalid UTF-8 / JSON headers, truncation, and oversized input.
//! `none` is never treated as a pass, and no malformed token ever panics.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_crypto::{CryptoVerificationError, JwsEdDsa};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Minimal unpadded base64url encoder for building adversarial test tokens.
fn b64url(data: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[(n >> 18 & 63) as usize] as char);
        out.push(ALPHA[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHA[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHA[(n & 63) as usize] as char);
        }
    }
    out
}

/// Build a genuinely-signed compact JWS with the given header/payload JSON.
fn token(sk: &SigningKey, header_json: &str, payload_json: &str) -> String {
    let h = b64url(header_json.as_bytes());
    let p = b64url(payload_json.as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = sk.sign(signing_input.as_bytes());
    let s = b64url(&sig.to_bytes());
    format!("{h}.{p}.{s}")
}

#[test]
fn genuine_eddsa_jws_verifies() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"agent"}"#);
    let payload = JwsEdDsa::new()
        .verify(t.as_bytes(), vk.as_bytes())
        .expect("genuine EdDSA JWS verifies");
    assert_eq!(payload, br#"{"sub":"agent"}"#);
}

#[test]
fn alg_none_is_never_a_pass() {
    // Even if a well-formed token claims `alg:none`, it must be rejected as
    // UnsupportedAlgorithm, never treated as "no signature required".
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"alg":"none"}"#, r#"{"sub":"agent"}"#);
    assert_eq!(
        JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::UnsupportedAlgorithm)
    );
}

#[test]
fn swapped_and_symmetric_algorithms_rejected() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    for alg in [
        "HS256", "HS512", "RS256", "ES256", "PS256", "", "eddsa", "ED25519",
    ] {
        let header = format!(r#"{{"alg":"{alg}"}}"#);
        let t = token(&sk, &header, r#"{"sub":"a"}"#);
        assert_eq!(
            JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::UnsupportedAlgorithm),
            "alg {alg:?} must be rejected as unsupported"
        );
    }
}

#[test]
fn tampered_jws_payload_is_signature_invalid() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    let mut parts: Vec<&str> = t.split('.').collect();
    let tampered = b64url(br#"{"sub":"evil"}"#);
    parts[1] = &tampered;
    let forged = parts.join(".");
    assert_eq!(
        JwsEdDsa::new().verify(forged.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::SignatureInvalid)
    );
}

#[test]
fn invalid_base64url_segment_is_malformed() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    let parts: Vec<&str> = t.split('.').collect();
    // Replace the header with standard-alphabet / padded base64 (invalid url64).
    let bad_header = "a+b/c=";
    let forged = format!("{}.{}.{}", bad_header, parts[1], parts[2]);
    assert_eq!(
        JwsEdDsa::new().verify(forged.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
}

#[test]
fn invalid_utf8_header_is_malformed() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    // Header bytes that decode to invalid UTF-8 (0xFF 0xFE).
    let bad_header = b64url(&[0xFF, 0xFE]);
    let payload = b64url(br#"{"sub":"a"}"#);
    let sig = b64url(&[0u8; 64]);
    let forged = format!("{bad_header}.{payload}.{sig}");
    assert_eq!(
        JwsEdDsa::new().verify(forged.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
}

#[test]
fn invalid_json_header_is_malformed() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    // Valid UTF-8, valid base64url, but not a JSON object naming `alg`.
    let t = token(&sk, "not-json-at-all", r#"{"sub":"a"}"#);
    assert_eq!(
        JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
}

#[test]
fn wrong_segment_count_is_malformed_no_panic() {
    let vk = signing_key(5).verifying_key();
    for bad in ["onlyone", "two.parts", "a.b.c.d", "...", ""] {
        assert_eq!(
            JwsEdDsa::new().verify(bad.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::MalformedPayload),
            "token {bad:?} must be MalformedPayload"
        );
    }
}

#[test]
fn truncated_jws_is_structured_error_no_panic() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    // Lop off the final third of the token (signature region). Depending on
    // where the cut lands this is either a malformed/short signature or a
    // segment-count error, but it is always a structured error and never a
    // panic, and never Verified.
    let cut = &t[..t.len() * 2 / 3];
    let result = JwsEdDsa::new().verify(cut.as_bytes(), vk.as_bytes());
    assert!(
        matches!(
            result,
            Err(CryptoVerificationError::MalformedPayload)
                | Err(CryptoVerificationError::MalformedSignature)
                | Err(CryptoVerificationError::SignatureInvalid)
        ),
        "truncated token must be a structured error, got {result:?}"
    );
}

#[test]
fn signature_wrong_length_in_jws_is_malformed_signature() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let h = b64url(br#"{"alg":"EdDSA"}"#);
    let p = b64url(br#"{"sub":"a"}"#);
    // A valid base64url segment that decodes to fewer than 64 bytes.
    let short_sig = b64url(&[0u8; 10]);
    let forged = format!("{h}.{p}.{short_sig}");
    assert_eq!(
        JwsEdDsa::new().verify(forged.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedSignature)
    );
}

#[test]
fn oversized_jws_is_oversized_input() {
    let vk = signing_key(5).verifying_key();
    let big = vec![b'a'; 64 * 1024 + 1];
    assert_eq!(
        JwsEdDsa::new().verify(&big, vk.as_bytes()),
        Err(CryptoVerificationError::OversizedInput)
    );
}

#[test]
fn malformed_key_length_surfaces_as_malformed_key() {
    // A genuine token verified against a wrong-length key must report
    // MalformedKey, not a panic and not Verified.
    let sk = signing_key(5);
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    assert_eq!(
        JwsEdDsa::new().verify(t.as_bytes(), &[0u8; 31]),
        Err(CryptoVerificationError::MalformedKey)
    );
}

#[test]
fn duplicate_alg_member_is_rejected_not_first_match() {
    // RFC 7515/8259 require unique member names. A header carrying two `alg`
    // members (EdDSA then none) must be rejected as ambiguous rather than
    // silently accepting the first — otherwise a lenient downstream consumer
    // could honor the smuggled trailing `alg:none`.
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"alg":"EdDSA","alg":"none"}"#, r#"{"sub":"a"}"#);
    assert_eq!(
        JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
    // Reversed order is equally rejected: the ambiguity itself is the defect.
    let t2 = token(&sk, r#"{"alg":"none","alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    assert_eq!(
        JwsEdDsa::new().verify(t2.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
}

#[test]
fn unsupported_crit_header_is_rejected() {
    // RFC 7515 §4.1.11: a `crit` member names extensions the recipient MUST
    // understand or else reject the JWS. This verifier understands none, so any
    // present `crit` must fail closed even when `alg` is the accepted EdDSA and
    // the signature is otherwise genuine.
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    for crit in [
        r#"{"alg":"EdDSA","crit":["b64"]}"#,
        r#"{"alg":"EdDSA","crit":["exp","custom"]}"#,
        r#"{"crit":["x"],"alg":"EdDSA"}"#,
    ] {
        let t = token(&sk, crit, r#"{"sub":"a"}"#);
        assert_eq!(
            JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::UnsupportedAlgorithm),
            "crit header {crit:?} must be rejected"
        );
    }
}

#[test]
fn alg_substring_inside_a_value_is_not_treated_as_the_key() {
    // A value string that merely contains the text `"alg":"none"` must not be
    // mistaken for a second algorithm member; the single real `alg` key is
    // EdDSA, so a genuine token still verifies.
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(
        &sk,
        r#"{"kid":"has \"alg\":\"none\" inside","alg":"EdDSA"}"#,
        r#"{"sub":"a"}"#,
    );
    let payload = JwsEdDsa::new()
        .verify(t.as_bytes(), vk.as_bytes())
        .expect("single genuine alg key, value substring ignored");
    assert_eq!(payload, br#"{"sub":"a"}"#);
}
