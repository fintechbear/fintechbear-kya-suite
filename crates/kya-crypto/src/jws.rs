//! JWS compact-serialization verification restricted to EdDSA.
//!
//! This module parses the JWS compact form
//! `BASE64URL(header) || "." || BASE64URL(payload) || "." || BASE64URL(sig)`
//! (RFC 7515 §3.1/§7.1) and verifies the Ed25519 signature over the **exact**
//! signing input `ASCII(BASE64URL(header) + "." + BASE64URL(payload))`
//! (RFC 7515 §5.1). It is deliberately **not** a general JWT/JOSE framework:
//! only an `EdDSA` `alg` is accepted and `alg: none` is rejected, so the
//! algorithm-confusion and `alg: none` downgrade attacks are structurally
//! impossible here.
//!
//! The decoded payload bytes are returned to the caller for its own claim
//! parsing; this module only establishes authenticity over the exact signing
//! input and the algorithm allowlist.

use kya_core::verification::{SignatureVerifier, VerificationStatus};

use crate::b64url;
use crate::error::CryptoVerificationError;
use crate::verifier::{Ed25519SignatureVerifier, ACCEPTED_ALGORITHM};

/// Maximum accepted size, in bytes, of a compact JWS token. Bounds untrusted
/// input so an oversized token is rejected before any allocation-heavy work.
const MAX_JWS_LEN: usize = 64 * 1024;

/// A verifier for JWS compact-form tokens using the Ed25519 (`EdDSA`)
/// algorithm only.
///
/// Holds no state; the public key bytes are supplied per call (resolved by the
/// caller from a trusted key store).
#[derive(Debug, Clone, Copy, Default)]
pub struct JwsEdDsa;

impl JwsEdDsa {
    /// Construct the JWS-EdDSA verifier.
    pub fn new() -> Self {
        JwsEdDsa
    }

    /// Verify a compact JWS token against `public_key` and return the decoded
    /// payload bytes on success.
    ///
    /// Steps, in order and all fail-closed:
    /// 1. bound the token size ([`CryptoVerificationError::OversizedInput`]);
    /// 2. split into exactly three dot-separated segments
    ///    ([`CryptoVerificationError::MalformedPayload`] otherwise);
    /// 3. base64url-decode the protected header and confirm its `alg` is
    ///    exactly `EdDSA` ([`CryptoVerificationError::UnsupportedAlgorithm`] for
    ///    `none`, HMAC, RSA, ECDSA, missing, or anything else);
    /// 4. base64url-decode the signature (must be 64 bytes) and the payload;
    /// 5. verify the Ed25519 signature over the exact ASCII signing input
    ///    `header_b64 + "." + payload_b64`.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoVerificationError`] for any malformed, oversized, or
    /// non-verifying token. Never panics on untrusted input.
    pub fn verify(
        &self,
        token: &[u8],
        public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoVerificationError> {
        if token.len() > MAX_JWS_LEN {
            return Err(CryptoVerificationError::OversizedInput);
        }

        // Exactly three segments; reject extra dots or missing segments.
        let mut parts = token.split(|&b| b == b'.');
        let header_b64 = parts
            .next()
            .ok_or(CryptoVerificationError::MalformedPayload)?;
        let payload_b64 = parts
            .next()
            .ok_or(CryptoVerificationError::MalformedPayload)?;
        let sig_b64 = parts
            .next()
            .ok_or(CryptoVerificationError::MalformedPayload)?;
        if parts.next().is_some() {
            return Err(CryptoVerificationError::MalformedPayload);
        }
        if header_b64.is_empty() || payload_b64.is_empty() || sig_b64.is_empty() {
            return Err(CryptoVerificationError::MalformedPayload);
        }

        // Header: decode and enforce the algorithm allowlist.
        let header = b64url::decode(header_b64).ok_or(CryptoVerificationError::MalformedPayload)?;
        let alg = extract_alg(&header)?.ok_or(CryptoVerificationError::MalformedPayload)?;
        if alg != ACCEPTED_ALGORITHM {
            // Covers "none", "HS256", "RS256", "ES256", "", and any other id.
            return Err(CryptoVerificationError::UnsupportedAlgorithm);
        }
        // RFC 7515 §4.1.11: if a `crit` (critical) header is present, every
        // listed member must be understood and processed. This verifier
        // understands no extensions, so any present `crit` member means the
        // token relies on semantics we cannot honor — fail closed rather than
        // ignore it.
        reject_unsupported_crit(&header)?;

        // Signature and payload bytes.
        let signature =
            b64url::decode(sig_b64).ok_or(CryptoVerificationError::MalformedSignature)?;
        let payload =
            b64url::decode(payload_b64).ok_or(CryptoVerificationError::MalformedPayload)?;

        // The exact RFC 7515 signing input: ASCII(header_b64 + "." + payload_b64).
        let mut signing_input = Vec::with_capacity(header_b64.len() + 1 + payload_b64.len());
        signing_input.extend_from_slice(header_b64);
        signing_input.push(b'.');
        signing_input.extend_from_slice(payload_b64);

        let verifier = Ed25519SignatureVerifier::new();
        if verifier.verify(public_key, &signing_input, &signature)? == VerificationStatus::Verified
        {
            Ok(payload)
        } else {
            Err(CryptoVerificationError::SignatureInvalid)
        }
    }
}

/// Extract the string value of the top-level `"alg"` member from a JWS
/// protected header, without pulling in a JSON framework.
///
/// This is a minimal, strict, non-panicking scanner tailored to the one field
/// the allowlist needs. It accepts a flat JSON object whose `alg` value is a
/// plain ASCII string with no escape sequences (the registered JOSE `alg`
/// values are plain ASCII). Any structural oddity, an escaped or non-ASCII
/// value, or a missing key yields `Ok(None)` (the caller maps that to a typed
/// error). It never indexes out of bounds and never panics.
///
/// # Duplicate members
///
/// RFC 7515 §4 / RFC 8259 require member names in a JOSE header to be unique. A
/// duplicate `"alg"` is an **algorithm-smuggling** vector: a strict allowlist
/// scanner that took the first match could accept `EdDSA` while a lenient
/// consumer downstream honored a trailing `alg:none`. This function therefore
/// returns [`CryptoVerificationError::MalformedPayload`] if more than one
/// top-level `"alg"` key string is present, rather than silently taking the
/// first.
fn extract_alg(header: &[u8]) -> Result<Option<String>, CryptoVerificationError> {
    // Must be valid UTF-8 JSON-ish text to begin with.
    let text = match core::str::from_utf8(header) {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };

    let occurrences = find_string_key_positions(text.as_bytes(), b"\"alg\"");
    // Duplicate `alg` members are rejected outright (smuggling defense).
    if occurrences.len() > 1 {
        return Err(CryptoVerificationError::MalformedPayload);
    }
    let Some(&key_end) = occurrences.first() else {
        return Ok(None);
    };
    Ok(read_string_value_at(text, key_end))
}

/// Reject a JWS whose protected header carries a `crit` (critical) member.
///
/// Per RFC 7515 §4.1.11, every name listed in `crit` is an extension the
/// recipient MUST understand and process, or else reject the JWS. This verifier
/// implements no header extensions, so the only safe handling of a present
/// `crit` is to fail closed. A duplicate `crit` is likewise rejected. The value
/// shape is not otherwise parsed: its mere presence is disqualifying.
///
/// # Errors
///
/// Returns [`CryptoVerificationError::UnsupportedAlgorithm`] if a `crit` member
/// is present (it names an unsupported critical extension), or
/// [`CryptoVerificationError::MalformedPayload`] if the header is not valid
/// UTF-8.
fn reject_unsupported_crit(header: &[u8]) -> Result<(), CryptoVerificationError> {
    let text =
        core::str::from_utf8(header).map_err(|_| CryptoVerificationError::MalformedPayload)?;
    if find_string_key_positions(text.as_bytes(), b"\"crit\"").is_empty() {
        Ok(())
    } else {
        Err(CryptoVerificationError::UnsupportedAlgorithm)
    }
}

/// Return the end index (just past the closing quote of the key token) of every
/// occurrence of `needle` that appears as a JSON string **key**, i.e.
/// immediately followed (after optional whitespace) by a `:`.
///
/// This deliberately ignores matches of the token inside string *values* by
/// requiring the `:` separator, and it skips over the contents of any quoted
/// string so a needle appearing inside a value string is not miscounted. It
/// never panics and performs no unchecked indexing.
fn find_string_key_positions(bytes: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut positions = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        // Skip over any quoted string wholesale so a needle inside a value is
        // never treated as a key. We detect key tokens explicitly below.
        if c == b'"' {
            // Does a key token start here?
            if i + needle.len() <= bytes.len() && &bytes[i..i + needle.len()] == needle {
                let after_key = i + needle.len();
                let j = skip_ws(bytes, after_key);
                if bytes.get(j) == Some(&b':') {
                    positions.push(after_key);
                    i = after_key;
                    continue;
                }
            }
            // Otherwise, advance past this whole string (respecting escapes) so
            // its contents cannot be rescanned as keys.
            i = skip_string(bytes, i);
            continue;
        }
        i += 1;
    }
    positions
}

/// Given an index just past a `"key"` token, read a plain ASCII JSON string
/// value (after `:` and optional whitespace). Returns `None` for any structural
/// oddity, escape sequence, or control byte. Never panics.
fn read_string_value_at(text: &str, key_end: usize) -> Option<String> {
    let bytes = text.as_bytes();
    let mut j = skip_ws(bytes, key_end);
    if bytes.get(j) != Some(&b':') {
        return None;
    }
    j += 1;
    j = skip_ws(bytes, j);
    if bytes.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    let start = j;
    while j < bytes.len() {
        let c = bytes[j];
        if c == b'"' {
            return Some(text[start..j].to_owned());
        }
        if c == b'\\' || c.is_ascii_control() {
            return None;
        }
        j += 1;
    }
    None
}

/// Advance past a JSON string that starts at `open` (the opening quote),
/// returning the index just past its closing quote. Honors backslash escapes so
/// an escaped quote does not end the string early. If the string is
/// unterminated, returns `bytes.len()`. Never panics.
fn skip_string(bytes: &[u8], open: usize) -> usize {
    let mut j = open + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2, // skip the escaped byte
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    bytes.len()
}

/// Skip ASCII whitespace starting at `from`, returning the next index.
fn skip_ws(bytes: &[u8], from: usize) -> usize {
    let mut j = from;
    while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() {
        j += 1;
    }
    j
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Minimal unpadded base64url encoder for building test tokens.
    fn b64url_encode(data: &[u8]) -> String {
        const ALPHA: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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

    fn make_token(sk: &SigningKey, header_json: &str, payload_json: &str) -> String {
        let h = b64url_encode(header_json.as_bytes());
        let p = b64url_encode(payload_json.as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig = sk.sign(signing_input.as_bytes());
        let s = b64url_encode(&sig.to_bytes());
        format!("{h}.{p}.{s}")
    }

    #[test]
    fn verifies_a_genuine_eddsa_jws() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let token = make_token(&sk, r#"{"alg":"EdDSA","typ":"JWT"}"#, r#"{"sub":"a"}"#);
        let payload = JwsEdDsa::new()
            .verify(token.as_bytes(), vk.as_bytes())
            .expect("genuine token verifies");
        assert_eq!(payload, br#"{"sub":"a"}"#);
    }

    #[test]
    fn rejects_alg_none() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let token = make_token(&sk, r#"{"alg":"none"}"#, r#"{"sub":"a"}"#);
        assert_eq!(
            JwsEdDsa::new().verify(token.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn rejects_non_eddsa_algorithms() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        for alg in ["HS256", "RS256", "ES256", "", "eddsa"] {
            let header = format!(r#"{{"alg":"{alg}"}}"#);
            let token = make_token(&sk, &header, r#"{"sub":"a"}"#);
            assert_eq!(
                JwsEdDsa::new().verify(token.as_bytes(), vk.as_bytes()),
                Err(CryptoVerificationError::UnsupportedAlgorithm),
                "alg {alg} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_tampered_payload() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let token = make_token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
        // Swap the payload segment for a different valid base64url payload.
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = b64url_encode(br#"{"sub":"b"}"#);
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");
        assert_eq!(
            JwsEdDsa::new().verify(tampered.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_wrong_segment_count() {
        let vk = signing_key(5).verifying_key();
        assert_eq!(
            JwsEdDsa::new().verify(b"onlyone", vk.as_bytes()),
            Err(CryptoVerificationError::MalformedPayload)
        );
        assert_eq!(
            JwsEdDsa::new().verify(b"a.b.c.d", vk.as_bytes()),
            Err(CryptoVerificationError::MalformedPayload)
        );
    }

    #[test]
    fn rejects_oversized_input() {
        let vk = signing_key(5).verifying_key();
        let big = vec![b'a'; MAX_JWS_LEN + 1];
        assert_eq!(
            JwsEdDsa::new().verify(&big, vk.as_bytes()),
            Err(CryptoVerificationError::OversizedInput)
        );
    }

    #[test]
    fn extract_alg_handles_whitespace_and_order() {
        assert_eq!(
            extract_alg(br#"{ "typ" : "JWT" , "alg" : "EdDSA" }"#),
            Ok(Some("EdDSA".to_owned()))
        );
    }

    #[test]
    fn extract_alg_rejects_escapes_and_missing() {
        assert_eq!(extract_alg(br#"{"alg":"Ed\u0044SA"}"#), Ok(None));
        assert_eq!(extract_alg(br#"{"typ":"JWT"}"#), Ok(None));
        assert_eq!(extract_alg(b"not json"), Ok(None));
    }

    #[test]
    fn extract_alg_rejects_duplicate_alg_members() {
        // Two `alg` keys: the first is EdDSA (would pass the allowlist), the
        // second is none. Taking the first would smuggle `none` past a lenient
        // downstream consumer. We reject the ambiguity outright.
        assert_eq!(
            extract_alg(br#"{"alg":"EdDSA","alg":"none"}"#),
            Err(CryptoVerificationError::MalformedPayload)
        );
        // Order does not matter: still rejected.
        assert_eq!(
            extract_alg(br#"{"alg":"none","alg":"EdDSA"}"#),
            Err(CryptoVerificationError::MalformedPayload)
        );
    }

    #[test]
    fn extract_alg_ignores_alg_substring_inside_values() {
        // An `alg`-looking token inside a VALUE string must not be mistaken for
        // a key, so this header has exactly one real `alg` key.
        assert_eq!(
            extract_alg(br#"{"typ":"\"alg\":fake","alg":"EdDSA"}"#),
            Ok(Some("EdDSA".to_owned()))
        );
    }

    #[test]
    fn reject_unsupported_crit_fails_closed_when_present() {
        assert_eq!(
            reject_unsupported_crit(br#"{"alg":"EdDSA","crit":["b64"]}"#),
            Err(CryptoVerificationError::UnsupportedAlgorithm)
        );
        // Absent crit is fine.
        assert_eq!(reject_unsupported_crit(br#"{"alg":"EdDSA"}"#), Ok(()));
    }

    #[test]
    fn verify_rejects_token_with_crit_header() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let token = make_token(&sk, r#"{"alg":"EdDSA","crit":["exp"]}"#, r#"{"sub":"a"}"#);
        assert_eq!(
            JwsEdDsa::new().verify(token.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn verify_rejects_token_with_duplicate_alg() {
        let sk = signing_key(5);
        let vk = sk.verifying_key();
        let token = make_token(&sk, r#"{"alg":"EdDSA","alg":"none"}"#, r#"{"sub":"a"}"#);
        assert_eq!(
            JwsEdDsa::new().verify(token.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::MalformedPayload)
        );
    }

    #[test]
    fn does_not_panic_on_arbitrary_bytes() {
        let vk = signing_key(5).verifying_key();
        let _ = JwsEdDsa::new().verify(&[0xFFu8; 10], vk.as_bytes());
        let _ = JwsEdDsa::new().verify(b"..", vk.as_bytes());
        let _ = JwsEdDsa::new().verify(b"", vk.as_bytes());
    }
}
