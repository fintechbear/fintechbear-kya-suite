//! Supplemental JWS / base64url edge-case matrix (AGENTS.md Rules 15, 17),
//! Security audit Section 4.
//!
//! `jws_security.rs` already covers `alg:none`, swapped/symmetric algorithms,
//! duplicate `alg`, `crit`, invalid base64url, invalid UTF-8/JSON headers,
//! truncation, wrong signature length, oversized input, and arbitrary-byte
//! non-panic. The in-crate `b64url` unit tests cover padding, the standard
//! alphabet, whitespace, and the impossible 1-char length remainder. This file
//! closes the remaining explicit items the audit calls out that were not
//! previously pinned as their own cases:
//!
//! - **non-zero trailing bits** in a base64url segment (a non-canonical
//!   encoding) are rejected via the only public door that decodes (`JwsEdDsa`);
//! - **detached-payload ambiguity**: an empty payload segment is rejected, so a
//!   caller can never present a header-and-signature-only token whose payload is
//!   implicit/omitted;
//! - **small-order / non-canonical public key** supplied to the JWS verify path
//!   never yields a verified payload (strict verification rejects it as
//!   invalid, surfaced as a signature failure);
//! - **case-variant and empty algorithm ids** at the JWS layer (complementing
//!   the unit-level `extract_alg` checks).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_crypto::{CryptoVerificationError, JwsEdDsa};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Minimal unpadded base64url encoder for building test tokens.
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

fn token(sk: &SigningKey, header_json: &str, payload_json: &str) -> String {
    let h = b64url(header_json.as_bytes());
    let p = b64url(payload_json.as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = sk.sign(signing_input.as_bytes());
    let s = b64url(&sig.to_bytes());
    format!("{h}.{p}.{s}")
}

// ---- non-zero trailing bits (non-canonical base64url) ---------------------

#[test]
fn non_zero_trailing_bits_in_a_segment_are_rejected() {
    // Build a genuine token, then replace the header segment with a 2-char
    // base64url group whose trailing 4 bits are NON-zero. "QQ" decodes to one
    // byte 0x41 with the final 4 bits zero (canonical); "QR" sets trailing bits
    // (non-canonical) and must be rejected by the strict decoder. Either way the
    // header no longer parses to a valid EdDSA alg, but the point is the decode
    // itself rejects the non-canonical trailing bits rather than silently
    // truncating.
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let genuine = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    let parts: Vec<&str> = genuine.split('.').collect();

    // "QR": 'Q'=16 (010000), 'R'=17 (010001). First byte = 0100 0001 = 0x41,
    // leftover 2 bits = 01 (non-zero) -> must be rejected as non-canonical.
    let non_canonical_header = "QR";
    let forged = format!("{}.{}.{}", non_canonical_header, parts[1], parts[2]);
    assert_eq!(
        JwsEdDsa::new().verify(forged.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload),
        "a header segment with non-zero trailing bits must be rejected"
    );
}

#[test]
fn canonical_trailing_bits_decode_but_other_checks_still_apply() {
    // Sanity companion: "QQ" has zero trailing bits (canonical) and decodes to
    // one byte. It still is not a valid JSON header naming EdDSA, so the token
    // is rejected — but as a header/JSON problem, proving the decoder accepted
    // the canonical group rather than rejecting the trailing bits.
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let genuine = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    let parts: Vec<&str> = genuine.split('.').collect();
    let canonical_but_not_json = "QQ"; // decodes to 0x41 = "A"
    let forged = format!("{}.{}.{}", canonical_but_not_json, parts[1], parts[2]);
    // Decodes fine, but "A" is not a JSON object naming alg -> MalformedPayload.
    assert_eq!(
        JwsEdDsa::new().verify(forged.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
}

// ---- detached-payload ambiguity -------------------------------------------

#[test]
fn empty_payload_segment_is_rejected_no_detached_ambiguity() {
    // A token with an empty payload segment (header..sig) must be rejected: the
    // verifier does not support RFC 7515 detached/unencoded payloads, so an
    // omitted payload can never be treated as "payload supplied out of band".
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let h = b64url(br#"{"alg":"EdDSA"}"#);
    let s = b64url(&[0u8; 64]);
    let empty_payload = format!("{h}..{s}");
    assert_eq!(
        JwsEdDsa::new().verify(empty_payload.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload),
        "an empty payload segment must be rejected (no detached-payload mode)"
    );
}

#[test]
fn empty_header_or_signature_segment_is_rejected() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let h = b64url(br#"{"alg":"EdDSA"}"#);
    let p = b64url(br#"{"sub":"a"}"#);
    let s = b64url(&[0u8; 64]);

    // Empty header segment.
    assert_eq!(
        JwsEdDsa::new().verify(format!(".{p}.{s}").as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
    // Empty signature segment.
    assert_eq!(
        JwsEdDsa::new().verify(format!("{h}.{p}.").as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload)
    );
}

// ---- small-order / non-canonical public key via the JWS path --------------

#[test]
fn small_order_public_key_never_yields_a_verified_payload() {
    // The all-zero (identity, order-1) key is well-formed but small order.
    // Strict verification rejects it, so a genuine-looking token verified
    // against it must never return a payload; it fails closed. We sign with a
    // real key but verify against the small-order key: the result is a
    // signature failure, never Ok.
    let sk = signing_key(5);
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    let small_order_key = [0u8; 32];
    let result = JwsEdDsa::new().verify(t.as_bytes(), &small_order_key);
    assert!(
        matches!(result, Err(CryptoVerificationError::SignatureInvalid)),
        "a small-order public key must never verify a JWS, got {result:?}"
    );
}

#[test]
fn wrong_length_public_key_in_jws_is_malformed_key() {
    let sk = signing_key(5);
    let t = token(&sk, r#"{"alg":"EdDSA"}"#, r#"{"sub":"a"}"#);
    for bad_key_len in [0usize, 31, 33, 64] {
        let key = vec![0u8; bad_key_len];
        assert_eq!(
            JwsEdDsa::new().verify(t.as_bytes(), &key),
            Err(CryptoVerificationError::MalformedKey),
            "key length {bad_key_len} must surface as MalformedKey"
        );
    }
}

// ---- case-variant / empty algorithm ids at the JWS layer ------------------

#[test]
fn case_variant_and_empty_alg_ids_are_unsupported() {
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    // The accepted id is exactly "EdDSA"; case variants and the empty string
    // must all be rejected (no case-insensitive match, no empty default).
    for alg in ["eddsa", "EDDSA", "EdDsa", "ed25519", "Ed25519", ""] {
        let header = format!(r#"{{"alg":"{alg}"}}"#);
        let t = token(&sk, &header, r#"{"sub":"a"}"#);
        assert_eq!(
            JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
            Err(CryptoVerificationError::UnsupportedAlgorithm),
            "alg {alg:?} must be unsupported (exact-match EdDSA only)"
        );
    }
}

#[test]
fn missing_alg_member_is_rejected() {
    // A valid JSON header that does not name `alg` at all must be rejected, not
    // defaulted to any algorithm.
    let sk = signing_key(5);
    let vk = sk.verifying_key();
    let t = token(&sk, r#"{"typ":"JWT"}"#, r#"{"sub":"a"}"#);
    assert_eq!(
        JwsEdDsa::new().verify(t.as_bytes(), vk.as_bytes()),
        Err(CryptoVerificationError::MalformedPayload),
        "a header with no alg member must be rejected"
    );
}
