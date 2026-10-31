//! RFC 8032 §7.1 Ed25519 conformance vectors.
//!
//! These tests anchor [`Ed25519SignatureVerifier`] against the *official*,
//! published Ed25519 test vectors from RFC 8032 section 7.1. The public key,
//! message, and signature are transcribed verbatim as hex from the RFC and
//! decoded in-test; the engine MUST report
//! [`VerificationStatus::Verified`](kya_core::verification::VerificationStatus)
//! for each genuine vector, including the empty-message vector (TEST 1) and a
//! non-empty vector (TEST 2 and TEST 3).
//!
//! To guard against a silent transcription error in the literal bytes, each
//! vector is *also* independently reconstructed from the RFC's 32-byte secret
//! seed via `ed25519-dalek` and cross-checked: the derived public key and the
//! derived signature MUST equal the published ones. The published literal bytes
//! remain the conformance anchor; the derivation is a belt-and-suspenders
//! integrity check on the transcription.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::{Signer, SigningKey};

use kya_core::verification::{SignatureVerifier, VerificationStatus};
use kya_crypto::Ed25519SignatureVerifier;

/// Decode an ASCII hex string into bytes. Panics (test-only) on malformed hex.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex length must be even");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i]);
        let lo = nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        other => panic!("invalid hex digit: {other}"),
    }
}

/// One RFC 8032 §7.1 vector: the published secret seed, public key, message,
/// and signature, all as hex (message may be empty).
struct Rfc8032Vector {
    name: &'static str,
    secret_seed: &'static str,
    public_key: &'static str,
    message: &'static str,
    signature: &'static str,
}

/// RFC 8032 §7.1 TEST 1 (empty message).
const TEST1: Rfc8032Vector = Rfc8032Vector {
    name: "RFC 8032 7.1 TEST 1",
    secret_seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    message: "",
    signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
};

/// RFC 8032 §7.1 TEST 2 (one-byte message 0x72).
const TEST2: Rfc8032Vector = Rfc8032Vector {
    name: "RFC 8032 7.1 TEST 2",
    secret_seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    message: "72",
    signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
};

/// RFC 8032 §7.1 TEST 3 (two-byte message af82).
const TEST3: Rfc8032Vector = Rfc8032Vector {
    name: "RFC 8032 7.1 TEST 3",
    secret_seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    message: "af82",
    signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
};

/// Reconstruct the public key and signature from the RFC secret seed and assert
/// they equal the published literals, catching any hex transcription slip.
fn assert_derived_matches_published(v: &Rfc8032Vector) {
    let seed = hex(v.secret_seed);
    let seed: [u8; 32] = seed.as_slice().try_into().expect("32-byte seed");
    let sk = SigningKey::from_bytes(&seed);

    let derived_pk = sk.verifying_key().to_bytes().to_vec();
    assert_eq!(
        derived_pk,
        hex(v.public_key),
        "{}: derived public key does not match published literal",
        v.name
    );

    let msg = hex(v.message);
    let derived_sig = sk.sign(&msg).to_bytes().to_vec();
    assert_eq!(
        derived_sig,
        hex(v.signature),
        "{}: derived signature does not match published literal",
        v.name
    );
}

/// The engine MUST report Verified for the genuine published vector.
fn assert_engine_verifies(v: &Rfc8032Vector) {
    let verifier = Ed25519SignatureVerifier::new();
    let status = verifier
        .verify(&hex(v.public_key), &hex(v.message), &hex(v.signature))
        .expect("well-formed published vector");
    assert_eq!(
        status,
        VerificationStatus::Verified,
        "{}: engine must report Verified for the genuine RFC vector",
        v.name
    );
}

#[test]
fn rfc8032_test1_empty_message_verifies() {
    assert_derived_matches_published(&TEST1);
    assert_engine_verifies(&TEST1);
}

#[test]
fn rfc8032_test2_one_byte_message_verifies() {
    assert_derived_matches_published(&TEST2);
    assert_engine_verifies(&TEST2);
}

#[test]
fn rfc8032_test3_two_byte_message_verifies() {
    assert_derived_matches_published(&TEST3);
    assert_engine_verifies(&TEST3);
}

#[test]
fn rfc8032_vector_fails_under_a_different_key() {
    // The genuine TEST 2 signature/message must NOT verify under TEST 3's key.
    let verifier = Ed25519SignatureVerifier::new();
    let status = verifier
        .verify(
            &hex(TEST3.public_key),
            &hex(TEST2.message),
            &hex(TEST2.signature),
        )
        .expect("well-formed inputs");
    assert_eq!(
        status,
        VerificationStatus::Invalid,
        "a genuine vector must not verify under a different public key"
    );
}

#[test]
fn rfc8032_vector_fails_when_message_tampered() {
    // Flip the single message byte of TEST 2 (0x72 -> 0x73); signature no longer
    // matches the message under the correct key.
    let verifier = Ed25519SignatureVerifier::new();
    let status = verifier
        .verify(&hex(TEST2.public_key), &[0x73], &hex(TEST2.signature))
        .expect("well-formed inputs");
    assert_eq!(
        status,
        VerificationStatus::Invalid,
        "a tampered message must not verify against the genuine signature"
    );
}
