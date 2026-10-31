#![no_main]
//! Coverage-guided fuzz target exercising the strict base64url decoder.
//!
//! `kya_crypto::b64url::decode` is a crate-private module, so it cannot be
//! called directly from this external harness. The decoder is reached through
//! the only public surface that uses it: `JwsEdDsa::verify` base64url-decodes
//! the header, payload, and signature segments of a compact JWS. We therefore
//! place the fuzzer-provided bytes into each of the three dot-separated segments
//! so libFuzzer explores the decoder's input space (alphabet checks, padding
//! rejection, impossible length remainders, non-zero trailing bits) via that
//! public door.
//!
//! Invariant under test: the decoder (and the verify path around it) must NEVER
//! panic on arbitrary bytes and must always return a typed result.

use libfuzzer_sys::fuzz_target;

use kya_crypto::JwsEdDsa;

fuzz_target!(|data: &[u8]| {
    // A fixed, well-formed public key length so the decode paths (not the key
    // parse) dominate; the key content is irrelevant because most inputs fail
    // long before signature verification.
    let key = [0u8; 32];

    // (1) Feed the raw bytes as a single blob: exercises segment splitting plus
    //     whatever decode happens on each piece. Must not panic.
    let _ = JwsEdDsa::new().verify(data, &key);

    // (2) Place the bytes specifically in the header segment (decoded first),
    //     with trivial valid-looking payload/sig segments, to drive the decoder
    //     with attacker-chosen content directly.
    let mut as_header = Vec::with_capacity(data.len() + 4);
    as_header.extend_from_slice(data);
    as_header.extend_from_slice(b".AA.AA");
    let _ = JwsEdDsa::new().verify(&as_header, &key);

    // (3) Place the bytes in the signature segment (decoded as the 64-byte sig).
    let mut as_sig = Vec::with_capacity(data.len() + 8);
    as_sig.extend_from_slice(b"eyJhbGciOiJFZERTQSJ9.AA.");
    as_sig.extend_from_slice(data);
    let _ = JwsEdDsa::new().verify(&as_sig, &key);
});
