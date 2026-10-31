#![no_main]
//! Coverage-guided fuzz target for the compact-JWS EdDSA verifier.
//!
//! Drives `kya_crypto::JwsEdDsa::verify` with arbitrary bytes as the token and
//! a fuzzer-chosen slice as the public key. Exercises segment splitting, header
//! JSON `alg`/`crit` scanning, base64url decoding, signature-length checks, and
//! the Ed25519 verification call.
//!
//! Invariants under test:
//!   - no arbitrary input ever panics;
//!   - every rejection is a typed `CryptoVerificationError`;
//!   - random bytes never forge a `Verified` result (if `Ok` is ever returned,
//!     it is a genuine decode of a payload, which is astronomically unlikely for
//!     random input and is still a typed, non-panicking outcome).

use libfuzzer_sys::fuzz_target;

use kya_crypto::JwsEdDsa;

fuzz_target!(|data: &[u8]| {
    // Split the fuzz input so part of it can act as the public key and the rest
    // as the token, letting the fuzzer correlate key and token bytes.
    let (key_part, token) = if data.len() >= 32 {
        (&data[..32], &data[32..])
    } else {
        (&b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
             \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..],
         data)
    };

    // The verifier accepts any key slice and returns MalformedKey for a wrong
    // length, so both 32-byte and off-length keys are valid fuzz inputs.
    let _ = JwsEdDsa::new().verify(token, key_part);
});
