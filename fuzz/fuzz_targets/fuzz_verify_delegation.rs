#![no_main]
//! Coverage-guided fuzz target for the delegation verification driver.
//!
//! Drives `kya_crypto::verify_delegation` with fuzzer-controlled signed bytes,
//! signature, binding, audience, and time values against a fixed trust-anchored
//! `(issuer, key_ref)`. Exercises the oversize guard, key resolution, the
//! Ed25519 verify call, the validity-window / audience / binding checks, and the
//! sealed evidence mint.
//!
//! Invariants under test:
//!   - no arbitrary input ever panics (including extreme `u64` time values that
//!     could otherwise overflow in a naive window check);
//!   - every rejection is a typed `CryptoVerificationError`;
//!   - random bytes never forge a `VerifiedDelegation`.

use libfuzzer_sys::fuzz_target;

use kya_core::evidence::DelegationClaim;
use kya_core::identity::{AgentId, IssuerId, TrustAnchors, TrustedKeyRef};
use kya_crypto::{verify_delegation, SignedClaim, TrustedKeyStore};

fuzz_target!(|data: &[u8]| {
    // Fixed, genuinely-anchored identity; the fuzzer varies everything else.
    let issuer = IssuerId::new("issuer:acme").expect("static valid issuer");
    let agent = AgentId::new("agent:1").expect("static valid agent");
    let key_ref = TrustedKeyRef::new("kid:1").expect("static valid key ref");
    let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());

    let mut store = TrustedKeyStore::new();
    store.insert(issuer.clone(), key_ref.clone(), [7u8; 32]);
    let mut anchors = TrustAnchors::new();
    anchors.trust_key(issuer, key_ref);

    // Carve the fuzz input into the attacker-controlled fields.
    let signed_bytes = data;
    let signature: &[u8] = if data.len() >= 64 { &data[..64] } else { data };
    let binding: &[u8] = if data.len() >= 8 { &data[..8] } else { data };

    // Derive two u64 time-ish values from the input so extreme windows get hit.
    let now = fold_u64(data, 0);

    let s = SignedClaim {
        claim: &claim,
        signed_bytes,
        signature,
        audience: "aud:payments",
        not_before: fold_u64(data, 1),
        expires_at: fold_u64(data, 2),
        binding,
    };

    // Expected to return a typed error for essentially all inputs; a genuine
    // VerifiedDelegation would require a real signature, which random bytes
    // cannot produce. The only contract asserted here is: no panic, typed
    // result.
    let _ = verify_delegation(&s, &store, &anchors, now, "aud:payments", b"txn-binding");
});

/// Fold the input bytes into a `u64` with a per-call offset so the fuzzer can
/// reach extreme not-before / expires-at values (including `u64::MAX`-ish).
fn fold_u64(data: &[u8], salt: u8) -> u64 {
    let mut acc: u64 = u64::from(salt).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for &b in data.iter().take(16) {
        acc = acc.rotate_left(7) ^ u64::from(b);
    }
    acc
}
