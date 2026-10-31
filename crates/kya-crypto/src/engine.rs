//! The restricted path from a signed claim to verified delegation evidence.
//!
//! [`verify_delegation`] is the single orchestration point of this crate. It
//! performs, in strict fail-closed order:
//!
//! 1. **Key resolution + trust check.** Resolve the claimed `(issuer, key_ref)`
//!    to concrete Ed25519 public-key bytes from the explicit
//!    [`TrustedKeyStore`], and confirm the same pair is anchored in the
//!    caller's [`kya_core::identity::TrustAnchors`]. An unknown issuer, an
//!    unbound key, or an unanchored pair fails closed.
//! 2. **Signature verification through the crate-private mint-point.** Run the
//!    concrete [`Ed25519SignatureVerifier`] through this crate's
//!    [`crate::evidence`] mint-point ([`run_verifier`]) so the resulting
//!    verified outcome carries the unforgeable proof. The mint-point is
//!    crate-private and bound to the one reviewed verifier; a caller-provided
//!    boolean, enum, or external verifier can never substitute for it.
//! 3. **Claim validity.** Validate audience, not-before / expiration (against
//!    an injected current time), and transaction binding — each with a distinct
//!    structured error.
//! 4. **Evidence.** Only if all of the above pass, call
//!    [`VerifiedDelegation::establish`](crate::evidence::VerifiedDelegation) with
//!    the genuine outcome and the trust anchors.
//!
//! The result is verified *evidence*: authenticity + trust-anchoring + validity
//! window + binding (stages A/B and the static parts). It is **not** an
//! authorization. This function never returns an `Allow` and never performs
//! final payment authorization; stage D lives in `kya-client`.
//!
//! What it verifies is the **issuer's** signature over the delegation/mandate.
//! It is **not** proof that the **agent** possesses its own private key: no
//! agent challenge-response or agent key check is performed. The verified
//! representations report that gap explicitly through
//! [`kya_core::evidence::ProofOfPossession::NotEstablished`]; see the
//! `kya_core::evidence` module docs.

use kya_core::evidence::DelegationClaim;
use kya_core::identity::{IssuerId, TrustAnchors, TrustedKeyRef};
use kya_core::mandate::Mandate;
use kya_core::verification::{AlgorithmId, VerificationContext};

use crate::error::CryptoVerificationError;
use crate::evidence::{run_verifier, VerifiedDelegation, VerifiedMandate};
use crate::keystore::TrustedKeyStore;
use crate::verifier::{Ed25519SignatureVerifier, ACCEPTED_ALGORITHM};

/// Maximum accepted size, in bytes, of any single untrusted byte input handled
/// directly here (signed bytes, signature, binding). Bounds attacker input so
/// an oversized blob is rejected before heavy work.
const MAX_INPUT_LEN: usize = 256 * 1024;

/// A signed claim ready for the restricted verification path.
///
/// The caller supplies the **exact** protocol-defined signed bytes (for a raw
/// detached Ed25519 use case these are verbatim; for JWS-EdDSA they are the
/// RFC 7515 signing input, produced via [`crate::JwsEdDsa`]). This crate does
/// **not** invent a canonicalization of `kya-protocol` wire fields, which are
/// not a standardized signed format.
///
/// Alongside the signature, the claim carries the validity and binding facts
/// the engine checks: the audience the claim is addressed to, the `nbf`/`exp`
/// window (unix seconds), and the exact transaction-binding bytes the signer
/// committed to.
#[derive(Debug, Clone)]
pub struct SignedClaim<'a> {
    /// The raw delegation claim (issuer / agent / claimed key reference).
    pub claim: &'a DelegationClaim,
    /// The exact bytes the signature was computed over.
    pub signed_bytes: &'a [u8],
    /// The detached Ed25519 signature (expected 64 bytes; validated downstream).
    pub signature: &'a [u8],
    /// The audience the claim is addressed to (exact match required).
    pub audience: &'a str,
    /// Not-before time in unix seconds. The claim is rejected if `now < nbf`.
    pub not_before: u64,
    /// Expiration time in unix seconds. The claim is rejected if `now >= exp`.
    pub expires_at: u64,
    /// The exact transaction-binding bytes the signer committed to (e.g. a hash
    /// of the transaction intent). Compared byte-for-byte, never by tolerance.
    pub binding: &'a [u8],
}

/// Validate audience, validity window, and binding for a signed claim against
/// the presented expectations. Returns `Ok(())` only if all three match.
///
/// Time comparisons are checked integer comparisons on `u64`; there is no
/// subtraction, so extreme values cannot overflow or panic.
fn validate_claim_facts(
    claim: &SignedClaim<'_>,
    now: u64,
    expected_audience: &str,
    expected_binding: &[u8],
) -> Result<(), CryptoVerificationError> {
    if claim.audience != expected_audience {
        return Err(CryptoVerificationError::AudienceMismatch);
    }
    // Not yet valid: current time strictly before nbf.
    if now < claim.not_before {
        return Err(CryptoVerificationError::NotYetValid);
    }
    // Expired: current time at or after exp (exp is exclusive).
    if now >= claim.expires_at {
        return Err(CryptoVerificationError::Expired);
    }
    // Exact byte binding; constant-time is unnecessary for a public commitment,
    // but the comparison is exact (no tolerance, no float).
    if claim.binding != expected_binding {
        return Err(CryptoVerificationError::BindingMismatch);
    }
    Ok(())
}

/// Run the full restricted path and, on success, return verified delegation
/// evidence.
///
/// # Parameters
///
/// - `signed`: the signed claim bundle (exact bytes, signature, audience,
///   validity window, binding).
/// - `store`: the explicit trusted-key byte registry.
/// - `anchors`: the caller's trust anchors gating which pairs are trusted.
/// - `now`: the current time in unix seconds, injected so verification is
///   deterministic and testable (the engine never reads the system clock).
/// - `expected_audience`: the audience the verifier requires the claim to name.
/// - `expected_binding`: the exact transaction-binding bytes the request
///   presents.
///
/// # Errors
///
/// Returns a [`CryptoVerificationError`] for any failure: oversized input,
/// unknown issuer, untrusted key, malformed key/signature, a non-verifying
/// signature, audience mismatch, not-yet-valid, expired, or binding mismatch.
/// It never panics on untrusted input.
pub fn verify_delegation(
    signed: &SignedClaim<'_>,
    store: &TrustedKeyStore,
    anchors: &TrustAnchors,
    now: u64,
    expected_audience: &str,
    expected_binding: &[u8],
) -> Result<VerifiedDelegation, CryptoVerificationError> {
    // Bound untrusted inputs up front.
    if signed.signed_bytes.len() > MAX_INPUT_LEN
        || signed.signature.len() > MAX_INPUT_LEN
        || signed.binding.len() > MAX_INPUT_LEN
    {
        return Err(CryptoVerificationError::OversizedInput);
    }

    let issuer: &IssuerId = signed.claim.issuer();
    let key_ref: &TrustedKeyRef = signed.claim.claimed_key_ref();

    // (1) Resolve bytes AND confirm the pair is trust-anchored. Both are
    // required; neither alone suffices. Distinguish unknown issuer from an
    // untrusted/unbound key for a precise structured error.
    let public_key = match store.resolve(issuer, key_ref) {
        Some(bytes) => bytes,
        None => {
            if store.knows_issuer(issuer) {
                return Err(CryptoVerificationError::UntrustedKey);
            }
            return Err(CryptoVerificationError::UnknownIssuer);
        }
    };
    if !anchors.trusts_key(issuer, key_ref) {
        return Err(CryptoVerificationError::UntrustedKey);
    }

    // (2) Verify the signature THROUGH the crate-private kya-crypto mint-point
    // (`run_verifier`) so the outcome carries the unforgeable proof. A verified
    // outcome asserts authenticity only; trust was checked above and is
    // re-checked by `establish`.
    let algorithm = AlgorithmId::new(ACCEPTED_ALGORITHM)?;
    let context = VerificationContext::new(issuer.clone(), key_ref.clone(), algorithm);
    let verifier = Ed25519SignatureVerifier::new();
    let outcome = run_verifier(
        &verifier,
        context,
        public_key,
        signed.signed_bytes,
        signed.signature,
    )?;
    if !outcome.is_verified() {
        return Err(CryptoVerificationError::SignatureInvalid);
    }

    // (3) Validity window, audience, and binding.
    validate_claim_facts(signed, now, expected_audience, expected_binding)?;

    // (4) Mint verified evidence through the only constructor. This re-checks
    // issuer match and trust-anchoring independently of step (1).
    let evidence = VerifiedDelegation::establish(signed.claim, &outcome, anchors)?;
    Ok(evidence)
}

/// A signed **mandate** ready for the restricted mandate-binding verification
/// path.
///
/// Unlike [`SignedClaim`], which carries opaque caller-supplied `signed_bytes`,
/// this bundle carries the full [`Mandate`] itself. The engine derives the
/// exact bytes the signature must cover from
/// [`Mandate::canonical_encoding`] — it does **not** accept arbitrary caller
/// bytes for the policy path — so the signature provably commits to this exact
/// mandate and no substituted one. The claimed `(issuer, key_ref)` is taken
/// from `claim` and MUST agree with the mandate's issuer (checked fail-closed).
///
/// The audience / validity-window / binding facts are still carried and checked
/// exactly as for [`SignedClaim`]; they are request-time conditions layered on
/// top of the mandate-binding guarantee.
#[derive(Debug, Clone)]
pub struct SignedMandate<'a> {
    /// The raw delegation claim (issuer / agent / claimed key reference). Its
    /// issuer must match the mandate's issuer.
    pub claim: &'a DelegationClaim,
    /// The mandate whose canonical encoding the signature must cover.
    pub mandate: &'a Mandate,
    /// The detached Ed25519 signature over the mandate's canonical encoding
    /// (expected 64 bytes; validated downstream).
    pub signature: &'a [u8],
    /// The audience the claim is addressed to (exact match required).
    pub audience: &'a str,
    /// Not-before time in unix seconds. The claim is rejected if `now < nbf`.
    pub not_before: u64,
    /// Expiration time in unix seconds. The claim is rejected if `now >= exp`.
    pub expires_at: u64,
    /// The exact transaction-binding bytes the signer committed to. Compared
    /// byte-for-byte, never by tolerance.
    pub binding: &'a [u8],
}

/// Run the full restricted path for a **mandate** and, on success, return an
/// authenticated [`VerifiedMandate`] whose constraints are cryptographically
/// bound to the verified signature.
///
/// This is the mandate-bound counterpart of [`verify_delegation`] and is the
/// path the stage-C policy evaluator ([`kya_core::policy::evaluate`]) consumes.
/// It performs, in strict fail-closed order:
///
/// 1. **Key resolution + trust check** of the claimed `(issuer, key_ref)`,
///    exactly as [`verify_delegation`].
/// 2. **Signature verification through the crate-private mint-point** over the
///    **canonical encoding of the mandate** ([`Mandate::canonical_encoding`]),
///    not over arbitrary caller bytes. A signature that was computed over a
///    different payload will not verify here.
/// 3. **Claim validity**: audience, not-before / expiration (against the
///    injected `now`), and transaction binding.
/// 4. **Authenticated mandate**: call `VerifiedMandate::establish` with the
///    genuine outcome, the exact canonical bytes that were verified, and the
///    trust anchors. `establish` recomputes the canonical encoding and requires
///    byte-equality, so a mandate differing in any security-relevant field
///    cannot be paired with this signature.
///
/// The result is an authenticated mandate (stages A/B plus the static validity
/// facts). It is **not** an authorization; stage D lives in `kya-client`.
///
/// # Errors
///
/// Returns a [`CryptoVerificationError`] for any failure: oversized input,
/// unknown issuer, untrusted key, malformed key/signature, a non-verifying
/// signature, audience mismatch, not-yet-valid, expired, binding mismatch, or a
/// mandate that does not match the signed canonical bytes. It never panics on
/// untrusted input.
pub fn verify_mandate(
    signed: &SignedMandate<'_>,
    store: &TrustedKeyStore,
    anchors: &TrustAnchors,
    now: u64,
    expected_audience: &str,
    expected_binding: &[u8],
) -> Result<VerifiedMandate, CryptoVerificationError> {
    // The exact bytes the signature must cover are DERIVED from the mandate, not
    // supplied by the caller: this is what binds the signature to this mandate.
    let canonical = signed.mandate.canonical_encoding();

    // Bound untrusted inputs up front (the canonical encoding is derived from
    // already-validated domain types, but the signature and binding are
    // attacker-controlled).
    if canonical.len() > MAX_INPUT_LEN
        || signed.signature.len() > MAX_INPUT_LEN
        || signed.binding.len() > MAX_INPUT_LEN
    {
        return Err(CryptoVerificationError::OversizedInput);
    }

    let issuer: &IssuerId = signed.claim.issuer();
    let key_ref: &TrustedKeyRef = signed.claim.claimed_key_ref();

    // (1) Resolve bytes AND confirm the pair is trust-anchored.
    let public_key = match store.resolve(issuer, key_ref) {
        Some(bytes) => bytes,
        None => {
            if store.knows_issuer(issuer) {
                return Err(CryptoVerificationError::UntrustedKey);
            }
            return Err(CryptoVerificationError::UnknownIssuer);
        }
    };
    if !anchors.trusts_key(issuer, key_ref) {
        return Err(CryptoVerificationError::UntrustedKey);
    }

    // (2) Verify the signature over EXACTLY the mandate's canonical encoding,
    // through the crate-private kya-crypto mint-point (`run_verifier`).
    let algorithm = AlgorithmId::new(ACCEPTED_ALGORITHM)?;
    let context = VerificationContext::new(issuer.clone(), key_ref.clone(), algorithm);
    let verifier = Ed25519SignatureVerifier::new();
    let outcome = run_verifier(&verifier, context, public_key, &canonical, signed.signature)?;
    if !outcome.is_verified() {
        return Err(CryptoVerificationError::SignatureInvalid);
    }

    // (3) Validity window, audience, and binding.
    let facts = SignedClaim {
        claim: signed.claim,
        signed_bytes: &canonical,
        signature: signed.signature,
        audience: signed.audience,
        not_before: signed.not_before,
        expires_at: signed.expires_at,
        binding: signed.binding,
    };
    validate_claim_facts(&facts, now, expected_audience, expected_binding)?;

    // (4) Mint the authenticated mandate through its only constructor. This
    // recomputes the canonical encoding and requires byte-equality with the
    // exact bytes that were verified, re-checks the issuer match, and re-checks
    // trust-anchoring. The mandate is cloned into the immutable VerifiedMandate.
    let verified =
        VerifiedMandate::establish(signed.mandate.clone(), &outcome, &canonical, anchors)
            .map_err(mandate_binding_error)?;
    Ok(verified)
}

/// Map a [`kya_core::evidence::MandateBindingError`] into the engine's
/// structured error, fail-closed. A binding mismatch (the mandate does not
/// match the signed bytes) surfaces as [`CryptoVerificationError::BindingMismatch`]
/// so the caller sees a precise, non-authorizing failure; the identity/trust
/// variants reduce to the same classes the delegation path already reports.
fn mandate_binding_error(e: kya_core::evidence::MandateBindingError) -> CryptoVerificationError {
    use kya_core::evidence::MandateBindingError as M;
    match e {
        M::SignatureNotVerified => CryptoVerificationError::SignatureInvalid,
        M::IssuerMismatch => CryptoVerificationError::UntrustedKey,
        M::UntrustedKey => CryptoVerificationError::UntrustedKey,
        M::MandateBindingMismatch => CryptoVerificationError::BindingMismatch,
        // `MandateBindingError` is `#[non_exhaustive]`; a future variant maps
        // fail-closed to a signature-invalid failure rather than panicking.
        _ => CryptoVerificationError::SignatureInvalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use kya_core::identity::AgentId;

    const NOW: u64 = 1_000;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    struct Fixture {
        claim: DelegationClaim,
        store: TrustedKeyStore,
        anchors: TrustAnchors,
        signed_bytes: Vec<u8>,
        signature: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let issuer = IssuerId::new("issuer:acme").expect("valid");
        let agent = AgentId::new("agent:1").expect("valid");
        let key_ref = TrustedKeyRef::new("kid:1").expect("valid");
        let sk = signing_key(42);
        let vk = sk.verifying_key();

        let signed_bytes = b"exact-protocol-bytes".to_vec();
        let signature = sk.sign(&signed_bytes).to_bytes().to_vec();

        let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());
        let mut store = TrustedKeyStore::new();
        store.insert(issuer.clone(), key_ref.clone(), *vk.as_bytes());
        let mut anchors = TrustAnchors::new();
        anchors.trust_key(issuer, key_ref);

        Fixture {
            claim,
            store,
            anchors,
            signed_bytes,
            signature,
        }
    }

    fn signed<'a>(f: &'a Fixture) -> SignedClaim<'a> {
        SignedClaim {
            claim: &f.claim,
            signed_bytes: &f.signed_bytes,
            signature: &f.signature,
            audience: "aud:payments",
            not_before: 500,
            expires_at: 2_000,
            binding: b"txn-binding",
        }
    }

    #[test]
    fn happy_path_establishes_evidence() {
        let f = fixture();
        let s = signed(&f);
        let evidence = verify_delegation(
            &s,
            &f.store,
            &f.anchors,
            NOW,
            "aud:payments",
            b"txn-binding",
        )
        .expect("should verify");
        assert_eq!(evidence.issuer().as_str(), "issuer:acme");
        assert_eq!(evidence.agent().as_str(), "agent:1");
        assert_eq!(evidence.key_ref().as_str(), "kid:1");
    }

    #[test]
    fn unknown_issuer_fails_closed() {
        let f = fixture();
        let s = signed(&f);
        // Empty store: issuer unknown.
        let empty = TrustedKeyStore::new();
        assert_eq!(
            verify_delegation(&s, &empty, &f.anchors, NOW, "aud:payments", b"txn-binding"),
            Err(CryptoVerificationError::UnknownIssuer)
        );
    }

    #[test]
    fn known_issuer_unbound_key_is_untrusted() {
        let issuer = IssuerId::new("issuer:acme").expect("valid");
        let agent = AgentId::new("agent:1").expect("valid");
        let key_ref = TrustedKeyRef::new("kid:1").expect("valid");
        let other_key = TrustedKeyRef::new("kid:other").expect("valid");
        let sk = signing_key(42);
        let signed_bytes = b"bytes".to_vec();
        let signature = sk.sign(&signed_bytes).to_bytes().to_vec();
        let claim = DelegationClaim::new(issuer.clone(), agent, key_ref.clone());

        // Store knows the issuer, but only under a different key ref.
        let mut store = TrustedKeyStore::new();
        store.insert(
            issuer.clone(),
            other_key.clone(),
            *sk.verifying_key().as_bytes(),
        );
        let mut anchors = TrustAnchors::new();
        anchors.trust_key(issuer, other_key);

        let s = SignedClaim {
            claim: &claim,
            signed_bytes: &signed_bytes,
            signature: &signature,
            audience: "a",
            not_before: 0,
            expires_at: 10,
            binding: b"b",
        };
        assert_eq!(
            verify_delegation(&s, &store, &anchors, 1, "a", b"b"),
            Err(CryptoVerificationError::UntrustedKey)
        );
    }

    #[test]
    fn resolvable_but_unanchored_key_is_untrusted() {
        let f = fixture();
        let s = signed(&f);
        // Store resolves the key, but anchors are empty.
        let empty_anchors = TrustAnchors::new();
        assert_eq!(
            verify_delegation(
                &s,
                &f.store,
                &empty_anchors,
                NOW,
                "aud:payments",
                b"txn-binding"
            ),
            Err(CryptoVerificationError::UntrustedKey)
        );
    }

    #[test]
    fn tampered_signature_is_signature_invalid() {
        let f = fixture();
        let mut bad_sig = f.signature.clone();
        bad_sig[0] ^= 0xFF;
        let s = SignedClaim {
            signature: &bad_sig,
            ..signed(&f)
        };
        assert_eq!(
            verify_delegation(
                &s,
                &f.store,
                &f.anchors,
                NOW,
                "aud:payments",
                b"txn-binding"
            ),
            Err(CryptoVerificationError::SignatureInvalid)
        );
    }

    #[test]
    fn audience_mismatch_is_reported() {
        let f = fixture();
        let s = signed(&f);
        assert_eq!(
            verify_delegation(&s, &f.store, &f.anchors, NOW, "aud:other", b"txn-binding"),
            Err(CryptoVerificationError::AudienceMismatch)
        );
    }

    #[test]
    fn not_yet_valid_and_expired_are_distinct() {
        let f = fixture();
        let s = signed(&f);
        // now < nbf
        assert_eq!(
            verify_delegation(
                &s,
                &f.store,
                &f.anchors,
                100,
                "aud:payments",
                b"txn-binding"
            ),
            Err(CryptoVerificationError::NotYetValid)
        );
        // now >= exp
        assert_eq!(
            verify_delegation(
                &s,
                &f.store,
                &f.anchors,
                2_000,
                "aud:payments",
                b"txn-binding"
            ),
            Err(CryptoVerificationError::Expired)
        );
    }

    #[test]
    fn binding_mismatch_is_reported() {
        let f = fixture();
        let s = signed(&f);
        assert_eq!(
            verify_delegation(&s, &f.store, &f.anchors, NOW, "aud:payments", b"different"),
            Err(CryptoVerificationError::BindingMismatch)
        );
    }

    #[test]
    fn oversized_input_is_rejected() {
        let f = fixture();
        let big = vec![0u8; MAX_INPUT_LEN + 1];
        let s = SignedClaim {
            signed_bytes: &big,
            ..signed(&f)
        };
        assert_eq!(
            verify_delegation(
                &s,
                &f.store,
                &f.anchors,
                NOW,
                "aud:payments",
                b"txn-binding"
            ),
            Err(CryptoVerificationError::OversizedInput)
        );
    }

    #[test]
    fn does_not_panic_on_extreme_time_values() {
        let f = fixture();
        let s = SignedClaim {
            not_before: u64::MAX,
            expires_at: u64::MAX,
            ..signed(&f)
        };
        // now = 0 < nbf = u64::MAX -> NotYetValid, no overflow/panic.
        assert_eq!(
            verify_delegation(&s, &f.store, &f.anchors, 0, "aud:payments", b"txn-binding"),
            Err(CryptoVerificationError::NotYetValid)
        );
    }
}
