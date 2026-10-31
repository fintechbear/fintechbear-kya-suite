//! Stage-B verification entry for the AP2 adapter.
//!
//! [`verify_ap2_delegation`] is the adapter's bridge into the concrete crypto
//! engine. It takes the AP2 mandate's constraints together with the
//! **caller-supplied exact signed bytes** and signature, and routes them
//! through the sealed [`kya_crypto::verify_delegation`] path to obtain genuine
//! [`kya_crypto::VerifiedDelegation`] evidence.
//!
//! # The adapter does not invent what AP2 signs
//!
//! Per ADR-0001 the exact AP2 signature **envelope** is `[UNVERIFIED]` and
//! therefore **BLOCKED**. This entry therefore does **not** parse an AP2 token,
//! does **not** canonicalize any wire fields, and does **not** guess the byte
//! layout AP2 commits to. The caller presents the exact bytes the signature was
//! computed over (`signed_bytes`) and the detached Ed25519 signature; the
//! adapter verifies *those* bytes and makes no claim that they match any
//! particular AP2 serialization. When the AP2 envelope is later verified from
//! the published schemas, a byte-exact parser can be layered in front of this
//! seam without changing it. Until then, byte-for-byte AP2 interop is not
//! implemented and not claimed.
//!
//! # What a successful verification means (and does not mean)
//!
//! Success yields verified *evidence*: the signature is authentic over the
//! presented bytes, the `(issuer, key_ref)` pair is trust-anchored, and the
//! engine's audience / validity-window / binding checks passed. This is stage
//! A/B plus the engine's static checks. It is **not** an authorization. The
//! adapter never produces a [`kya_core::decision::Decision`] and never yields an
//! `Allow`. Issuer authorization, revocation, cumulative budget, and replay
//! remain **stage D**, reached only through the fail-closed
//! `kya_client::authorize` bridge. The returned evidence is the input to the
//! unchanged stage-C evaluator [`kya_core::policy::evaluate`].

use kya_core::evidence::DelegationClaim;
use kya_core::identity::TrustAnchors;
use kya_core::mandate::Mandate;
use kya_crypto::{
    verify_delegation, verify_mandate, SignedClaim, SignedMandate, TrustedKeyStore,
    VerifiedDelegation, VerifiedMandate,
};

use crate::error::Ap2AdapterError;

/// A caller-assembled AP2 signed-mandate bundle for the verification seam.
///
/// The caller supplies the raw [`DelegationClaim`] (issuer / agent / claimed
/// key reference) and the **exact** bytes the signature was computed over,
/// along with the audience, validity window, and transaction-binding bytes the
/// engine checks. None of these are parsed from an AP2 token by this crate: the
/// adapter makes no claim about AP2's wire serialization (that is `[UNVERIFIED]`
/// and BLOCKED). The lifetime ties the borrowed slices to the caller's buffers.
#[derive(Debug, Clone)]
pub struct Ap2SignedMandate<'a> {
    /// The raw delegation claim (issuer / agent / claimed key reference).
    pub claim: &'a DelegationClaim,
    /// The exact bytes the signature was computed over. The caller is
    /// responsible for producing these; the adapter verifies them verbatim and
    /// does not synthesize them from an AP2 object.
    pub signed_bytes: &'a [u8],
    /// The detached Ed25519 signature over `signed_bytes`.
    pub signature: &'a [u8],
    /// The audience the claim is addressed to (exact match required).
    pub audience: &'a str,
    /// Not-before time in Unix seconds; the claim is rejected if `now < nbf`.
    pub not_before: u64,
    /// Expiration time in Unix seconds; the claim is rejected if `now >= exp`.
    pub expires_at: u64,
    /// The exact transaction-binding bytes the signer committed to, compared
    /// byte-for-byte.
    pub binding: &'a [u8],
}

/// Verify an AP2 signed mandate over caller-supplied exact bytes and, on
/// success, return verified delegation evidence.
///
/// This routes directly through [`kya_crypto::verify_delegation`]: it resolves
/// and trust-anchors the key, verifies the Ed25519 signature through the sealed
/// `kya-core` mint-point, and checks the audience, validity window, and binding
/// — all fail-closed. It never reads the system clock; `now` is injected by the
/// caller so verification is deterministic (mirroring the rest of the SDK).
///
/// # Parameters
///
/// - `mandate`: the caller-assembled signed-mandate bundle (exact bytes,
///   signature, audience, validity window, binding).
/// - `store`: the explicit trusted-key byte registry.
/// - `anchors`: the caller's trust anchors gating which `(issuer, key)` pairs
///   are trusted.
/// - `now`: the current time in Unix seconds, injected.
/// - `expected_audience`: the audience the verifier requires the claim to name.
/// - `expected_binding`: the exact transaction-binding bytes the request
///   presents.
///
/// # Errors
///
/// Returns [`Ap2AdapterError::Verification`] wrapping the engine's structured
/// [`kya_crypto::CryptoVerificationError`] for any failure: oversized input,
/// unknown issuer, untrusted key, malformed key/signature, a non-verifying
/// signature, audience mismatch, not-yet-valid, expired, or binding mismatch.
/// It never panics on untrusted input. It never returns an authorization.
pub fn verify_ap2_delegation(
    mandate: &Ap2SignedMandate<'_>,
    store: &TrustedKeyStore,
    anchors: &TrustAnchors,
    now: u64,
    expected_audience: &str,
    expected_binding: &[u8],
) -> Result<VerifiedDelegation, Ap2AdapterError> {
    let signed = SignedClaim {
        claim: mandate.claim,
        signed_bytes: mandate.signed_bytes,
        signature: mandate.signature,
        audience: mandate.audience,
        not_before: mandate.not_before,
        expires_at: mandate.expires_at,
        binding: mandate.binding,
    };
    let evidence = verify_delegation(
        &signed,
        store,
        anchors,
        now,
        expected_audience,
        expected_binding,
    )?;
    Ok(evidence)
}

/// A caller-assembled AP2 signed-**mandate** bundle for the mandate-binding
/// verification seam.
///
/// Unlike [`Ap2SignedMandate`], which carries opaque caller-supplied
/// `signed_bytes`, this bundle carries the full [`Mandate`] the signature must
/// cover. The engine derives the exact bytes-to-verify from the mandate's
/// canonical encoding, so the signature provably commits to this exact mandate
/// — no field can be substituted between sign time and evaluation time. Use
/// [`crate::constraints::Ap2MandateConstraints::to_mandate`] to build the
/// mandate from AP2 constraint fields, then sign its
/// [`kya_core::mandate::Mandate::canonical_encoding`].
///
/// This still makes **no** claim about AP2's wire envelope (which is
/// `[UNVERIFIED]` and BLOCKED per ADR-0001): the canonical encoding is
/// `kya-core`'s own internal, non-standardized format, not an AP2 serialization.
#[derive(Debug, Clone)]
pub struct Ap2SignedMandateBinding<'a> {
    /// The raw delegation claim (issuer / agent / claimed key reference). Its
    /// issuer must match the mandate's issuer.
    pub claim: &'a DelegationClaim,
    /// The mandate whose canonical encoding the signature must cover.
    pub mandate: &'a Mandate,
    /// The detached Ed25519 signature over the mandate's canonical encoding.
    pub signature: &'a [u8],
    /// The audience the claim is addressed to (exact match required).
    pub audience: &'a str,
    /// Not-before time in Unix seconds; the claim is rejected if `now < nbf`.
    pub not_before: u64,
    /// Expiration time in Unix seconds; the claim is rejected if `now >= exp`.
    pub expires_at: u64,
    /// The exact transaction-binding bytes the signer committed to, compared
    /// byte-for-byte.
    pub binding: &'a [u8],
}

/// Verify an AP2 signed mandate whose signature covers the mandate's canonical
/// encoding and, on success, return an authenticated [`VerifiedMandate`].
///
/// This is the mandate-bound counterpart of [`verify_ap2_delegation`] and is
/// the path that feeds the stage-C evaluator [`kya_core::policy::evaluate`]: the
/// mandate evaluated is provably the one whose canonical bytes were signed, so a
/// substituted mandate cannot be slipped into evaluation. It routes through
/// [`kya_crypto::verify_mandate`], which verifies the Ed25519 signature over the
/// derived canonical encoding through the crate-private `kya-crypto` mint-point,
/// trust-anchors the key, checks audience / validity / binding, and mints the
/// [`VerifiedMandate`] only when the signed bytes equal the mandate's canonical
/// encoding. It never reads the system clock; `now` is injected.
///
/// # Errors
///
/// Returns [`Ap2AdapterError::Verification`] wrapping the engine's structured
/// [`kya_crypto::CryptoVerificationError`] for any failure, including a mandate
/// that does not match the signed canonical bytes
/// ([`kya_crypto::CryptoVerificationError::BindingMismatch`]). It never panics
/// on untrusted input and never returns an authorization.
pub fn verify_ap2_mandate(
    signed: &Ap2SignedMandateBinding<'_>,
    store: &TrustedKeyStore,
    anchors: &TrustAnchors,
    now: u64,
    expected_audience: &str,
    expected_binding: &[u8],
) -> Result<VerifiedMandate, Ap2AdapterError> {
    let bundle = SignedMandate {
        claim: signed.claim,
        mandate: signed.mandate,
        signature: signed.signature,
        audience: signed.audience,
        not_before: signed.not_before,
        expires_at: signed.expires_at,
        binding: signed.binding,
    };
    let verified = verify_mandate(
        &bundle,
        store,
        anchors,
        now,
        expected_audience,
        expected_binding,
    )?;
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use kya_core::identity::{AgentId, IssuerId, TrustedKeyRef};
    use kya_crypto::CryptoVerificationError;

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

        let signed_bytes = b"ap2-caller-supplied-exact-bytes".to_vec();
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

    fn signed<'a>(f: &'a Fixture) -> Ap2SignedMandate<'a> {
        Ap2SignedMandate {
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
    fn genuine_signature_verifies_through_kya_crypto() {
        let f = fixture();
        let s = signed(&f);
        let evidence = verify_ap2_delegation(
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
    fn tampered_signature_fails_closed() {
        let f = fixture();
        let mut bad_sig = f.signature.clone();
        bad_sig[0] ^= 0xFF;
        let s = Ap2SignedMandate {
            signature: &bad_sig,
            ..signed(&f)
        };
        assert_eq!(
            verify_ap2_delegation(
                &s,
                &f.store,
                &f.anchors,
                NOW,
                "aud:payments",
                b"txn-binding"
            ),
            Err(Ap2AdapterError::Verification(
                CryptoVerificationError::SignatureInvalid
            ))
        );
    }

    #[test]
    fn untrusted_issuer_fails_closed() {
        let f = fixture();
        let s = signed(&f);
        let empty = TrustedKeyStore::new();
        assert_eq!(
            verify_ap2_delegation(&s, &empty, &f.anchors, NOW, "aud:payments", b"txn-binding"),
            Err(Ap2AdapterError::Verification(
                CryptoVerificationError::UnknownIssuer
            ))
        );
    }

    #[test]
    fn binding_substitution_fails_closed() {
        let f = fixture();
        let s = signed(&f);
        assert_eq!(
            verify_ap2_delegation(&s, &f.store, &f.anchors, NOW, "aud:payments", b"different"),
            Err(Ap2AdapterError::Verification(
                CryptoVerificationError::BindingMismatch
            ))
        );
    }

    #[test]
    fn audience_mismatch_fails_closed() {
        let f = fixture();
        let s = signed(&f);
        assert_eq!(
            verify_ap2_delegation(&s, &f.store, &f.anchors, NOW, "aud:other", b"txn-binding"),
            Err(Ap2AdapterError::Verification(
                CryptoVerificationError::AudienceMismatch
            ))
        );
    }

    #[test]
    fn expired_mandate_fails_closed() {
        let f = fixture();
        let s = signed(&f);
        assert_eq!(
            verify_ap2_delegation(
                &s,
                &f.store,
                &f.anchors,
                2_000,
                "aud:payments",
                b"txn-binding"
            ),
            Err(Ap2AdapterError::Verification(
                CryptoVerificationError::Expired
            ))
        );
    }

    // ---- mandate-bound path ---------------------------------------------

    use crate::constraints::{Ap2Identities, Ap2MandateConstraints, Ap2SpendingLimit};
    use kya_core::mandate::Mandate;

    fn constraints(limit_minor: i128, currency: &str) -> Ap2MandateConstraints {
        Ap2MandateConstraints {
            identities: Ap2Identities {
                issuer: "issuer:acme".to_owned(),
                principal: "principal:alice".to_owned(),
                agent: "agent:1".to_owned(),
                allowed_merchants: Some(vec!["merchant:store".to_owned()]),
                allowed_resources: Some(vec!["order:42".to_owned()]),
            },
            permitted_action: "transfer".to_owned(),
            spending_limit: Ap2SpendingLimit {
                max_minor_units: limit_minor,
                currency: currency.to_owned(),
            },
            not_before: 0,
            not_after: 3_000,
            required_audience: Some("aud:payments".to_owned()),
            requires_human_approval: false,
            transaction_binding: Some("mandate:A".to_owned()),
        }
    }

    fn signed_mandate_binding<'a>(
        f: &'a Fixture,
        mandate: &'a Mandate,
        signature: &'a [u8],
    ) -> Ap2SignedMandateBinding<'a> {
        Ap2SignedMandateBinding {
            claim: &f.claim,
            mandate,
            signature,
            audience: "aud:payments",
            not_before: 500,
            expires_at: 2_000,
            binding: b"txn-binding",
        }
    }

    #[test]
    fn mandate_bound_path_verifies_genuine_mandate() {
        let f = fixture();
        let mandate = constraints(10_000, "USD").to_mandate().expect("valid");
        let signature = signing_key(42)
            .sign(&mandate.canonical_encoding())
            .to_bytes()
            .to_vec();
        let s = signed_mandate_binding(&f, &mandate, &signature);
        let verified = verify_ap2_mandate(
            &s,
            &f.store,
            &f.anchors,
            NOW,
            "aud:payments",
            b"txn-binding",
        )
        .expect("genuine mandate should verify");
        assert_eq!(verified.issuer().as_str(), "issuer:acme");
        assert_eq!(verified.agent().as_str(), "agent:1");
    }

    #[test]
    fn mandate_bound_path_rejects_substituted_mandate() {
        let f = fixture();
        // Sign the canonical encoding of a 10_000 USD mandate...
        let signed = constraints(10_000, "USD").to_mandate().expect("valid");
        let signature = signing_key(42)
            .sign(&signed.canonical_encoding())
            .to_bytes()
            .to_vec();
        // ...but present a mandate with a raised spending limit. The engine
        // derives the bytes-to-verify from the PRESENTED mandate, so the
        // genuine signature no longer verifies over those bytes: it fails
        // closed with SignatureInvalid (the signature does not cover the
        // substituted mandate). Either SignatureInvalid or BindingMismatch is a
        // fail-closed, non-authorizing rejection.
        let presented = constraints(100_000_000, "USD").to_mandate().expect("valid");
        let s = signed_mandate_binding(&f, &presented, &signature);
        let result = verify_ap2_mandate(
            &s,
            &f.store,
            &f.anchors,
            NOW,
            "aud:payments",
            b"txn-binding",
        );
        assert!(
            matches!(
                result,
                Err(Ap2AdapterError::Verification(
                    CryptoVerificationError::SignatureInvalid
                )) | Err(Ap2AdapterError::Verification(
                    CryptoVerificationError::BindingMismatch
                ))
            ),
            "substituted mandate must fail closed, got {result:?}"
        );
    }
}
