//! The sealed verified-outcome and verified-evidence types, owned by the
//! reviewed crypto crate.
//!
//! This module is the root-cause fix for the verifier-sanction bypass. The
//! authority to mint a **verified** [`VerificationOutcome`] and to build
//! verified evidence ([`VerifiedDelegation`], [`VerifiedMandate`]) lives here,
//! in `kya-crypto`, bound to the single reviewed concrete verifier
//! [`crate::Ed25519SignatureVerifier`]. It is **not** in `kya-core`.
//!
//! # Why this closes the bypass as a true visibility wall
//!
//! `kya-core` must not depend on `kya-crypto` (AGENTS.md Rule 2) and cannot name
//! the concrete Ed25519 verifier. When the mint-point lived in `kya-core` behind
//! a `#[doc(hidden)] pub` generic registration seam, no pure-visibility rule
//! could admit exactly `kya-crypto` while rejecting every other external crate —
//! both saw the same public surface, so a hostile crate could implement an
//! always-`Verified` verifier and forge trusted evidence with no cryptography.
//!
//! By relocating the constructors here:
//!
//! - [`VerificationProof::new`], the `verified` [`VerificationOutcome`]
//!   constructor, and [`VerifiedDelegation::establish`] /
//!   [`VerifiedMandate::establish`] are all `pub(crate)` or private to
//!   `kya-crypto`. No external crate can name or reach them.
//! - The **only** way to obtain a verified outcome or verified evidence is to go
//!   through [`run_verifier`] (and the public [`crate::verify_delegation`] /
//!   [`crate::verify_mandate`]), which run the reviewed
//!   [`crate::Ed25519SignatureVerifier`] over real bytes. There is no generic
//!   door and no sanction token an external crate could mint.
//! - The verifier is a concrete, crate-private choice: [`run_verifier`] takes
//!   `&Ed25519SignatureVerifier`, so an external always-`Verified` verifier
//!   cannot be substituted at all.
//!
//! A verified outcome asserts **authenticity only**. Trust is checked
//! independently against the caller's
//! [`kya_core::identity::TrustAnchors`] inside the `establish` constructors.

use kya_core::evidence::{
    AuthenticatedMandate, DelegationClaim, EvidenceError, MandateBindingError, ProofOfPossession,
};
use kya_core::identity::{AgentId, IssuerId, TrustAnchors, TrustedKeyRef};
use kya_core::mandate::Mandate;
use kya_core::verification::{
    SignatureVerifier, VerificationContext, VerificationError, VerificationStatus,
};

use crate::verifier::Ed25519SignatureVerifier;

/// Private, zero-sized sealing marker.
///
/// `Sealed` lives in a **private** module of `kya-crypto`, so no other crate —
/// including `kya-core` — can name or construct it. It is the single field of
/// [`VerificationProof`], giving that type a private, unnameable field and thus
/// no external constructor.
mod sealed {
    /// The unnameable sealing marker. See the module docs.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Sealed;
}

use sealed::Sealed;

/// An unforgeable proof that a real signature verification ran, inside this
/// reviewed crypto crate, and returned [`VerificationStatus::Verified`].
///
/// It has a private, unnameable field (the `Sealed` marker), no public
/// constructor, and no `Default`/`From`/`Deserialize`. The only mint-point is
/// `VerificationProof::new`, which is `pub(crate)` and only reached from
/// `run_verifier` after the reviewed [`Ed25519SignatureVerifier`] returns
/// `Ok(Verified)`.
///
/// # Externally unreachable mint-point (regression lock-in)
///
/// These `compile_fail` doc-tests run under `cargo test --doc` and assert, from
/// the perspective of an external crate using only the public API, that the
/// relocated mint-point cannot be reached. `VerificationProof::new` is
/// `pub(crate)`, so an external crate cannot construct a proof:
///
/// ```compile_fail
/// // error[E0624]: associated function `new` is private
/// let _ = kya_crypto::VerificationProof::new();
/// ```
///
/// The `run_verifier` driver (the only thing that mints a proof) lives in a
/// private module and is `pub(crate)`, so it is not nameable externally even to
/// pass the concrete verifier:
///
/// ```compile_fail
/// // error[E0603]: module `evidence` is private (and `run_verifier` is pub(crate))
/// let _ = kya_crypto::evidence::run_verifier;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationProof {
    _sealed: Sealed,
}

impl VerificationProof {
    /// Mint a verification proof. Crate-internal: the only way to cause a proof
    /// to exist is [`run_verifier`] observing a genuine `Ok(Verified)`.
    pub(crate) fn new() -> Self {
        VerificationProof { _sealed: Sealed }
    }
}

/// The status of a verification attempt paired with the context it was
/// performed under.
///
/// This is the auditable record of stage B. It is **not** an authorization and
/// cannot be converted into one; it only reports whether some bytes were
/// authentic under a named key and algorithm.
///
/// A [`VerificationStatus::Verified`] outcome can only be constructed via the
/// `pub(crate)` `VerificationOutcome::verified`, which requires an unforgeable
/// [`VerificationProof`]. [`VerificationStatus::Invalid`] outcomes are
/// constructible via the public [`VerificationOutcome::invalid`] so negative
/// cases can be represented, but an invalid outcome can never become verified.
///
/// # Externally unreachable verified constructor (regression lock-in)
///
/// This `compile_fail` doc-test asserts that an external crate cannot mint a
/// *verified* outcome: `VerificationOutcome::verified` is `pub(crate)` and
/// additionally requires a [`VerificationProof`] it cannot build.
///
/// ```compile_fail
/// use kya_core::identity::{IssuerId, TrustedKeyRef};
/// use kya_core::verification::{AlgorithmId, VerificationContext};
/// let ctx = VerificationContext::new(
///     IssuerId::new("issuer:x").unwrap(),
///     TrustedKeyRef::new("kid:x").unwrap(),
///     AlgorithmId::new("EdDSA").unwrap(),
/// );
/// // error[E0624]: associated function `verified` is private (and no public
/// // way to obtain the required VerificationProof).
/// let _ = kya_crypto::VerificationOutcome::verified(ctx, todo!());
/// ```
///
/// The public [`VerificationOutcome::invalid`] constructor is intentionally
/// reachable — a rejection is safe to represent — and this doc-test confirms it
/// compiles while never yielding a verified outcome:
///
/// ```
/// use kya_core::identity::{IssuerId, TrustedKeyRef};
/// use kya_core::verification::{AlgorithmId, VerificationContext};
/// let ctx = VerificationContext::new(
///     IssuerId::new("issuer:x").unwrap(),
///     TrustedKeyRef::new("kid:x").unwrap(),
///     AlgorithmId::new("EdDSA").unwrap(),
/// );
/// let outcome = kya_crypto::VerificationOutcome::invalid(ctx);
/// assert!(!outcome.is_verified());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationOutcome {
    status: VerificationStatus,
    context: VerificationContext,
}

impl VerificationOutcome {
    /// Construct a **verified** outcome. Crate-internal and requires an
    /// unforgeable [`VerificationProof`], which only [`run_verifier`] can
    /// produce, so no caller (in or out of this crate) can forge a verified
    /// outcome without a real verification having run.
    pub(crate) fn verified(context: VerificationContext, proof: VerificationProof) -> Self {
        // Binding `proof` makes the unforgeable token a required argument;
        // discarding it afterwards is intentional.
        let VerificationProof { _sealed: _ } = proof;
        VerificationOutcome {
            status: VerificationStatus::Verified,
            context,
        }
    }

    /// Construct an **invalid** outcome. Freely available so a genuine rejection
    /// can produce an auditable record. It can never yield a verified outcome.
    pub fn invalid(context: VerificationContext) -> Self {
        VerificationOutcome {
            status: VerificationStatus::Invalid,
            context,
        }
    }

    /// The binary verification status.
    pub fn status(&self) -> VerificationStatus {
        self.status
    }

    /// The context the verification was performed under.
    pub fn context(&self) -> &VerificationContext {
        &self.context
    }

    /// Returns `true` only if the outcome's status is
    /// [`VerificationStatus::Verified`].
    pub fn is_verified(&self) -> bool {
        self.status.is_verified()
    }
}

/// Run the reviewed [`Ed25519SignatureVerifier`] and translate its result into
/// a sealed [`VerificationOutcome`].
///
/// This is the **only** mint-point for a [`VerificationStatus::Verified`]
/// outcome, and it lives inside `kya-crypto` bound to the one reviewed concrete
/// verifier. A verified outcome is produced **only** when the verifier returns
/// `Ok(VerificationStatus::Verified)` for the supplied `public_key`, `payload`,
/// and `signature`; any `Ok(Invalid)` becomes an invalid outcome, and any
/// verifier error propagates unchanged.
///
/// There is no generic parameter: an arbitrary always-`Verified` verifier
/// defined in another crate cannot be passed here at all, so it can never reach
/// the proof-minting path. Trust is **not** established here; a verified outcome
/// asserts authenticity only, and the `establish` constructors check trust
/// anchoring independently.
///
/// # Errors
///
/// Returns the [`VerificationError`] produced by the verifier when the inputs
/// are malformed or the algorithm is unsupported.
pub(crate) fn run_verifier(
    verifier: &Ed25519SignatureVerifier,
    context: VerificationContext,
    public_key: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<VerificationOutcome, VerificationError> {
    match verifier.verify(public_key, payload, signature)? {
        VerificationStatus::Verified => Ok(VerificationOutcome::verified(
            context,
            VerificationProof::new(),
        )),
        // `VerificationStatus` is `#[non_exhaustive]`; any non-`Verified`
        // status (including a future variant) fails closed to an invalid
        // outcome and never mints a proof (AGENTS.md Rule 9).
        _ => Ok(VerificationOutcome::invalid(context)),
    }
}

/// **Verified** evidence that an issuer delegated authority to an agent.
///
/// A value of this type is a proof token: its mere existence means the
/// delegation's signature verified against a key that is trust-anchored to the
/// claimed issuer. It cannot be constructed any other way — there is no public
/// field, no `Default`, and no `From`. The only constructor is
/// `VerifiedDelegation::establish`, which is `pub(crate)` and reached only
/// through [`crate::verify_delegation`]. This is what prevents a "fake verified
/// identity" from being minted by any external crate.
///
/// It still is not an authorization (see the crate docs): it is the input a
/// mandate's static policy (stage C) and the online authority (stage D) build
/// on.
///
/// # Externally unreachable constructor (regression lock-in)
///
/// This `compile_fail` doc-test asserts that an external crate cannot call
/// `VerifiedDelegation::establish`; it is `pub(crate)`, so the relocated
/// mint-point cannot forge delegation evidence from outside `kya-crypto`.
///
/// ```compile_fail
/// use kya_core::evidence::DelegationClaim;
/// fn attempt(claim: &DelegationClaim) {
///     // error[E0624]: associated function `establish` is private (and no
///     // public way to obtain the required verified VerificationOutcome).
///     let _ = kya_crypto::VerifiedDelegation::establish(claim, todo!(), todo!());
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelegation {
    issuer: IssuerId,
    agent: AgentId,
    key_ref: TrustedKeyRef,
}

impl VerifiedDelegation {
    /// Establish verified delegation evidence from a raw claim, the outcome of
    /// verifying that claim's signature, and the configured trust anchors.
    ///
    /// Crate-internal: the `outcome` can only have been produced by
    /// [`run_verifier`]. All three conditions must hold or the call fails
    /// closed:
    ///
    /// 1. `outcome.status()` is [`VerificationStatus::Verified`];
    /// 2. the outcome's context names the same issuer as the claim;
    /// 3. the (issuer, key) pair from the outcome's context is present in
    ///    `anchors`.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`EvidenceError`] variant for whichever
    /// condition fails first.
    pub(crate) fn establish(
        claim: &DelegationClaim,
        outcome: &VerificationOutcome,
        anchors: &TrustAnchors,
    ) -> Result<Self, EvidenceError> {
        if outcome.status() != VerificationStatus::Verified {
            return Err(EvidenceError::SignatureNotVerified);
        }

        let ctx = outcome.context();
        if ctx.issuer() != claim.issuer() {
            return Err(EvidenceError::IssuerMismatch);
        }

        if !anchors.trusts_key(ctx.issuer(), ctx.key_ref()) {
            return Err(EvidenceError::UntrustedKey);
        }

        Ok(VerifiedDelegation {
            issuer: claim.issuer().clone(),
            agent: claim.agent().clone(),
            key_ref: ctx.key_ref().clone(),
        })
    }

    /// The issuer whose delegation has been verified.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The agent the verified delegation is for.
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// The trusted key reference the delegation was verified against.
    pub fn key_ref(&self) -> &TrustedKeyRef {
        &self.key_ref
    }

    /// The agent proof-of-possession state for this verified delegation.
    ///
    /// Always [`ProofOfPossession::NotEstablished`] in v0.1: an issuer-signed
    /// delegation proves the *issuer* signed it, not that the *agent* holds its
    /// own private key. This SDK performs no agent key check, so it reports the
    /// absence of that proof explicitly rather than letting a caller assume it.
    pub fn proof_of_possession(&self) -> ProofOfPossession {
        ProofOfPossession::NotEstablished
    }
}

/// **Verified** evidence that a trust-anchored issuer signed the **complete**
/// applicable mandate.
///
/// This is the authenticated, immutable representation of a mandate. Its mere
/// existence means a real signature verified against a trust-anchored key over
/// the exact [`Mandate::canonical_encoding`] of the mandate it holds. There is
/// no public field, no `Default`, and no `From`: the only constructor is the
/// `pub(crate)` `VerifiedMandate::establish`, reached only through
/// [`crate::verify_mandate`].
///
/// It implements the `kya-core` [`AuthenticatedMandate`] view trait so the
/// stage-C [`kya_core::policy::evaluate`] can read its fields without `kya-core`
/// depending on `kya-crypto`.
///
/// # Why this is stronger than [`VerifiedDelegation`]
///
/// A [`VerifiedDelegation`] binds only `(issuer, agent, key_ref)`. A
/// `VerifiedMandate` additionally requires the verified bytes to equal the
/// mandate's canonical encoding, so the signature provably covers *this* mandate
/// and no substituted one.
///
/// Like a [`VerifiedDelegation`], a `VerifiedMandate` is still **not** an
/// authorization: it is the authenticated input to stage C and, past that, the
/// online authority (stage D).
///
/// # Externally unreachable constructor (regression lock-in)
///
/// This `compile_fail` doc-test asserts that an external crate cannot call
/// `VerifiedMandate::establish`; it is `pub(crate)`, so the relocated
/// mint-point cannot forge mandate evidence from outside `kya-crypto`.
///
/// ```compile_fail
/// use kya_core::mandate::Mandate;
/// fn attempt(mandate: Mandate) {
///     // error[E0624]: associated function `establish` is private (and no
///     // public way to obtain the required verified VerificationOutcome).
///     let _ = kya_crypto::VerifiedMandate::establish(mandate, todo!(), b"", todo!());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedMandate {
    mandate: Mandate,
    key_ref: TrustedKeyRef,
}

impl VerifiedMandate {
    /// Establish an authenticated verified mandate from the mandate itself, the
    /// outcome of verifying a signature, the exact bytes that signature covered,
    /// and the configured trust anchors.
    ///
    /// Crate-internal: the `outcome` can only have been produced by
    /// [`run_verifier`]. All four conditions must hold or the call fails closed:
    ///
    /// 1. `outcome.status()` is [`VerificationStatus::Verified`];
    /// 2. the outcome's context names the same issuer as the mandate;
    /// 3. the (issuer, key) pair from the outcome's context is present in
    ///    `anchors`;
    /// 4. `verified_bytes` equals [`Mandate::canonical_encoding`] of `mandate`.
    ///
    /// # Errors
    ///
    /// Returns the corresponding [`MandateBindingError`] variant for whichever
    /// condition fails first (checked in the order above).
    pub(crate) fn establish(
        mandate: Mandate,
        outcome: &VerificationOutcome,
        verified_bytes: &[u8],
        anchors: &TrustAnchors,
    ) -> Result<Self, MandateBindingError> {
        if outcome.status() != VerificationStatus::Verified {
            return Err(MandateBindingError::SignatureNotVerified);
        }

        let ctx = outcome.context();
        if ctx.issuer() != mandate.issuer() {
            return Err(MandateBindingError::IssuerMismatch);
        }

        if !anchors.trusts_key(ctx.issuer(), ctx.key_ref()) {
            return Err(MandateBindingError::UntrustedKey);
        }

        // The decisive check: the bytes that actually verified must be the
        // canonical encoding of THIS mandate. Otherwise the signature covers a
        // different payload and cannot authenticate this mandate.
        if mandate.canonical_encoding() != verified_bytes {
            return Err(MandateBindingError::MandateBindingMismatch);
        }

        let key_ref = ctx.key_ref().clone();
        Ok(VerifiedMandate { mandate, key_ref })
    }

    /// The issuer whose signature over this mandate has been verified.
    pub fn issuer(&self) -> &IssuerId {
        self.mandate.issuer()
    }

    /// The agent the verified mandate was granted to.
    pub fn agent(&self) -> &AgentId {
        self.mandate.agent()
    }

    /// The trusted key reference the mandate was verified against.
    pub fn key_ref(&self) -> &TrustedKeyRef {
        &self.key_ref
    }

    /// The authenticated mandate. Its constraints have been cryptographically
    /// bound to the verified signature and are safe for stage-C evaluation to
    /// treat as established.
    pub fn mandate(&self) -> &Mandate {
        &self.mandate
    }

    /// The agent proof-of-possession state for this verified mandate.
    ///
    /// Always [`ProofOfPossession::NotEstablished`] in v0.1. A `VerifiedMandate`
    /// cryptographically binds the *issuer's* signature to this mandate's
    /// complete canonical encoding; it does **not** prove the *agent* possesses
    /// its own private key. No agent key check is performed.
    pub fn proof_of_possession(&self) -> ProofOfPossession {
        ProofOfPossession::NotEstablished
    }
}

impl AuthenticatedMandate for VerifiedMandate {
    fn mandate(&self) -> &Mandate {
        &self.mandate
    }

    fn issuer(&self) -> &IssuerId {
        self.mandate.issuer()
    }

    fn agent(&self) -> &AgentId {
        self.mandate.agent()
    }

    fn key_ref(&self) -> &TrustedKeyRef {
        &self.key_ref
    }

    fn proof_of_possession(&self) -> ProofOfPossession {
        ProofOfPossession::NotEstablished
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kya_core::verification::AlgorithmId;

    fn ctx(issuer: &IssuerId, key: &TrustedKeyRef) -> VerificationContext {
        VerificationContext::new(
            issuer.clone(),
            key.clone(),
            AlgorithmId::new("ed25519").expect("valid"),
        )
    }

    fn ids() -> (IssuerId, AgentId, TrustedKeyRef) {
        (
            IssuerId::new("issuer:acme").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            TrustedKeyRef::new("kid:1").expect("valid"),
        )
    }

    fn anchors_trusting(issuer: &IssuerId, key: &TrustedKeyRef) -> TrustAnchors {
        let mut a = TrustAnchors::new();
        a.trust_key(issuer.clone(), key.clone());
        a
    }

    /// Build a verified outcome through the only mint-point using the genuine
    /// reviewed verifier over a real Ed25519 signature.
    fn verified_outcome(
        issuer: &IssuerId,
        key: &TrustedKeyRef,
        bytes: &[u8],
    ) -> VerificationOutcome {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let sig = sk.sign(bytes).to_bytes();
        run_verifier(
            &Ed25519SignatureVerifier::new(),
            ctx(issuer, key),
            sk.verifying_key().as_bytes(),
            bytes,
            &sig,
        )
        .expect("well-formed inputs")
    }

    #[test]
    fn invalid_outcome_is_not_verified() {
        let (issuer, _agent, key) = ids();
        let outcome = VerificationOutcome::invalid(ctx(&issuer, &key));
        assert!(!outcome.is_verified());
        assert_eq!(outcome.status(), VerificationStatus::Invalid);
    }

    #[test]
    fn run_verifier_mints_verified_only_on_genuine_match() {
        let (issuer, _agent, key) = ids();
        let outcome = verified_outcome(&issuer, &key, b"genuine-bytes");
        assert!(outcome.is_verified());
        assert_eq!(outcome.context().issuer().as_str(), "issuer:acme");
    }

    #[test]
    fn run_verifier_yields_invalid_on_bad_signature() {
        let (issuer, _agent, key) = ids();
        let outcome = run_verifier(
            &Ed25519SignatureVerifier::new(),
            ctx(&issuer, &key),
            &[0u8; 32],
            b"bytes",
            &[0u8; 64],
        )
        .expect("well-formed lengths");
        assert!(!outcome.is_verified());
    }

    #[test]
    fn delegation_establishes_when_all_conditions_hold() {
        let (issuer, agent, key) = ids();
        let claim = DelegationClaim::new(issuer.clone(), agent.clone(), key.clone());
        let outcome = verified_outcome(&issuer, &key, b"bytes");
        let anchors = anchors_trusting(&issuer, &key);
        let ev = VerifiedDelegation::establish(&claim, &outcome, &anchors).expect("establishes");
        assert_eq!(ev.issuer(), &issuer);
        assert_eq!(ev.agent(), &agent);
        assert_eq!(ev.key_ref(), &key);
        assert_eq!(ev.proof_of_possession(), ProofOfPossession::NotEstablished);
    }

    #[test]
    fn delegation_rejects_untrusted_key_even_when_signature_verifies() {
        let (issuer, agent, key) = ids();
        let claim = DelegationClaim::new(issuer.clone(), agent, key.clone());
        let outcome = verified_outcome(&issuer, &key, b"bytes");
        // Empty anchors: authentic but not anchored.
        assert_eq!(
            VerifiedDelegation::establish(&claim, &outcome, &TrustAnchors::new()),
            Err(EvidenceError::UntrustedKey)
        );
    }

    #[test]
    fn delegation_rejects_invalid_outcome() {
        let (issuer, agent, key) = ids();
        let claim = DelegationClaim::new(issuer.clone(), agent, key.clone());
        let outcome = VerificationOutcome::invalid(ctx(&issuer, &key));
        let anchors = anchors_trusting(&issuer, &key);
        assert_eq!(
            VerifiedDelegation::establish(&claim, &outcome, &anchors),
            Err(EvidenceError::SignatureNotVerified)
        );
    }

    #[test]
    fn mandate_rejects_binding_mismatch() {
        use kya_core::identity::PrincipalId;
        use kya_core::mandate::ValidityWindow;
        use kya_core::scope::{Action, Scope};
        let (issuer, _agent, key) = ids();
        let mandate = Mandate::new(
            issuer.clone(),
            PrincipalId::new("principal:alice").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            Scope::new().allow(Action::new("transfer").expect("valid")),
            ValidityWindow::new(1_000, 2_000).expect("valid"),
        );
        // Verified over UNRELATED bytes, not the mandate's canonical encoding.
        let outcome = verified_outcome(&issuer, &key, b"unrelated-bytes");
        let anchors = anchors_trusting(&issuer, &key);
        assert!(matches!(
            VerifiedMandate::establish(mandate, &outcome, b"unrelated-bytes", &anchors),
            Err(MandateBindingError::MandateBindingMismatch)
        ));
    }
}
