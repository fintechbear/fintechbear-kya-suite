//! Delegation evidence: the raw-claim types, the typed failure reasons, and the
//! read-only **view traits** that stage-C policy consumes.
//!
//! The single most important rule of the SDK is that an unverified claim and
//! verified evidence are *different Rust types*, and there is no way to turn the
//! first into the second except by passing through actual cryptographic
//! verification against a trust anchor. This encodes the requirement that a
//! cryptographic signature is not, by itself, an authorization, and the stricter
//! requirement that the SDK never invents a "verified identity" out of thin air.
//!
//! - [`DelegationClaim`] is what arrives from the untrusted input boundary: an
//!   agent *claims* an issuer delegated authority to it. Anyone can construct
//!   one; it proves nothing. It lives here, in `kya-core`.
//! - The **verified** representations (`kya_crypto::VerifiedDelegation` and
//!   `kya_crypto::VerifiedMandate`) and their only constructors live in the
//!   reviewed `kya-crypto` crate, not here. See the
//!   [`crate::verification`] module docs for why: `kya-core` cannot name or
//!   depend on the concrete reviewed verifier, so the authority to mint verified
//!   evidence is placed in the one crate that performs real cryptography. That
//!   is the root-cause fix for the verifier-sanction bypass — an external crate
//!   has no visibility path to the verified-evidence constructors.
//!
//! Even verified evidence is **not** an authorization. It establishes
//! authenticity and trust-anchoring (stages A and B). Scope conformance is
//! stage C and current authority (revocation/budget/replay) is stage D.
//!
//! # What stays in `kya-core`
//!
//! This module keeps the crypto-free pieces every crate needs without naming a
//! verifier: the raw [`DelegationClaim`], the typed failure reasons
//! ([`EvidenceError`], [`MandateBindingError`]), the honest
//! [`ProofOfPossession`] state, and the read-only [`AuthenticatedMandate`] view
//! trait that the stage-C [`crate::policy::evaluate`] function reads. The
//! concrete verified-mandate type in `kya-crypto` implements
//! [`AuthenticatedMandate`], so `kya-core` can evaluate authenticated mandates
//! without depending on `kya-crypto` (dependencies still point inward).
//!
//! Implementing [`AuthenticatedMandate`] is **not** a trust claim: the trait is
//! a read-only accessor over a mandate and only ever produces a
//! [`crate::decision::PolicyOutcome`] (stage C), never an authorization. The
//! security boundary is the *construction* of a `VerifiedMandate`, which only
//! `kya-crypto` can perform.
//!
//! # Agent proof-of-possession is explicitly NOT established (v0.1)
//!
//! Everything the SDK verifies is an **issuer-signed** delegation/mandate: the
//! signature proves that a trust-anchored *issuer* key signed the delegation or
//! the mandate's canonical encoding. That is **not** proof that the *agent*
//! named in the delegation currently possesses its own private key. No
//! challenge-response, no agent-signed nonce, and no agent key check of any kind
//! is performed anywhere in this SDK.
//!
//! Rather than leave this gap implicit, the verified representations expose it
//! explicitly through [`ProofOfPossession`]. In v0.1 the verified-delegation and
//! verified-mandate proof-of-possession accessors both return
//! [`ProofOfPossession::NotEstablished`]. This is a deliberate, typed statement
//! of an absent capability (AGENTS.md Rule 20: no unverified capability may be
//! presented as if it existed), not a placeholder for one that secretly runs.

use crate::identity::{AgentId, IssuerId, TrustedKeyRef};
use crate::mandate::Mandate;
use core::fmt;

/// Explicit, typed state of **agent** proof-of-possession for a verified
/// representation.
///
/// Verifying an issuer-signed delegation or mandate (stages A/B) proves the
/// *issuer* signed it. It says nothing about whether the *agent* currently
/// controls its own private key. This SDK performs no agent key check, so the
/// only state it can honestly report is [`NotEstablished`](Self::NotEstablished).
///
/// The enum exists so that the absence of agent proof-of-possession is a value
/// a caller can observe and branch on, never an implicit assumption. It is
/// `#[non_exhaustive]` so that if a real proof-of-possession mechanism is ever
/// added it can be introduced as an additional variant without a breaking
/// change (AGENTS.md Rule 21) — but no such mechanism exists in v0.1, and none
/// is invented here (AGENTS.md Rule 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofOfPossession {
    /// The agent's possession of its private key has **not** been established.
    ///
    /// This is the only state v0.1 reports: the SDK verified an issuer-signed
    /// delegation/mandate and nothing more. A caller that requires the agent to
    /// have demonstrated key possession must obtain that proof by some other
    /// means; this SDK does not provide it and does not pretend to.
    NotEstablished,
}

impl fmt::Display for ProofOfPossession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofOfPossession::NotEstablished => {
                f.write_str("agent proof-of-possession not established")
            }
        }
    }
}

/// An **unverified** claim that an issuer delegated authority to an agent.
///
/// This is raw input from the untrusted boundary. Constructing one asserts
/// nothing about authenticity or trust; it is merely the structured form of
/// "the agent says issuer X delegated to it, signing with key reference K".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationClaim {
    issuer: IssuerId,
    agent: AgentId,
    claimed_key_ref: TrustedKeyRef,
}

impl DelegationClaim {
    /// Record a raw delegation claim. This performs no verification.
    pub fn new(issuer: IssuerId, agent: AgentId, claimed_key_ref: TrustedKeyRef) -> Self {
        DelegationClaim {
            issuer,
            agent,
            claimed_key_ref,
        }
    }

    /// The issuer the agent claims delegated to it.
    pub fn issuer(&self) -> &IssuerId {
        &self.issuer
    }

    /// The agent the claim is about.
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }

    /// The key reference the claim says the issuer signed with.
    pub fn claimed_key_ref(&self) -> &TrustedKeyRef {
        &self.claimed_key_ref
    }
}

/// Why a [`DelegationClaim`] could not be promoted to verified delegation
/// evidence.
///
/// Each variant is a distinct, fail-closed reason; none of them is a near-miss
/// that could be rounded up to "verified". `kya-crypto`'s verified-delegation
/// constructor returns these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceError {
    /// The verification outcome's status was not `Verified`.
    SignatureNotVerified,
    /// The issuer named by the claim did not match the issuer in the verified
    /// context. A signature verified for one issuer cannot vouch for another.
    IssuerMismatch,
    /// The issuer/key pair that produced the outcome is not in the configured
    /// trust anchors. Authenticity without trust-anchoring is not evidence.
    UntrustedKey,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvidenceError::SignatureNotVerified => {
                f.write_str("delegation signature did not verify")
            }
            EvidenceError::IssuerMismatch => {
                f.write_str("verified issuer does not match the claimed issuer")
            }
            EvidenceError::UntrustedKey => {
                f.write_str("verifying key is not an anchored trust for this issuer")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

/// Why a mandate could not be promoted to verified-mandate evidence.
///
/// Each variant is a distinct, fail-closed reason. The crucial one is
/// [`MandateBindingMismatch`](MandateBindingError::MandateBindingMismatch): the
/// signature verified over *some* bytes, but those bytes are not the canonical
/// encoding of the mandate presented for evaluation, so the signature does not
/// cover this mandate. That is exactly the substitution attack this defeats.
/// `kya-crypto`'s verified-mandate constructor returns these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MandateBindingError {
    /// The verification outcome's status was not `Verified`.
    SignatureNotVerified,
    /// The issuer named by the mandate did not match the issuer in the verified
    /// context. A signature verified for one issuer cannot vouch for another's
    /// mandate.
    IssuerMismatch,
    /// The issuer/key pair that produced the outcome is not in the configured
    /// trust anchors. Authenticity without trust-anchoring is not evidence.
    UntrustedKey,
    /// The bytes that were actually verified are **not** the canonical encoding
    /// of the mandate presented here. The signature therefore does not commit
    /// to this mandate: a genuine signature over one mandate is being paired
    /// with a different (substituted) mandate. Fails closed.
    MandateBindingMismatch,
}

impl fmt::Display for MandateBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MandateBindingError::SignatureNotVerified => {
                f.write_str("mandate signature did not verify")
            }
            MandateBindingError::IssuerMismatch => {
                f.write_str("verified issuer does not match the mandate issuer")
            }
            MandateBindingError::UntrustedKey => {
                f.write_str("verifying key is not an anchored trust for this issuer")
            }
            MandateBindingError::MandateBindingMismatch => {
                f.write_str("verified signature does not cover this mandate's canonical encoding")
            }
        }
    }
}

impl std::error::Error for MandateBindingError {}

/// A read-only view of an **authenticated** mandate that stage-C policy
/// evaluation consumes.
///
/// This trait exists so that [`crate::policy::evaluate`] can read the
/// authenticated mandate's fields without `kya-core` depending on `kya-crypto`
/// (where the concrete `VerifiedMandate` lives). Dependencies still point
/// inward: `kya-crypto` implements this `kya-core` trait for its verified type.
///
/// # Implementing this is not a trust assertion
///
/// Implementing `AuthenticatedMandate` does **not** mint trusted evidence and
/// does **not** yield an authorization. `evaluate` only ever produces a
/// [`crate::decision::PolicyOutcome`] (stage C), which can never become an
/// `Allow` without the stage-D authority. The security boundary is the
/// *construction* of a `VerifiedMandate`, which only `kya-crypto` can do by
/// running the reviewed verifier over a real signature. A test or adapter may
/// implement this trait to exercise the evaluator, exactly as it could always
/// build a `TransactionIntent`; neither is an authorization.
pub trait AuthenticatedMandate {
    /// The authenticated mandate whose constraints evaluation reads.
    fn mandate(&self) -> &Mandate;

    /// The issuer whose signature over this mandate was verified.
    fn issuer(&self) -> &IssuerId;

    /// The agent the verified mandate was granted to.
    fn agent(&self) -> &AgentId;

    /// The trusted key reference the mandate was verified against.
    fn key_ref(&self) -> &TrustedKeyRef;

    /// The agent proof-of-possession state. Always
    /// [`ProofOfPossession::NotEstablished`] in v0.1.
    fn proof_of_possession(&self) -> ProofOfPossession {
        ProofOfPossession::NotEstablished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (IssuerId, AgentId, TrustedKeyRef) {
        (
            IssuerId::new("issuer:acme").expect("valid"),
            AgentId::new("agent:1").expect("valid"),
            TrustedKeyRef::new("kid:1").expect("valid"),
        )
    }

    #[test]
    fn delegation_claim_is_a_pure_record() {
        let (issuer, agent, key) = ids();
        let claim = DelegationClaim::new(issuer.clone(), agent.clone(), key.clone());
        assert_eq!(claim.issuer(), &issuer);
        assert_eq!(claim.agent(), &agent);
        assert_eq!(claim.claimed_key_ref(), &key);
    }

    #[test]
    fn evidence_error_display_is_honest_and_non_sensitive() {
        assert_eq!(
            EvidenceError::SignatureNotVerified.to_string(),
            "delegation signature did not verify"
        );
        assert_eq!(
            EvidenceError::IssuerMismatch.to_string(),
            "verified issuer does not match the claimed issuer"
        );
        assert_eq!(
            EvidenceError::UntrustedKey.to_string(),
            "verifying key is not an anchored trust for this issuer"
        );
    }

    #[test]
    fn mandate_binding_error_display_is_honest_and_non_sensitive() {
        assert_eq!(
            MandateBindingError::SignatureNotVerified.to_string(),
            "mandate signature did not verify"
        );
        assert_eq!(
            MandateBindingError::MandateBindingMismatch.to_string(),
            "verified signature does not cover this mandate's canonical encoding"
        );
    }

    #[test]
    fn proof_of_possession_display_is_honest() {
        assert_eq!(
            ProofOfPossession::NotEstablished.to_string(),
            "agent proof-of-possession not established"
        );
    }
}
