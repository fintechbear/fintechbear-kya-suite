#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Rule 6: production paths must not use unwrap/expect (clippy warns workspace-wide).
// Tests MAY use them for brevity, so relax the lint under `cfg(test)` only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # kya-crypto
//!
//! The concrete, outer-ring cryptographic verification engine of the
//! FintechBear KYA SDK. This crate provides the real Ed25519 (and JWS-EdDSA
//! compact-form) signature verification that [`kya_core`] deliberately refuses
//! to carry, and it depends *inward* on `kya-core` (Clean Architecture,
//! AGENTS.md Rule 2). `kya-core` itself stays crypto-free: it holds no key
//! bytes and no cryptographic dependency.
//!
//! ## What a verified signature means (and does not mean)
//!
//! A successful signature verification proves **authenticity and integrity** of
//! some bytes under a key. That is stage B. It is emphatically **not** an
//! authorization. This engine establishes authenticity, trust-anchoring, the
//! validity window (nbf/exp), audience, and transaction binding — the stage-A/B
//! and static parts of the model — and it returns verified *evidence*
//! ([`VerifiedDelegation`]). It never returns an `Allow` and
//! never performs final payment authorization; the online authoritative check
//! (stage D) lives in `kya-client`.
//!
//! It also does **not** prove **agent proof-of-possession**. The signature this
//! engine verifies is the *issuer's* over the delegation/mandate; it is not a
//! fresh demonstration that the *agent* currently controls its own private key.
//! No agent challenge-response or agent key check exists in v0.1. That gap is
//! reported explicitly by [`kya_core::evidence::ProofOfPossession`]
//! (always [`NotEstablished`](kya_core::evidence::ProofOfPossession::NotEstablished)),
//! which the verified representations surface so the two facts are never
//! conflated.
//!
//! ## Trust is explicit and allow-listed
//!
//! A valid signature over trusted key bytes is still only authenticity. Whether
//! a key is *trusted* for an issuer is decided independently against the
//! caller's [`kya_core::identity::TrustAnchors`]. There is no URL fetching, no
//! implicit trust, and no wildcard trust (AGENTS.md Rule 11). The caller
//! supplies a [`TrustedKeyStore`] mapping an `(issuer, key_ref)` pair to the
//! concrete Ed25519 public-key bytes, and that pair must *also* be present in
//! the `TrustAnchors` before any evidence is minted.
//!
//! ## The sealed path to evidence
//!
//! The only way this engine produces a [`VerifiedDelegation`] is by routing the
//! concrete [`Ed25519SignatureVerifier`] through this crate's own sealed
//! mint-point (`crate::evidence`, bound to that one reviewed verifier) to obtain
//! a genuine verified outcome, then validating audience, nbf/exp, and binding,
//! and only then calling the crate-private verified-evidence constructor. A
//! caller-provided boolean or enum is never sufficient, and no external verifier
//! can reach the mint-point.
//!
//! ## Algorithm allowlist
//!
//! Only Ed25519 / `EdDSA` is accepted. `alg: none`, HMAC, RSA, and ECDSA
//! algorithm names, the empty string, and any other identifier are rejected
//! with [`CryptoVerificationError::UnsupportedAlgorithm`] (algorithm-confusion
//! and downgrade defense). The compact-JWS parser is implemented directly
//! against this allowlist rather than via a general JWT framework.
//!
//! ## Protocol compatibility scope
//!
//! Per `docs/first-adapter-decision.md`, the real AP2 envelope and its
//! algorithms are UNVERIFIED. This crate therefore implements only
//! independently verifiable primitives — raw detached Ed25519 and JWS-EdDSA
//! over caller-supplied **exact** bytes — and makes **no** claim of AP2 wire
//! compatibility. In particular it does not invent a canonicalization of
//! `kya-protocol`'s wire fields, which are not a standardized signed format.

mod b64url;
mod engine;
mod error;
mod evidence;
mod jws;
mod keystore;
mod verifier;

pub use engine::{verify_delegation, verify_mandate, SignedClaim, SignedMandate};
pub use error::CryptoVerificationError;
pub use evidence::{VerificationOutcome, VerificationProof, VerifiedDelegation, VerifiedMandate};
pub use jws::JwsEdDsa;
pub use keystore::{Ed25519PublicKeyBytes, TrustedKeyStore};
pub use verifier::{Ed25519SignatureVerifier, ACCEPTED_ALGORITHM};
