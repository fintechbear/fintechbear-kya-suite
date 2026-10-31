#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Rule 6: production paths must not use unwrap/expect (clippy warns workspace-wide).
// Tests MAY use them for brevity, so relax the lint under `cfg(test)` only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # kya-core
//!
//! Pure, dependency-light core of the FintechBear KYA SDK. This crate holds the
//! domain and protocol value types, exact monetary arithmetic, the
//! trust/cryptographic-verification **trait seams** (no concrete algorithm), the
//! deterministic static policy evaluator, and the fail-closed decision types.
//!
//! ## What this crate deliberately does NOT do
//!
//! - It performs **no I/O**: no HTTP, no database, no cloud or payment-provider
//!   access. Those live behind traits in `kya-client`.
//! - It implements **no cryptographic algorithm**. Signature verification is
//!   expressed only as the [`verification::SignatureVerifier`] trait seam.
//! - It never uses floating point for money.
//! - It does **not** establish **agent proof-of-possession**. Verifying an
//!   issuer-signed delegation/mandate proves the *issuer* signed it, not that
//!   the *agent* holds its own private key; no agent key check exists. That gap
//!   is surfaced explicitly as [`evidence::ProofOfPossession::NotEstablished`]
//!   on the verified representations (see [`evidence`]).
//!
//! ## The five authorization stages (see `AGENTS.md`)
//!
//! Authorization is split into five non-interchangeable stages:
//!
//! - **Stage A — Identity**: resolve who the agent claims to be ([`identity`]),
//!   and separate a raw delegation claim from verified delegation evidence
//!   ([`evidence`]).
//! - **Stage B — Signature**: verify cryptographic authenticity of the mandate
//!   ([`verification`], trait seam only).
//! - **Stage C — Static policy**: deterministic scope/limit checks, offline
//!   ([`policy`], producing a [`decision::PolicyOutcome`]).
//! - **Stage D — Online authoritative authorization**: revocation, cumulative
//!   budget, global replay state. Lives in `kya-client`; **not** in this crate.
//! - **Stage E — Execution enforcement**: lives in the integration layer.
//!
//! A valid signature (stage B) is **not** an authorization. Stages C and D are
//! not interchangeable: offline evaluation cannot establish current revocation,
//! cumulative budget, or global replay state without trustworthy authoritative
//! evidence.

pub mod decision;
pub mod error;
pub mod evidence;
pub mod identity;
pub mod mandate;
pub mod money;
pub mod policy;
pub mod scope;
pub mod verification;
