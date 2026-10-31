#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Rule 6: production paths must not use unwrap/expect (clippy warns workspace-wide).
// Tests MAY use them for brevity, so relax the lint under `cfg(test)` only.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # kya-adapter-ap2
//!
//! <div class="warning">
//!
//! **EXPERIMENTAL AND INCOMPLETE — NOT full AP2 support.** This crate models
//! AP2-*style* mandate **constraints** locally and verifies signatures over
//! **caller-supplied exact bytes** (or the SDK's own internal canonical mandate
//! encoding). It does **not** implement the Google Agent Payments Protocol
//! (AP2) wire envelope: it parses no AP2 token, invents no canonicalization,
//! schema, or endpoints, has **no** AP2 conformance test vectors, and makes
//! **no** claim of AP2 wire compatibility, certification, or audit.
//! **Official affiliation: none.** Do **not** rely on it for production AP2
//! interoperability. See "What this crate IS / is NOT" below for the precise
//! boundary.
//!
//! </div>
//!
//! The first protocol adapter of the FintechBear KYA SDK, targeting the Google
//! Agent Payments Protocol (AP2) per [`docs/first-adapter-decision.md`]
//! (ADR-0001). It is an **outer-ring** crate: it depends *inward* on
//! [`kya_core`] (the domain) and on [`kya_crypto`] (the concrete stage-B
//! engine), and it introduces **no** HTTP, database, cloud, or endpoint
//! dependency and **no** new third-party dependency (Clean Architecture,
//! AGENTS.md Rules 2 and 13).
//!
//! ## What this crate IS (independently verifiable)
//!
//! This adapter implements only the parts of an AP2-style mandate that can be
//! modeled and tested **without** the unverified AP2 signature envelope:
//!
//! - Explicit, strongly-typed Rust types for the AP2 mandate **constraint**
//!   concepts that map cleanly onto the KYA domain — a permitted
//!   [`kya_core::scope::Action`], an exact [`kya_core::money::Money`] amount, a
//!   [`kya_core::money::CurrencyCode`] restriction, and the issuer / agent /
//!   principal / merchant / resource identities
//!   ([`constraints::Ap2MandateConstraints`]).
//! - A pure mapping function that turns those typed constraints into a
//!   [`kya_core::mandate::Mandate`] (with its [`kya_core::scope::Scope`]) so the
//!   existing deterministic **stage-C** evaluator
//!   ([`kya_core::policy::evaluate`]) runs **unchanged**
//!   ([`constraints::Ap2MandateConstraints::to_mandate`]).
//! - A verification entry ([`verify::verify_ap2_delegation`]) that accepts the
//!   **caller-supplied exact signed bytes** and signature and routes them
//!   through the sealed [`kya_crypto::verify_delegation`] path to obtain genuine
//!   [`kya_crypto::VerifiedDelegation`] evidence. The adapter never
//!   invents what bytes AP2 signs.
//!
//! ## What this crate is NOT, and what is BLOCKED
//!
//! Per ADR-0001 the exact AP2 signature **envelope** (JWT/JWS vs a W3C-VC-style
//! proof) and its accepted algorithms, and whether AP2 publishes standalone
//! **test vectors**, are both **`[UNVERIFIED]`**. Those are hard dependencies for
//! byte-for-byte AP2 interop, so that work is **BLOCKED** and deliberately not
//! attempted here:
//!
//! - This crate parses **no** real AP2 token and asserts **no** AP2
//!   wire-compatibility. The caller is responsible for producing the exact
//!   signed bytes; the adapter does not claim those bytes match any AP2 layout.
//! - It invents **no** canonicalization of wire fields (that would be an
//!   unverifiable guess), **no** provider endpoints (Google/Visa/Skyfire/
//!   Mastercard), and **no** universal payment mandate.
//! - It never produces a [`kya_core::decision::Decision`] and never yields an
//!   `Allow`. Issuer authorization, revocation, cumulative budget, and global
//!   replay remain **stage D**, reachable only through the fail-closed
//!   `kya_client::authorize` bridge. A verified AP2 constraint set is at most
//!   [`kya_core::decision::PolicyOutcome::EligibleForOnlineAuthorization`],
//!   which is explicitly **not** permission to execute a payment.
//!
//! The honest status, including the BLOCKED boundary, is recorded in
//! [`docs/protocol-compatibility.md`] and ADR-0001's "Open questions". This
//! crate makes **no** claim of AP2 certification, audit, affiliation, or wire
//! compatibility (AGENTS.md Rule 20).
//!
//! ## Honest status summary
//!
//! - **Supported behaviour:** typed AP2-*style* constraint concepts (permitted
//!   action, exact amount, currency, issuer / agent / principal / merchant /
//!   resource identities, validity window, optional audience / approval /
//!   binding) mapped onto the `kya-core` mandate/scope domain, plus signature
//!   verification over caller-supplied exact bytes or the mandate's internal
//!   canonical encoding, routed through the real `kya-crypto` engine.
//! - **Unsupported AP2 features:** the real AP2 signature envelope (JWT/JWS vs
//!   W3C-VC proof), AP2 wire canonicalization / field layout / schema, provider
//!   endpoints (Google / Visa / Skyfire / Mastercard), a universal payment
//!   mandate, and any stage-D authority behaviour.
//! - **Missing interoperability evidence:** no AP2 conformance test vectors are
//!   available or verified, and no AP2 wire envelope has been verified, so
//!   byte-for-byte AP2 interop is neither implemented nor claimed.
//! - **Official affiliation: none.** No affiliation with, endorsement by, or
//!   certification from Google or any AP2 stakeholder.
//! - **Production usage limitations:** because the wire envelope is unverified
//!   and no conformance vectors exist, this adapter must not be relied on for
//!   production AP2 interoperability. It is suitable only for modeling and
//!   testing AP2-*style* constraints locally against the KYA domain.
//!
//! ## How the pieces fit
//!
//! A typical offline flow:
//!
//! 1. Build [`constraints::Ap2MandateConstraints`] from the AP2 mandate's
//!    constraint fields (action, amount, currency, identities, validity, and
//!    optional audience / approval / binding).
//! 2. Call [`constraints::Ap2MandateConstraints::to_mandate`] to get a
//!    [`kya_core::mandate::Mandate`].
//! 3. Call [`verify::verify_ap2_delegation`] with the caller-supplied exact
//!    signed bytes + signature to obtain verified evidence via `kya-crypto`.
//! 4. Hand the evidence, mandate, and a [`kya_core::mandate::TransactionIntent`]
//!    to [`kya_core::policy::evaluate`] (stage C). A passing result is
//!    *eligibility*, not authorization.
//!
//! [`docs/first-adapter-decision.md`]: https://github.com/fintechbear/fintechbear-kya-suite/blob/main/docs/first-adapter-decision.md
//! [`docs/protocol-compatibility.md`]: https://github.com/fintechbear/fintechbear-kya-suite/blob/main/docs/protocol-compatibility.md

pub mod constraints;
pub mod error;
pub mod verify;

pub use constraints::{Ap2Identities, Ap2MandateConstraints, Ap2SpendingLimit};
pub use error::Ap2AdapterError;
pub use verify::{
    verify_ap2_delegation, verify_ap2_mandate, Ap2SignedMandate, Ap2SignedMandateBinding,
};
