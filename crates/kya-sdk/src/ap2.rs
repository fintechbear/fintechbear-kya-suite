//! Experimental, incomplete AP2 constraint adapter — **not** full AP2 support.
//!
//! <div class="warning">
//!
//! **EXPERIMENTAL AND INCOMPLETE.** This module surfaces the `kya-adapter-ap2`
//! crate through the facade, but it does **not** implement the Google Agent
//! Payments Protocol (AP2) wire format. It is a local, AP2-*style* constraint
//! mapping with real signature verification over **caller-supplied exact
//! bytes** (or the SDK's own internal canonical mandate encoding). Do not treat
//! it as AP2 interoperability.
//!
//! </div>
//!
//! The facade deliberately keeps the AP2 adapter out of its top-level surface
//! and out of the [`crate::prelude`] so that a consumer only reaches it after
//! reading these limitations. To use it, depend on `kya-adapter-ap2` directly;
//! this module documents the honest boundary and links to that crate.
//!
//! # Supported behaviour
//!
//! - Explicit, strongly-typed Rust types for AP2-*style* mandate **constraint**
//!   concepts (permitted action, exact [`crate::Money`] amount and
//!   [`crate::CurrencyCode`], and the issuer / agent / principal / merchant /
//!   resource identities), mapped onto the `kya-core` [`crate::Mandate`] /
//!   [`crate::Scope`] domain so the unchanged stage-C evaluator runs over them.
//! - Signature verification routed through the real [`crate::verify_delegation`]
//!   / [`crate::verify_mandate`] engine, either over caller-supplied **exact**
//!   signed bytes or over the SDK's internal canonical mandate encoding. The
//!   same sealed, fail-closed guarantees apply; a verified AP2-style constraint
//!   set is at most eligible for stage D and is never an authorization.
//!
//! # Unsupported AP2 features
//!
//! - **No** parsing of a real AP2 signature envelope (JWT/JWS vs a
//!   W3C-VC-style proof is unverified).
//! - **No** AP2 wire canonicalization, field layout, or schema.
//! - **No** provider endpoints (Google / Visa / Skyfire / Mastercard) and **no**
//!   universal payment mandate.
//! - **No** stage-D authority, revocation, budget, or replay handling (those
//!   stay behind the fail-closed [`crate::authorize`] bridge).
//!
//! # Missing interoperability evidence
//!
//! - There are **no** AP2 conformance test vectors available or verified.
//! - There is **no** verified AP2 wire envelope: the exact bytes AP2 signs are
//!   not established, so byte-for-byte AP2 interop is neither implemented nor
//!   claimed.
//!
//! # Official affiliation: none
//!
//! This adapter has **no** affiliation with, endorsement by, or certification
//! from Google or any AP2 stakeholder. It makes **no** claim of AP2
//! certification, audit, or protocol compatibility (AGENTS.md Rule 20).
//!
//! # Production usage limitations
//!
//! Because the wire envelope is unverified and no conformance vectors exist, do
//! **not** rely on this adapter for production AP2 interoperability. It is
//! suitable for modeling and testing AP2-*style* constraints locally against
//! the KYA domain, nothing more. When the AP2 envelope is later verified from
//! published schemas, a byte-exact parser can be layered in front of the
//! existing verification seam without weakening it.
//!
//! See the `kya-adapter-ap2` crate documentation for the full, matching
//! statement of this boundary.
