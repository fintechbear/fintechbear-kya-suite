# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Public APIs follow semantic versioning: breaking changes require a major version
bump, and error enums are `#[non_exhaustive]` to permit additive evolution.

## [Unreleased] - v0.1.0 in progress (NOT a release)

This section records work in progress toward `v0.1.0` (through the Phase 8
public-release preparation). It is **not** a release and does not declare the
SDK production-ready, audited, or certified.

### Added

- **`kya-sdk` public facade crate.** A thin, outermost-ring crate that
  re-exports a curated, stable surface over the inner crates so a consumer can
  run the whole verify + evaluate + authorize flow from one entry point
  (`use kya_sdk::prelude::*;`). It adds no new behaviour and no new trust. It
  bundles trust anchors and the key store together in `TrustConfiguration`, and
  exposes `requires_online_authorization` and `online_state_is_unestablished`
  helpers that make "eligibility is not authorization" explicit.
- **Ten runnable examples** under `examples/` (`example_01_configure_trust`
  through `example_10_ap2_adapter`) plus `offline_evaluation`, and a
  public-surface integration test at `crates/kya-sdk/tests/public_surface.rs`.
- **Expanded project documentation:** a rewritten 18-section `README.md`, new
  `docs/quickstart.md`, `docs/api-usage.md`, `docs/supported-protocols.md`,
  `docs/security-limitations.md`, and `docs/future-commercial-platform.md`, and
  updates to `docs/architecture.md` and `docs/trust-model.md`.

### Changed

- **AP2 honesty correction.** The AP2 adapter (`kya-adapter-ap2`) is documented
  as **experimental and incomplete**: it maps AP2 mandate constraint concepts
  onto stage C and verifies over caller-supplied exact bytes, but it parses no
  real AP2 envelope and makes no AP2 wire-compatibility, conformance, or
  certification claim. It is deliberately not part of the facade.

### Security

- **Check A - exported-macro verifier bypass fixed at the root.** The
  verified-evidence mint-point no longer lives in `kya-core` behind a
  downstream-callable seam. It was relocated privately into `kya-crypto`, bound
  to the one reviewed concrete `Ed25519SignatureVerifier`: the mint-point is
  crate-private and takes the verifier by concrete type, so an external crate
  can no longer mint a fake verified outcome from an always-`Verified` verifier.
  Locked in by an external-crate forgery regression test.
- **Check B - full-mandate cryptographic binding.** Verification now mints a
  `VerifiedMandate` that cryptographically binds the **complete** mandate to the
  signature via the mandate's canonical encoding (an internal, non-standardized,
  versioned byte format). Stage C (`evaluate`) consumes the verified mandate, so
  a valid signature over one payload can no longer be paired with a substituted
  mandate. Field-substitution regression tests were added.
- **Check C - fail-closed decision bridge confirmed.** `kya_client::authorize`
  remains the only `PolicyOutcome` to `Decision` bridge; it contacts the
  authority only on an eligible outcome and maps denial, approval-required, and
  every error to `Deny`. There is still no `From<PolicyOutcome> for Decision`.
- **Check D - explicit proof-of-possession state.** `VerifiedMandate` and
  `VerifiedDelegation` expose `ProofOfPossession::NotEstablished`: the SDK
  verifies only an issuer signature and does not prove agent key possession. The
  gap is represented explicitly in the type system rather than hidden.

## [0.1.0]

Initial open-source workspace foundation.

### Added

- Cargo workspace with three library crates:
  - `kya-core`: domain and protocol value types, exact monetary arithmetic
    (`i128` minor units plus an explicit ISO-4217 `CurrencyCode`, no floats,
    checked and fail-closed), identity and explicit allow-listed trust anchors,
    scope and mandate types, the `SignatureVerifier` trait seam (no cryptographic
    algorithm), the deterministic stage-C policy evaluator, and the
    `Decision` / `PolicyOutcome` / `ReasonCode` types. Performs no I/O.
  - `kya-protocol`: the protocol version marker and language-independent wire
    shapes that reference the core domain types.
  - `kya-client`: the stage-D `OnlineAuthorizer` seam, the stage-E
    `IntegrationClient` seam, a runtime-agnostic pure-`std` `block_on`, and the
    fail-closed `authorize` bridge.
- The deliberate absence of `From<PolicyOutcome> for Decision`: the only path
  from a static outcome to a final decision is the fail-closed `authorize`
  bridge.
- The `offline_evaluation` example demonstrating stages A, B, and C running
  offline and showing that the result is not an authorization.
- Project documentation: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `AGENTS.md`, and the `docs/` set covering architecture,
  threat model, product strategy, the open-source and commercial boundary, and
  the future platform architecture.
- Dual licensing under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- CI quality gates: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, `cargo test --workspace
  --all-features`, and `cargo doc --workspace --no-deps`.

### Security

- Deny-by-default, fail-closed authorization posture throughout.
- `#![forbid(unsafe_code)]` in every crate; `unsafe_code = "forbid"` workspace
  wide.
- Documented the central security distinction: a valid signature is not an
  authorization, and offline verification cannot establish current revocation,
  cumulative-budget, or global replay state without trustworthy authoritative
  evidence.

<!--
Repository URL reconciled (Phase 9): all links below use
https://github.com/fintechbear/fintechbear-kya-suite, the configured git remote
`origin` and the only verified offline signal of the repository location. Offline
verification cannot confirm who controls that GitHub repository, so the owner must
confirm they control it before publishing. No URL is invented. See
docs/publication-checklist.md.
-->
[Unreleased]: https://github.com/fintechbear/fintechbear-kya-suite/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/fintechbear/fintechbear-kya-suite/releases/tag/v0.1.0
