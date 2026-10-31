# Release Notes — v0.1.0

**Status: early foundation, work in progress. This is NOT a production release.**
FintechBear KYA ("Know Your Agent") `v0.1.0` is the open-source Rust foundation
for verifying AI-agent delegated authority. It ships the offline-evaluable
stages (A identity, B real Ed25519 / JWS-EdDSA verification, C static policy) and
the fail-closed trait seams for stages D and E. It ships **no** concrete online
authority and **no** concrete execution path, has not been independently audited,
carries no certification, and is not declared production-safe.

FintechBear is the maintainer of this open-source project. It has no affiliation
with and no endorsement from Google, Visa, Mastercard, Skyfire, or any payment
network or standards body.

## Highlights

- **One-import public facade (`kya-sdk`).** Run the whole verify + evaluate +
  authorize-seam flow from `use kya_sdk::prelude::*;`. The facade adds no
  behavior and no trust; it re-exports the reviewed inner crates. It bundles
  trust anchors and the key store in `TrustConfiguration` and exposes
  `requires_online_authorization` / `online_state_is_unestablished` so
  "eligibility is not authorization" is explicit in code.
- **Real cryptographic engine (`kya-crypto`).** Ed25519 (RFC 8032) and compact
  JWS-EdDSA (`alg: EdDSA`, RFC 7515 / 7518 / 8037) over the exact signing input.
  `alg: none`, HMAC, RSA, and ECDSA are rejected. Anchored by the official RFC
  8032 §7.1 vectors.
- **Full-mandate cryptographic binding.** A `VerifiedMandate` binds the complete
  mandate to the signature via the mandate's canonical encoding (an internal,
  non-standardized, versioned byte format), so a signature over one payload can
  never be paired with a substituted mandate.
- **Deterministic, offline stage-C evaluator.** Permitted action, exact amount
  and currency (integer minor units + ISO-4217, no floats), acting agent,
  validity window, audience, transaction binding, and approval requirement,
  producing a structured `PolicyOutcome` / `ReasonCode`.
- **Fail-closed stage-D bridge.** `kya_client::authorize` is the only path from a
  static `PolicyOutcome` to a final `Decision`. There is deliberately no
  `From<PolicyOutcome> for Decision`, and every error / timeout / unknown state /
  approval-required signal resolves to `Deny`.
- **Stable, machine-readable error codes.** Every public typed error is
  `#[non_exhaustive]`, implements `Display` + `std::error::Error`, and maps to a
  stable kebab-case `ErrorCode` via `AsErrorCode`.
- **Eleven runnable examples** covering trust configuration, signature
  verification (success and fail-closed rejections), stage-C evaluation, the
  missing-online-state case, and the experimental AP2 adapter — all using
  deterministic synthetic test keys and all stating what they do NOT verify.

## Security correction in this cycle

- **Verifier-sanction mint-point bypass (P0) fixed.** A confirmed
  release-blocking bypass that let an external crate mint trusted verified
  evidence with no cryptography was fixed by relocating ownership of the trusted
  verified-evidence types into `kya-crypto`, binding the sealed constructor to
  the reviewed verifier with no external parameterization and no dependency
  cycle. See [security-audit.md](security-audit.md) (finding KYA-P0-001).

## Honest status of the AP2 adapter

The `kya-adapter-ap2` crate is **experimental and incomplete**. It models
AP2-*style* constraints and verifies signatures over caller-supplied exact
bytes; it does **not** parse the real AP2 wire envelope, bundles no conformance
vectors, invents no endpoints, and makes **no** AP2 compatibility, conformance,
or certification claim. Official AP2 affiliation: none. It is deliberately not
part of the `kya-sdk` facade. See
[protocol-compatibility.md](protocol-compatibility.md).

## What this release does NOT do

See [known-limitations.md](known-limitations.md) for the full list. In brief:
no agent proof of possession, no online revocation, no distributed/cumulative
budget enforcement, no global replay protection, no payment-execution
enforcement, no AP2 wire interop, a narrow Ed25519/JWS-EdDSA subset (not general
JOSE), and no independent third-party audit or certification.

## Supported platforms

Developed and gate-verified on Windows (MSVC). Linux CI (`ubuntu-latest`) runs
the same Rule 16 gates. macOS is not verified in this cycle. MSRV is **1.85**,
edition 2021.

## Installation

The crates are unpublished (not on crates.io). Depend on the facade by git or
local path; see [../README.md](../README.md) section 4. The canonical public
repository URL is pending owner confirmation (OWNER INPUT REQUIRED): the
`Cargo.toml` metadata and the actual git remote currently disagree. See
[publication-checklist.md](publication-checklist.md).

## License

Dual-licensed under MIT OR Apache-2.0 at your option
([../LICENSE-MIT](../LICENSE-MIT), [../LICENSE-APACHE](../LICENSE-APACHE)).

## Verification this cycle

The full Rule 16 gate set (fmt, clippy `-D warnings`, tests, doctests, and
`RUSTDOCFLAGS=-D warnings` doc) passes on the MSVC host, and all 11 examples
compile and run. See [release-readiness.md](release-readiness.md) for the
per-gate and per-example evidence and the NOT RUN / NOT VERIFIED list,
[public-release-manifest.md](public-release-manifest.md) for the exact
SHIP / DO-NOT-SHIP file set, and [publication-checklist.md](publication-checklist.md)
for the required owner actions before publishing.
