# Known Limitations

This document lists the structural limitations of the FintechBear KYA ("Know
Your Agent") open-source SDK at `v0.1.0`. These are deliberate boundaries of an
offline-evaluable foundation, not oversights. Read them before relying on the
SDK. They are consistent with [../README.md](../README.md),
[../SECURITY.md](../SECURITY.md), [security-limitations.md](security-limitations.md),
and [threat-model.md](threat-model.md).

FintechBear is the maintainer of this open-source project. It has no affiliation
with and no endorsement from Google, Visa, Mastercard, Skyfire, or any payment
network or standards body.

## Security capability limitations

### Agent proof of possession is NOT established

Local verification proves only an **issuer** signature over a delegation or
mandate. It does **not** prove that the agent currently controls its own private
key. The SDK reports this honestly: `VerifiedMandate` and `VerifiedDelegation`
expose `ProofOfPossession::NotEstablished`. Do not treat an issuer-signed
delegation as agent proof of possession.

### Online revocation is NOT implemented

The open-source core ships **no** concrete revocation service. Whether a mandate
has been revoked since issuance is a global, mutable, stage-D fact. The core
provides only the `OnlineAuthorizer` trait seam and the fail-closed `authorize`
bridge; the integrator (or a future managed platform) supplies the
implementation.

### Distributed / cumulative budget enforcement is NOT implemented

The core ships **no** budget ledger. Static evaluation checks a
per-transaction limit only; it cannot know how much an agent has already spent
across prior transactions. Cumulative-budget enforcement is a stage-D concern
behind the same `OnlineAuthorizer` seam.

### Global replay protection is NOT implemented

The core ships **no** replay store. Whether a request is a replay of one already
processed is a global, mutable, stage-D fact. It is not established offline.

### Payment execution enforcement is NOT provided by the local SDK

Execution enforcement (stage E) is a trait seam (`IntegrationClient`) only. The
open-source core ships no concrete payment or ledger execution path and makes
**no** production payment-execution-enforcement claim. Only an `Allow` from the
fail-closed `authorize` bridge should ever reach execution, and the integrator
owns the enforcement.

### Eligibility is not authorization (by design, stated for completeness)

A passing static evaluation (`EligibleForOnlineAuthorization`) is only
eligibility to proceed to stage D; it is never an `Allow` on its own. There is
deliberately no `From<PolicyOutcome> for Decision`.

## Protocol and cryptographic limitations

### AP2 wire interop is NOT interoperable

The `kya-adapter-ap2` crate is experimental and incomplete. It models
AP2-*style* mandate **constraints** and verifies signatures over caller-supplied
exact bytes, but it does **not** parse the real AP2 signature envelope, invents
no canonicalization or schema, bundles **no** AP2 conformance vectors, and makes
**no** AP2 wire-compatibility, conformance, or certification claim. Official AP2
affiliation: none. The exact AP2 envelope and whether AP2 publishes standalone
test vectors are `[UNVERIFIED]` and that byte-for-byte interop is BLOCKED. See
[protocol-compatibility.md](protocol-compatibility.md) and
[first-adapter-decision.md](first-adapter-decision.md).

### Only a narrow JWS subset is accepted

Only **Ed25519 / EdDSA** is accepted: raw Ed25519 (RFC 8032) and JWS
compact-form EdDSA (`alg: EdDSA`, RFC 7515 / 7518 / 8037) over the exact signing
input. `alg: none`, HMAC, RSA, and ECDSA are rejected. This is **not** a general
JOSE implementation: there is no JWE, no key-agreement, no JWK set resolution, no
`x5c`/`jku` fetching, and no algorithm negotiation. The base64url decoder is
strict (no padding, canonical trailing bits).

## Release / environment limitations (as verified in this environment)

### crates.io name availability is UNVERIFIED

The crates are unpublished. Whether the `kya-*` names are available on crates.io
was **not** verified in this offline environment and must be checked on a
networked host before any publish.

### Linux / macOS are NOT VERIFIED here

The Rule 16 gate set was run and is green on the Windows MSVC host used for this
work. Linux and macOS builds and gate runs could **not** be executed here and are
**NOT VERIFIED** in this environment; CI (`.github/workflows/ci.yml`,
`ubuntu-latest`) is responsible for the Linux run.

### Network-dependent supply-chain scans were NOT RUN here

`cargo deny check advisories` (RustSec DB), `cargo audit`, coverage-guided fuzz
*runs*, and SBOM generation were NOT RUN in this offline environment (the
advisory DB and the tools were unreachable / uninstallable). `cargo deny check
bans licenses sources` passed. See [release-readiness.md](release-readiness.md)
for the full NOT RUN / NOT VERIFIED list and the `deny.toml` posture.

### No independent third-party audit

The audit recorded in [security-audit.md](security-audit.md) is an **internal**
audit by the project's own engineering process. No independent third-party
security audit, penetration test, or formal verification has been performed, and
no regulatory, PCI-DSS, or SOC 2 certification is claimed. The SDK is not
declared production-safe.
