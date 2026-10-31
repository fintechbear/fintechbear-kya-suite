# Security Policy

FintechBear KYA is a security-critical financial-authorization SDK. We take
security reports seriously and we try to be honest about what the SDK does and
does not protect against.

## Supported versions

The project is at an early `v0.1.0` foundation. Only the latest `0.1.x` release
line receives security fixes. Pre-release and unreleased code is not covered.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |
| < 0.1   | No                 |

## Threat model summary

FintechBear KYA treats all mandates, requests, signatures, and keys arriving
from an agent or the network as attacker-controlled. Those inputs are parsed
without panicking and yield typed errors on malformed input. Nothing from that
boundary is trusted until it is verified against an explicitly configured,
allow-listed trust anchor and checked by policy. The full adversary and trust-
boundary analysis is in [docs/threat-model.md](docs/threat-model.md) and
[docs/trust-model.md](docs/trust-model.md).

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**. Do not open a public
issue, pull request, or discussion for a security problem.

The primary channel is **GitHub Private Vulnerability Reporting** via GitHub
Security Advisories. To submit a report:

1. Go to the repository on GitHub:
   [https://github.com/fintechbear/fintechbear-kya-suite](https://github.com/fintechbear/fintechbear-kya-suite).
2. Open the **Security** tab, then choose **Report a vulnerability**. This
   opens a private draft security advisory that is visible only to you and the
   repository maintainers (the advisories live at
   [https://github.com/fintechbear/fintechbear-kya-suite/security/advisories](https://github.com/fintechbear/fintechbear-kya-suite/security/advisories)).
3. Fill in the affected crate and version, a clear description of the issue, and
   a proof of concept if you have one.
4. Submit the advisory privately. Do not include live secrets or third-party
   data in your report.

Reporting through GitHub Private Vulnerability Reporting keeps the discussion
confidential until a fix is coordinated, and it lets the maintainers request a
CVE and publish an advisory when the fix ships.

> **OWNER ACTION (cannot be confirmed in this offline environment):** The
> repository is published, so the "before public release" gate no longer
> applies. What remains is confirming that GitHub Private Vulnerability
> Reporting is **enabled** for the repository: a repository admin enables it in
> GitHub under **Settings -> Code security and analysis -> Private vulnerability
> reporting -> Enable**. Whether this channel is currently enabled **cannot be
> verified from this offline environment**, so it is **not claimed to be active
> here**. Until you can confirm the "Report a vulnerability" button appears on
> the repository's Security tab, treat enabling and confirming this channel as a
> pending owner action.

## Coordinated disclosure and response

- We aim to acknowledge a report within a few business days.
- We will work with you to understand and validate the issue, assign a severity,
  and prepare a fix.
- We ask that you give us reasonable time to release a fix before any public
  disclosure, and we will coordinate timing with you.
- Any change that fixes a security issue in identity, verification, policy,
  decision, or authorization code will ship with a security regression test that
  locks in the corrected behavior.

These timelines are good-faith targets, not contractual commitments.

## Scope and limitations (read this carefully)

The open-source core is deliberately limited in what it can assert. Understanding
these boundaries is itself part of using the SDK safely.

### A valid signature is not an authorization

A valid cryptographic signature proves the authenticity and integrity of some
bytes. It does **not** prove that a transaction is authorized. A signed mandate
can still be revoked, over budget, or replayed.

### Offline verification cannot establish current authoritative state

Offline evaluation **cannot** establish:

- current **revocation** state (has the mandate been revoked since it was
  issued?),
- **cumulative budget** state (has the agent already spent its allowance across
  prior transactions?), or
- global **replay** state (is this request a replay of one already processed?).

These facts are global and mutable. Establishing them requires trustworthy
authoritative evidence obtained online. The offline stages (A, B, and C) can
only tell you that nothing static forbids the request.

### Agent proof of possession is not established

Local verification proves only an **issuer** signature over a delegation or
mandate. It does **not** prove that the agent currently controls its own private
key. The SDK reports this honestly: a `VerifiedMandate` and `VerifiedDelegation`
expose `ProofOfPossession::NotEstablished`. Do not treat an issuer-signed
delegation as agent proof of possession.

### Eligibility is not authorization

A passing static evaluation (`EligibleForOnlineAuthorization`) is only
eligibility to proceed to stage D. It is never an `Allow` on its own. The only
path from a static `PolicyOutcome` to a final `Decision` is the fail-closed
`kya_client::authorize` bridge.

### What the open-source core does and does not provide in v0.1.0

- **Stage B (signature verification)** now ships a real engine in the
  `kya-crypto` outer-ring crate (Ed25519 per RFC 8032 and JWS-EdDSA per RFC
  7515 / 7518 / 8037). Only Ed25519 / EdDSA is accepted; `alg: none`, HMAC, RSA,
  and ECDSA are rejected. `kya-core` itself still carries no cryptographic
  algorithm and only defines the trait description seam; the verified-evidence
  mint-points live privately inside `kya-crypto`.
- **Stage D (online authoritative authorization)** ships as a trait seam
  (`OnlineAuthorizer`) plus the fail-closed `authorize` bridge. The core ships no
  concrete authority, so revocation, cumulative-budget, and replay checks are not
  performed by the open-source core itself.
- **Stage E (execution enforcement)** ships as a trait seam
  (`IntegrationClient`). The core ships no concrete payment or ledger execution
  path, and the SDK makes no production payment-execution-enforcement claim.

Downstream integrators, or the future commercial platform described in
[docs/future-commercial-platform.md](docs/future-commercial-platform.md),
supply the concrete stage-D and stage-E implementations.

## Fail-closed posture

The SDK is deny-by-default. Any error, timeout, unknown state, or
approval-required signal resolves to `Deny`. There is intentionally no
`From<PolicyOutcome> for Decision`; the only path from a static outcome to a
final decision is the fail-closed `kya_client::authorize` bridge.

## No certification, audit, or affiliation claimed

No independent security audit has been performed on this SDK, and no security
certification is claimed. This project holds no regulatory, PCI-DSS, or SOC 2
certification, and it asserts no full AP2 conformance and no production
payment-execution enforcement. Do not represent the SDK as audited, certified,
or production-safe. FintechBear is the maintainer; the project has no affiliation
with and no endorsement from Google, Visa, Mastercard, Skyfire, or any payment
network or standards body.
