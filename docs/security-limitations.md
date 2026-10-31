# Security Limitations

This document states, plainly, what the open-source FintechBear KYA SDK cannot
establish and what it does not claim. These limits are structural, not
oversights. Understanding them is part of using the SDK safely. It is consistent
with [SECURITY.md](../SECURITY.md), [threat-model.md](threat-model.md), and
[trust-model.md](trust-model.md).

FintechBear is the maintainer. The project has no affiliation with and no
endorsement from Google, Visa, Mastercard, Skyfire, or any payment network or
standards body.

## Verification vs authorization (the central distinction)

A valid cryptographic signature proves the authenticity and integrity of some
bytes. It does **not** prove that a transaction is authorized. Local
verification and static evaluation (stages A, B, C) produce **eligibility**, not
an **authorization**. Authorization requires an online authority (stage D).

The type system enforces this: there is deliberately no
`From<PolicyOutcome> for Decision`, and the only path from a static
`PolicyOutcome` to a final `Decision` is the fail-closed `kya_client::authorize`
bridge. An `EligibleForOnlineAuthorization` outcome is never an `Allow` on its
own.

## Offline verification cannot establish current authoritative state

Offline evaluation **cannot** establish:

- current **revocation** state. A mandate valid when signed may have been
  revoked since; a revoked mandate can still produce a perfectly valid signature
  and a passing stage-C outcome.
- **cumulative budget** state. Whether the agent has already spent its allowance
  across prior transactions is global, mutable state the offline flow cannot see.
- global **replay** state. Two independently valid-looking copies of the same
  signed request are indistinguishable offline.

These facts are global and mutable. Only an `OnlineAuthorizer` with
authoritative, consistent state (stage D) can establish them, and it is reached
only through the fail-closed `authorize` bridge.

## Agent proof of possession is NOT established

Local verification proves only an **issuer** signature over a delegation or
mandate. `kya_crypto::verify_delegation` and `verify_mandate` verify the
**issuer's** signature; that the issuer signed a delegation naming an agent does
**not** prove the agent currently controls its own private key.

The SDK represents this gap explicitly rather than hiding it: a
`VerifiedDelegation` and a `VerifiedMandate` expose
`ProofOfPossession::NotEstablished`. Present agent proof of possession would
require the agent to sign request-specific bytes, verified as a separate step;
the SDK does not perform that step and invents no mechanism for it.

## What the open-source core does not provide

- **Stage D (online authoritative authorization)** ships as a trait seam
  (`OnlineAuthorizer`) plus the fail-closed `authorize` bridge. No concrete
  authority ships, so no revocation, budget, or replay check is performed by the
  core itself.
- **Stage E (execution enforcement)** ships as a trait seam
  (`IntegrationClient`). No concrete payment or ledger execution path ships, and
  no production payment-execution enforcement is claimed.

## No audit, no certification

- No independent security audit has been performed.
- No regulatory, PCI-DSS, or SOC 2 certification is held or claimed.
- No full AP2 conformance is claimed; the AP2 adapter is experimental and
  incomplete (see [supported-protocols.md](supported-protocols.md)).
- This is an early `v0.1.0` work in progress and is **not** declared
  production-safe.

## Fail-closed posture

The SDK is deny-by-default. Any error, timeout, unknown state, or
approval-required signal resolves to `Deny`. The `Decision` type has no
`Unknown` variant that could be mistaken for a pass.

## Reporting

If you find a security issue, or a claim in this repository that is not truthful
or evidence-backed, follow the private disclosure process in
[SECURITY.md](../SECURITY.md).
