# Open-Source and Commercial Boundary

This document draws a clear line between what lives in the open-source core
(Product 1) and what belongs to the future commercial platform (Product 2, not
built). The boundary is a design, not a paywall across the verification logic:
the core defines the traits, and concrete services, whether yours or the future
commercial platform's, implement them.

See [product-strategy.md](product-strategy.md) for the two-product context.

## The principle: traits in the core, implementations at the edge

The core expresses every I/O-bound or environment-specific concern as a **trait
seam**. The core never implements those seams; it only consumes them. This is
how the commercial platform can reuse the core without forking its verification
logic: it supplies implementations of the same traits the open-source SDK
already defines.

The dependency direction is fixed by [AGENTS.md](../AGENTS.md) Rule 2:
dependencies point inward toward the domain core. `kya-core` depends on nothing
in-repo and performs no I/O. `kya-protocol` and `kya-client` may depend on
`kya-core`. Concrete crypto, HTTP, database, and cloud code live outside the
core, behind traits. A commercial platform is just another outer ring that
depends inward; it cannot invert that direction.

## What lives in the open-source core (Product 1)

- **Protocol and domain types.** `kya-core` value types (identity, scope,
  mandate, money) and the `kya-protocol` version marker and wire shapes.
- **Exact monetary arithmetic.** Integer minor units plus an explicit ISO-4217
  currency, checked and fail-closed, no floats.
- **Stage A - Identity.** Identity resolution and explicit, allow-listed trust
  anchors.
- **Stage B - Signature verification (trait seam).** The `SignatureVerifier`
  trait. The core ships no cryptographic algorithm.
- **Stage C - Static policy evaluation.** The deterministic, offline evaluator
  producing a `PolicyOutcome`.
- **The fail-closed decision types and bridge.** `Decision`, `PolicyOutcome`,
  `ReasonCode`, and the `kya_client::authorize` bridge. There is deliberately no
  `From<PolicyOutcome> for Decision`.
- **The stage-D and stage-E seams.** The `OnlineAuthorizer` and
  `IntegrationClient` traits in `kya-client`, with no concrete transport.

Everything in this list is offline-evaluable or a pure seam. None of it requires
an account, a subscription, a cloud service, or a paid API.

## What belongs to the future commercial platform (Product 2, not built)

These are **managed services** that implement or surround the core's seams. They
are documented in [future-platform-architecture.md](future-platform-architecture.md)
and are **not implemented now**.

- A concrete **stage-B signature verifier** using standard, reviewed
  cryptographic primitives.
- A concrete **stage-D online authority** (`OnlineAuthorizer`) backed by managed
  services: a managed agent registry, mandate management, revocation, atomic
  budget reservations, and global replay protection.
- Human approval workflows for the `ApprovalRequired` path.
- A concrete **stage-E execution enforcement** path (`IntegrationClient`) into
  payment providers and ledgers.
- Audit infrastructure, enterprise APIs, and a dashboard.

## How the boundary stays clean

- **One security model.** Because the commercial platform consumes the core's
  types and traits, the authorization model does not diverge. A fix in the core
  applies to both products.
- **No forked verification logic.** The commercial platform does not reimplement
  stage C or the fail-closed bridge; it reuses them.
- **Fail-closed is preserved across the boundary.** The only path from a static
  `PolicyOutcome` to a final `Decision` is the core's `authorize` bridge, which
  denies on any error, timeout, unknown state, or approval-required signal. A
  commercial authority plugs into that bridge; it cannot bypass it.
- **The open-source product remains whole.** Removing the commercial services
  leaves a coherent, usable SDK. Nothing in the core depends outward on them.
