# Product Strategy

FintechBear KYA is built as two products, in a deliberate order. This document
explains what they are, why they are separate, and what is and is not built
today.

## Naming note

The names "KYA" and "Know Your Agent" are descriptive project names that have
not been cleared for trademark. This document claims no registered mark, no
affiliation with any third party, and no certification. Read this note before
treating any name below as a protected brand.

## Product 1: the open-source Rust SDK (built now)

Product 1 is this repository: an independently usable, fully open-source Rust SDK
for AI agent identity, delegated authority verification, transaction-level policy
checks, and protocol integration.

Defining properties:

- It is **independently usable**. You do not need Product 2 to get value from it.
- It works with **no FintechBear account, no subscription, no cloud service, and
  no paid API**. A Rust toolchain is sufficient to build and use it.
- It performs **no I/O** in its core. The `kya-core` crate has no HTTP, database,
  cloud, or payment-provider dependency.
- It provides the offline-evaluable stages (A identity, B signature verification
  as a trait seam, and C static policy), plus the fail-closed seams for stage D
  (online authoritative authorization) and stage E (execution enforcement).

Product 1 is honest about its limits. A valid signature is not an authorization,
and offline evaluation cannot establish current revocation, cumulative-budget, or
global replay state. Those require trustworthy authoritative evidence obtained
online, which the open-source core does not itself provide.

## Product 2: the FintechBear KYA enterprise platform (future, not built)

Product 2 is a **future** commercial FintechBear KYA enterprise platform. It is
**not implemented now**, and nothing in this repository ships it.

The key strategic constraint: Product 2 is built **directly on the same
open-source Rust core**. It reuses the verification logic in `kya-core` rather
than rewriting it. The commercial platform supplies concrete implementations of
the trait seams the core defines (signature verification, the online authority,
and execution enforcement), plus managed services around them.

Planned capabilities for Product 2 are documented, but not built, in
[future-platform-architecture.md](future-platform-architecture.md): a managed
agent registry, mandate management, real-time (stage D) authorization,
revocation, atomic budget reservations, human approval workflows, audit
infrastructure, payment execution (stage E) enforcement, and enterprise APIs and
a dashboard.

## Why this order and this separation

- **Trust through transparency.** The verification logic that decides whether an
  agent action is permitted is open source and auditable by anyone. The
  commercial platform does not hide or fork that logic.
- **No lock-in for the core model.** Users who only need the offline-evaluable
  stages can use Product 1 forever without a commercial relationship.
- **One source of truth.** Because Product 2 reuses the core, the security model
  does not diverge between the open-source and commercial offerings. A fix to the
  core benefits both.

The boundary between what is open source and what belongs to the commercial
platform is described in
[open-source-commercial-boundary.md](open-source-commercial-boundary.md).

## What this means for contributors

Contributions to the open-source core are governed solely by the project's
licenses (MIT OR Apache-2.0) and [AGENTS.md](../AGENTS.md). The existence of a
future commercial product does not change the open-source status, license, or
governance of Product 1.
