# FintechBear KYA — Open-Source Rust Agent Authorization SDK

FintechBear KYA ("Know Your Agent") is an open-source Rust SDK for AI agent
identity, delegated authority verification, transaction-level policy checks, and
protocol integration. It gives systems that let AI agents act on behalf of a
principal a disciplined, fail-closed way to reason about whether a given agent
action should be allowed.

FintechBear KYA is an **independent open-source implementation**. FintechBear is
the maintainer of this open-source project.

## Naming and trademark notice

The names "KYA" and "Know Your Agent" are used here as descriptive project
names. "Know Your Agent" is a generic industry concept; this project makes **no
claim to have invented it**. The names have not been cleared for trademark, and
this project claims no registered mark, no affiliation with, and no endorsement
or certification by any third party. This project has **no official affiliation
with and no endorsement from** Google, Visa, Mastercard, Skyfire, or any payment
network or standards body; those names, where they appear, are used descriptively
only. The AP2-style functionality is **experimental only, with no confirmed AP2
wire interoperability**; the SDK ships **no payment-execution enforcement** and
has **no independent security certification**. Read this notice before relying on
the names in any public, commercial, or compliance context. Unresolved naming and
trademark questions remain **OWNER REVIEW REQUIRED**; see
[docs/naming-and-branding-review.md](docs/naming-and-branding-review.md) for the
fuller per-name risk breakdown and the open owner-review items.

## 1. What FintechBear KYA is

FintechBear KYA is the fully open-source foundation (Product 1) for verifying
AI-agent delegated authority. It runs entirely on your own infrastructure. It
works **without any FintechBear account, without a subscription, without a cloud
service, and without a paid API**. You can clone it, build it, and use its
offline-evaluable logic with nothing but a Rust toolchain.

It provides:

- A curated public facade crate, `kya-sdk`, that exposes the whole
  verify + evaluate + authorize flow from one import (`use kya_sdk::prelude::*;`).
- Domain value types with strong type safety: identities, scope, mandate, exact
  money (integer minor units plus an explicit ISO-4217 currency, no floats).
- A real Ed25519 / JWS-EdDSA signature-verification engine (`kya-crypto`).
- A deterministic, offline static-policy evaluator producing a structured
  `PolicyOutcome`.
- The fail-closed `authorize` bridge and the trait seams for the online
  authority and execution layers.

## 2. What problem the SDK solves

When an AI agent acts on behalf of a principal and asks to move money, the
system has to answer a hard question: is this specific action, right now,
actually allowed? A signature alone cannot answer that. FintechBear KYA gives
you a disciplined decomposition of the question into five non-interchangeable
stages, a type system that refuses to let a "looks fine offline" result be
mistaken for an authorization, and a fail-closed bridge that only yields `Allow`
when an online authority explicitly approves.

### The central security distinction

A valid cryptographic signature is **not** sufficient to authorize a financial
transaction. A signature proves authenticity and integrity of some bytes. It
says nothing about whether the delegating mandate is still valid, whether a
budget is exhausted, or whether the request is a replay.

Offline verification **cannot** establish current revocation state, cumulative
budget state, or global replay state. Those facts are global and mutable, and
establishing them requires trustworthy authoritative evidence obtained online.
Treating an offline "looks fine" as "authorized" is a defect, not a shortcut.

## 3. What it does NOT do

- It does **not** ship a concrete online authority. Revocation, cumulative
  budget, and global replay state are stage-D concerns behind a trait seam
  (`OnlineAuthorizer`); the open-source core ships no implementation.
- It does **not** ship a concrete payment or ledger execution path. Execution
  enforcement (stage E) is a trait seam (`IntegrationClient`) only.
- It does **not** establish agent proof of possession. Local verification proves
  only an **issuer** signature; the SDK reports this honestly as
  `ProofOfPossession::NotEstablished`.
- It does **not** perform any network, database, cloud, or payment-provider I/O
  in local verification and evaluation. Those operations are synchronous and
  offline.
- It is **not** full AP2 support. The AP2 adapter is experimental and incomplete
  (see section 13).
- It has **not** been independently audited and carries no regulatory, PCI-DSS,
  or SOC 2 certification. It is not declared production-safe.

## 4. Installation from the repository

The crates are **unpublished** (not on crates.io). Depend on them by git path or
by cloning the repository.

Clone and build:

```sh
git clone https://github.com/fintechbear/fintechbear-kya-suite.git
cd fintechbear-kya-suite
cargo build --workspace
```

Depend on the facade from your own crate using a git dependency in your
`Cargo.toml`:

```toml
[dependencies]
kya-sdk = { git = "https://github.com/fintechbear/fintechbear-kya-suite.git" }
```

> **Note (OWNER CONFIRMATION REQUIRED):** the repository URL above has been
> reconciled to the configured git remote `origin`
> (`https://github.com/fintechbear/fintechbear-kya-suite`), which is the only
> verified signal of where this project lives. Ownership and control of that
> GitHub repository could not be verified in this offline environment, so the
> owner must still **confirm they control**
> `https://github.com/fintechbear/fintechbear-kya-suite` before relying on the
> git dependency or publishing. See
> [docs/publication-checklist.md](docs/publication-checklist.md).

Or use a local path dependency against a checkout:

```toml
[dependencies]
kya-sdk = { path = "../fintechbear-kya-suite/crates/kya-sdk" }
```

The AP2 adapter is experimental and is deliberately not part of the facade. If
you want to experiment with it, depend on `kya-adapter-ap2` directly.

## 5. Minimum supported Rust version

The minimum supported Rust version (MSRV) is **1.85**, edition 2021. It is
declared as `rust-version` in the workspace `Cargo.toml`.

## 6. Quick Start

The fastest path is to run a real, compiling example. The
[`example_02_verify_signed_evidence`](examples/example_02_verify_signed_evidence.rs)
example produces a genuine Ed25519 signature over a mandate's canonical encoding
and verifies it through the facade:

```sh
cargo run -p kya-examples --example example_02_verify_signed_evidence
```

The snippet below mirrors that example and the public-surface integration test
at [`crates/kya-sdk/tests/public_surface.rs`](crates/kya-sdk/tests/public_surface.rs).
It is marked `no_run` because it needs a test-only signing key to produce a real
signature; see the example file for the complete, compiling source.

```rust,no_run
use ed25519_dalek::{Signer, SigningKey};
use kya_sdk::prelude::*;

fn main() {
    // TEST-ONLY deterministic key, never a production secret.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let public_key = signing_key.verifying_key();

    let issuer = IssuerId::new("issuer:acme-bank").unwrap();
    let principal = PrincipalId::new("principal:acme-treasury").unwrap();
    let agent = AgentId::new("agent:treasury-bot").unwrap();
    let key_ref = TrustedKeyRef::new("kid:acme-2026").unwrap();

    // Stage A: explicit, allow-listed trust (anchors + key bytes bundled).
    let mut trust = TrustConfiguration::new();
    trust
        .trust_issuer_key(issuer.clone(), key_ref.clone(), public_key.as_bytes())
        .unwrap();

    // Build the mandate the issuer signs over.
    let limit = Money::from_code(10_000, "USD").unwrap();
    let scope = Scope::new()
        .allow(Action::new("transfer").unwrap())
        .with_per_transaction_limit(limit);
    let mandate = Mandate::new(
        issuer.clone(),
        principal,
        agent.clone(),
        scope,
        ValidityWindow::new(0, 2_000).unwrap(),
    );

    let audience = "aud:acme-payments";
    let binding = b"txn-binding:invoice-2026-0042";
    let now: u64 = 1_000;

    // A genuine signature over the mandate's canonical encoding.
    let signature = signing_key
        .sign(&mandate.canonical_encoding())
        .to_bytes()
        .to_vec();

    let claim = DelegationClaim::new(issuer, agent, key_ref);
    let signed = SignedMandate {
        claim: &claim,
        mandate: &mandate,
        signature: &signature,
        audience,
        not_before: 0,
        expires_at: 2_000,
        binding,
    };

    // Stage B: verify the real signature through the facade.
    let verified: VerifiedMandate = verify_mandate(
        &signed,
        trust.key_store(),
        trust.anchors(),
        now,
        audience,
        binding,
    )
    .expect("genuine signature over the canonical encoding must verify");

    // Stage C: static, offline policy evaluation over the verified mandate.
    let intent = TransactionIntent::new(
        AgentId::new("agent:treasury-bot").unwrap(),
        MerchantId::new("merchant:supplier-co").unwrap(),
        ResourceId::new("invoice:2026-0042").unwrap(),
        Action::new("transfer").unwrap(),
        Money::from_code(5_000, "USD").unwrap(),
    );
    let outcome = evaluate(&verified, &intent, now);

    // Eligibility is NOT authorization. The request stays UNAUTHORIZED until a
    // stage-D authority approves it via `authorize`.
    assert!(requires_online_authorization(&outcome));
}
```

## 7. Trusted key configuration

Trust is **explicit and allow-listed**; there is no implicit or wildcard trust
and no key discovery over the network. The facade bundles the two things that
verification needs together, because configuring them separately is the most
common first-day mistake:

- the **trust anchors** (`TrustAnchors`): which `(issuer, key_ref)` pairs are
  trusted, and
- the **key store** (`TrustedKeyStore`): the concrete 32-byte Ed25519 public-key
  bytes.

```rust,no_run
use kya_sdk::prelude::*;

let issuer = IssuerId::new("issuer:acme-bank").unwrap();
let key_ref = TrustedKeyRef::new("kid:acme-2026").unwrap();
let public_key_bytes: [u8; 32] = [0u8; 32]; // the issuer's real public key

let mut trust = TrustConfiguration::new();
trust
    .trust_issuer_key(issuer.clone(), key_ref.clone(), &public_key_bytes)
    .expect("32-byte Ed25519 public key");

assert!(trust.trusts_issuer_key(&issuer, &key_ref));
```

A malformed key is rejected up front with `TrustConfigurationError`. See
[`example_01_configure_trust`](examples/example_01_configure_trust.rs).

## 8. Signature and delegation verification

`verify_mandate` runs the real `kya-crypto` Ed25519 / JWS-EdDSA engine through
the facade and, on success, mints an authenticated `VerifiedMandate`. The
verified mandate cryptographically binds the **complete** mandate to the
signature via the mandate's canonical encoding (an internal, non-standardized,
versioned byte format, not a standardized wire format), so a signature over one
payload can never be paired with a substituted mandate.

`verify_delegation` is the analogous entry point for a `SignedClaim`. See
[`example_02_verify_signed_evidence`](examples/example_02_verify_signed_evidence.rs),
[`example_03_reject_tampered_payload`](examples/example_03_reject_tampered_payload.rs),
[`example_04_reject_unknown_issuer`](examples/example_04_reject_unknown_issuer.rs),
and
[`example_05_verify_delegation_evidence`](examples/example_05_verify_delegation_evidence.rs).

Passing stage B is **not** authorization.

## 9. Static transaction policy evaluation

`evaluate(&verified, &intent, now)` runs the deterministic, offline stage-C
evaluator over a `VerifiedMandate` and a concrete `TransactionIntent`, producing
a structured `PolicyOutcome` with a `ReasonCode`. It reads no system clock (time
is injected as `now`) and performs no I/O.

```rust,no_run
use kya_sdk::prelude::*;

# fn demo(verified: VerifiedMandate) {
let intent = TransactionIntent::new(
    AgentId::new("agent:treasury-bot").unwrap(),
    MerchantId::new("merchant:supplier-co").unwrap(),
    ResourceId::new("invoice:2026-0042").unwrap(),
    Action::new("transfer").unwrap(),
    Money::from_code(5_000, "USD").unwrap(),
);
let outcome = evaluate(&verified, &intent, 1_000);
println!("reason: {:?}", outcome.reason());
# }
```

See
[`example_06_evaluate_valid_scope`](examples/example_06_evaluate_valid_scope.rs),
[`example_07_reject_over_limit`](examples/example_07_reject_over_limit.rs), and
[`example_08_reject_currency_mismatch`](examples/example_08_reject_currency_mismatch.rs).
An `EligibleForOnlineAuthorization` outcome is **not** an authorization.

## 10. Verification vs authorization

This is the central distinction, and it is enforced by the type system.

- **Eligibility** is the result of local verification and static evaluation
  (stages A, B, C). It says only that nothing static forbids the request.
- **Authorization** requires an online authority (stage D) to rule on
  revocation, cumulative budget, and global replay.

There is deliberately **no** `From<PolicyOutcome> for Decision` anywhere in the
SDK. The only bridge from a static `PolicyOutcome` to a final `Decision` is the
fail-closed `kya_client::authorize` function. The facade helpers
`requires_online_authorization(&outcome)` and
`online_state_is_unestablished(&outcome)` make this explicit in code.

```rust,no_run
use kya_sdk::prelude::*;
use kya_sdk::runtime::block_on;

# fn demo<A: OnlineAuthorizer>(authority: &A, outcome: &PolicyOutcome) {
// Eligibility is not authorization: you still owe an online check.
assert!(requires_online_authorization(outcome));
assert!(kya_sdk::online_state_is_unestablished(outcome));

// Only an explicit authority approval, via the fail-closed bridge, yields Allow.
let decision = block_on(authorize(authority, outcome));
if decision.is_allowed() {
    // proceed to stage E (execution enforcement)
}
# }
```

See
[`example_09_missing_online_state`](examples/example_09_missing_online_state.rs)
and the end-to-end flow in
[`crates/kya-sdk/tests/public_surface.rs`](crates/kya-sdk/tests/public_surface.rs).

## 11. Supported algorithms

Only **Ed25519 / EdDSA** is accepted:

- raw Ed25519 signatures (RFC 8032), and
- JWS compact-form EdDSA (`alg: EdDSA`, RFC 7515 / 7518 / 8037) over the exact
  signing input.

`alg: none`, HMAC, RSA, and ECDSA are **rejected**. The accepted algorithm
identifier is exported as `ACCEPTED_ALGORITHM`. Cryptography uses standard,
reviewed primitives; no algorithm is invented.

## 12. Supported protocol capabilities

The SDK verifies signatures over **caller-supplied exact bytes** and maps
mandate **constraints** (permitted action, exact amount and currency, acting
agent, validity window, audience, transaction binding, approval) onto the
stage-C evaluator. The cryptographic engine is protocol-independent: it parses
no wire envelope and invents no canonicalization. See
[docs/supported-protocols.md](docs/supported-protocols.md) and
[docs/protocol-compatibility.md](docs/protocol-compatibility.md) for the exact
supported / unsupported boundary.

## 13. AP2 adapter: experimental and incomplete

The AP2 constraint adapter (`kya-adapter-ap2`) is **experimental and
incomplete**. It maps AP2 mandate *constraint concepts* onto the stage-C domain
and verifies signatures over caller-supplied exact bytes, but it does **not**
parse the real AP2 signature envelope and makes **no** AP2 wire-compatibility,
conformance, or certification claim. The byte-for-byte AP2 envelope and any AP2
test-vector conformance are unverified and blocked. The adapter is deliberately
**not** re-exported from the `kya-sdk` facade; depend on `kya-adapter-ap2`
directly to experiment with it. See
[`example_10_ap2_adapter`](examples/example_10_ap2_adapter.rs),
[docs/supported-protocols.md](docs/supported-protocols.md), and
[docs/first-adapter-decision.md](docs/first-adapter-decision.md).

## 14. Security limitations

Read these before relying on the SDK. They are structural, not oversights.

- **Agent proof of possession is NOT established.** Local verification proves
  only an **issuer** signature over a delegation or mandate. It does not prove
  the agent currently controls its own private key. The SDK reports this
  honestly as `ProofOfPossession::NotEstablished`.
- **Offline verification cannot establish current authoritative state.** It
  cannot know current **revocation** state, **cumulative budget** state, or
  global **replay** state. Those are global, mutable facts behind stage D.
- **Eligibility is not authorization.** A passing static evaluation is only
  eligibility to proceed to stage D; it is never an `Allow` on its own.
- **No independent security audit** has been performed, and **no** regulatory,
  PCI-DSS, or SOC 2 certification is claimed.

See [docs/security-limitations.md](docs/security-limitations.md),
[SECURITY.md](SECURITY.md), and [docs/threat-model.md](docs/threat-model.md).

## 15. How to run tests

The project is a standard Cargo workspace. Run:

```sh
cargo test --workspace --all-features
cargo test --doc --workspace
```

On **Windows**, the MSVC linker is required for the crypto-linked crates
(`kya-crypto` and anything depending on it, including `kya-sdk`, the examples,
and `kya-adapter-ap2`). `link.exe` is not on `PATH` by default, so source
`vcvars64.bat` first, for example:

```bat
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cargo test --workspace --all-features
```

The CI quality gates (AGENTS.md Rule 16) are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --doc --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## 16. How to contribute

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) (the engineering constitution and its 22 rules) first.
All participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Report security issues privately per [SECURITY.md](SECURITY.md).

## 17. License

Licensed under either of

- MIT License ([LICENSE-MIT](LICENSE-MIT)), or
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Dual licensing is subject to third-party license compatibility.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## 18. Future commercial platform relationship

FintechBear's long-term strategy is two products:

- **Product 1:** this free, independent, public Rust SDK (what you are reading).
- **Product 2:** a future commercial FintechBear KYA authorization platform
  built directly on the **same** open Rust core.

Product 2 is **not built** and ships nothing in this repository. Using Product 1
requires no FintechBear account. The future platform would supply concrete
implementations of the core's stage-D and stage-E seams (managed agent registry,
trusted key management, delegation and mandate management, online revocation,
atomic budget reservations, human approval workflows, an authoritative
authorization API, tamper-evident audit, execution-point payment enforcement,
and an enterprise dashboard) without forking the verification logic. See
[docs/future-commercial-platform.md](docs/future-commercial-platform.md).

## Status and honesty

This is an early `v0.1.0` work in progress, not a release. It provides the
offline-evaluable stages (A identity, B real Ed25519 / JWS-EdDSA verification,
C static policy) plus the fail-closed seams for stages D and E. It does **not**
ship a concrete online authority or a concrete execution path, has not been
independently audited, carries no certification, and is not declared
production-safe.

No independent security audit has been performed, and no security certification
is claimed. All compatibility and security claims in this repository are intended
to be truthful and evidence-backed per the project's engineering rules (see
[AGENTS.md](AGENTS.md) Rule 20). If you find a claim that is not, that is a bug;
please report it.

## Further reading

- [docs/quickstart.md](docs/quickstart.md) - a detailed quick start.
- [docs/api-usage.md](docs/api-usage.md) - the public facade usage, task by task.
- [docs/architecture.md](docs/architecture.md) - clean architecture and the stage model.
- [docs/trust-model.md](docs/trust-model.md) - explicit allow-listed trust.
- [docs/supported-protocols.md](docs/supported-protocols.md) - supported protocol capabilities.
- [docs/security-limitations.md](docs/security-limitations.md) - the structural limits.
- [docs/known-limitations.md](docs/known-limitations.md) - the consolidated v0.1.0 limitation list.
- [docs/security-audit.md](docs/security-audit.md) - the internal (not third-party) security audit.
- [docs/release-readiness.md](docs/release-readiness.md) - gate, example, and supply-chain evidence.
- [docs/release-notes-v0.1.0.md](docs/release-notes-v0.1.0.md) - the v0.1.0 release notes.
- [docs/public-release-manifest.md](docs/public-release-manifest.md) - the SHIP / DO-NOT-SHIP file set for the public release.
- [docs/publication-checklist.md](docs/publication-checklist.md) - the required owner actions before publishing.
- [docs/threat-model.md](docs/threat-model.md) - trust boundaries, adversaries, and honest gaps.
- [docs/product-strategy.md](docs/product-strategy.md) - the two-product strategy.
- [docs/open-source-commercial-boundary.md](docs/open-source-commercial-boundary.md) - open source vs future commercial.
- [docs/future-commercial-platform.md](docs/future-commercial-platform.md) - how the same core can later support a managed platform.
- [AGENTS.md](AGENTS.md) - the engineering constitution and the 22 rules.
- [SECURITY.md](SECURITY.md) - vulnerability disclosure and scope.
