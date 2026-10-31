# Release Readiness - FintechBear KYA SDK v0.1.0

This document is the FINAL release-readiness record for `v0.1.0`. It records the
first-hand re-verification evidence for the public GitHub release preparation. It
is organized as:

- **Sections 1 to 6:** quality-gate results, example results, supply-chain
  results, public-API assessment, AP2 status, and the honest NOT RUN / NOT
  VERIFIED list.
- **Section 7:** the component inventory, packaging status, clean-checkout /
  portability readiness, cross-platform status, and the FINAL 20-point report
  plus the single release verdict.

This is an **internal** engineering review, not an independent third-party audit
(AGENTS.md Rule 20). All results below were produced first-hand on a Windows
MSVC host with network access unavailable; items that could not be run are
recorded as NOT RUN / NOT VERIFIED rather than asserted. None of the NOT RUN /
NOT VERIFIED / UNVERIFIED items has been upgraded to PASS.

Environment: branch `rebuild/kya-foundation-v0.1.0` at HEAD `b06f8e6`; Windows,
PowerShell, MSVC `vcvars64.bat` sourced for crypto-linked crates. No git mutation
occurred during this re-verification: read-only `git status` / `git log` /
`git ls-files` only; HEAD remains `b06f8e6`.

See also [public-release-manifest.md](public-release-manifest.md) for the exact
SHIP / DO-NOT-SHIP file set and [publication-checklist.md](publication-checklist.md)
for the required owner actions.

---

## 1. Rule 16 quality gates

All five gates were run and are **GREEN**.

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | **PASS** (no diff, EXIT 0) |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** (0 warnings, EXIT 0) |
| Tests | `cargo test --workspace --all-features` | **PASS** (339 tests, 0 failed) |
| Doctests | `cargo test --doc --workspace` | **PASS** (6 kya-crypto doctests: 5 compile-fail + 1 positive) |
| Docs | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | **PASS** (EXIT 0) |

Test breakdown (unit + integration, per crate, all passing):

- `kya-adapter-ap2`: 23 unit + 5 `ap2_stage_c` = 28
- `kya-client`: 8 unit + 8 `end_to_end` = 16
- `kya-core`: 94 unit + 14 `canonical_encoding` + 4 `property_identity` +
  8 `property_money` + 2 `property_policy` = 122
- `kya-crypto`: 53 unit + 5 `cross_context_reuse` + 21 `engine_security` +
  3 `forgery_regression` + 8 `jws_encoding_edges` + 15 `jws_security` +
  12 `mandate_binding` + 4 `property_fuzz` + 5 `rfc8032_conformance` = 126
- `kya-protocol`: 28 unit + 3 `property_wire` + 4 `version_gate` = 35
- `kya-sdk`: 8 unit + 4 `public_surface` = 12
- Workspace total: **339** test cases, plus 6 kya-crypto doctests.

## 2. Example validation

All 11 example targets in `examples/Cargo.toml` were compiled and **run** via
`cargo run -p kya-examples --example <name>` with MSVC sourced. Each exited 0,
each prints an explicit "Does NOT verify" statement, and each uses deterministic
synthetic test-only keys (`SigningKey::from_bytes(&[N; 32])`), never a
production secret. No example needed a fix in this phase (the verified-evidence
types already resolve from `kya-crypto` through the facade).

| Example | Exit | Observed behavior |
|---|---|---|
| `offline_evaluation` | 0 | Stages A/B/C run offline; eligible outcome, explicitly NOT an authorization |
| `example_01_configure_trust` | 0 | Explicit allow-listed trust; configuring trust is not authorization |
| `example_02_verify_signed_evidence` | 0 | Genuine Ed25519 signature verifies; PoP not established |
| `example_03_reject_tampered_payload` | 0 | Flipped byte → `VerificationSignatureInvalid`, fail-closed |
| `example_04_reject_unknown_issuer` | 0 | Unconfigured issuer / unanchored key rejected |
| `example_05_verify_delegation_evidence` | 0 | Mandate-bound delegation evidence; PoP not established |
| `example_06_evaluate_valid_scope` | 0 | Stage C passes → eligible; online state unestablished |
| `example_07_reject_over_limit` | 0 | `Denied { AmountExceedsLimit }`, terminal fail-closed |
| `example_08_reject_currency_mismatch` | 0 | `Denied { CurrencyNotPermitted }`, no silent conversion |
| `example_09_missing_online_state` | 0 | Approval-required and timeout both map to `Deny` |
| `example_10_ap2_adapter` | 0 | Experimental AP2 constraint mapping; NOT AP2 wire interop; affiliation none |

## 3. Supply-chain status

- **`cargo deny check bans licenses sources`** → **`bans ok, licenses ok,
  sources ok`** (EXIT 0) with the reviewed `deny.toml`.
- **Dependency inventory:** the only external dependency is `ed25519-dalek
  v2.2.0` (pinned, `default-features = false`, `features = ["std"]`) and its
  standard RustCrypto/dalek transitive tree. The six `kya-*` crates are
  first-party. `kya-core` depends on nothing in-repo (Rule 2, no cycle).
- **License inventory (via `cargo deny list`):** MIT, Apache-2.0, BSD-3-Clause,
  BSD-1-Clause, Unicode-3.0. No copyleft present or allowed. The project itself
  is MIT OR Apache-2.0.
- **Secret scan:** no secrets in tracked files; test keys are deterministic
  in-code seeds; `.gitignore` excludes `.env`, `*.pem`, `*.key`, `*.p12`,
  `*.pfx`, `secrets/`.
- **`deny.toml` posture:** `advisories version = 2` with empty `ignore`
  (fail-closed on a networked host); `bans.wildcards = "deny"`;
  `sources.unknown-registry = "deny"`, `unknown-git = "deny"`,
  `allow-registry = [crates.io]`.

## 4. Public-API / clean-code assessment

Reviewed the `kya-sdk` facade (`lib.rs`, `prelude.rs`, `trust.rs`, `ap2.rs`) and
the public surfaces of the inner crates from an independent Rust developer's
perspective. Conclusion: the surface is clean, honest, and misuse-resistant; **no
genuine API-misuse or correctness defect required a code change in this phase.**

- Verified-evidence types (`VerifiedMandate` / `VerifiedDelegation`) are only
  constructible through the real `kya-crypto` verification path.
- Public typed errors are `#[non_exhaustive]`, implement `Display` +
  `std::error::Error`, and map to a stable kebab-case `ErrorCode` via
  `AsErrorCode` (including `CryptoVerificationError`). Error messages leak no key
  material (Rule 18).
- `TrustConfiguration::trust_issuer_key` validates key length up front and leaves
  the config unchanged on a malformed key (no half-registration).
- `requires_online_authorization` / `online_state_is_unestablished` make
  "eligibility is not authorization" explicit; there is no
  `From<PolicyOutcome> for Decision`.
- Security-critical production paths return typed errors; `unwrap`/`expect`
  appear only under `#[cfg(test)]`.
- **Open-source independence confirmed:** the whole offline flow runs with only
  caller-configured trust keys — no FintechBear account, subscription, backend,
  or network I/O — demonstrated by the 11 offline examples.

See [security-audit.md](security-audit.md) for the full write-up.

## 5. AP2 / trademark honesty status

The `kya-adapter-ap2` crate makes it unmistakable — in its name, its crate docs
(a rendered warning block), and its public API — that it implements AP2-*style*
local constraints only: **no** AP2 wire envelope, **no** canonicalization or
schema, **no** conformance vectors, **no** provider endpoints, and **official
affiliation: none**. It is deliberately not in the `kya-sdk` prelude or
top-level surface. All compatibility claims in
[protocol-compatibility.md](protocol-compatibility.md),
[supported-protocols.md](supported-protocols.md), and
[first-adapter-decision.md](first-adapter-decision.md) were checked against the
implementation; the unverified AP2 envelope and test-vector facts are recorded
as `[UNVERIFIED]` / BLOCKED. Trademark review of "AP2", "Know Your Agent", and
the provider names is recorded in the README "Naming and trademark notice": the
names are descriptive and uncleared, with no claim of registration, affiliation,
or endorsement. No external trademark registry was queried offline, so trademark
clearance remains an honestly-stated open risk.

## 6. NOT RUN / NOT VERIFIED in this environment

| Item | Reason |
|---|---|
| `cargo deny check advisories` (RustSec DB) | Offline: `github.com` unreachable. Config is valid and fail-closed; re-run on a networked host. |
| `cargo audit` | Offline: `cargo-audit` not installable (`index.crates.io` unreachable) and not cached. |
| cargo-fuzz bounded runs | Offline (`libfuzzer-sys` uncached) + stable MSVC host lacks nightly + libFuzzer. Target sources exist in `fuzz/` for CI/Linux. |
| SBOM (`cargo cyclonedx`) | Offline: not installable, not cached. |
| Linux / macOS cross-platform gate run | Cannot run on this Windows host; NOT VERIFIED here. Linux CI (`ubuntu-latest`) covers Linux. |
| crates.io name availability for `kya-*` | Offline: registry name lookup unavailable; UNVERIFIED. Must be checked before publish. |
| `cargo publish --dry-run` | NOT RUN: requires the crates.io index, which is unreachable offline. `cargo package --list` works for all six crates (see §7.2). |
| Clean-checkout release claim | Strict read-only git; HEAD cannot be advanced. Release-file readiness is a git-tracked-vs-untracked distinction, not a committed-snapshot claim. See §7.3. |
| Correct public repository URL | RECONCILED (Phase 9) to the configured git remote `origin` `https://github.com/fintechbear/fintechbear-kya-suite`; workspace `Cargo.toml` metadata and all release docs now point there consistently. OWNER CONFIRMATION still required: offline cannot verify who controls that GitHub repo. See §7.2 and [publication-checklist.md](publication-checklist.md). |

An isolated-source build was run as a substitute for a clean-checkout build (see
§7.3): the source tree (excluding `target/`, `.git/`, `.agents/`, IDE caches, and
`fuzz/`) was copied into a temporary directory inside the workspace and built and
tested offline. It passed (339 tests + 6 doctests), with no dependency on the
original paths, private files, machine-specific absolute paths, or the network,
and the temporary directory was then removed. This is an **isolated-source test
and explicitly NOT a git clean-checkout** (no committed snapshot exists this
phase).

---

## 7. Component inventory, packaging, clean-checkout, and the FINAL report

This section synthesizes Sections 1 to 6, the `audit-notes.md` from the audit
phase, and the companion [security-audit.md](security-audit.md), and records the
packaging status, clean-checkout / isolated-source enumeration, and
cross-platform status as re-verified first-hand. **No `git` mutation of any kind
occurred:** HEAD remains `b06f8e6`; read-only `git status` / `git log` /
`git ls-files` only; no commit, push, tag, branch, reset, amend, publish, or
release. **This phase authorizes no publish.**

### 7.1 Component inventory (six library crates + examples)

All six library crates share the workspace package metadata: `version = 0.1.0`,
`edition = 2021`, `rust-version = 1.85`, `license = "MIT OR Apache-2.0"`,
`repository` / `homepage` = `https://github.com/fintechbear/fintechbear-kya-suite`
(RECONCILED in Phase 9 to the configured git remote `origin`; OWNER CONFIRMATION
still required that the owner controls that repo, see §7.2),
`#![forbid(unsafe_code)]`,
`#![deny(missing_docs)]`. Dependency direction is strictly inward (AGENTS.md
Rule 2). Inventory is from first-hand reading of each crate's `src` and
`Cargo.toml` plus the per-crate test counts observed in the §1 test run.

| Crate | Responsibility | Public API summary | Security boundary | In-repo deps | External deps | Tests | Known limitations |
|---|---|---|---|---|---|---|---|
| **kya-core** | Pure domain: identity, money, mandate/scope, verification trait seam, static policy, fail-closed decision. No I/O, no crypto. | `identity`, `money`, `mandate`, `scope`, `policy`, `evidence`, `decision`, `verification` (trait `SignatureVerifier` seam only), `error` (`ErrorCode`/`AsErrorCode`). Newtype IDs, `#[non_exhaustive]` typed errors. | Stages A + C. Holds the trait seam but **no** verifier impl and **no** verified-evidence constructor (relocated to kya-crypto). `Decision` is `Allow`/`Deny` only; no `From<PolicyOutcome> for Decision`. | none (Rule 2 root) | none | 94 unit + 14 `canonical_encoding` + 4 `property_identity` + 8 `property_money` + 2 `property_policy` = **122** | No agent proof-of-possession (`ProofOfPossession::NotEstablished`); no online/revocation/budget/replay state (stage D elsewhere). |
| **kya-protocol** | Language-independent protocol surface: version marker + fail-closed wire field-map decode/encode referencing core types. | `PROTOCOL_VERSION*`, `ProtocolVersion`, `check_supported_version`, `WireFields`, `WireMandate`, `WireDelegationClaim`, `WireTransactionIntent`, `WireError`, `VersionError`. | Untrusted-input decode boundary; never panics (Rule 5), fail-closed version gate (Rule 9). Decoding yields only a *claim*, never verified evidence. | kya-core | none | 28 unit + 3 `property_wire` + 4 `version_gate` = **35** | v0.1 field-map is **not** a wire-compatible external protocol (no JSON/serde); makes no external-protocol compatibility claim. |
| **kya-crypto** | Concrete outer-ring crypto engine: strict Ed25519 + narrow compact-JWS-EdDSA verification over exact bytes; owns the sealed verified-evidence mint-point. | `verify_delegation`, `verify_mandate`, `SignedClaim`, `SignedMandate`, `JwsEdDsa`, `Ed25519SignatureVerifier`, `ACCEPTED_ALGORITHM`, `Ed25519PublicKeyBytes`, `TrustedKeyStore`, `VerificationOutcome`/`VerificationProof`/`VerifiedDelegation`/`VerifiedMandate` (accessors public; constructors `pub(crate)`), `CryptoVerificationError`. | Stage B. **The single mint-point for verified evidence**, `pub(crate)` and bound to the concrete `Ed25519SignatureVerifier`. `verify_strict` rejects malleable/small-order; EdDSA-only allowlist; explicit allow-listed trust. | kya-core | `ed25519-dalek 2.2.0` (`default-features=false`, `features=["std"]`) + its RustCrypto/dalek tree | 53 unit + 5 `cross_context_reuse` + 21 `engine_security` + 3 `forgery_regression` + 8 `jws_encoding_edges` + 15 `jws_security` + 12 `mandate_binding` + 4 `property_fuzz` + 5 `rfc8032_conformance` = **126** (+ 6 doctests, 5 compile-fail) | Narrow JWS-EdDSA subset only (not general JOSE); verifies the *issuer's* signature, not agent PoP; hand-written strict base64url + compact-JWS parser. |
| **kya-client** | Stage D online-authorization seam + fail-closed `authorize` bridge; runtime-agnostic async + dependency-free `block_on`. | `OnlineAuthorizer`/`IntegrationClient` traits, `AuthorityVerdict`, `AuthorizerError`, `authorize`, `runtime::block_on`. | Stage D seam + the **only** `PolicyOutcome -> Decision` bridge, fail-closed: any error/timeout/unknown/approval-required → `Deny`; `Allow` only on explicit approval. | kya-core, kya-protocol (dev: kya-crypto, ed25519-dalek) | none (runtime) | 8 unit + 8 `end_to_end` = **16** | Ships **no** concrete authority/transport/HTTP/DB; consumer supplies the stage-D impl. `block_on` busy-polls (fine for simple sync call sites). |
| **kya-adapter-ap2** | Experimental outer-ring adapter: models AP2-*style* mandate **constraints** onto the core domain; verifies over caller-supplied exact bytes via kya-crypto. | `constraints::Ap2MandateConstraints` (+ `to_mandate`), `verify::verify_ap2_delegation`, `error` types. | Stage A/B/C mapping only. Produces at most `EligibleForOnlineAuthorization`, **never** `Allow`/`Decision`. Not in the facade prelude. | kya-core, kya-crypto (dev: ed25519-dalek) | none (ships no new third-party) | 23 unit + 5 `ap2_stage_c` = **28** | **NOT** AP2 wire interop: no envelope, no canonicalization, no endpoints, no conformance vectors, no certification, **affiliation none** (Rule 20). |
| **kya-sdk** | Ergonomic public **facade** re-exporting a curated stable surface over core/crypto/client for the full verify + evaluate + authorize flow. | `lib.rs` re-exports + `prelude`, `TrustConfiguration`/`RequestConditions`/`TrustConfigurationError` (`trust.rs`), `ap2` module (opt-in, outside prelude). | Adds no new trust and no verified-evidence constructor; routes through the same sealed, fail-closed paths. Open-source independent (no account/backend/network). | kya-core, kya-crypto, kya-client (dev: ed25519-dalek) | none | 8 unit + 4 `public_surface` = **12** | Facade only — no new behavior; stage D still requires a caller-supplied authority. |
| **examples** (`kya-examples`, `publish = false`) | 11 runnable examples over the real public APIs with synthetic test keys. | `offline_evaluation` + `example_01..10`; `src/lib.rs` is an empty lib target. | Demonstration only; each prints an explicit "Does NOT verify" note and uses deterministic in-code test keys. | kya-core, kya-client, kya-crypto, kya-sdk, kya-adapter-ap2 (dev: ed25519-dalek) | none | 0 (examples run, not unit-tested; all 11 run EXIT 0 per §2) | Not published; library crates never depend on it. |

Workspace test total: **339** test cases + **6** kya-crypto doctests, all green (§1).

### 7.2 Packaging status (tree is UNCOMMITTED; publish dry-run NOT RUN)

All commands were MSVC-sourced. **The working tree is dirty/uncommitted**
(14 tracked files modified; most of kya-crypto/kya-adapter-ap2/kya-sdk/examples
are untracked — see §7.3). This is reported honestly, not worked around: no
commit/reset was performed to satisfy Cargo's VCS-clean check.

**Manifest verification (all six library crates + examples + root):**

- Package names: `kya-core`, `kya-protocol`, `kya-crypto`, `kya-client`,
  `kya-adapter-ap2`, `kya-sdk`, and `kya-examples` — all correct and unique.
- `version = 0.1.0`, `edition = 2021`, `rust-version = 1.85`,
  `license = "MIT OR Apache-2.0"` — inherited from `[workspace.package]` by every
  member (verified in each `Cargo.toml`). ✔
- `repository` / `homepage` = `https://github.com/fintechbear/fintechbear-kya-suite`
  — inherited by all. RECONCILED (Phase 9) to the configured git remote `origin`;
  the metadata URL and the remote now agree. **OWNER CONFIRMATION REQUIRED:**
  offline verification cannot confirm who controls that GitHub repository, so the
  owner must confirm control (or correct the canonical URL) before publish (see
  [publication-checklist.md](publication-checklist.md) §B.1).
- Descriptions: present and accurate on every crate; each path dependency also
  carries an explicit `version = "0.1.0"` alongside its `path` (required for a
  future registry publish). ✔
- `kya-examples` has `publish = false`. ✔
- Dependency versions: the only external dependency is `ed25519-dalek = 2.2.0`
  (pinned, `default-features = false`, `features = ["std"]`), appearing as a
  normal dep of kya-crypto and as a dev-dep elsewhere. ✔
- README references: no crate `Cargo.toml` sets a `readme = ...` key, so each
  crate would fall back to a sibling `README.md` if present (only the repo-root
  `README.md` exists). Non-blocking; a per-crate `readme` or `exclude` tweak can
  be added before publish if desired.

**`cargo package --list` (files that would ship) — run per crate:**

| Crate | `cargo package --list` result |
|---|---|
| kya-core | 15 listed (`.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml`, `Cargo.toml.orig`, `src/*.rs` incl. `money/`, `tests/*.rs`). `cargo package` (full, offline) **packaged 19 files, 178.6 KiB (41.8 KiB compressed), verify-compiled OK**. |
| kya-protocol | 7 listed (`src/lib.rs`, `tests/property_wire.rs`, `tests/version_gate.rs`, + manifests/lock). |
| kya-crypto | 18 listed (`src/{b64url,engine,error,evidence,jws,keystore,lib,verifier}.rs`, 8 `tests/*.rs`, + manifests/lock). |
| kya-client | 7 listed (`src/{lib,runtime}.rs`, `tests/end_to_end.rs`, + manifests/lock). |
| kya-adapter-ap2 | 9 listed (`src/{constraints,error,lib,verify}.rs`, `tests/ap2_stage_c.rs`, + manifests/lock). |
| kya-sdk | 9 listed (`src/{ap2,lib,prelude,trust}.rs`, `tests/public_surface.rs`, + manifests/lock). |
| kya-examples | 13 listed (11 example `.rs` + `src/lib.rs` + manifests/lock) — but `publish = false`, so it is excluded from any registry publish. |

**Non-shippable directory check / `exclude`:** every `cargo package --list`
output shows only `src/`, `tests/`, the manifests, `Cargo.lock`, and the
generated `.cargo_vcs_info.json` / `Cargo.toml.orig`. **No crate would package
`.agents/`, `target/`, `fuzz/`, `docs/`, or `examples/` into a sibling crate**
because Cargo's VCS-aware packaging already excludes untracked/ignored paths and
non-member directories. **No `exclude` key is required** for correctness in
v0.1. (A defensive `exclude` could still be added later as belt-and-suspenders,
but nothing leaks today.)

**`cargo publish --dry-run -p kya-core` (the only crate with no in-repo path
deps):**

- `cargo publish --dry-run --allow-dirty -p kya-core` → **cannot complete here**:
  `Updating crates.io index` then `Could not resolve host: index.crates.io`
  (offline). With `--offline` it refuses: `attempting to make an HTTP request,
  but --offline was specified`. **A publish dry-run inherently requires reaching
  the registry index**, which is unavailable in this sandbox.
- As the achievable offline substitute, **`cargo package --allow-dirty --offline
  -p kya-core` fully succeeded**: it packaged the tarball **and verify-compiled
  it** from `target/package/kya-core-0.1.0`. This is the strongest packaging
  evidence obtainable offline for the one crate with no path deps.

**Path-dependency publish blocker (the real constraint):** crates with in-repo
path deps **cannot be registry-packaged until their deps are published first.**
Demonstrated empirically: `cargo package --allow-dirty --offline -p kya-protocol`
fails with `no matching package named 'kya-core' found — location searched:
crates.io index`. Cargo resolves each path dep's `version = "0.1.0"` against the
registry during packaging, so the required **publish order** is:

> `kya-core` → `kya-protocol` → `kya-crypto` → `kya-client` → `kya-adapter-ap2`
> → `kya-sdk`  (then `kya-examples` is **excluded** / `publish = false`).

This is a normal first-publish ordering requirement, **not a defect**, but it
means only `kya-core` is independently packageable today; the rest become
packageable as each predecessor lands on the registry.

**crates.io name availability for the six `kya-*` names: `UNVERIFIED`.** The
registry index is unreachable offline, so name availability / squatting cannot
be checked here. This MUST be verified on a networked host before publish. No
crates.io readiness is claimed.

### 7.3 Clean-checkout / portability readiness

Enumerated with **read-only** `git status` / `git ls-files` at HEAD `b06f8e6`.

**Git-TRACKED release-relevant files (committed at HEAD):** `Cargo.toml`,
`Cargo.lock`, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`CODE_OF_CONDUCT.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `.gitignore`,
`.github/workflows/ci.yml`; `crates/kya-core/**` (manifest + all `src/` incl.
`money/`), `crates/kya-protocol/**` (manifest + `src/lib.rs`),
`crates/kya-client/{Cargo.toml,src/lib.rs,src/runtime.rs,tests/end_to_end.rs}`;
`examples/{Cargo.toml,offline_evaluation.rs,src/lib.rs}`; and the original docs
(`architecture`, `first-adapter-decision`, `protocol-compatibility`,
`security-invariants`, `threat-model`, `trust-model`, plus the committed
strategy/research docs). Several tracked files are **modified** in the working
tree (14 `M` entries, incl. `Cargo.toml`, `Cargo.lock`, `README.md`,
`SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and the kya-core/-protocol/
-client sources).

**Git-UNTRACKED release-relevant files (present in the working tree only, `??`):**
the **entire** `crates/kya-crypto/`, `crates/kya-adapter-ap2/`, and
`crates/kya-sdk/` crates; `crates/kya-core/src/error.rs` and
`crates/kya-core/tests/`; `crates/kya-protocol/tests/`; the 10 numbered
`examples/example_0*.rs`; `deny.toml`; `fuzz/`; the new docs
(`known-limitations`, `release-notes-v0.1.0`, `release-readiness`,
`security-audit`, `quickstart`, `supported-protocols`, `api-usage`,
`cryptographic-architecture`, `security-limitations`, `future-commercial-platform`);
and the GitHub files (`SUPPORT.md`, `.github/dependabot.yml`,
`.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`).

**Honest clean-checkout conclusion:** because the working tree holds large
UNTRACKED portions of the release, a fresh `git clone` of HEAD `b06f8e6` would
**not** contain most of the release (three whole crates, the tests, the examples,
half the docs, `deny.toml`, CI companions). **A clean-checkout build therefore
cannot be proven in this phase**, because proving it requires a committed
snapshot, and this phase is **forbidden** to create one (strict read-only git; no
commit authorized). This is the single genuine release-process gap: **the working
tree must be committed into a reviewed snapshot before any clean-checkout build or
publish is attempted.** All gates pass on the working tree as it stands, so the
code is ready; the *commit* is the missing step and is an owner decision.

**Isolated-source test (substitute for, and explicitly NOT, a git
clean-checkout):** as the achievable offline substitute, the source tree was
copied into a temporary directory inside the workspace, excluding `target/`,
`.git/`, `.agents/`, IDE caches, and `fuzz/`, and then built and tested offline.
It passed (339 tests + 6 doctests) with no dependency on the original paths, on
private files, on machine-specific absolute paths, or on the network. The
temporary directory was then removed. This demonstrates that the source set
builds in isolation, but it is **NOT a git clean-checkout**: no committed snapshot
exists in this phase, so it does not prove a `git clone` build. The two claims are
kept distinct on purpose.

**Environment / portability notes:**
- `Cargo.lock` is **tracked and must be kept** (`.gitignore` documents this for
  reproducible builds). ✔
- `.gitignore` excludes `/target`, `*.rs.bk`, `*.pdb`, IDE dirs, and secret
  patterns (`.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `secrets/`). ✔
- **Windows MSVC requirement:** kya-crypto and anything above it need MSVC
  `link.exe` (ed25519-dalek's proc-macro tree); `vcvars64.bat` must be sourced on
  Windows. kya-core / kya-protocol link without it. Documented in `context.json`.
- **examples** depend only on in-repo path crates + a dev-dep; they use
  synthetic in-code keys and no local fixture files, so they are portable.
- **`.agents/audit/kya-bypass-probe`** carries its own `[workspace]` table and
  `path` deps to `../../../crates/kya-core` + `../../../crates/kya-crypto`; it is
  a **non-member** regression probe, not part of the shippable workspace, and its
  isolated lockfile needs `--offline` to reuse the cached `ed25519-dalek`.
- `fuzz/` is likewise a **non-member** crate (own `[workspace]`), so it does not
  affect the Rule 16 gates or packaging.

### 7.4 Cross-platform status

- **Windows (this host):** full Rule 16 gate set GREEN (see §7.6), MSVC sourced.
- **Linux:** the repository's CI (`.github/workflows/ci.yml`) runs
  fmt / clippy / `cargo test --workspace --all-features` / doc on
  `ubuntu-latest` with SHA-pinned `actions/checkout` and
  `dtolnay/rust-toolchain` and least-privilege `permissions: contents: read`.
  That workflow is configured and committed, but **this phase did not execute a
  CI run**, so Linux is **NOT VERIFIED here** (it will be exercised by CI once a
  commit/push happens — which this phase does not do).
- **macOS:** **NOT VERIFIED.** No macOS host is available in this sandbox and CI
  defines no macOS job.

### 7.5 — FINAL 20-POINT RELEASE REPORT

> Internal engineering review (AGENTS.md Rule 20): **not** an independent
> third-party audit. Evidence is first-hand, on a Windows MSVC host, offline.

**1. Verified repository state.** Branch `rebuild/kya-foundation-v0.1.0` at HEAD
`b06f8e68055107c4cb2647488f68c1715425f2ec` (confirmed by read-only
`git log -1 --format=%H`). Working tree is **dirty**: 14 tracked files modified,
plus a large untracked set (~63 entries) holding most of the release. No git
mutation occurred in this phase.

**2. Security vulnerabilities found.** One **P0** was confirmed empirically in a
prior audit phase and is tracked as **KYA-P0-001**: an external crate could call
the `pub` (doc-hidden) generic `kya_core::verification::internal::register::<V>()`
to mint a `VerifierSanction` for an always-`Verified` fake verifier and forge a
`VerifiedDelegation`/`VerifiedMandate` with **zero cryptography** (the probe
printed `BYPASS SUCCEEDED`). No *new* vulnerability was discovered in the
adversarial matrices (mandate binding, crypto/JWS, authorization/financial) or in
the public-surface reviews, including this phase's re-verification.

**3. Security defects fixed.** **KYA-P0-001 is CLOSED**: the verified-evidence
mint-point was relocated out of kya-core into
`crates/kya-crypto/src/evidence.rs`, bound to the concrete
`Ed25519SignatureVerifier` via `pub(crate)` constructors + a private
`sealed::Sealed` marker. The former `pub` generic seam is gone. The external
probe now **cannot compile** the attack path (E0603/E0624) and prints
**`BYPASS IMPOSSIBLE`** (re-verified first-hand this phase); five compile-fail
doctests + a forgery-regression suite lock it in. No dependency cycle was
introduced; `#![forbid(unsafe_code)]`, `Decision = Allow/Deny` only, and "no
`From<PolicyOutcome> for Decision`" all hold.

**4. Remaining P0 / P1 / P2 / P3 findings.** **No open P0 or P1.** No open P2 or
P3 security/correctness defects. Open *non-defect* items are all honestly
documented and environmental: crates.io name availability `UNVERIFIED`;
`cargo deny check advisories`, `cargo audit`, cargo-fuzz runs, and SBOM
`NOT RUN` (offline); Linux/macOS gate runs `NOT VERIFIED` here; the public
repository URL is **OWNER INPUT REQUIRED** (metadata vs git remote disagree); and
the working tree is not yet committed (see point 14 / §7.3).

**5. Verifier-registration security assessment.** The historical hole was the
generic verifier-registration seam. Post-fix, the *only* producer of verified
evidence is kya-crypto's `pub(crate)` mint-point bound to the one reviewed
`Ed25519SignatureVerifier`; an external type implementing `SignatureVerifier`
can be constructed but can **never** reach a `VerificationProof`,
verified `VerificationOutcome`, `VerifiedDelegation`, or `VerifiedMandate`.
Verified first-hand by the `.agents/audit/kya-bypass-probe` regression guard
(`BYPASS IMPOSSIBLE`, EXIT 0) and by in-tree compile-fail tests.

**6. Signed-mandate binding assessment.** Sound (OBS-01/OBS-02 in
`audit-notes.md`). `Mandate::canonical_encoding` is length-prefixed, magic-tagged
(`KYA-MANDATE`) and versioned; it is injective over its fields, and
`VerifiedMandate::establish` enforces byte-equality with the exact verified
bytes. Field substitution/omission/reordering, cross-format frames, future
versions, and two-mandates-one-signature all fail closed — locked in by
`canonical_encoding.rs` (14), `mandate_binding.rs` (12), and
`cross_context_reuse.rs` (5).

**7. Authorization-semantics assessment.** Fail-closed and deny-by-default
(OBS-04). `InvalidEvidence`/`Denied`/`RequiresApproval`/`Indeterminate` never
become `Allow`; authority `Timeout`/`Transport`/`Unknown` all map to `Deny`;
missing online state never implies permission; the at-limit boundary passes and
+1 minor unit denies; cross-currency is rejected with no float and no silent
conversion; checked `i128` arithmetic does not panic at `i128::MAX`. The only
`PolicyOutcome → Decision` path is the fail-closed `kya_client::authorize`;
there is no `From<PolicyOutcome> for Decision`. Backed by
`end_to_end.rs` (incl. `no_negative_stage_c_outcome_can_become_allow`),
policy unit tests, and `property_policy.rs`.

**8. Actual AP2 compatibility status.** **AP2-style constraints only; no AP2
wire interoperability.** `kya-adapter-ap2` maps constraint concepts onto the core
domain and verifies over caller-supplied exact bytes; it implements **no** AP2
envelope, canonicalization, schema, endpoints, or conformance vectors, claims
**no** certification, and has **official affiliation: none**. It never yields
`Allow`. The crate name, a rendered crate-doc warning block, and its exclusion
from the facade prelude make this unmistakable (Rule 20).

**9. Public-SDK quality assessment.** Clean, honest, misuse-resistant (§4,
`security-audit.md`). Curated `kya-sdk` facade + small prelude; verified-evidence
types constructible only through the real kya-crypto path; typed
`#[non_exhaustive]` errors with `Display`+`Error` and stable kebab-case
`ErrorCode`; up-front trust-key validation (no half-registration); no key bytes
in error messages (Rule 18); `unwrap`/`expect` only under `#[cfg(test)]`. **Works
fully offline with no FintechBear account/backend** — demonstrated by 11 running
examples. No API-misuse or correctness defect required a code change.

**10. Tests and real command results.** `cargo test --workspace --all-features`
= **PASS, 339 test cases, 0 failed** (per-crate: kya-core 122, kya-crypto 126,
kya-adapter-ap2 28, kya-client 16, kya-protocol 35, kya-sdk 12) + **6** kya-crypto
doctests (5 compile-fail + 1 positive). All 11 examples run EXIT 0 (§2). Full
gate commands and outcomes in §7.6.

**11. Dependency and license assessment.** Single external dependency:
`ed25519-dalek 2.2.0` (pinned, `default-features=false`, `features=["std"]`) and
its standard RustCrypto/dalek tree. `cargo deny check bans licenses sources` =
**`bans ok, licenses ok, sources ok`**. Licenses present: MIT, Apache-2.0,
BSD-3-Clause, BSD-1-Clause, Unicode-3.0 — no copyleft; project is
MIT OR Apache-2.0. `cargo deny check advisories` / `cargo audit` / SBOM =
**NOT RUN (offline)**, config is valid and fail-closed. Secret scan over tracked
files = none (test keys are deterministic in-code seeds).

**12. GitHub CI readiness.** `.github/workflows/ci.yml` runs
fmt / clippy / `cargo test --workspace --all-features` / doc on `ubuntu-latest`,
with `permissions: contents: read`, SHA-pinned `actions/checkout@11bd719` and
`dtolnay/rust-toolchain@a54c7af`, and `concurrency` cancel-in-progress.
`.github/dependabot.yml` (cargo + github-actions, weekly), issue/PR templates,
and `SUPPORT.md` are present (untracked — see point 14). CI is **configured and
least-privilege**; it has **not been executed in this phase**.

**13. Package status.** Manifests verified (names, inherited
version/edition/MSRV/license, descriptions; `kya-examples` `publish=false`; the
`repository` URL is **OWNER INPUT REQUIRED** (metadata vs git remote disagree)).
`cargo package --list` run for all seven crates — **no non-shippable dir
(`.agents/`, `target/`, `fuzz/`, `docs/`) would be packaged**, so **no `exclude`
is required**. `cargo package` for **kya-core succeeded fully offline** (19 files,
verify-compiled). `cargo publish --dry-run` is **NOT RUN** (needs the registry
index, unreachable offline). Path-dep crates are blocked until predecessors
publish; required order:
core -> protocol -> crypto -> client -> adapter-ap2 -> sdk (examples excluded).
See §7.2.

**14. Clean-checkout readiness.** **Not provable in this phase.** Most of the
release (all of kya-crypto/kya-adapter-ap2/kya-sdk, the tests, numbered examples,
`deny.toml`, `fuzz/`, new docs, GitHub companions) is **untracked** in the
working tree; a `git clone` of HEAD `b06f8e6` would not contain it. Proving a
clean-checkout build needs a **committed snapshot**, which this phase is
**forbidden** to create (strict read-only git). All gates pass on the working
tree, so the *code* is ready; committing the reviewed snapshot is the missing
owner step. Tracked-vs-untracked enumeration in §7.3.

**15. Cross-platform test status.** Windows (this host): all five gates GREEN.
Linux: CI configured for `ubuntu-latest` but **NOT VERIFIED here** (no CI run in
this phase). macOS: **NOT VERIFIED** (no host, no CI job). See §7.4.

**16. Current open-source capabilities.** Offline, account-free stages A–C:
explicit allow-listed trust configuration; **real** Ed25519 / narrow JWS-EdDSA
signature verification over exact bytes (strict, malleability- and
small-order-rejecting); issuer/audience/validity-window/transaction-binding
checks; authenticated-mandate inspection with honest
`ProofOfPossession::NotEstablished`; deterministic exact-integer monetary stage-C
policy evaluation producing structured outcomes; the fail-closed stage-D
`authorize` bridge and trait seams for a caller-supplied authority; and an
experimental, clearly-labeled AP2-*style* constraint adapter.

**17. Unsupported capabilities.** Agent proof-of-possession (NOT established);
online revocation, cumulative/distributed budget, and global replay protection
(stage D — seams only, no implementation shipped); payment execution enforcement
(stage E — integration layer, not the local SDK); AP2 wire interoperability
(none); general JOSE/JWT (only the narrow EdDSA subset); any
account/subscription/hosted backend (none required and none shipped).

**18. Remaining release blockers.** **No security (P0/P1) blocker.** The
remaining items are release-**process**/environment, all honestly documented and
none a code defect: (a) the working tree is uncommitted, so a clean-checkout
build is unprovable here and a reviewed commit is required before publish
(owner action; this phase cannot commit); (b) crates.io name availability for the
six `kya-*` names is `UNVERIFIED` (offline); (c) `cargo deny check advisories` /
`cargo audit` / cargo-fuzz / SBOM are `NOT RUN` (offline) and should run on a
networked host/CI; (d) Linux/macOS gate runs are `NOT VERIFIED` here; (e) the
public repository URL was **RECONCILED (Phase 9)** to the configured git remote
`origin` `https://github.com/fintechbear/fintechbear-kya-suite` and now agrees
with the workspace `Cargo.toml` metadata, with **OWNER CONFIRMATION** still
required that the owner controls that repo (offline cannot verify control);
(f) path-dep publish order must be followed. None of these authorize or require
weakening any security control.

**19. Files modified (this phase).** Documentation only (**no production source
changed**):
- `docs/public-release-manifest.md`: new, the SHIP / DO-NOT-SHIP file set.
- `docs/publication-checklist.md`: new, the required owner-action checklist.
- `docs/release-readiness.md`: this final record (stale phase scaffolding
  removed; Phase-8 re-verification folded in).
- `docs/security-audit.md`, `docs/known-limitations.md`,
  `docs/release-notes-v0.1.0.md`: finalized for the public release.
- `README.md` / `CHANGELOG.md`: reviewed for the repository-URL discrepancy
  (OWNER INPUT REQUIRED note added; no URL invented or changed).
- `.agents/tasks/task-kya-phase8-github-release/features/FEAT-001.json`: status
  and `findings`.
No `git` operation other than read-only `status`/`log`/`diff`/`ls-files` was
performed.

**20. FINAL RELEASE VERDICT.**

# READY FOR OWNER REVIEW

**Justification.** The one confirmed release-blocking defect (KYA-P0-001, the
verifier-sanction bypass) is **closed at the root** and locked in by the external
probe (`BYPASS IMPOSSIBLE`) and in-tree compile-fail/forgery-regression tests.
All five Rule 16 gates are **GREEN**; all 339 tests + 6 doctests pass; all 11
examples run; `cargo deny` bans/licenses/sources are **ok**; the public surface
is clean, honest, and offline/account-free; AP2 and trademark status are stated
truthfully; packaging produces clean file lists with no non-shippable leakage and
a correct publish-order plan. **No open P0 or P1 security or financial-correctness
defect remains.** The only outstanding items are the honestly-documented
`NOT RUN` / `NOT VERIFIED` / `UNVERIFIED` environmental items and the
release-process step of committing the reviewed working tree — none of which is a
security defect, and all of which are owner/CI actions.

**This verdict explicitly does NOT authorize publishing.** Before any publish the
owner must: commit the reviewed working tree into a clean snapshot and prove a
clean-checkout build; confirm/correct the `repository`/`homepage` URL and
crates.io name availability; run the advisory/audit/fuzz/SBOM scans and the
Linux/macOS gates on a networked host; and publish in the required path-dep order.
**No publish, tag, release, commit, or push occurred in this phase, and none is
authorized by it.**

### 7.6 Final Rule 16 gate run (this phase, MSVC sourced)

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | **PASS** (EXIT 0, no diff) |
| Clippy | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **PASS** (EXIT 0, 0 warnings) |
| Tests | `cargo test --workspace --all-features` | **PASS** (339 tests, 0 failed, EXIT 0) |
| Doctests | `cargo test --doc --workspace` | **PASS** (6 kya-crypto doctests: 5 compile-fail + 1 positive, EXIT 0) |
| Docs | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | **PASS** (EXIT 0) |

Read-only `git log -1 --format=%H` after all work:
`b06f8e68055107c4cb2647488f68c1715425f2ec` — **HEAD unchanged**, working-tree
entries preserved.
