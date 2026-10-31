# Community launch and growth readiness

This document collects the **organic**, honest launch assets for the FintechBear
KYA SDK, plus the exact owner instructions for every GitHub action that cannot
be performed from this offline environment.

It optimizes for **organic discovery only**. There is **no** growth hacking in
this plan: no bots, no stars-for-stars exchanges, no vote manipulation, no spam,
no fabricated adoption statistics, and no unsupported compliance or certification
claims. Everything here follows [AGENTS.md](../AGENTS.md) Rule 20 (honest
compatibility and security claims). If a statement here cannot be backed by
evidence in the repository, it does not belong here.

> **Scope and honesty note.** Several items below require live GitHub network or
> admin access (repository metadata, security settings, labels, inspecting the
> live Release page, and whether Dependabot has opened pull requests). This
> environment is **offline** and cannot reach `github.com`, so those items are
> written as **exact owner instructions** and are explicitly marked
> **NOT APPLIED - remaining owner action**. Nothing in this document claims that
> any GitHub setting, label, topic, or metadata value has been applied or
> enabled, and the current live state of anything on GitHub is **not asserted**.

---

## 1. The pitch

### One-sentence pitch

> Know what an AI agent is authorized to do: a security-first Rust SDK for
> verifying AI-agent delegated authority and evaluating transaction policies,
> with a type system that refuses to mistake "looks fine offline" for
> "authorized."

### Technical elevator pitch

FintechBear KYA is an open-source Rust SDK (dual licensed MIT OR Apache-2.0) that
decomposes agent authorization into five non-interchangeable stages: identity
(A), signature verification (B), static policy evaluation (C), online
authoritative authorization (D), and execution enforcement (E). It ships a real
Ed25519 / JWS-EdDSA verification engine (`kya-crypto`, standard reviewed
primitives, no invented cryptography), exact integer money (minor units plus an
explicit ISO-4217 currency, no floats), and a deterministic offline policy
evaluator. Its defining property is a **type-level wall between eligibility and
authorization**: there is deliberately no `From<PolicyOutcome> for Decision`
anywhere in the SDK, so a passing offline evaluation can never be converted into
an `Allow` except through the fail-closed `kya_client::authorize` bridge, which
requires an explicit online authority. It is honest about its limits: no
confirmed AP2 wire interoperability, no agent proof-of-possession, no real-time
revocation, no distributed budget, no global replay protection, no production
payment-execution enforcement, and no independent third-party audit.

---

## 2. Target audiences

The primary audiences, in rough priority order:

1. **Rust developers building AI-agent frameworks** who need a principled
   authorization model and type-safe domain primitives rather than ad-hoc
   permission checks.
2. **Fintech and payments platform engineers** evaluating how to let agents act
   on behalf of a principal without conflating a valid signature with a valid
   authorization.
3. **AI-agent tooling authors** who want a verification + policy layer they can
   embed, with explicit trust anchors and deny-by-default semantics.
4. **Security engineers** interested in the fail-closed design, the sealed
   verified-evidence minting, the explicit allow-listed trust model, and the
   EdDSA-only algorithm allowlist.

---

## 3. Working demo

The single recommended primary demo drives the whole verify -> evaluate ->
authorize flow and narrates each stage:

```sh
cargo run -p kya-examples --example demo
```

See [demo.md](demo.md) for the plain-language walkthrough and the real captured
output. The numbered `examples/example_01..10` files drill into individual
facets. On Windows, source `vcvars64.bat` first (see the README Quick Start
note).

---

## 4. Top technical differentiators

Each differentiator below is backed by code in this repository.

- **A type-level eligibility-vs-authorization wall.** There is deliberately no
  `From<PolicyOutcome> for Decision` anywhere in the SDK. A static
  `PolicyOutcome` cannot be turned into a final `Decision` except through the
  fail-closed bridge. (AGENTS.md Rule 12.)
- **A fail-closed `authorize` bridge.** Any error, timeout, unknown state, or
  approval-required signal resolves to `Deny`; `Allow` requires explicit
  authoritative approval from an online authority you supply. (Rule 9.)
- **Exact integer money, no floats.** Money is integer minor units plus an
  explicit ISO-4217 currency; arithmetic is checked and fails closed on
  overflow; cross-currency operations are rejected. (Rule 8.)
- **Sealed verified-evidence minting owned inside `kya-crypto`.** The
  verified-outcome and verified-evidence constructors (`VerificationProof`,
  `VerificationOutcome::verified`, `run_verifier`, `VerifiedDelegation::establish`,
  `VerifiedMandate::establish`) are `pub(crate)`/private **inside `kya-crypto`**,
  bound to the one concrete `Ed25519SignatureVerifier`. `kya-core` holds only a
  pure description seam and cannot mint verified evidence, so an external
  always-`Verified` verifier can describe a result but can never cause verified
  evidence to be minted.
- **Explicit, allow-listed trust.** Trust is explicit and allow-listed; there is
  no implicit or wildcard trust and no key discovery over the network. Issuers
  are verified against configured trust anchors. (Rule 11.)
- **EdDSA-only algorithm allowlist.** Only Ed25519 / EdDSA is accepted (raw
  Ed25519 per RFC 8032 and JWS compact-form EdDSA per RFC 7515 / 7518 / 8037).
  `alg: none`, HMAC, RSA, and ECDSA are rejected.

---

## 5. Honest capability limitations

These are structural, not oversights. They are the same seven limitations stated
in the [README](../README.md) and [docs/known-limitations.md](known-limitations.md):

1. **No confirmed full AP2 wire interoperability.** The AP2 adapter is
   experimental and incomplete; it does not parse the real AP2 signature
   envelope and makes no AP2 conformance or certification claim.
2. **No agent proof-of-possession.** Local verification proves only an issuer
   signature, not that the agent currently controls its own private key; the SDK
   reports this honestly as `ProofOfPossession::NotEstablished`.
3. **No real-time revocation.** Revocation state is a stage-D concern behind the
   `OnlineAuthorizer` seam; the open-source core ships no implementation.
4. **No distributed (cumulative) budget enforcement.** Cumulative budget state
   is a stage-D concern; the core ships no implementation.
5. **No global replay protection.** Global replay state is a stage-D concern;
   the core ships no implementation.
6. **No production payment-execution enforcement.** Execution enforcement
   (stage E) is a trait seam (`IntegrationClient`) only; the core ships no
   concrete payment or ledger execution path.
7. **No independent third-party security audit** has been performed, and no
   regulatory, PCI-DSS, or SOC 2 certification is claimed. The only audit on
   record is internal (see [security-audit.md](security-audit.md)); it is **not**
   a third-party audit.

Any launch post that omits these, or that implies audit/certification/wire
compatibility, violates Rule 20 and must not be published.

---

## 6. Suggested GitHub topics

Use the validated topic list from Section 11 (Step 1). The same ten lowercase,
hyphenated-where-multiword topics apply: `rust`, `ai-agents`, `agentic-ai`,
`authorization`, `identity`, `fintech`, `cryptography`, `security`,
`open-source`, `sdk`.

---

## 7. Organic launch assets

These are drafts for the maintainer to post. They are honest and avoid any
engagement manipulation. Fill in only facts that remain true at posting time.

### 7.1 DEV.to article outline

Working title: **"Why a valid signature is not an authorization: designing a
fail-closed agent-authorization SDK in Rust"**

1. **Hook.** AI agents can act. But who decides what they are allowed to do? A
   signature proves authenticity, not authorization.
2. **The five-stage model.** Identity, signature verification, static policy,
   online authority, execution enforcement; why they must not be collapsed.
3. **The type-level wall.** Walk through why there is no
   `From<PolicyOutcome> for Decision` and how the compiler enforces that
   eligibility cannot become an `Allow` by accident.
4. **Fail-closed by construction.** The `authorize` bridge and deny-by-default
   semantics.
5. **Exact money, no floats.** Integer minor units + ISO-4217, checked
   arithmetic, cross-currency rejection.
6. **Sealed verified-evidence minting.** How `kya-crypto` owns the mint-points
   so a hostile verifier implementation is inert.
7. **What it does NOT do (on purpose).** The seven limitations, stated plainly.
8. **Try it.** `cargo run -p kya-examples --example demo`, link to the repo and
   [demo.md](demo.md).
9. **Call for contributors.** Point at the good-first-issue flow (Section 12).

### 7.2 r/rust technical announcement (draft)

> **FintechBear KYA: a fail-closed, type-safe agent-authorization SDK (v0.1.0,
> MIT OR Apache-2.0)**
>
> I have been building an open-source Rust SDK that separates "an agent's
> request is cryptographically authentic" from "an agent's request is
> authorized." The core idea is a type-level wall: there is deliberately no
> `From<PolicyOutcome> for Decision`, so a passing offline policy check can
> never become an `Allow` without going through a fail-closed bridge that
> requires an online authority.
>
> Highlights: real Ed25519 / JWS-EdDSA verification (no invented crypto),
> exact integer money (no floats), deterministic offline policy evaluation,
> explicit allow-listed trust, and `#![forbid(unsafe_code)]` across the
> workspace. CI runs fmt / clippy -D warnings / tests / doctests / rustdoc -D
> warnings / examples build on a 3-OS matrix, plus cargo-deny.
>
> Honest limitations (v0.1.0): no confirmed AP2 wire interop, no agent
> proof-of-possession, no real-time revocation, no distributed budget, no
> global replay protection, no production payment-execution enforcement, and no
> independent third-party audit. Those are structural and documented.
>
> Demo: `cargo run -p kya-examples --example demo`. Feedback on the API and the
> threat model is very welcome.

Post it as a self-text technical post, respond to questions, and do not ask for
upvotes.

### 7.3 Show HN positioning (draft)

> **Show HN: FintechBear KYA - a Rust SDK that refuses to confuse a signature
> with an authorization**
>
> It is an open-source, fail-closed agent-authorization SDK. A valid signature
> proves authenticity, not that a transaction is allowed right now, so the SDK
> splits authorization into five stages and uses the type system to keep
> offline eligibility from ever becoming an `Allow` without an online authority.
> Early v0.1.0; honest about what it does not do yet (no AP2 wire interop, no
> real-time revocation/budget/replay, no execution enforcement, no third-party
> audit). Would love feedback on the model.

Keep the title factual (no superlatives), and engage with critical comments
directly.

### 7.4 LinkedIn technical introduction (draft)

> I open-sourced FintechBear KYA, a security-first Rust SDK for AI-agent
> authorization. The premise: an AI agent acting on your behalf can produce a
> perfectly valid signature and still not be authorized to move money. The SDK
> separates identity, signature verification, static policy, online authority,
> and execution into five stages, and uses Rust's type system to prevent an
> offline "looks fine" result from being mistaken for an authorization.
>
> It is early (v0.1.0), dual licensed MIT OR Apache-2.0, and deliberately honest
> about its limits (no AP2 wire interop, no real-time revocation/budget/replay,
> no execution enforcement, no third-party audit yet). If you work on agent
> frameworks, payments, or authorization, I would value your feedback.

No affiliation or endorsement claims; FintechBear is the independent maintainer.

---

## 8. CI, fuzz, and Dependabot static review (Step 7)

This is a **static** review of the committed workflow and configuration files.
It does not and cannot assert the live state of any GitHub Actions run; that can
only be observed online.

### 8.1 `.github/workflows/ci.yml`

- **Least privilege.** The workflow declares `permissions: contents: read`, so
  the quality-gate jobs only read the repository. This is the correct minimum
  and should not be widened without a documented reason.
- **Three-OS matrix.** The `quality-gates` job runs on `ubuntu-latest`,
  `windows-latest`, and `macos-latest` with `fail-fast: false`, so one OS
  failing does not cancel the others and the full cross-platform signal stays
  visible.
- **The full gate set, as steps.** fmt (`cargo fmt --all -- --check`), clippy
  (`cargo clippy --workspace --all-targets --all-features -- -D warnings`),
  tests (`cargo test --workspace --all-features`), doctests
  (`cargo test --doc --workspace`), rustdoc (`cargo doc --workspace --no-deps`
  with `RUSTDOCFLAGS: -D warnings`), and an examples build
  (`cargo build -p kya-examples --examples`). These match AGENTS.md Rule 16 and
  must not be weakened.
- **Dependency hygiene.** A second `cargo-deny` job runs
  `cargo deny check licenses bans sources advisories` on ubuntu. The advisories
  check needs the RustSec database (network), which GitHub-hosted runners have.
  All four checks are treated as hard gates.
- **Action pinning.** Third-party actions are pinned to commit SHAs:
  `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` and
  `dtolnay/rust-toolchain@a54c7afa936fefeb4456b2dd8068152669aa8203`. SHA pinning
  (rather than a floating tag) is the supply-chain-safe choice. `cargo-deny` and
  `cargo-fuzz` are installed from crates.io with `--locked` because no reviewed,
  pre-pinned action SHA is available for them in this repo; that is an honest
  trade-off noted in the workflow comments, not a gap to paper over.

**Recommendation (owner action):** require the CI checks as required status
checks on `main` before merge (see Section 10, Step 6). This is a repository
setting and cannot be applied offline.

### 8.2 `.github/workflows/fuzz.yml`

- **What it is.** A nightly-toolchain job on `ubuntu-latest` with
  `permissions: contents: read`. It installs `cargo-fuzz` (from crates.io,
  `--locked`), **builds** all four libFuzzer targets (`fuzz_b64url_decode`,
  `fuzz_jws_verify`, `fuzz_mandate_binding`, `fuzz_verify_delegation`), then
  **runs** each with `-max_total_time=60`, i.e. short bounded sessions of about
  60 seconds each.
- **What it is NOT (stated honestly).** These short bounded runs are **not** a
  full coverage-guided fuzzing campaign. Sixty seconds per target per run is a
  smoke-level exercise that catches harness breakage and shallow panics; it is
  not a sustained corpus-building campaign and does not establish absence of
  deeper bugs. Building a fuzz target is not the same as fuzzing it, and target
  compilation must not be described as completed fuzzing. For meaningful
  coverage, run the targets with a much larger time budget (or an OSS-Fuzz-style
  continuous setup) outside per-commit CI. The deterministic SplitMix64 property
  loops in the test tree (`crates/kya-crypto/tests/property_fuzz.rs` and the
  `kya-core` property suites) are fixed-seed pseudo-random suites and are **not**
  coverage-guided fuzzing either.

### 8.3 `.github/dependabot.yml`

- **What it does.** Weekly updates for two ecosystems: `cargo` (directory `/`,
  the workspace root manifest) and `github-actions` (directory `/`). Each has
  `open-pull-requests-limit: 5`. Cargo PRs carry labels `dependencies` and
  `rust` with commit prefix `chore(deps)`; Actions PRs carry `dependencies` and
  `github-actions` with prefix `chore(ci)`.
- **Provenance caution (owner action).** Dependabot opens pull requests that the
  existing CI gates then evaluate; it grants no extra workflow privileges.
  **Major-version action upgrades must be reviewed for provenance before merge,
  and a pinned action SHA should only be advanced after verifying it corresponds
  to the claimed release.** Treat a Dependabot bump that unpins an action, or
  that advances a SHA you cannot map to a reviewed tag, as a change to scrutinize,
  not to auto-merge.
- **Offline caveat.** Whether Dependabot has actually opened any pull requests
  (and what they contain) **cannot be checked from this offline environment**.
  Review the live "Pull requests" and "Insights -> Dependency graph ->
  Dependabot" views on GitHub when online.

No check in any of these files should be weakened to make CI green (AGENTS.md
Rule 22).

---

## 9. Release presentation assessment (Step 8)

> **The v0.1.0 pre-release already exists and MUST NOT be touched.** This
> document does not delete, recreate, retag, force-move, or re-point the tag,
> does not add invented binaries, and does not publish any crate. The **live
> Release page cannot be reviewed from this offline environment**, so its current
> contents are **not asserted** here.

### 9.1 What a good release description should contain

For reference when the owner reviews or revises release notes online:

- A concise **feature summary** (the five-stage model; real Ed25519 / JWS-EdDSA
  verification; exact integer money; deterministic offline policy; the
  fail-closed `authorize` bridge).
- **Install-from-git instructions**, because the crates are **unpublished** (not
  on crates.io): clone and `cargo build --workspace`, or a git dependency on
  `kya-sdk`. State the MSRV (**1.85**, edition 2021).
- **Version limitations**: the seven honest limitations from Section 5.
- **Honest test claims**: "339 unit/integration tests + 6 doctests across the
  workspace, verified on a 3-OS CI matrix (ubuntu/windows/macos)." Do not round
  up or imply external validation.
- **Security disclaimers**: not independently audited, no certification, not
  production-safe; a valid signature is not an authorization.
- **Crate publishing status**: unpublished.
- **AP2 status**: experimental, no confirmed wire interoperability.

### 9.2 Future v0.1.1 maintenance release recommendation

**Recommendation: YES, cut a future v0.1.1.** The documentation, demo, and
contributor-experience improvements in this work are source changes that land
**after** the v0.1.0 tag, so they are not part of v0.1.0 and should be bundled
into a small maintenance release. Cutting v0.1.1 from `main` after this pull
request merges is an **owner action** (tag + GitHub Release) and is **not
performed here**. Doing so leaves the historical v0.1.0 pre-release accurate and
untouched while giving users a clean version that includes the corrected docs and
the primary demo. See [release-readiness.md](release-readiness.md) for the gate
and supply-chain evidence that a maintenance release would reference.

---

## 10. Owner instructions: security settings (Step 6)

> **NOT APPLIED - remaining owner action.** None of the settings below can be
> changed or read from this offline environment. Nothing here is claimed to be
> enabled. Do not invent a security contact; the private reporting channel is
> GitHub Private Vulnerability Reporting, as documented in
> [SECURITY.md](../SECURITY.md).

Perform these as a repository admin for `fintechbear/fintechbear-kya-suite`.

### 10.1 Private Vulnerability Reporting (PVR)

- **UI:** Settings -> Code security and analysis -> **Private vulnerability
  reporting** -> **Enable**.
- **Verify:** the Security tab shows a **Report a vulnerability** button.

### 10.2 Dependabot alerts and security updates

- **UI:** Settings -> Code security and analysis -> enable **Dependabot alerts**
  and **Dependabot security updates**.
- (Version-update PRs are already configured in
  [`.github/dependabot.yml`](../.github/dependabot.yml).)

### 10.3 Secret scanning and push protection

- **UI:** Settings -> Code security and analysis -> enable **Secret scanning**
  and **Push protection**.

### 10.4 Branch protection / ruleset on `main` (do NOT lock out the solo owner)

Use a **branch ruleset** (Settings -> Rules -> Rulesets -> New branch ruleset)
targeting `main` with:

- **Require a pull request before merging** (you may keep required approvals at 0
  for a solo maintainer so you are not blocked waiting on a second reviewer).
- **Require status checks to pass before merging**, and select the CI checks as
  required (see 10.5).
- **Block force pushes** and **restrict deletions** of `main`.
- Do **not** enable "Do not allow bypassing the above settings" in a way that
  locks you out; keep repository admins on the bypass list so a solo owner can
  still perform maintenance.

CLI sketch (adjust the exact check contexts to the names GitHub reports once CI
has run at least once):

```sh
# Example: create/update a ruleset via the REST API. Confirm the required
# status-check contexts first from an actual CI run.
gh api -X POST repos/fintechbear/fintechbear-kya-suite/rulesets \
  -f name='protect-main' -f target='branch' -f enforcement='active' \
  -F conditions='{"ref_name":{"include":["refs/heads/main"],"exclude":[]}}' \
  -F rules='[{"type":"pull_request"},{"type":"non_fast_forward"},{"type":"deletion"},{"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"fmt / clippy / test / doc / examples (ubuntu-latest)"}],"strict_required_status_checks_policy":false}}]'
```

> The exact `context` strings must match what GitHub records for the matrix jobs;
> read them from a real CI run before finalizing the ruleset. Nothing above is
> applied here.

### 10.5 Recommended required status checks

Require the CI quality-gate job (all three OS matrix legs) and the `cargo-deny`
job as required status checks before merging to `main`. Requiring passing CI
before merge is the single highest-value protection and is an **owner action**.

### 10.6 GitHub Actions permissions

- **UI:** Settings -> Actions -> General -> **Workflow permissions** -> set the
  default `GITHUB_TOKEN` to **Read repository contents permission** (read-only).
  This matches the workflows, which already declare `permissions: contents:
  read`.
- Leave "Allow GitHub Actions to create and approve pull requests" **off** unless
  a specific workflow needs it.

---

## 11. Owner instructions: repository metadata (Step 1)

> **NOT APPLIED - remaining owner action.** The description, topics, and homepage
> cannot be set or read offline. On a previous observation the description,
> topics, and homepage appeared **empty**; because this environment cannot query
> GitHub, that observation is **not re-verified here** and the current live state
> is **not asserted**. **Do not invent a homepage URL.**

### 11.1 Recommended description

```
Security-first Rust SDK for AI agent identity, delegated authority verification, and transaction policy evaluation.
```

### 11.2 Recommended topics (validated)

Ten topics: `rust`, `ai-agents`, `agentic-ai`, `authorization`, `identity`,
`fintech`, `cryptography`, `security`, `open-source`, `sdk`.

**Topic-rule validation (GitHub constraints):**

- **Lowercase:** every topic above is lowercase. OK.
- **Hyphenated where multiword:** `ai-agents`, `agentic-ai`, `open-source` use
  hyphens; all others are single words. OK.
- **<= 50 characters each:** the longest is `authorization`/`cryptography` (13
  characters). OK.
- **<= 20 topics total:** 10 topics. OK.
- Characters are limited to lowercase letters, digits, and hyphens, and each
  starts with a letter or digit. All ten comply.

### 11.3 Apply via gh CLI (owner runs these online)

```sh
# Description (homepage intentionally omitted - do not invent one).
gh repo edit fintechbear/fintechbear-kya-suite \
  --description 'Security-first Rust SDK for AI agent identity, delegated authority verification, and transaction policy evaluation.'

# Topics (replaces the full topic set on the repository).
gh api -X PUT repos/fintechbear/fintechbear-kya-suite/topics \
  -H 'Accept: application/vnd.github+json' \
  -f names='rust' -f names='ai-agents' -f names='agentic-ai' \
  -f names='authorization' -f names='identity' -f names='fintech' \
  -f names='cryptography' -f names='security' -f names='open-source' \
  -f names='sdk'
```

### 11.4 Apply via Settings UI (alternative)

- Description: click the **About** gear on the repository home page, fill in the
  **Description** field. Leave **Website** blank (no homepage to claim).
- Topics: same **About** gear -> **Topics** field -> add the ten topics above.

---

## 12. Owner instructions: labels and starter issues (Step 5)

> **NOT APPLIED - remaining owner action.** The labels and issues below are
> **proposals**. None have been created. Create them online once you agree.

### 12.1 Label set

| Label | Color (hex) | Description |
|-------|-------------|-------------|
| `good first issue` | `7057ff` | Good for newcomers; small, well-scoped. |
| `help wanted` | `008672` | Extra attention or contributors wanted. |
| `bug` | `d73a4a` | A defect in the SDK (not a security vulnerability). |
| `documentation` | `0075ca` | Improvements or additions to docs. |
| `enhancement` | `a2eeef` | New capability or improvement. |
| `security` | `b60205` | Security-relevant work (never a vuln report; those go private). |
| `protocol` | `5319e7` | Protocol-compatibility / AP2 adapter work. |
| `rust` | `dea584` | Rust toolchain / crate-dependency work (used by Dependabot). |
| `testing` | `fbca04` | Tests, property suites, fuzz harnesses, CI. |

`bug`, `enhancement`, `dependencies`, `rust`, and `github-actions` are already
referenced by the issue templates and Dependabot config; creating the full set
above keeps the triage vocabulary consistent.

### 12.2 `gh label create` commands (owner runs these online)

```sh
R=fintechbear/fintechbear-kya-suite
gh label create "good first issue" --repo "$R" --color 7057ff --description "Good for newcomers; small, well-scoped." --force
gh label create "help wanted"      --repo "$R" --color 008672 --description "Extra attention or contributors wanted." --force
gh label create "bug"              --repo "$R" --color d73a4a --description "A defect in the SDK (not a security vulnerability)." --force
gh label create "documentation"    --repo "$R" --color 0075ca --description "Improvements or additions to docs." --force
gh label create "enhancement"      --repo "$R" --color a2eeef --description "New capability or improvement." --force
gh label create "security"         --repo "$R" --color b60205 --description "Security-relevant work (never a vuln report; those go private)." --force
gh label create "protocol"         --repo "$R" --color 5319e7 --description "Protocol-compatibility / AP2 adapter work." --force
gh label create "rust"             --repo "$R" --color dea584 --description "Rust toolchain / crate-dependency work." --force
gh label create "testing"          --repo "$R" --color fbca04 --description "Tests, property suites, fuzz harnesses, CI." --force
```

### 12.3 Proposed starter issues (grounded in real repo needs)

Each issue below is small, actionable, grounded in something actually observed in
the repository, and has testable acceptance criteria. They are **proposals only**
and have **not** been created. Do not file speculative or duplicate work.

#### Issue A - Add explicit negative tests for strict base64url decoding via the public JWS door

- **Labels:** `good first issue`, `testing`, `security`
- **Context (real):** `kya_crypto::b64url::decode` is crate-private and is only
  reachable publicly through `JwsEdDsa::verify`. The fuzz target
  `fuzz/fuzz_targets/fuzz_b64url_decode.rs` documents the decoder's rejection
  rules (alphabet checks, padding rejection, impossible length remainders,
  non-zero trailing bits) but these are driven only by the fuzzer, not by named
  deterministic unit tests.
- **Task:** add deterministic negative tests (e.g. in
  `crates/kya-crypto/tests/jws_encoding_edges.rs`) that feed a JWS whose segments
  contain: (1) a standard-base64 `+`/`/` character, (2) `=` padding, (3) a length
  with an impossible remainder, and (4) non-zero trailing bits, and assert
  `JwsEdDsa::verify` returns the appropriate typed error and never panics.
- **Acceptance criteria:** at least four new `#[test]` cases, each asserting a
  typed `Err` (no panic) for a distinct malformed-base64url class; the full gate
  set stays green; no production code changed.

#### Issue B - Clarify in protocol-compatibility.md what "constraint adapter" verification does and does not cover

- **Labels:** `good first issue`, `documentation`, `protocol`
- **Context (real):** [protocol-compatibility.md](protocol-compatibility.md)
  states the AP2 adapter verifies signatures "over caller-supplied exact bytes"
  and that the real AP2 envelope is `[UNVERIFIED]`/BLOCKED. New readers often
  miss that "exact bytes" means the caller is responsible for producing the
  signing input, and that no AP2 wire parsing happens.
- **Task:** add a short "What "caller-supplied exact bytes" means" subsection
  with a concrete one-paragraph example of the caller's responsibility, and a
  one-line pointer from the README AP2 section to it.
- **Acceptance criteria:** the new subsection exists, makes no new compatibility
  claim, keeps every existing `[UNVERIFIED]`/BLOCKED marker intact, and
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` still passes.

#### Issue C - Add a runnable example for the JWS-EdDSA verification path

- **Labels:** `good first issue`, `enhancement`, `documentation`
- **Context (real):** `examples/example_02_verify_signed_evidence.rs` and the new
  `examples/demo.rs` exercise the raw-Ed25519 detached-signature path. The SDK
  also accepts JWS compact-form EdDSA (RFC 7515/7518/8037), but no numbered
  example demonstrates verifying a compact JWS specifically.
- **Task:** add `examples/example_11_verify_jws_eddsa.rs` that builds a valid
  compact JWS (`alg: EdDSA`) with a test-only deterministic key, verifies it
  through the public surface, and prints a short narration; register it in
  `examples/Cargo.toml`.
- **Acceptance criteria:** `cargo run -p kya-examples --example
  example_11_verify_jws_eddsa` succeeds; the key is clearly labeled test-only;
  `cargo clippy ... -D warnings` and the examples build stay green; no production
  code changed.

#### Issue D - Point the bug-report template and docs at the primary demo as a repro baseline

- **Labels:** `good first issue`, `documentation`
- **Context (real):** the new `examples/demo.rs` / [demo.md](demo.md) are the
  recommended first run, but `.github/ISSUE_TEMPLATE/bug_report.md` does not
  mention them as a baseline to confirm against before filing.
- **Task:** add one line to the bug-report template asking whether the issue
  reproduces against the primary demo (`cargo run -p kya-examples --example
  demo`), keeping the existing fields unchanged.
- **Acceptance criteria:** the template still prompts for crate+version,
  platform, toolchain, and a minimal repro; the new line is additive; the
  security redirect is untouched.

#### Issue E - Expand the EdDSA-only algorithm-rejection tests to cover each rejected `alg` by name

- **Labels:** `help wanted`, `testing`, `security`
- **Context (real):** the README and docs state `alg: none`, HMAC, RSA, and
  ECDSA are rejected, and `crates/kya-crypto/tests/jws_security.rs` covers
  rejection. Confirm there is one explicit named test per rejected family so a
  future regression is unambiguous.
- **Task:** audit `jws_security.rs`; for any rejected `alg` family not already
  covered by a dedicated named test (`none`, `HS256`, `RS256`, `ES256`), add one
  that asserts a typed rejection (never a panic, never a verify success).
- **Acceptance criteria:** one clearly named `#[test]` per rejected family; each
  asserts a typed `Err`; the full gate set stays green; no production code or
  existing test weakened (Rule 22).

---

## 13. First-time contributor onboarding

A short on-ramp for new contributors (see [CONTRIBUTING.md](../CONTRIBUTING.md)
and [AGENTS.md](../AGENTS.md) for the authoritative detail).

1. **Start with a `good first issue`.** Pick one of the proposals in Section 12
   (once filed), or ask on a Discussion. Keep the pull request focused on a
   single concern.
2. **Learn the five-stage mental model.** Identity (A), signature verification
   (B), static policy (C), online authority (D), execution enforcement (E). They
   are never collapsed; eligibility (A+B+C) is never authorization. See
   [architecture.md](architecture.md).
3. **Run the demo and the gates locally.** `cargo run -p kya-examples --example
   demo`, then the five quality gates CI enforces:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo test --workspace --all-features`
   - `cargo test --doc --workspace`
   - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`

   On Windows, source `vcvars64.bat` first.
4. **Know the security-regression-test expectation.** Any change to identity,
   verification, policy, decision, or authorization code must add or update a
   security regression test that locks in the secure behavior (AGENTS.md Rule
   17), and must not weaken, skip, or delete an existing test to make CI green
   (Rule 22).
5. **Report security issues privately.** Never open a public issue, pull request,
   or discussion for a vulnerability; use GitHub Private Vulnerability Reporting
   per [SECURITY.md](../SECURITY.md).
6. **Sign off your commits (DCO).** Use `git commit -s` to attest to the
   Developer Certificate of Origin, as described in CONTRIBUTING.md.
