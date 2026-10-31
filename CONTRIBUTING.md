# Contributing to FintechBear KYA

Thank you for your interest in contributing. This is a security-critical
financial-authorization SDK, so the bar for changes is high and deliberate.
Before you start, read [AGENTS.md](AGENTS.md): it is the authoritative
engineering constitution, and every contribution must comply with its 22 rules.

## The 22 rules in brief

[AGENTS.md](AGENTS.md) is authoritative and holds the full text. Every
contribution must comply with all 22 rules. In brief:

1. Clean Code, SOLID, DRY, KISS, YAGNI.
2. Clean architecture: dependencies point inward toward `kya-core`; the core
   depends on nothing in-repo and performs no I/O.
3. Idiomatic Rust with strong type safety; make illegal states unrepresentable.
4. No unsafe Rust by default (`#![forbid(unsafe_code)]` in every crate).
5. No panic from untrusted input.
6. No `unwrap` / `expect` / panicking indexing in security-critical production
   paths (tests may use them for brevity).
7. Explicit, typed, `#[non_exhaustive]` error enums implementing `Display` and
   `std::error::Error`.
8. Exact monetary arithmetic; integer minor units plus ISO-4217 currency, no
   floats, checked and fail-closed, cross-currency rejected.
9. Deny by default and fail closed.
10. Standard cryptography only; no invented algorithms.
11. Explicit, allow-listed trust anchors and issuer verification; no wildcard.
12. No silent authorization fallback (no `From<PolicyOutcome> for Decision`).
13. Minimal, reviewed, pinned dependencies.
14. Comprehensive unit and integration testing.
15. Negative, property-based, and fuzz testing for security-sensitive parsers.
16. Strict formatting, Clippy, and CI quality gates.
17. Security regression tests for security-sensitive changes.
18. Secure logging and secrets management; never log keys or signatures.
19. Documented threat modeling and trust boundaries.
20. Honest protocol-compatibility and security claims.
21. API stability and semantic versioning.
22. No weakening tests to make CI pass.

## The five non-interchangeable stages

Authorization is decomposed into five stages that must never be conflated,
reordered into a shortcut, or collapsed into one another:

- **Stage A - Identity.** Resolve who the agent and issuer claim to be, against
  explicit trust anchors (`kya-core::identity`).
- **Stage B - Signature verification.** Verify cryptographic authenticity
  (`kya-core::verification` seam + the `kya-crypto` engine). Passing stage B is
  not authorization.
- **Stage C - Static policy evaluation.** Deterministic, offline scope and limit
  checks producing a `PolicyOutcome` (`kya-core::policy`). Eligibility is not
  authorization.
- **Stage D - Online authoritative authorization.** Revocation, cumulative
  budget, and global replay, via `kya-client::OnlineAuthorizer`. The only stage
  that can yield `Allow`, reached only through the fail-closed `authorize`
  bridge.
- **Stage E - Execution enforcement.** Only an authorized `Decision` is ever
  executed (`kya-client::IntegrationClient` seam).

See [docs/architecture.md](docs/architecture.md) for the full stage model.

## Ground rules

- Be honest. Compatibility and security claims must be truthful and
  evidence-backed (Rule 20). Do not claim certification or audit without
  evidence.
- Fail closed. The default answer is deny; `Allow` requires explicit
  authoritative approval (Rule 9).
- Keep the dependency direction inward toward `kya-core` (Rule 2). The core
  performs no I/O.
- Do not weaken tests to make CI pass (Rule 22). Fix the code, not the test.

## Building and testing locally

Install the pinned toolchain (it is declared in `rust-toolchain.toml`, so
`rustup` will select it automatically). Then run the quality gates CI enforces,
in order:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --doc --workspace
cargo doc --workspace --no-deps
```

All five of them must pass before you open a pull request. `clippy` runs with
`-D warnings`, so warnings are errors.

### Running the examples

The fastest way to see the whole verify -> evaluate -> authorize flow is the
single recommended primary demo, which narrates each stage A-E:

```sh
cargo run -p kya-examples --example demo
```

See [docs/demo.md](docs/demo.md) for a plain-language walkthrough with the real
captured output. The numbered `examples/example_01..10` files drill into
individual facets (trust configuration, verification, policy evaluation, the
stage-D bridge, and the experimental AP2 adapter). Build them all with:

```sh
cargo build -p kya-examples --examples
```

### Windows build note (MSVC)

On Windows the MSVC linker is required for the crypto-linked crates
(`kya-crypto` and anything depending on it, including `kya-sdk`, the examples,
and `kya-adapter-ap2`). `link.exe` is not on `PATH` by default, so source
`vcvars64.bat` first, for example:

```bat
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cargo test --workspace --all-features
```

## Testing expectations

- Every module with logic must have unit tests (Rule 14). Cross-crate behavior
  should have integration tests.
- Security-sensitive parsers and verifiers must have negative tests (malformed
  and adversarial input) and should grow property-based and fuzz tests as they
  mature (Rule 15).
- Any change to identity, verification, policy, decision, or authorization code
  must add or update a security regression test that locks in the secure
  behavior (Rule 17).
- The fail-closed `authorize` bridge and the monetary arithmetic must stay
  tested (Rule 14).
- Security-critical production paths must not use `unwrap`, `expect`, or
  panicking indexing (Rule 6). Tests may use them for brevity.

## Dependencies

Dependencies must be minimal, justified, and reviewed (Rule 13). Prefer `std`
for the v0.1 foundation. A new dependency needs a clear justification in the pull
request, should be pinned, and should be a well-known, actively maintained crate.
Flag anything whose name resembles a typosquat.

## Coding standards

Follow the conventions already in the codebase: idiomatic Rust, strong type
safety (make illegal states unrepresentable), typed `#[non_exhaustive]` error
enums implementing `Display` and `std::error::Error`, exact integer monetary
arithmetic with no floats, and `#![forbid(unsafe_code)]` at the top of every
crate. See [AGENTS.md](AGENTS.md) for the complete list.

## Commits and pull requests

- Keep pull requests focused on a single concern.
- Write clear commit messages that explain the why, not just the what.
- Describe in the pull request what changed, what you tested, and any security
  implications.
- Make sure the five gates pass locally before requesting review.
- A failing security test is a blocker, not a nuisance. Do not disable or loosen
  it to get CI green.

## Licensing of contributions (inbound = outbound)

FintechBear KYA is dual licensed under MIT OR Apache-2.0. Contributions follow
the inbound-equals-outbound model: unless you explicitly state otherwise, any
contribution you intentionally submit for inclusion in the work, as defined in
the Apache-2.0 license, is dual licensed under **MIT OR Apache-2.0**, with no
additional terms or conditions.

By submitting a contribution you certify the Developer Certificate of Origin
([DCO 1.1](https://developercertificate.org/)): that you wrote the contribution
or otherwise have the right to submit it under the project's licenses. Sign your
commits off with:

```sh
git commit -s
```

which appends a `Signed-off-by` trailer attesting to the DCO.

## Code of conduct

All participation is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Do not open a public issue for a vulnerability. Follow the private disclosure
process in [SECURITY.md](SECURITY.md).
