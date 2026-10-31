# Publication Checklist - FintechBear KYA SDK v0.1.0

This is the step-by-step checklist for publishing the FintechBear KYA ("Know
Your Agent") SDK to GitHub. It is an internal engineering record (AGENTS.md
Rule 20), not a certification or an authorization to publish.

This checklist DESCRIBES the required actions and performs NONE of them. Every
item marked as a REQUIRED HUMAN ACTION must be carried out by the project owner.
This document (and the phase that produced it) executed only read-only git
(`status` / `log` / `diff` / `show` / `ls-files`); HEAD remains exactly at
`b06f8e68055107c4cb2647488f68c1715425f2ec` and the working tree is preserved.

---

## A. Preconditions (already verified first-hand)

These were confirmed in Phase 8 and do not require re-running before publish,
although re-running them is harmless:

- Rule 16 gate set GREEN on the Windows MSVC host: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo test --workspace --all-features` (339 tests), `cargo test --doc
  --workspace` (6 kya-crypto doctests: 5 compile-fail + 1 positive), and
  `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.
- All 11 examples run EXIT 0.
- The `kya-bypass-probe` regression probe prints `BYPASS IMPOSSIBLE` (the
  Phase-7 P0 verifier-forgery fix holds).
- `cargo deny check licenses bans sources` PASS.
- Isolated-source build+test PASS offline (339 tests + 6 doctests), described in
  [release-readiness.md](release-readiness.md) as an isolated-source test and
  explicitly NOT a git clean-checkout.
- The SHIP / DO-NOT-SHIP file set is enumerated in
  [public-release-manifest.md](public-release-manifest.md).

Items that are honestly NOT RUN / NOT VERIFIED / UNVERIFIED in this environment
(and therefore remain owner/CI follow-ups, not satisfied preconditions):

- `cargo deny check advisories` and `cargo audit`: NOT RUN (offline).
- `cargo publish --dry-run`: NOT RUN (crates.io index offline).
- crates.io name availability for the six `kya-*` names: UNVERIFIED (offline).
- cargo-fuzz runs of the four libFuzzer targets: NOT RUN (needs nightly +
  libFuzzer on Linux).
- Linux / macOS gate runs: NOT VERIFIED on this Windows host.

None of these NOT-RUN items are upgraded to PASS by this checklist.

---

## B. REQUIRED HUMAN ACTIONS (the owner must do these; this phase does not)

### B.1 - Confirm the canonical GitHub repository location (OWNER CONFIRMATION REQUIRED)

The repository URL has been **reconciled** (Phase 9) to the configured git
remote `origin`:

- The configured git remote `origin` is
  `https://github.com/fintechbear/fintechbear-kya-suite.git`. This is the only
  verified offline signal of where the project lives.
- The workspace `Cargo.toml` metadata (`repository` / `homepage`), `README.md`,
  `CHANGELOG.md`, `SECURITY.md`, `SUPPORT.md`, `docs/quickstart.md`, and the rest
  of the release docs now all point to
  `https://github.com/fintechbear/fintechbear-kya-suite` consistently. No stray
  reference to the old `https://github.com/fintechbear/kya` URL remains, and no
  third URL was invented.

What remains is **OWNER CONFIRMATION**: offline verification cannot establish who
controls that GitHub repository. Before publishing, the owner must confirm they
control `https://github.com/fintechbear/fintechbear-kya-suite`. If the owner
intends a different canonical URL, they must re-reconcile all the files listed
above to that URL as a separate reviewed change.

### B.2 - Approve public project branding (OWNER INPUT REQUIRED)

Approve the public branding before the project is made public:

- The maintainer name "FintechBear".
- The descriptive names "KYA" and "Know Your Agent" (used analogously to the
  established "KYC"; the README already carries a naming/trademark notice
  disclaiming affiliation with Google, Visa, Mastercard, and Skyfire).
- The six crate names `kya-core`, `kya-protocol`, `kya-crypto`, `kya-client`,
  `kya-adapter-ap2`, `kya-sdk`.

Note: third-party "Know Your Agent" usage (for example by Skyfire) could not be
fully verified offline from its JS-rendered homepage, so trademark clearance
remains an open, honestly-stated risk requiring owner review. See the README
"Naming and trademark notice" and the fuller per-name risk breakdown in
[naming-and-branding-review.md](naming-and-branding-review.md).

### B.3 - Review the license and the security-disclosure process

- Confirm the dual MIT OR Apache-2.0 license is correct and that `LICENSE-MIT`
  and `LICENSE-APACHE` are the intended texts.
- Review `SECURITY.md`: the placeholder email (`security@example.invalid`) has
  been **removed** (Phase 9). The disclosure process now routes through **GitHub
  Private Vulnerability Reporting** (Security tab -> "Report a vulnerability")
  against `https://github.com/fintechbear/fintechbear-kya-suite/security/advisories`.
  This channel is **OWNER ACTION REQUIRED**: a repo admin must enable it
  (Settings -> Code security and analysis -> Private vulnerability reporting ->
  Enable) and confirm the "Report a vulnerability" button appears before the
  project is public. It could not be verified offline and is NOT claimed active
  yet; a working private reporting channel is REQUIRED before public release.

### B.4 - Approve the actual git commit and push (OWNER ACTION)

The working tree is currently UNCOMMITTED at HEAD `b06f8e6` (a read-only
`git status` shows modified tracked files plus a large untracked set holding most
of the release: three whole crates, tests, numbered examples, `deny.toml`,
`fuzz/`, and most docs). No clean-checkout build can be proven until a reviewed
snapshot is committed.

The owner must:

1. Stage the SHIP set by explicit path per
   [public-release-manifest.md](public-release-manifest.md). Do NOT use
   `git add -A` / `git add .`. Phase 9 added `.agents/` (and `.kiro/` plus
   temporary-artifact patterns) to `.gitignore`, so those are excluded by git
   itself; still stage by explicit allowlist path and never force-add ignored
   internal paths.
2. Create the release commit.
3. Push to the repository confirmed in B.1.

This phase performs none of these steps.

### B.5 - Approve creation of the GitHub release and tag (OWNER ACTION)

After the commit/push in B.4, the owner may create the `v0.1.0` tag and the
GitHub release, using [release-notes-v0.1.0.md](release-notes-v0.1.0.md) as the
release body. This phase does NOT create any tag or release.

---

## C. Deferred / optional: crates.io publication

crates.io publication is DEFERRED and is explicitly NOT a blocker for the GitHub
release. GitHub is the primary release target.

- crates.io name availability for the six `kya-*` names is UNVERIFIED (the
  registry index was offline); the owner must check it on a networked host before
  any publish.
- `cargo publish --dry-run` was NOT RUN (registry index offline).
- Because the crates have in-repo path dependencies, a first registry publish
  must proceed in dependency order:

  > `kya-core` -> `kya-protocol` -> `kya-crypto` -> `kya-client` ->
  > `kya-adapter-ap2` -> `kya-sdk`

  (`kya-examples` is `publish = false` and is not published.)

The GitHub release in Section B is NOT blocked on crates.io name reservation or
on any of the deferred crates.io steps.

---

## D. Post-publish follow-ups (networked host / CI)

These should be run once network is available; they do not gate the initial
GitHub release but should be completed promptly after:

- `cargo deny check advisories` and `cargo audit` against the RustSec DB.
- The Linux CI gate run (`.github/workflows/ci.yml`, `ubuntu-latest`).
- cargo-fuzz runs of the four libFuzzer targets on a Linux host with nightly +
  libFuzzer.
- macOS verification if a macOS target is intended (CI defines no macOS job
  today).
- crates.io name checks and the dependency-ordered publish in Section C, if and
  when registry publication is desired.
