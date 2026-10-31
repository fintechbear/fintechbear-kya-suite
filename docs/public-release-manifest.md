# Public Release File Manifest - FintechBear KYA SDK v0.1.0

This document defines the exact file set that SHIPS in the public GitHub release
of the FintechBear KYA ("Know Your Agent") SDK, and the exact set that MUST NOT
ship. It is an internal engineering record (AGENTS.md Rule 20), not a third-party
certification. It is grounded in a first-hand read-only `git status` /
`git ls-files` enumeration of the working tree at HEAD `b06f8e6` on branch
`rebuild/kya-foundation-v0.1.0`.

This manifest describes intent and policy; it does not perform any git operation.
No commit, add, push, tag, or release is executed by producing this file. The
actual commit and push are owner actions, tracked in
[publication-checklist.md](publication-checklist.md).

---

## 1. What SHIPS in the public release

The following tracked and release-relevant paths constitute the public release.
Everything here is source, governance, documentation, examples, CI, or the
reviewed non-member fuzz scaffold. None of it contains secrets or machine-local
artifacts.

### Root governance and metadata

- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `SUPPORT.md`
- `CODE_OF_CONDUCT.md`
- `AGENTS.md` (the engineering constitution; it is public policy and ships)
- `LICENSE-MIT`
- `LICENSE-APACHE`
- `Cargo.toml` (workspace manifest)
- `Cargo.lock` (intentionally tracked for reproducible example/binary builds)
- `deny.toml` (cargo-deny policy)
- `rust-toolchain.toml`
- `rustfmt.toml`
- `.gitignore`

### Source crates (all six library crates)

- `crates/kya-core/` (manifest, all `src/` including `money/`, and `tests/`)
- `crates/kya-protocol/` (manifest, `src/`, `tests/`)
- `crates/kya-crypto/` (manifest, `src/`, `tests/`)
- `crates/kya-client/` (manifest, `src/`, `tests/`)
- `crates/kya-adapter-ap2/` (manifest, `src/`, `tests/`)
- `crates/kya-sdk/` (manifest, `src/`, `tests/`)

### Examples

- `examples/` (the `kya-examples` crate: `offline_evaluation` + the 10 numbered
  `example_0*.rs`, `src/lib.rs`, and its `Cargo.toml`). The crate is marked
  `publish = false`, so it ships on GitHub but is excluded from any crates.io
  publish.

### Fuzz scaffold

- `fuzz/` (the non-member cargo-fuzz crate with its own `[workspace]` table and
  the four libFuzzer targets `fuzz_b64url_decode`, `fuzz_jws_verify`,
  `fuzz_mandate_binding`, `fuzz_verify_delegation`). The targets are source-only
  scaffolding for a Linux CI fuzz job; they were NOT built or run on the Windows
  host used for this phase (see [release-readiness.md](release-readiness.md)).

### Documentation

- `docs/` (all project markdown, including this manifest and
  [publication-checklist.md](publication-checklist.md),
  [release-readiness.md](release-readiness.md),
  [security-audit.md](security-audit.md),
  [known-limitations.md](known-limitations.md),
  [release-notes-v0.1.0.md](release-notes-v0.1.0.md), and the
  architecture/threat-model/trust-model/protocol docs).

### GitHub metadata

- `.github/` (`workflows/ci.yml`, `dependabot.yml`, `ISSUE_TEMPLATE/`, and
  `PULL_REQUEST_TEMPLATE.md`).

---

## 2. What MUST NOT ship

The following paths MUST NOT be included in the public release. They are build
artifacts, local tooling state, internal process history, non-shippable probes,
or secret-bearing patterns.

### Build and tool artifacts

- `target/` (all build output; excluded by `.gitignore`)
- `*.pdb` (debug symbols; excluded by `.gitignore`)
- `*.rs.bk` (rustfmt backups; excluded by `.gitignore`)

### Version-control internals

- `.git/` internals (the repository's own metadata is never part of a release
  tarball or archive; a `git archive` or GitHub source download excludes it by
  construction)

### Internal process history and non-member probe

- `.agents/`: the entire internal task-and-review history (task state, feature
  JSON, review logs). This is engineering process memory, not a product artifact.
  It is currently UNTRACKED in git (see Section 3), but it MUST be kept out of the
  release regardless of how the owner stages files.
- `.agents/audit/kya-bypass-probe/`: called out explicitly. This is an external,
  NON-MEMBER security regression probe. It carries its own `[workspace]` table and
  `path` dependencies that point back into `crates/kya-core` and
  `crates/kya-crypto` (`../../../crates/...`). Shipping it would publish an
  internal attack harness and could confuse Cargo's workspace resolution. It MUST
  NOT ship.

### Editor and IDE state

- `.idea/` (JetBrains)
- `.vs/` (Visual Studio)
- `.kiro/` (local agent/editor settings)

### Secrets and secret-bearing patterns

- `.env`
- `*.pem`
- `*.key`
- `*.p12`
- `*.pfx`
- `secrets/`

### Phase-8 temporary workspace

- Any `.release-snapshot-phase8/` (or similarly named `.release-snapshot-*`)
  directory. The Phase-8 isolated-source build was run in such a temporary
  directory and has already been removed. If any such directory reappears it MUST
  NOT ship.

### `.gitignore` already covers the artifact and secret patterns

As of Phase 9, the committed `.gitignore` excludes `/target`, `*.pdb`, `*.rs.bk`,
the common IDE directories (`.idea/`, `.vs/`), `.kiro/`, the internal `.agents/`
tree, temporary artifacts (`*.log`, `*.tmp`, `.release-snapshot-*/`, `.DS_Store`,
`Thumbs.db`), and the secret patterns (`.env`, `.env.*`, `*.pem`, `*.key`,
`*.p12`, `*.pfx`, `secrets/`, `*.secret`, `generated-secrets/`). So for those
categories the exclusion is enforced by git itself and does not depend on manual
staging discipline. `Cargo.lock` is intentionally NOT ignored.

---

## 3. `.agents/` is now excluded by `.gitignore` (explicit caution)

A read-only `git status` at HEAD `b06f8e6` shows the entire `.agents/` tree
(including `.agents/audit/kya-bypass-probe/`) as UNTRACKED (`??`). Because it is
not committed, a `git archive` of the current HEAD would not contain it.

Phase 9 added `.agents/` (along with `.kiro/` and the temporary-artifact
patterns) to `.gitignore`, so the exclusion is now enforced by git itself: a
broad staging command would no longer sweep the internal task history or the
bypass probe into the index for these ignored paths. The caution still stands,
because a `-f`/`--force` add or an unignored stray file could bypass the ignore:

- Do NOT use `git add -A` / `git add .` when preparing the release commit.
- Stage the SHIP set from Section 1 (the explicit by-path ALLOWLIST) by name.
- `.agents/` (internal task history + the non-member bypass probe) is both
  UNTRACKED and now git-ignored, so it is excluded by default; never force-add
  it.

---

## 4. Relationship to crate packaging

Crate packaging (`cargo package`) is a separate concern from the GitHub source
release. First-hand Phase-8 inspection confirmed that `cargo package --list` for
each of the six library crates lists only that crate's `src/`, `tests/`, its
manifests, `Cargo.lock`, and Cargo's generated `.cargo_vcs_info.json` /
`Cargo.toml.orig`. No crate would package `.agents/`, `target/`, `fuzz/`,
`docs/`, or a sibling crate, so no `exclude` key is required for correctness in
v0.1. crates.io name availability and `cargo publish --dry-run` were NOT RUN /
UNVERIFIED offline; see [release-readiness.md](release-readiness.md) and
[publication-checklist.md](publication-checklist.md).
