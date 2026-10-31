# Final GitHub Publication Plan - FintechBear KYA SDK v0.1.0

This document is an **internal engineering record** (AGENTS.md Rule 20: honest,
evidence-backed claims only). It describes a **future** publication sequence and
performs **no** git or release action now. Phase 9 executed **read-only git only**
(`status` / `log` / `diff` / `show` / `ls-files` / `remote -v` / `grep`); HEAD
remains exactly at `b06f8e68055107c4cb2647488f68c1715425f2ec` on branch
`rebuild/kya-foundation-v0.1.0`, and the working tree is preserved (no commit,
push, reset, rebase, squash, tag, publish, GitHub release, branch create/delete,
amend, history rewrite, or git config change).

This plan is the authoritative future-sequence companion to
[publication-checklist.md](publication-checklist.md) (the required owner actions)
and [public-release-manifest.md](public-release-manifest.md) (the SHIP /
DO-NOT-SHIP file set and the explicit by-path staging allowlist). It does not
supersede either; it orders them into the exact publication sequence.

---

## Environment honesty (what could NOT be verified here)

The following facts constrain this plan and are stated honestly (never described
as PASS):

- The network is **offline** in the environment that produced this plan: DNS
  resolution for `github.com` fails. Therefore the **ownership/control** of
  `https://github.com/fintechbear/fintechbear-kya-suite` could **not** be
  verified, GitHub Private Vulnerability Reporting could **not** be verified as
  enabled, `crates.io` name availability is **UNVERIFIED**, and the RustSec
  advisory database (`cargo deny check advisories` / `cargo audit`) was **NOT
  RUN**.
- **Linux and macOS** gate runs are **NOT VERIFIED**: this is a Windows MSVC
  host. Only the Windows gates were run first-hand.
- Coverage-guided **fuzz** runs were **NOT RUN** (need nightly + libFuzzer on
  Linux).

None of the above is upgraded to a verified/PASS status by this plan.

---

## The exact future publication sequence

Execute these steps in this order. The numbering and wording below are the
authoritative sequence. **Do NOT execute any of them now.**

1. **Confirm canonical GitHub repository.**
   The repository URL has been reconciled (Phase 9) to the configured git remote
   `origin` `https://github.com/fintechbear/fintechbear-kya-suite`, the only
   verified offline signal. The owner must confirm they **control** that
   repository (offline could not verify control). If a different canonical URL is
   intended, re-reconcile all references first. See
   [publication-checklist.md](publication-checklist.md) §B.1.

2. **Confirm FintechBear branding.**
   Confirm the maintainer name "FintechBear", the descriptive names "KYA" /
   "Know Your Agent" (independent open-source implementation; no claim to have
   invented the generic concept; no official affiliation with Google, Visa,
   Mastercard, Skyfire, or any payment network), and the six crate names. The
   naming/trademark risks remain **OWNER REVIEW REQUIRED**; no trademark
   clearance is claimed. See [naming-and-branding-review.md](naming-and-branding-review.md).

3. **Confirm private vulnerability reporting.**
   A repository admin must **enable** GitHub Private Vulnerability Reporting
   (Settings -> Code security and analysis -> Private vulnerability reporting ->
   Enable) and confirm the Security tab shows "Report a vulnerability". This
   channel is **not verified/active yet** and is **required before public
   release**. See [SECURITY.md](../SECURITY.md).

4. **Review explicit public staging manifest.**
   Review the SHIP / DO-NOT-SHIP set in
   [public-release-manifest.md](public-release-manifest.md) and stage only the
   SHIP allowlist **by explicit path**. **Never run `git add -A` or `git add .`.**
   Phase 9 added `.agents/`, `.kiro/`, and temporary-artifact patterns to
   `.gitignore`, but staging must still use the explicit by-path allowlist.

5. **Obtain owner authorization for commit.**
   The owner must explicitly authorize the release commit. No automated agent
   commits on the owner's behalf.

6. **Commit the approved files.**
   Create the release commit from the reviewed, explicitly staged SHIP set. This
   is the first git mutation and is an owner action.

7. **Push the development branch.**
   Push the branch (`rebuild/kya-foundation-v0.1.0`, or the owner's chosen
   development branch) to the confirmed repository from step 1. Do not push to
   `main`/`master` directly unless the owner directs it.

8. **Run GitHub Actions on the pushed commit.**
   Let `.github/workflows/ci.yml` run the Rule 16 gates on the pushed commit.

9. **Verify Linux, Windows and macOS results.**
   Verify the CI matrix across Linux, Windows, and macOS. Note: Linux and macOS
   were **NOT VERIFIED** on the Windows host used in Phase 9; CI is the first
   place those platforms are actually exercised.

10. **Review dependency advisory results.**
    Review `cargo deny check advisories` / `cargo audit` results from CI. These
    were **NOT RUN** offline in Phase 9 (RustSec DB unreachable), so CI is the
    first authoritative advisory check.

11. **Fix any release-blocking issues.**
    Fix any gate failure, advisory, or cross-platform issue surfaced by steps
    8-10 before proceeding. A failing security gate is a blocker, not a nuisance
    (AGENTS.md Rules 16 and 22).

12. **Merge the validated changes into the intended release branch.**
    Once CI is green across platforms and advisories are reviewed, merge the
    validated development branch into the intended release branch.

13. **Obtain owner approval for public release.**
    The owner must explicitly approve making the project public / cutting the
    release. Confirm repository visibility is handled by the owner only.

14. **Create the v0.1.0 tag from the verified commit.**
    Create the `v0.1.0` tag from the verified, CI-green commit. Use
    [release-notes-v0.1.0.md](release-notes-v0.1.0.md) as the basis for the
    release content.

15. **Publish GitHub Release with accurate notes.**
    Publish the GitHub Release for `v0.1.0` using the accurate notes from
    [release-notes-v0.1.0.md](release-notes-v0.1.0.md). Claims must stay honest
    and evidence-backed (Rule 20): no certification, no independent audit, no AP2
    wire-interoperability, and no payment-execution-enforcement claims.

---

## Explicit non-goals of this plan

- **Do NOT publish to crates.io.** crates.io publication is **deferred** and is
  not part of this GitHub release. crates.io name availability for the six
  `kya-*` names is UNVERIFIED (offline); the owner must check it on a networked
  host before any future registry publish, and a first publish must follow the
  path-dependency order documented in
  [publication-checklist.md](publication-checklist.md) §C.
- The future **commercial FintechBear KYA platform** is developed **separately**,
  on this **same** open-source Rust core. It ships nothing in this repository and
  is out of scope for this publication plan. See
  [future-commercial-platform.md](future-commercial-platform.md).

---

## Cross-references

- [publication-checklist.md](publication-checklist.md) - the required owner
  actions (A preconditions, B required human actions, C crates.io deferral,
  D post-publish follow-ups).
- [public-release-manifest.md](public-release-manifest.md) - the SHIP /
  DO-NOT-SHIP file set and the explicit by-path staging allowlist.
- [release-readiness.md](release-readiness.md) - the gate, example, and
  supply-chain evidence (and what was NOT RUN / NOT VERIFIED offline).
- [release-notes-v0.1.0.md](release-notes-v0.1.0.md) - the v0.1.0 release body
  used in steps 14 and 15.
- [SECURITY.md](../SECURITY.md) - the GitHub Private Vulnerability Reporting
  disclosure process and the owner action to enable it.
