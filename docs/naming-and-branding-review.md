# Naming and Branding Review - FintechBear KYA SDK

This document is an internal engineering record (AGENTS.md Rule 20: honest
claims). It reviews the public names this project uses and records the naming
and trademark risks that remain unresolved. It does NOT claim legal trademark
clearance, it does NOT rename any crate, and it does NOT assert ownership of any
term. Every unresolved risk is recorded as OWNER REVIEW REQUIRED.

The phase that produced this document executed only read-only git and preserved
the working tree; it made no code or crate-name changes.

---

## 1. Names reviewed

This review covers the public-facing names the project exposes:

- The maintainer name: **FintechBear**.
- The descriptive concept names: **KYA** and **Know Your Agent**.
- The facade crate name: **kya-sdk**.
- The remaining library crate names: **kya-core**, **kya-protocol**,
  **kya-crypto**, **kya-client**, **kya-adapter-ap2**.

---

## 2. What "KYA" / "Know Your Agent" means here

In this project, "Know Your Agent" and its abbreviation "KYA" are used as
**descriptive** names, by analogy to the long-established "Know Your Customer"
(KYC) compliance concept. KYC ("Know Your Customer/Client") is a well-known
financial-compliance term; this was verified first-hand during Phase 8 against
the public Wikipedia article "Know your customer"
(https://en.wikipedia.org/wiki/Know_your_customer). The project uses "Know Your
Agent" to describe, by analogy, the task of establishing what an autonomous
agent is authorized to do before letting it act.

Descriptive use of a term does NOT establish exclusive ownership of it, and this
project makes no claim of exclusive ownership. Equally, the project does NOT
claim to have originated or invented the term "Know Your Agent" or "KYA." The
term is used descriptively and nothing here should be read as a claim of
coinage, priority, or a registered mark.

---

## 3. What could and could NOT be verified about third-party use

Honesty note (AGENTS.md Rule 20): the following states exactly what was and was
not verifiable in this environment. This environment is offline with respect to
the crates.io registry index and most external web content.

- **Verified:** the KYC analogy, against the public Wikipedia "Know your
  customer" article (cited above). This is the only naming-related external
  source actually consulted and confirmed in this environment.
- **NOT verified (offline / not renderable):** during Phase 8 an attempt to
  inspect Skyfire's homepage (https://skyfire.xyz/) returned minimal /
  JS-rendered content, so no specific Skyfire "Know Your Agent" / "KYA" product
  usage could be confirmed or denied from this environment. Any assertion about
  whether Skyfire, or any other agent-identity or agent-payment provider, uses
  the term "Know Your Agent" / "KYA" is therefore **UNVERIFIED** here and
  **requires a networked owner review**.

Because of that, this document does NOT assert that FintechBear originated the
term, and does NOT assert that any third party owns it. Both positions require
evidence that was not obtainable in this offline environment.

---

## 4. This is an independent authorization SDK

To avoid confusion with any third-party product that may use a similar name:
the FintechBear KYA SDK is an **independent, open-source authorization SDK**. It
verifies AI-agent delegated authority through a fail-closed, five-stage
decomposition (identity, signature verification, static policy evaluation,
online authoritative authorization, execution enforcement).

It is **NOT** any third party's "Know Your Agent" / "KYA" identity product,
agent-identity service, or agent-payment product. It is not affiliated with,
endorsed by, certified by, or derived from any such product. Any name
similarity is a result of the common descriptive root (the KYC analogy), not a
shared origin or any commercial relationship.

---

## 5. Recorded naming risks (OWNER REVIEW REQUIRED)

The following risks are unresolved in this environment and each is recorded as
**OWNER REVIEW REQUIRED**. None of them is claimed to be cleared.

### 5.1 - Term collision risk (OWNER REVIEW REQUIRED)

"KYA" / "Know Your Agent" may collide with third-party products, services, or
trademarks (including, potentially, Skyfire or other agent-identity /
agent-payment providers). As stated in Section 3, third-party usage could not be
confirmed or denied offline. The owner must perform a networked review (web
search and, where appropriate, a trademark-register search) before relying on
these names in any public, commercial, or compliance context.

### 5.2 - crates.io crate-name availability (OWNER REVIEW REQUIRED)

The availability of the six crate names on crates.io
(`kya-core`, `kya-protocol`, `kya-crypto`, `kya-client`, `kya-adapter-ap2`,
`kya-sdk`) is **UNVERIFIED** because the crates.io registry index was offline in
this environment. Any of these names may already be taken. The owner must check
name availability on a networked host before any registry publish. No crate has
been renamed in this phase.

### 5.3 - "FintechBear" brand clearance (OWNER REVIEW REQUIRED)

No trademark or brand-clearance search was performed for the maintainer name
"FintechBear" in this environment. Its availability and clearance for public,
commercial, or compliance use are **UNVERIFIED** and require owner review.

---

## 6. No legal clearance is claimed

This document is an engineering risk record, not legal advice and not a
trademark clearance. **No legal trademark clearance is claimed** for any name
reviewed here. The owner is responsible for obtaining appropriate legal review
before relying on these names publicly or commercially. All risks in Section 5
remain open until the owner resolves them with verified evidence.

---

## 7. Relationship to the README notice

The repository README carries a "Naming and trademark notice" that disclaims
affiliation with Google, Visa, Mastercard, Skyfire, and any payment network or
standards body, states the names are descriptive and uncleared, and claims no
registered mark, affiliation, endorsement, or certification. This document is
consistent with that notice and expands it with the per-name risk breakdown
above. The README notice remains the short public-facing statement; this
document is the fuller internal record referenced from it and from
[publication-checklist.md](publication-checklist.md) (owner action "approve
public project branding").
