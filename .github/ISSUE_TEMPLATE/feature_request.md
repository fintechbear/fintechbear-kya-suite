---
name: Feature request
about: Suggest an improvement or new capability for the FintechBear KYA SDK
title: "[feature] "
labels: ["enhancement"]
assignees: []
---

<!--
Do NOT use this template for a security vulnerability. Report suspected
vulnerabilities privately per SECURITY.md.
-->

## Problem

<!-- What problem are you trying to solve? Describe the use case, not only a
proposed API. -->

## Proposed solution

<!-- What you would like to happen. -->

## Alternatives considered

<!-- Other approaches you thought about, and why they are worse. -->

## Fit with the project's constraints

This SDK follows AGENTS.md (the engineering constitution and its 22 rules).
Please confirm your request is consistent with them, in particular:

- [ ] It does not require a path that upgrades a non-authoritative result into
      an authorization (no silent authorization fallback; deny-by-default and
      fail-closed).
- [ ] It does not request invented cryptography, invented protocol
      functionality, or any unverified compatibility / certification claim.
- [ ] It keeps `kya-core` free of I/O and of dependencies on the outer crates
      (Clean Architecture; dependencies point inward).

## Additional context

<!-- Links, references, or examples. -->
