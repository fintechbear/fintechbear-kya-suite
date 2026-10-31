# Supported Protocols and Capabilities

This document states, honestly and with evidence, what the FintechBear KYA SDK
supports today and what it does not. It satisfies AGENTS.md Rule 20:
compatibility and security claims must be truthful and evidence-backed. The
detailed claims matrix lives in
[protocol-compatibility.md](protocol-compatibility.md); this page is the
consumer-facing summary.

## Affiliation

None. FintechBear is the maintainer of this open-source project. It has **no**
affiliation with and **no** endorsement from Google, Visa, Mastercard, Skyfire,
or any payment network or standards body. Any such names are used descriptively
only.

## Supported cryptographic algorithms

Only **Ed25519 / EdDSA** is accepted:

- raw Ed25519 signatures (RFC 8032), verified by `kya-crypto`'s
  `Ed25519SignatureVerifier` and anchored by the official RFC 8032 section 7.1
  test vectors;
- JWS compact-form EdDSA (`alg: EdDSA`, RFC 7515 / 7518 / 8037) over the exact
  signing input, via `kya-crypto`'s `JwsEdDsa`.

`alg: none`, HMAC, RSA, and ECDSA are **rejected**. The accepted algorithm
identifier is exported as `ACCEPTED_ALGORITHM`. No cryptographic algorithm is
invented (Rule 10).

## Supported verification and policy capabilities

- **Signature verification over caller-supplied exact bytes.** The crypto engine
  verifies the bytes it is given (verbatim for raw Ed25519, or the RFC 7515
  signing input for JWS-EdDSA). It invents no canonicalization and parses no
  wire envelope.
- **Full-mandate binding.** A `VerifiedMandate` cryptographically binds the
  complete mandate to the signature via the mandate's canonical encoding (an
  internal, non-standardized, versioned byte format, **not** a standardized wire
  format), so a signature over one payload cannot be paired with a substituted
  mandate.
- **Static constraint evaluation (stage C).** Permitted action, exact amount and
  currency, acting agent, validity window, audience, exact transaction binding,
  and approval requirement, mapped onto the `kya-core` `Mandate` / `Scope` /
  `Money` domain and evaluated deterministically and offline.

## AP2 adapter: experimental and incomplete

The AP2 constraint adapter (`kya-adapter-ap2`) is **experimental and
incomplete**. It:

- models AP2 mandate *constraint concepts* (permitted action, exact amount,
  currency, identities) as explicit Rust types,
- maps them onto the stage-C domain so the unchanged evaluator runs on them, and
- verifies signatures through `kya-crypto` over caller-supplied exact bytes.

It does **not**:

- parse the real AP2 signature envelope (JWT/JWS vs a W3C-VC-style proof is
  unverified and blocked),
- assert any AP2 wire compatibility, conformance, or certification, or
- run against real AP2 tokens, schemas, or conformance vectors.

There are **no conformance vectors**: AP2 was not confirmed to publish standalone
test vectors during research, and none are bundled or claimed. The adapter is
deliberately **not** re-exported from the `kya-sdk` facade; import
`kya-adapter-ap2` directly to experiment with it. See
[first-adapter-decision.md](first-adapter-decision.md) and the claims matrix in
[protocol-compatibility.md](protocol-compatibility.md).

## Other protocols

Visa TAP, Mastercard Agent Pay, and Skyfire are researched in
[protocol-research.md](protocol-research.md) but are **not** targeted now, and no
compatibility with any of them is claimed. RFC 9421 (HTTP Message Signatures) is
noted only as a candidate verification primitive, not as a compatibility claim
about any vendor layer built on top of it.

## Explicit non-claims

- No universal mandate standard is invented, published, or claimed.
- No AP2 wire compatibility, conformance, or certification.
- No regulatory, PCI-DSS, or SOC 2 certification.
- No independent security audit.
- No production payment-execution enforcement.

If you find an inaccurate claim anywhere in this repository, that is a bug; see
[SECURITY.md](../SECURITY.md) for disclosure.
