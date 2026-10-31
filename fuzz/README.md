# kya-fuzz — coverage-guided fuzzing harness

This crate holds [`cargo fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html)
(libFuzzer) targets for the security-critical untrusted-input parsers of the
FintechBear KYA SDK.

## What this is (and is not)

These are **coverage-guided** fuzz targets. They are deliberately distinct from
the deterministic, fixed-seed `SplitMix64` loops in
`crates/kya-crypto/tests/property_fuzz.rs` and `crates/kya-core/tests/*`. Those
property tests are valuable regression guards, but they explore a fixed,
pre-seeded set of inputs on every run — they are **not** coverage-guided
fuzzing and must not be described as such.

## Targets

| Target | Surface under test |
| --- | --- |
| `fuzz_b64url_decode` | strict base64url decoder (reached via `JwsEdDsa::verify` segments; the `b64url` module is crate-private) |
| `fuzz_jws_verify` | compact-JWS EdDSA verify: segment split, header `alg`/`crit` scan, decode, signature length, Ed25519 verify |
| `fuzz_mandate_binding` | `Mandate::canonical_encoding` totality/determinism + `verify_mandate` fail-closed binding |
| `fuzz_verify_delegation` | `verify_delegation` driver: oversize guard, key resolution, verify, validity/audience/binding, sealed mint |

Each target asserts the two invariants that matter for a security parser: it
**never panics** on arbitrary input, and it **never forges a verified result**
from random bytes.

## Running (Linux / nightly toolchain)

`cargo fuzz` requires a nightly toolchain and libFuzzer, which is generally only
available on Linux/macOS. From the repository root:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_b64url_decode     -- -max_total_time=60
cargo +nightly fuzz run fuzz_jws_verify        -- -max_total_time=60
cargo +nightly fuzz run fuzz_mandate_binding   -- -max_total_time=60
cargo +nightly fuzz run fuzz_verify_delegation -- -max_total_time=60
```

## Why this crate is not a workspace member

`fuzz/Cargo.toml` carries its own `[workspace]` table, so it is **excluded**
from the root workspace. That keeps the AGENTS.md Rule 16 gates
(`cargo fmt/clippy/test/doc --workspace`), which run on a stable MSVC Windows
host, from attempting to build the libFuzzer targets (which need nightly +
libFuzzer). The targets still exist in-tree so a Linux CI job can run them.
