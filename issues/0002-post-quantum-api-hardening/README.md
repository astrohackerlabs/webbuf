+++
status = "open"
opened = "2026-04-25"
+++

# Post-quantum API hardening

## Goal

Add safer high-level post-quantum APIs to WebBuf so that application code can
use ML-KEM, ML-DSA, and SLH-DSA in a manner closer to the finalized NIST
standards and current 2026 best practices, while preserving the existing
low-level deterministic/internal APIs for testing and conformance work.

The immediate outcome should be:

- high-level APIs that generate required randomness internally;
- signature APIs that expose the standardized message-level interface rather
  than only the internal primitive;
- documentation that clearly separates preferred application APIs from
  low-level/internal APIs;
- compatibility with existing callers that depend on the current low-level
  wrappers.

## Background

WebBuf already ships three post-quantum packages:

- `@webbuf/mlkem` / `rs/webbuf_mlkem`
- `@webbuf/mldsa` / `rs/webbuf_mldsa`
- `@webbuf/slhdsa` / `rs/webbuf_slhdsa`

The current implementations are thin wrappers over RustCrypto crates and they
validate cleanly against NIST ACVP test vectors. That is a strong starting
point: the code does not appear obviously broken, and the wrappers are small
enough that most correctness risk lives in the upstream cryptographic crates.

However, the current API layer exposes low-level primitives directly:

- **ML-KEM** exposes deterministic key generation and deterministic
  encapsulation, requiring the caller to provide `d`, `z`, and `m`.
- **ML-DSA** exposes `Sign_internal` / `Verify_internal`.
- **SLH-DSA** exposes the FIPS 205 internal sign/verify interface.

That interface shape is useful for conformance testing because the ACVP vector
files target those internal primitives. It is not the best API for application
code:

- callers must supply randomness correctly;
- callers must understand which inputs are internal-format values versus
  ordinary messages;
- callers do not get the safer, standardized context/domain-separating signing
  interface by default;
- the library's intended usage is not obvious from the function names alone.

The result is a library that is technically correct and well-tested, but easier
to misuse than it should be for application-facing packages.

## Why this needs its own issue

This is not the same problem as "implement post-quantum cryptography." That
work is done. The problem now is API hardening:

1. preserve the low-level deterministic/internal wrappers needed for ACVP
   validation and advanced users;
2. add preferred high-level APIs for normal application use;
3. make the secure path the easy path;
4. document the tradeoffs clearly enough that downstream packages do not have to
   reverse-engineer WebBuf's intent.

This split matters because WebBuf is both a primitives library and a dependency
for higher-level applications. It is acceptable for a primitives library to
retain advanced/footgun interfaces. It is not acceptable for those to be the
only interfaces exposed as the main path.

## Constraints

### Compatibility

Existing APIs should remain available unless there is a compelling reason to
make a breaking change. The preferred direction is additive:

- keep today's low-level functions;
- add new high-level functions;
- de-emphasize the low-level functions in docs and naming where possible
  without breaking imports.

### Standards alignment

The new APIs should match the standardized, application-facing behavior defined
by the relevant FIPS publications:

- FIPS 203 for ML-KEM;
- FIPS 204 for ML-DSA;
- FIPS 205 for SLH-DSA.

For ML-KEM, the high-level API should not force callers to provide deterministic
internal entropy inputs. For ML-DSA and SLH-DSA, the high-level API should
operate on normal message bytes and expose context handling where the standard
provides it.

### Runtime model

WebBuf's current model is synchronous Rust → WASM → base64-inlined → TypeScript.
The new APIs should fit that model. Randomness should come from the same
platform CSPRNG source already used elsewhere in the TypeScript packages
(`crypto.getRandomValues` through `FixedBuf.fromRandom` or equivalent).

### Testing

The existing ACVP vector coverage must remain intact. New high-level APIs will
need their own tests in addition to the current internal-interface vector tests.
Those tests should focus on:

- round-trip behavior;
- deterministic versus hedged behavior where applicable;
- context handling;
- equivalence to the low-level wrappers where appropriate;
- misuse-resistant defaults.

## Decision framing

The main design question is not whether to replace the current APIs. It is
whether to layer safer APIs on top while preserving the current ones.

The expected direction is:

- **default path:** new high-level APIs intended for application code;
- **advanced path:** existing low-level deterministic/internal APIs retained for
  conformance tests, vectors, and expert use.

If later experiments show that naming or packaging changes are needed, those can
be evaluated after the high-level API shape is clear.
