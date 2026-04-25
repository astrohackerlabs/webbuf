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

This is not the same problem as "implement post-quantum cryptography." That work
is done. The problem now is API hardening:

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
- de-emphasize the low-level functions in docs and naming where possible without
  breaking imports.

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

## Experiment 1: Design the preferred high-level API surface

### Goal

Define the application-facing API shape for ML-KEM, ML-DSA, and SLH-DSA before
changing code. The output should be concrete enough that the next experiment can
implement the smallest useful slice without debating names, parameter order, or
which functions are considered safe defaults.

### Questions

This experiment should answer:

- Which high-level functions should each package expose?
- Which existing low-level functions remain public, and how should they be
  documented?
- Where should randomness be generated: TypeScript wrapper, Rust/WASM layer, or
  both?
- How should ML-DSA and SLH-DSA expose context/domain separation?
- What names make the preferred path obvious without breaking existing callers?
- What tests are required to prove the new surface is wired correctly?

### Method

Survey the current TypeScript and Rust APIs for:

- `@webbuf/mlkem`
- `@webbuf/mldsa`
- `@webbuf/slhdsa`
- comparable classical packages such as `@webbuf/secp256k1`, `@webbuf/p256`,
  `@webbuf/aesgcm`, and `@webbuf/aescbc`

Then compare the current RustCrypto APIs against the FIPS-facing behavior WebBuf
should expose. The design should stay additive unless a breaking change is
clearly justified.

For each PQ package, write down:

- proposed high-level function names and signatures;
- retained low-level function names and labels;
- randomness requirements;
- context handling behavior;
- test cases needed for implementation.

### Expected shape

The likely direction is:

- **ML-KEM:** add `mlKem*KeyPair()` and `mlKem*Encapsulate()` variants that
  generate internal randomness automatically, while keeping deterministic
  variants for ACVP vectors.
- **ML-DSA:** add message-level `mlDsa*Sign()` / `mlDsa*Verify()` APIs with
  explicit context support, while keeping `*Internal` APIs for vector coverage.
- **SLH-DSA:** add message-level `slhDsa*Sign()` / `slhDsa*Verify()` APIs with
  explicit context support and hedged randomness defaults, while keeping
  `*Internal` APIs for vector coverage.

This expected shape is not yet the conclusion. The experiment should verify it
against the actual upstream APIs and WebBuf conventions before implementation.

### Deliverable

Record the proposed API design in this issue, including:

- the exact function signatures to implement first;
- the compatibility story for existing callers;
- any functions that should be documented as advanced/internal;
- a short test plan for the implementation experiment.

### Success criteria

This experiment passes if it produces a concrete, standards-aligned, additive API
design that can be implemented without further open-ended research.
