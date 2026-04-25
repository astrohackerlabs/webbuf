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

This experiment passes if it produces a concrete, standards-aligned, additive
API design that can be implemented without further open-ended research.

### Survey findings

The current WebBuf PQ packages expose the exact deterministic/internal surfaces
needed for ACVP testing:

- `@webbuf/mlkem` exposes deterministic key generation and deterministic
  encapsulation where callers supply `d`, `z`, and `m`.
- `@webbuf/mldsa` exposes seeded key generation plus `mlDsa*SignInternal` /
  `mlDsa*VerifyInternal`.
- `@webbuf/slhdsa` exposes internal seeded key generation plus
  `slhDsa*SignInternal` / `slhDsa*VerifyInternal`.

The comparable classical packages use a mixed style. `@webbuf/secp256k1` and
`@webbuf/p256` expose low-level caller-supplied nonce APIs. `@webbuf/aesgcm` and
`@webbuf/aescbc` expose more ergonomic defaults by generating IVs with
`FixedBuf.fromRandom` when the caller does not provide one. The PQ hardening
should follow the latter pattern for the new preferred APIs: use TypeScript-side
randomness for synchronous WASM compatibility and avoid adding async
initialization.

The pinned RustCrypto crates already contain the primitives needed for a safer
surface:

- `ml-kem 0.2.3` has randomized `KemCore::generate` and
  `Encapsulate::encapsulate`. It also documents the deterministic encapsulation
  interface as unsafe unless `m` is randomly generated.
- `ml-dsa 0.1.0-rc.8` has the standardized message-level `sign_deterministic`,
  `sign_randomized`, and `verify_with_context` APIs. It also documents
  `sign_internal` / `verify_internal` as missing the normal domain separator and
  context separation.
- `slh-dsa 0.2.0-rc.4` has `try_sign_with_context` and
  `try_verify_with_context`, with optional randomization for hedged signing.

### API design

The design is additive. Existing functions remain available with their current
names and behavior. New preferred calls use the same short names where overloads
are possible, and explicit deterministic/internal aliases make the advanced path
discoverable.

#### ML-KEM

Preferred application APIs:

```typescript
export function mlKem512KeyPair(): MlKemKeyPair<800, 1632>;
export function mlKem768KeyPair(): MlKemKeyPair<1184, 2400>;
export function mlKem1024KeyPair(): MlKemKeyPair<1568, 3168>;

export function mlKem512Encapsulate(
  encapsulationKey: FixedBuf<800>,
): MlKemEncapResult<768, 32>;
export function mlKem768Encapsulate(
  encapsulationKey: FixedBuf<1184>,
): MlKemEncapResult<1088, 32>;
export function mlKem1024Encapsulate(
  encapsulationKey: FixedBuf<1568>,
): MlKemEncapResult<1568, 32>;
```

Compatibility overloads:

```typescript
export function mlKem512KeyPair(
  d: FixedBuf<32>,
  z: FixedBuf<32>,
): MlKemKeyPair<800, 1632>;
export function mlKem512Encapsulate(
  encapsulationKey: FixedBuf<800>,
  m: FixedBuf<32>,
): MlKemEncapResult<768, 32>;
```

Equivalent overloads should exist for ML-KEM-768 and ML-KEM-1024. When entropy
arguments are omitted, the TypeScript wrapper generates them with
`FixedBuf.fromRandom(32)` and calls the existing deterministic Rust/WASM
function. This avoids needing Rust-side RNG plumbing while still using fresh
randomness for the application path.

New explicit advanced aliases:

```typescript
export function mlKem512KeyPairDeterministic(
  d: FixedBuf<32>,
  z: FixedBuf<32>,
): MlKemKeyPair<800, 1632>;
export function mlKem512EncapsulateDeterministic(
  encapsulationKey: FixedBuf<800>,
  m: FixedBuf<32>,
): MlKemEncapResult<768, 32>;
```

The existing two-argument `mlKem*KeyPair` and `mlKem*Encapsulate` forms remain
as compatibility aliases for the deterministic behavior.

#### ML-DSA

Preferred application APIs:

```typescript
export function mlDsa44KeyPair(): MlDsaKeyPair<1312, 2560>;
export function mlDsa65KeyPair(): MlDsaKeyPair<1952, 4032>;
export function mlDsa87KeyPair(): MlDsaKeyPair<2592, 4896>;

export function mlDsa44Sign(
  signingKey: FixedBuf<2560>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<2420>;
export function mlDsa65Sign(
  signingKey: FixedBuf<4032>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<3309>;
export function mlDsa87Sign(
  signingKey: FixedBuf<4896>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<4627>;

export function mlDsa44Verify(
  verifyingKey: FixedBuf<1312>,
  message: WebBuf,
  signature: FixedBuf<2420>,
  context?: WebBuf,
): boolean;
export function mlDsa65Verify(
  verifyingKey: FixedBuf<1952>,
  message: WebBuf,
  signature: FixedBuf<3309>,
  context?: WebBuf,
): boolean;
export function mlDsa87Verify(
  verifyingKey: FixedBuf<2592>,
  message: WebBuf,
  signature: FixedBuf<4627>,
  context?: WebBuf,
): boolean;
```

Compatibility overloads:

```typescript
export function mlDsa44KeyPair(seed: FixedBuf<32>): MlDsaKeyPair<1312, 2560>;
export function mlDsa65KeyPair(seed: FixedBuf<32>): MlDsaKeyPair<1952, 4032>;
export function mlDsa87KeyPair(seed: FixedBuf<32>): MlDsaKeyPair<2592, 4896>;
```

Implementation note: the preferred signing path should be hedged/randomized if
we enable the upstream `rand_core` feature and provide randomness from the
TypeScript wrapper. If that turns out to add unnecessary complexity in the next
experiment, the acceptable first implementation is the standardized
`sign_deterministic(message, context)` API, with randomized ML-DSA signing split
into the following experiment. In either case, the new `mlDsa*Sign` /
`mlDsa*Verify` functions must use the message-level context-separated RustCrypto
APIs, not `Sign_internal`.

New explicit advanced aliases:

```typescript
export function mlDsa44KeyPairDeterministic(
  seed: FixedBuf<32>,
): MlDsaKeyPair<1312, 2560>;
export function mlDsa44SignDeterministic(
  signingKey: FixedBuf<2560>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<2420>;
```

Equivalent aliases should exist for ML-DSA-65 and ML-DSA-87. The existing
`mlDsa*SignInternal` and `mlDsa*VerifyInternal` functions remain public and
should be documented as ACVP/internal primitives.

#### SLH-DSA

Preferred application APIs should be added for every existing parameter-set
function family:

```typescript
export function slhDsaSha2_128fKeyPair(): SlhDsaKeyPair<32, 64>;
export function slhDsaSha2_128fSign(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<17088>;
export function slhDsaSha2_128fVerify(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<17088>,
  context?: WebBuf,
): boolean;
```

Equivalent APIs should be generated for all SHA2 and SHAKE parameter sets.
Existing seeded keypair functions can become overloads:

```typescript
export function slhDsaSha2_128fKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64>;
```

Preferred signing should be hedged by default: the TypeScript wrapper generates
`addrnd` with the parameter set's seed size and passes it to a new Rust/WASM
context-signing wrapper around `try_sign_with_context`. Deterministic signing
should remain available through explicit names:

```typescript
export function slhDsaSha2_128fSignDeterministic(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<17088>;
```

The existing `slhDsa*SignInternal` and `slhDsa*VerifyInternal` functions remain
public and should be documented as ACVP/internal primitives.

### Documentation decisions

Package READMEs should identify preferred and advanced APIs separately:

- preferred APIs: no caller-supplied entropy for keygen/encapsulation/signing
  unless the caller chooses an explicit deterministic variant;
- deterministic APIs: useful for reproducible tests and vectors, not the default
  application path;
- internal APIs: match FIPS internal primitives and NIST ACVP vectors, but skip
  normal message-level context/domain handling.

The low-level functions should not be removed or hidden because the audit vector
suites depend on them.

### Test plan for the implementation experiment

ML-KEM tests:

- no-argument keypair returns the correct key sizes for all parameter sets;
- no-argument encapsulate returns ciphertext and shared secret of the correct
  sizes;
- encapsulate/decapsulate round-trips for all parameter sets;
- two no-argument keypairs are different with overwhelming probability;
- two no-argument encapsulations to the same key produce different ciphertexts
  with overwhelming probability;
- deterministic aliases reproduce the existing ACVP-vector behavior.

ML-DSA tests:

- no-argument keypair returns the correct key sizes for all parameter sets;
- high-level sign/verify succeeds with empty context;
- high-level sign/verify succeeds with non-empty context;
- verification fails with the wrong context;
- context longer than 255 bytes fails or returns false as appropriate;
- internal ACVP vector tests continue to pass unchanged.

SLH-DSA tests:

- no-argument keypair returns the correct key sizes for representative SHA2 and
  SHAKE parameter sets, then all parameter sets if runtime is acceptable;
- high-level sign/verify succeeds with empty context;
- high-level sign/verify succeeds with non-empty context;
- verification fails with the wrong context;
- default hedged signing produces different signatures for the same key/message
  with overwhelming probability;
- deterministic signing produces the same signature for the same key/message;
- internal ACVP vector tests continue to pass unchanged.

### Result: Pass

The experiment produced an additive API design that fits WebBuf's synchronous
WASM model, preserves the current ACVP/internal wrappers, and defines concrete
function signatures for the next implementation experiment.

The next experiment should implement the ML-KEM high-level API first. ML-KEM is
the smallest and lowest-risk slice because it can be implemented entirely in the
TypeScript wrapper by generating `d`, `z`, and `m` with `FixedBuf.fromRandom`
and delegating to the existing deterministic Rust/WASM functions.
