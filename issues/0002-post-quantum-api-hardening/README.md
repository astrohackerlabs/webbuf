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

## Experiment 2: Implement the ML-KEM high-level API

### Goal

Add the preferred ML-KEM application API designed in Experiment 1 without
breaking the existing deterministic interface used by ACVP vectors and current
callers.

### Questions

This experiment should answer:

- Can the safer ML-KEM path be implemented entirely in the TypeScript wrapper?
- Do overloads preserve the existing deterministic function names without
  weakening the preferred no-entropy API?
- Do explicit deterministic aliases make the advanced behavior clear enough for
  tests and conformance usage?
- Do existing ACVP tests continue to pass unchanged?

### Method

Implement overloads for all three ML-KEM parameter sets:

- `mlKem*KeyPair()` generates `d` and `z` with `FixedBuf.fromRandom(32)`;
- `mlKem*KeyPair(d, z)` remains a compatibility overload;
- `mlKem*Encapsulate(encapsulationKey)` generates `m` with
  `FixedBuf.fromRandom(32)`;
- `mlKem*Encapsulate(encapsulationKey, m)` remains a compatibility overload.

Add explicit deterministic aliases for every parameter set:

- `mlKem*KeyPairDeterministic(d, z)`;
- `mlKem*EncapsulateDeterministic(encapsulationKey, m)`.

Partial runtime key-generation calls with only one entropy input should throw,
because silently mixing caller-provided and wrapper-generated entropy would make
the API harder to reason about.

### Implementation

The implementation stayed in `@webbuf/mlkem`'s TypeScript wrapper. No Rust/WASM
changes were needed. The high-level overloads generate entropy with
`FixedBuf.fromRandom(32)` and delegate to the deterministic aliases, which in
turn call the existing WASM exports.

The test suite now covers:

- no-argument key generation and encapsulation round-trips for ML-KEM-512,
  ML-KEM-768, and ML-KEM-1024;
- fresh-randomness behavior for default key generation and encapsulation;
- deterministic alias equivalence with the existing compatibility overloads;
- deterministic alias availability for every ML-KEM parameter set;
- runtime rejection of partial deterministic key-generation entropy;
- unchanged ACVP vector coverage.

### Result: Pass

Experiment 2 passed. The ML-KEM package now has a safer application-facing
default path while retaining the old deterministic behavior for compatibility
and test-vector work.

Verification:

- `pnpm run typecheck` in `ts/npm-webbuf-mlkem`
- `pnpm test` in `ts/npm-webbuf-mlkem`

Both passed. The package test run included 189 passing tests, including the
existing ACVP audit vectors.

## Experiment 3: Implement the ML-DSA high-level API

### Goal

Expose the standardized ML-DSA message-level signing API with context
separation, while preserving the existing internal sign/verify wrappers used by
ACVP vectors and low-level callers.

### Questions

This experiment should answer:

- Can WebBuf expose ML-DSA.Sign / ML-DSA.Verify without breaking the existing
  `Sign_internal` / `Verify_internal` API?
- Can no-argument ML-DSA key generation follow the same TypeScript-side
  randomness pattern used for ML-KEM?
- Does the high-level signature path enforce FIPS 204 context separation?
- Do internal ACVP vector tests continue to pass unchanged?

### Method

Add Rust/WASM exports for all three ML-DSA parameter sets:

- `ml_dsa_44_sign`, `ml_dsa_65_sign`, and `ml_dsa_87_sign`;
- `ml_dsa_44_verify`, `ml_dsa_65_verify`, and `ml_dsa_87_verify`.

Those exports should use RustCrypto's message-level
`sign_deterministic(message, context)` and `verify_with_context` APIs, not the
internal primitives. Context strings longer than 255 bytes should fail signing
and return `false` for verification.

Add TypeScript wrappers:

- `mlDsa*KeyPair()` generates a 32-byte seed with `FixedBuf.fromRandom(32)`;
- `mlDsa*KeyPair(seed)` remains a compatibility overload;
- `mlDsa*KeyPairDeterministic(seed)` is the explicit advanced alias;
- `mlDsa*Sign(signingKey, message, context?)` signs at the message level;
- `mlDsa*Verify(verifyingKey, message, signature, context?)` verifies at the
  message level;
- `mlDsa*SignDeterministic(...)` is an explicit alias for the deterministic
  message-level signing variant.

The existing `mlDsa*SignInternal` and `mlDsa*VerifyInternal` functions remain
unchanged and public.

### Implementation

The Rust crate now decodes the existing expanded signing-key representation and
calls RustCrypto's context-aware message-level signing and verification
functions. The TypeScript package imports the new WASM exports, adds overloads
for random key generation, and routes the high-level sign/verify APIs through
empty context by default.

Randomized or hedged ML-DSA signing was not added in this experiment. The
preferred API uses the standardized deterministic ML-DSA.Sign variant because
it is available from the pinned crate without adding RNG plumbing to the Rust
WASM boundary. A future experiment can evaluate enabling upstream `rand_core`
and passing TypeScript-generated randomness into a randomized signing export.

The test suite now covers:

- no-argument key generation and message-level sign/verify for ML-DSA-44,
  ML-DSA-65, and ML-DSA-87;
- deterministic keypair aliases;
- deterministic message-level signing aliases;
- successful verification with the correct context;
- failed verification with the wrong context;
- rejection of contexts longer than 255 bytes;
- separation between message-level signatures and internal verification;
- preservation of internal sign/verify for ACVP-style use;
- unchanged ACVP vector coverage.

### Result: Pass

Experiment 3 passed. The ML-DSA package now has a safer message-level API with
context separation, while preserving the internal ACVP-compatible primitives.

Verification:

- `cargo test -p webbuf_mldsa` in `rs`
- `pnpm run build:wasm` in `ts/npm-webbuf-mldsa`
- `pnpm run typecheck` in `ts/npm-webbuf-mldsa`
- `pnpm test` in `ts/npm-webbuf-mldsa`

All passed, except the Rust `wasm-pack-bundler.zsh` helper still exits nonzero
after producing the bundle because it tries to remove a missing generated
`README.md`. The produced bundle was synced and inlined successfully. The
package test run included 191 passing tests, including the existing ACVP audit
vectors.

## Experiment 4: Implement the SLH-DSA high-level API

### Goal

Expose SLH-DSA message-level signing and verification with context separation
and hedged signing defaults, while preserving the existing internal wrappers
used by ACVP vectors and low-level callers.

### Questions

This experiment should answer:

- Can WebBuf expose SLH-DSA.Sign / SLH-DSA.Verify for every SHA2 and SHAKE
  parameter set without breaking the internal API?
- Can no-argument SLH-DSA key generation generate all three required seeds
  internally?
- Can default signing be hedged by generating `addrnd` in TypeScript?
- Do deterministic aliases and internal APIs remain available for reproducible
  tests and ACVP vectors?

### Method

Add Rust/WASM exports for all twelve SLH-DSA parameter sets:

- message-level `slh_dsa_*_sign`;
- message-level `slh_dsa_*_verify`.

Those exports use the pinned crate's `try_sign_with_context` and
`try_verify_with_context` APIs. The signing export accepts either an empty
`addrnd` value for deterministic signing or an `n`-byte value for hedged
signing. Contexts longer than 255 bytes fail signing and return `false` for
verification.

Add TypeScript wrappers:

- `slhDsa*KeyPair()` generates `skSeed`, `skPrf`, and `pkSeed`;
- `slhDsa*KeyPair(skSeed, skPrf, pkSeed)` remains a compatibility overload;
- `slhDsa*KeyPairDeterministic(...)` is the explicit seeded alias;
- `slhDsa*Sign(signingKey, message, context?)` generates `addrnd` and signs at
  the message level;
- `slhDsa*SignDeterministic(signingKey, message, context?)` signs at the
  message level without caller-provided randomness;
- `slhDsa*Verify(verifyingKey, message, signature, context?)` verifies at the
  message level.

The existing `slhDsa*SignInternal` and `slhDsa*VerifyInternal` functions remain
unchanged and public.

### Implementation

The Rust crate now exports message-level sign and verify wrappers for every
SHA2 and SHAKE parameter set. The TypeScript package imports those exports and
adds high-level overloads and aliases for the full parameter-set matrix.

Default high-level signing is hedged. The TypeScript wrapper generates an
`addrnd` buffer with the parameter set's seed size and passes it into the
message-level Rust/WASM export. Deterministic message-level signing remains
available through explicit `SignDeterministic` aliases.

The test suite now covers:

- no-argument key generation and high-level sign/verify for representative
  SHA2 and SHAKE parameter sets;
- deterministic seeded keypair aliases;
- deterministic message-level signing aliases;
- default hedged signing producing distinct signatures for the same
  key/message;
- successful verification with the correct context;
- failed verification with the wrong context;
- rejection of contexts longer than 255 bytes;
- separation between message-level signatures and internal verification;
- preservation of internal sign/verify for ACVP-style use;
- unchanged ACVP vector coverage.

### Result: Pass

Experiment 4 passed. The SLH-DSA package now has a safer message-level API with
context separation and hedged signing defaults, while preserving the internal
ACVP-compatible primitives.

Verification:

- `cargo test -p webbuf_slhdsa` in `rs`
- `pnpm run build:wasm` in `ts/npm-webbuf-slhdsa`
- `pnpm run typecheck` in `ts/npm-webbuf-slhdsa`
- `pnpm test` in `ts/npm-webbuf-slhdsa`
- `pnpm run build:typescript` in `ts/npm-webbuf-slhdsa`

All passed, except the Rust `wasm-pack-bundler.zsh` helper still exits nonzero
after producing the bundle because it tries to remove a missing generated
`README.md`. The produced bundle was synced and inlined successfully. The
package test run included 182 passing tests, including the existing ACVP audit
vectors.
