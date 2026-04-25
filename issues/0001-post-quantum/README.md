+++
status = "closed"
opened = "2026-04-25"
closed = "2026-04-25"
+++

# Post-quantum cryptography for WebBuf

## Goal

Add post-quantum signature and key-encapsulation primitives to WebBuf, packaged
the same way as the existing primitives: Rust → WASM → base64-inlined → TS
wrapper. WebBuf is a primitives library, so the goal is broad coverage — ship
every NIST-finalized PQC algorithm rather than narrowing to one consumer's
needs.

KeyPears is the immediate downstream consumer (see
`keypears/issues/0026-post-quantum`), but the WebBuf packages should serve any
TypeScript application needing NIST-approved post-quantum crypto.

## Background

### The threat

Google Quantum AI published a paper on April 17, 2026 ("Securing Elliptic Curve
Cryptocurrencies against Quantum Vulnerabilities," Babbush et al.,
[arXiv:2603.28846](https://arxiv.org/abs/2603.28846)) demonstrating that
breaking 256-bit ECDLP requires only \~1,200 logical qubits and \~90 million
Toffoli gates — \~9 minutes on a 500,000 physical-qubit superconducting machine.
A 20× reduction from prior estimates. The paper's argument: the margin before
cryptographically relevant quantum computers (CRQCs) arrive is narrowing, and
PQC migration should begin now.

### What needs replacing

Two primitives in the elliptic-curve family:

1. **Signatures**: ECDSA → post-quantum signature scheme.
2. **Key exchange**: ECDH → post-quantum key encapsulation mechanism (KEM).

Symmetric primitives (AES, SHA-256, BLAKE3, PBKDF2, HMAC) are unaffected —
Grover's algorithm only halves their security level, and they remain secure at
existing parameter sizes. WebBuf already has all of these.

### NIST-standardized PQC algorithms

All three are final FIPS standards (August 13, 2024):

- **ML-KEM** (FIPS 203, formerly CRYSTALS-Kyber) — key encapsulation. Lattice
  (Module-LWE).
- **ML-DSA** (FIPS 204, formerly CRYSTALS-Dilithium) — signatures. Lattice
  (Module-LWE/SIS).
- **SLH-DSA** (FIPS 205, formerly SPHINCS+) — hash-based signatures.

A fourth algorithm, **FN-DSA** (Falcon), is NIST-selected but the FIPS 206 draft
has not been published. It is not yet a final standard.

### Available Rust implementations

Three RustCrypto crates cover all three finalized standards:

| Algorithm | Crate     | Notes                                 |
| --------- | --------- | ------------------------------------- |
| ML-KEM    | `ml-kem`  | Pure Rust, ~1.1M downloads, unaudited |
| ML-DSA    | `ml-dsa`  | Pure Rust, early versions, unaudited  |
| SLH-DSA   | `slh-dsa` | Pure Rust, all 12 parameter sets      |

All three compile cleanly to `wasm32-unknown-unknown`, no C FFI, and fit the
existing webbuf pipeline. The `pqcrypto-*` crates wrap PQClean C code via FFI
and would require additional work to compile to WASM — not chosen.

The `ml-dsa` crate's "early versions" status is the most uncertain piece and is
worth verifying before committing to the implementation phase.

### Why build webbuf packages instead of consuming `@noble/post-quantum`

`@noble/post-quantum` is the leading pure-TS PQC library (300K downloads/month,
all four NIST algorithms, by paulmillr). It would be the fastest path for
KeyPears to integrate.

The reason to build webbuf packages anyway:

1. **Consistency.** All other crypto primitives KeyPears uses come from
   `@webbuf/*`. A mixed dependency story is worse than a uniform one.
2. **Constant-time.** `@noble/post-quantum` makes no constant-time guarantees;
   pure Rust has a better (though not perfect) story for side-channel resistance
   on the signing side.
3. **Synchronous API.** WebBuf's base64-inlined WASM pattern gives synchronous
   construction with no top-level await. Library consumers don't have to reason
   about async crypto initialization.
4. **Audit posture.** No PQC library has a third-party audit yet. Building on
   RustCrypto puts us on the same code path as a growing ecosystem (ml-kem alone
   has 1.1M downloads).

If the experiments fail (size, performance, build complexity), falling back to
`@noble/post-quantum` is straightforward.

### Package plan

Following existing webbuf naming (`webbuf_blake3`, `webbuf_secp256k1`, etc.):

- `rs/webbuf_mlkem` + `ts/npm-webbuf-mlkem` → `@webbuf/mlkem`
- `rs/webbuf_mldsa` + `ts/npm-webbuf-mldsa` → `@webbuf/mldsa`
- `rs/webbuf_slhdsa` + `ts/npm-webbuf-slhdsa` → `@webbuf/slhdsa`

Hybrid packages combining classical (P-256) and post-quantum primitives are out
of scope here — those live in downstream consumers or a follow-up WebBuf issue
once these primitives are proven.

## Plan

Map the NIST PQC landscape, then build webbuf packages for each finalized
standard, verify against NIST test vectors, and measure WASM size and runtime
performance. Each algorithm is its own experiment; outcomes inform what comes
next.

## Experiment 1: Survey NIST-approved post-quantum algorithms

### Goal

Identify every NIST-approved post-quantum algorithm, classify by cryptographic
type, and decide which to ship in WebBuf.

### NIST PQC landscape

NIST's post-quantum effort targets the two cryptographic primitives that quantum
computers break:

1. **Key encapsulation mechanisms (KEMs)** — replace ECDH and RSA key transport.
   Establish a shared secret between two parties.
2. **Digital signatures** — replace ECDSA and RSA signatures. Authenticate
   messages and identities.

Symmetric primitives (AES, ChaCha20), hash functions (SHA-2, SHA-3, BLAKE3),
MACs (HMAC, KMAC), and password hashing (PBKDF2, Argon2) are unaffected by
quantum attacks at appropriate parameter sizes — Grover's algorithm only halves
their effective security. Information-theoretic constructions like Shamir secret
sharing are quantum-safe by construction (no computational assumption to break).
None of these are part of the NIST PQC track.

### Finalized FIPS standards (August 13, 2024)

| Standard | Algorithm | Former name        | Type       | Family                   |
| -------- | --------- | ------------------ | ---------- | ------------------------ |
| FIPS 203 | ML-KEM    | CRYSTALS-Kyber     | KEM        | Lattice (Module-LWE)     |
| FIPS 204 | ML-DSA    | CRYSTALS-Dilithium | Signatures | Lattice (Module-LWE/SIS) |
| FIPS 205 | SLH-DSA   | SPHINCS+           | Signatures | Hash-based (stateless)   |

ML-KEM is the only standardized KEM. ML-DSA and SLH-DSA are both signature
schemes on different mathematical assumptions:

- **ML-DSA** is lattice-based, the same assumption family as ML-KEM. Smaller and
  faster than SLH-DSA. The default general-purpose PQC signature scheme.
- **SLH-DSA** is hash-based. Slower with much larger signatures (8KB+ for the
  small parameter sets), but its security rests only on hash function strength —
  the most conservative possible assumption. The hedge against a structural
  break in lattice cryptography.

### Selected but not yet final

| Status               | Algorithm | Type | Family                          |
| -------------------- | --------- | ---- | ------------------------------- |
| FIPS 206 draft       | FN-DSA    | Sig  | Lattice (NTRU, Gaussian sample) |
| Announced March 2025 | HQC       | KEM  | Code-based                      |
| Signatures on-ramp   | ~14 cands | Sig  | Various (non-lattice)           |

- **FN-DSA (Falcon)** — FIPS 206 draft pending. Smallest PQC signatures (~666
  bytes). Implementation is famously fragile due to discrete Gaussian sampling
  side-channels.
- **HQC** — NIST announced in March 2025 it will be standardized as a backup KEM
  on a different mathematical assumption (codes rather than lattices) to
  diversify the KEM track. Draft FIPS not yet published.
- **Additional signatures on-ramp** — NIST is evaluating ~14 candidates (MAYO,
  UOV, CROSS, SQIsign, FAEST, etc.) for a second non-lattice signature scheme.
  None standardized.

### Out of scope for NIST PQC

The NIST PQC universe is just two primitive slots: KEM and signatures.
Everything else falls into one of three buckets:

- **Already quantum-safe:** symmetric ciphers, hashes, MACs, password hashing,
  Shamir secret sharing.
- **No NIST PQC standard yet:** threshold signatures, BLS aggregate signatures,
  pairing-based crypto, identity-based encryption, attribute-based encryption.
- **Not a NIST target:** zero-knowledge proofs / SNARKs (hash-based STARKs are
  inherently quantum-safe).

### Decision

WebBuf will implement all three finalized FIPS standards:

1. **ML-KEM** (FIPS 203) → `@webbuf/mlkem`
2. **ML-DSA** (FIPS 204) → `@webbuf/mldsa`
3. **SLH-DSA** (FIPS 205) → `@webbuf/slhdsa`

Rationale:

- **WebBuf is a primitives library, not an application.** The cost of shipping
  all three is modest (three independent packages, all backed by pure-Rust
  RustCrypto crates that compile to WASM cleanly). The cost of forcing consumers
  to choose at the WebBuf layer is higher — different consumers will weigh
  signature size, performance, and assumption diversity differently.
- **SLH-DSA is the assumption-diversity hedge.** Both ML-KEM and ML-DSA rest on
  Module-LWE. A structural break against lattice cryptography would compromise
  both at once. SLH-DSA's hash-based foundation is the conservative fallback;
  worth shipping even though it's less convenient (larger signatures, slower).
- **All three are NIST-approved today.** No standards risk, no parameter churn.

Defer FN-DSA and HQC until their FIPS standards are final. Revisit once FIPS 206
publishes (FN-DSA) and HQC's draft FIPS is available. The "additional signatures
on-ramp" candidates are too early to commit to.

### Result: Pass

The NIST PQC landscape is fully mapped. Two cryptographic primitive slots (KEM
and signatures), three finalized algorithms, two pipeline candidates, roughly
fourteen on-ramp candidates further out. WebBuf will ship the three finalized
standards. Next experiment will survey the Rust crate ecosystem for each of the
three algorithms.

## Experiment 2: Survey Rust crate implementations

### Goal

For each of ML-KEM, ML-DSA, and SLH-DSA, identify every viable Rust crate
implementation and pick the best one for WebBuf to wrap. Hard requirements:

- **Pure Rust** (no C FFI — must compile to `wasm32-unknown-unknown`)
- **Active maintenance** with NIST-final parameters (FIPS 203/204/205, not
  pre-final Kyber/Dilithium round-3 specs)
- **NIST test vector compliance**

Soft preferences: independent audit (none exist yet — see below); formal
verification; documented constant-time properties; ergonomic API; ecosystem
consistency with the rest of WebBuf (which already wraps RustCrypto crates for
`sha2`, `hmac`, `ripemd`, `k256`, `aes`).

### The audit gap

**No Rust PQC implementation has received a publicly-disclosed independent audit
as of April 2026.** Project Eleven's July 2025 survey ("The State of
Post-Quantum Cryptography in Rust: The Belt is Vacant") explicitly identifies
this as the most important gap in the ecosystem and nothing has changed since.
Every RustCrypto PQC README still carries a "USE AT YOUR OWN RISK!" banner.

This isn't WebBuf-specific — it's a property of the entire Rust PQC ecosystem
right now. Audit posture must be disclosed in the package READMEs.

### `ml-dsa` advisory cluster (Dec 2025 – Mar 2026)

The most concerning data point in the survey: RustCrypto's `ml-dsa` crate had
**three CVE-class advisories land between Dec 2025 and Mar 2026**, all fixed
across the rc.2 → rc.8 release window:

- **RUSTSEC-2025-0144** — timing side-channel in `decompose` (Barrett reduction
  now replaces hardware divide).
- **CVE-2026-24850 / GHSA-5x2r-hc65-25f9** — signature malleability via
  duplicate hint indices.
- **RUSTSEC-2026-0075/0076/0077** — RNG-failure key generation, panic in hint
  decoding, signer-response-norm verification.

This is not a reason to avoid `ml-dsa` — it demonstrates active scrutiny and
responsive maintenance, and the fixes are landed. But it confirms that the
lattice signature scheme is subtle and the implementation is still maturing.
**Pin `>= 0.1.0-rc.8`** and track RUSTSEC.

### Eliminated by C-FFI / non-`wasm32-unknown-unknown`

Hard-disqualified from WebBuf:

| Crate                 | Reason                                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `pqcrypto-mlkem` etc. | C FFI to PQClean. WASM target is `wasm32-wasi` only.                                                        |
| `aws-lc-rs`           | C FFI to AWS-LC. `wasm32-unknown-unknown` not on platform support list. No SLH-DSA. ML-DSA marked unstable. |
| `oqs` (liboqs-rust)   | C FFI to liboqs. No WASM story. Maintainers position as a prototyping library.                              |
| Argyle `pqc_*`        | Stale (2023), targets pre-FIPS round-3 specs.                                                               |

### Viable candidates (pure Rust, WASM-compatible)

**ML-KEM**

| Crate            | Maintainer     | Latest     | Notes                                                                                                                                                                |
| ---------------- | -------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ml-kem`         | RustCrypto     | 0.3.0-rc.2 | Ergonomic API, CI-tested for wasm, no advisories.                                                                                                                    |
| `libcrux-ml-kem` | Cryspen        | 0.0.8      | **Formally verified** (hax + F\*) for panic-freedom, correctness, and secret-independence. Used in production by `rustls-post-quantum`. Must gate out SIMD for wasm. |
| `fips203`        | IntegrityChain | 0.4.3      | Pure Rust, no `unsafe`, explicit WASM design. Lower adoption.                                                                                                        |

**ML-DSA**

| Crate            | Maintainer     | Latest     | Notes                                                                  |
| ---------------- | -------------- | ---------- | ---------------------------------------------------------------------- |
| `ml-dsa`         | RustCrypto     | 0.1.0-rc.8 | Highest adoption. Pin `>= rc.8` (advisory cluster).                    |
| `libcrux-ml-dsa` | Cryspen        | 0.0.8      | Formal verification incomplete here (less mature than libcrux-ml-kem). |
| `fips204`        | IntegrityChain | 0.4.6      | Pure Rust, no `unsafe`. Stale (last release Oct 2024).                 |

**SLH-DSA**

| Crate     | Maintainer     | Latest     | Notes                                                                    |
| --------- | -------------- | ---------- | ------------------------------------------------------------------------ |
| `slh-dsa` | RustCrypto     | 0.2.0-rc.4 | Only meaningful pure-Rust option with active maintenance. No advisories. |
| `fips205` | IntegrityChain | 0.4.1      | Fallback. Stale (last release Dec 2024).                                 |

### Decision

WebBuf will wrap the three RustCrypto crates:

1. **ML-KEM** → `ml-kem` (RustCrypto)
2. **ML-DSA** → `ml-dsa` (RustCrypto), pinned `>= 0.1.0-rc.8`
3. **SLH-DSA** → `slh-dsa` (RustCrypto)

Rationale:

- **Ecosystem consistency.** WebBuf already wraps RustCrypto for `sha2`, `hmac`,
  `ripemd`, `k256`, and `aes`. Using RustCrypto for the PQC trio matches the
  existing pattern and keeps `Cargo.toml` dependency surface uniform.
- **Active maintenance.** All three crates are receiving regular releases
  through the rc cycle. The `ml-dsa` advisory cluster, while concerning, is
  evidence of active scrutiny — the algorithms are being fixed, not ignored.
- **API ergonomics.** RustCrypto's API conventions (generic `Signer` /
  `Verifier` / `KemCore` traits, generic-const parameter sets) are familiar to
  anyone using the broader ecosystem.
- **Wrap, don't implement.** Even RustCrypto shipped three CVE-class bugs in
  ML-DSA in three months. Reimplementing these algorithms in WebBuf would
  introduce parallel implementations with no safety benefit. The Cargo
  dependency model lets us pin to specific versions and bump cleanly when audits
  eventually arrive.

**Documented swap option:** If formal-verification value beats RustCrypto- stack
consistency for ML-KEM specifically, swap to `libcrux-ml-kem`.
`rustls-post-quantum` made exactly that trade-off. We will not start there (API
churn at 0.0.x is real, and `libcrux-ml-dsa` is less mature so we'd be mixing
libraries), but we'll keep it on the table as a future migration.

### Risks to disclose in package READMEs

- No independent audit exists on any Rust PQC implementation today.
- ML-DSA had three CVE-class advisories in three months (Dec 2025 – Mar 2026);
  pin tightly and run `cargo audit`.
- All three crates are pre-1.0 (`0.0.x` to `0.x.0-rc.N`); API churn is likely
  before stable releases.

### Result: Pass

Three pure-Rust RustCrypto crates cover all three NIST-finalized PQC standards,
all compile to `wasm32-unknown-unknown`, and all fit the existing WebBuf
pipeline. The audit gap is real but unavoidable — it's a property of the entire
Rust PQC ecosystem, not a WebBuf-specific problem. Next experiment will start
the implementation phase: scaffold `rs/webbuf_mlkem` and `ts/npm-webbuf-mlkem`
and verify the build pipeline end-to-end with NIST test vectors.

## Experiment 3: Scaffold `@webbuf/mlkem` and verify against NIST vectors

### Goal

Stand up the first PQC package in WebBuf — `@webbuf/mlkem` wrapping the
RustCrypto `ml-kem` crate — and prove the pipeline works end-to-end:

1. `rs/webbuf_mlkem` Rust crate compiles cleanly to `wasm32-unknown-unknown`.
2. `ts/npm-webbuf-mlkem` TypeScript wrapper builds via the existing Rust → WASM
   → base64-inline → TS pipeline.
3. The wrapper produces output matching official NIST ACVP/KAT test vectors for
   all three FIPS 203 parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024).

ML-KEM is the right starting point: simplest API (three operations: keygen,
encapsulate, decapsulate), no recent advisories, and the highest-priority
algorithm for downstream consumers (key exchange is the harvest-now-decrypt-
later target).

### Why ML-KEM first

- **Cleanest crate.** `ml-kem` 0.2.x is stable and has no RUSTSEC advisories.
  Starting here means any pipeline issues we hit are WebBuf-side problems, not
  crate-side problems.
- **Smallest API surface.** Three operations with four byte-buffer types
  (encapsulation key, decapsulation key, ciphertext, shared secret). If our Rust
  → WASM → TS pipeline has surprises, we discover them on the simplest possible
  API.
- **Highest priority for KeyPears.** Encrypted messages stored anywhere are
  vulnerable to harvest-now-decrypt-later if quantum computers arrive.
  Signatures only matter prospectively. So if work stalls partway through this
  issue, ML-KEM is the piece that has to land first.

### Design decisions

**Deterministic API.** `wasm32-unknown-unknown` has no entropy source. Rather
than wiring up `getrandom` to use `crypto.getRandomValues` (extra glue, more
moving parts), we expose deterministic functions that take 32-byte seeds as
input. The TypeScript layer is responsible for sourcing entropy via
`crypto.getRandomValues` and passing it down. This matches the pattern in
`webbuf_p256` (callers manage their own randomness) and is cleaner for a
primitives library.

**All three parameter sets.** Ship ML-KEM-512, ML-KEM-768, and ML-KEM-1024 in
the same package. Code cost is low (the RustCrypto crate parameterizes via
generic-const; each level is a few lines of glue) and consumers shouldn't have
to install separate packages for security-level choice.

**Concatenated output buffers.** WASM-bindgen returns `Vec<u8>` cleanly but
multi-return is awkward. Functions that produce multiple outputs (keygen returns
ek + dk; encapsulate returns ct + ss) concatenate the outputs and the TypeScript
wrapper splits them at known offsets. This matches how `webbuf_p256` returns
SEC1-encoded points.

### Plan

1. Look at the `ml-kem` 0.2.x API on docs.rs; pin the version.
2. Write `rs/webbuf_mlkem/Cargo.toml` and `src/lib.rs` exposing six functions:
   `ml_kem_{512,768,1024}_keypair_from_seed`,
   `ml_kem_{512,768,1024}_encapsulate`, `ml_kem_{512,768,1024}_decapsulate`.
   (Plus tests against NIST vectors at the Rust level.)
3. Add `webbuf_mlkem` to the `rs/Cargo.toml` workspace.
4. Run `wasm-pack-bundler.zsh`; confirm WASM size is reasonable.
5. Scaffold `ts/npm-webbuf-mlkem/` mirroring `ts/npm-webbuf-blake3/`'s layout:
   `package.json`, `tsconfig*.json`, `build-inline-wasm.ts`, `src/index.ts`,
   `test/`. Add to `pnpm-workspace.yaml` if needed.
6. Sync from Rust, build inline WASM, build TypeScript.
7. Vendor a representative subset of NIST ACVP-Server ML-KEM test vectors into
   `test/`. Write a `vitest` audit suite that exercises all three parameter sets
   across keygen, encapsulate, and decapsulate.
8. Run tests; record results, WASM size, and any pipeline gotchas.

### Implementation

Built `rs/webbuf_mlkem` (78 lines of Rust + 80 lines of round-trip tests via a
`mlkem_impl!` declarative macro that emits `keypair`, `encapsulate`, and
`decapsulate` functions per security level) and `ts/npm-webbuf-mlkem` (155 lines
of TypeScript wrapping the WASM exports with `WebBuf` / `FixedBuf` types and a
`splitKeypair` / `splitEncap` helper for the concatenated buffers).

Pipeline gotchas discovered:

- **`ml-kem` deterministic API is feature-gated.** The `B32`,
  `EncapsulateDeterministic`, and `KemCore::generate_deterministic` items are
  all behind `--features deterministic`. Without that feature, key generation
  requires an `RngCore` which is awkward for `wasm32-unknown-unknown`. Fix:
  `ml-kem = { version = "0.2.3", features = ["deterministic"] }`.
- **Trait import locations.** `EncapsulateDeterministic` re-exports from the
  crate root (`ml_kem::EncapsulateDeterministic`), but `Decapsulate` lives in
  `ml_kem::kem::Decapsulate`. Easy to get wrong from docs alone.
- **Compiler can't infer encapsulate return types.** The
  `EncapsulateDeterministic::encapsulate_deterministic` impl returns a
  `Result<(EK, SS), Error>` where `EK` and `SS` are generic. The compiler needs
  an explicit type annotation:
  `let (ct, ss): (ml_kem::Ciphertext<$kem>, ml_kem::SharedKey<$kem>) = ...`.
- **`hybrid_array::ArraySize` has no `SIZE` constant.** Use
  `Encoded::<T>::default().len()` for runtime size lookup instead.

None of these blocked progress; total scaffolding time was about an hour
including reading the `ml-kem` docs.

### Result: Pass

**Rust:** 5/5 unit tests pass (round-trip for all three parameter sets, plus
input validation). `cargo check` and `wasm-pack build --target bundler` both
clean.

**WASM size:** 89KB raw, 119KB after base64 inlining. Comparable to
`@webbuf/blake3` and well within the budget for a synchronous-load TypeScript
package.

**TypeScript:** typecheck passes, `pnpm run build` produces a clean `dist/`, and
the test suite reports:

```
✓ test/index.test.ts (5 tests) 6ms
✓ test/audit.test.ts (180 tests) 25ms

Test Files  2 passed (2)
     Tests  185 passed (185)
```

The 180 audit tests exercise the official NIST ACVP-Server FIPS 203 vectors
(commit `65370b8`) — 25 keyGen tests × 3 parameter sets = 75 keyGen, 25
encapsulation tests × 3 = 75 encap, 10 decapsulation tests × 3 = 30 decap. **All
180 NIST vectors match exactly.** Total runtime 32ms.

The pipeline works end-to-end. Confidence is high that ML-DSA and SLH-DSA will
follow the same template with similar effort. The base64-inline pattern that
gives WebBuf its synchronous-load story works fine for PQC payloads — even
ML-KEM-1024's larger keys round-trip through WASM cleanly.

Next experiment: scaffold `@webbuf/mldsa` (ML-DSA / FIPS 204) using the same
template, with `ml-dsa = ">=0.1.0-rc.8"` pinned per Experiment 2's findings, and
validate against NIST ACVP ML-DSA test vectors.

## Experiment 4: Scaffold `@webbuf/mldsa` and verify against NIST vectors

### Goal

Same shape as Experiment 3, applied to ML-DSA / FIPS 204:

1. `rs/webbuf_mldsa` Rust crate compiles cleanly to `wasm32-unknown-unknown`.
2. `ts/npm-webbuf-mldsa` TypeScript wrapper builds via the existing Rust → WASM
   → base64-inline → TS pipeline.
3. The wrapper produces output matching official NIST ACVP test vectors for all
   three FIPS 204 parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87) across
   keyGen, sigGen, and sigVer.

### API surface to expose

ML-DSA has more public API than ML-KEM. From FIPS 204 plus the `ml-dsa` crate's
exposure:

- **KeyGen**: 32-byte seed `xi` → public key (vk) + secret key (sk, expanded
  form per FIPS 204 §6.4.2). The seed-form is 32 bytes; the expanded sk is much
  larger (2560/4032/4896 bytes for the three parameter sets).
- **Sign internal** (FIPS 204 §6.2 ML-DSA.Sign_internal): expanded sk +
  message + 32-byte randomness `rnd` → signature. This is the primitive signing
  function that NIST ACVP `internal` vectors test against.
- **Verify internal** (FIPS 204 §6.3 ML-DSA.Verify_internal): vk + message +
  signature → bool.

The crate also exposes `sign_deterministic`, `sign_randomized`,
`sign_with_context`, `verify_with_context`, mu-mode signing, etc. Out of scope
for this experiment — we'll add them only if a downstream consumer needs them.

### Pinning the crate

Per Experiment 2's findings, pin `ml-dsa = "=0.1.0-rc.8"`. The recent advisory
cluster (Dec 2025 – Mar 2026: timing leak, signature malleability, RNG-failure
key gen, hint-decode panic, response-norm verify) was all fixed by rc.8. Pin
exactly so a `cargo update` doesn't pull a future rc that has breaking API
changes — the crate is still moving fast through release candidates.

### Plan

1. Look at the `ml-dsa` 0.1.0-rc.8 source for sign_internal / verify_internal /
   from_seed signatures.
2. Write `rs/webbuf_mldsa/Cargo.toml` (default-features = false to skip
   `rand_core` and `pkcs8`; we don't need them) and `src/lib.rs` with a macro
   emitting nine functions: `ml_dsa_{44,65,87}_keypair`,
   `ml_dsa_{44,65,87}_sign_internal`, `ml_dsa_{44,65,87}_verify_internal`.
3. Round-trip Rust tests for all three parameter sets.
4. Build WASM via `wasm-pack-bundler.zsh`. Expect a larger WASM than ML-KEM
   since the lattice signature scheme has more code paths.
5. Scaffold `ts/npm-webbuf-mldsa/` mirroring `ts/npm-webbuf-mlkem/`.
6. Vendor NIST ACVP-Server FIPS 204 vectors (keyGen, sigGen, sigVer
   `internalProjection.json` files).
7. Write a vitest audit suite that iterates all three test types across all
   three parameter sets.
8. Run; record results, WASM size, gotchas.

### Implementation

Built `rs/webbuf_mldsa` (~85 lines of Rust + ~95 lines of round-trip tests) and
`ts/npm-webbuf-mldsa` (~120 lines of TypeScript). The same `mldsa_impl!` macro
pattern from `webbuf_mlkem` emits keypair/sign/verify functions per parameter
set. Wrapper TypeScript exports per-parameter-set typed functions:
`mlDsa{44,65,87}KeyPair`, `mlDsa{44,65,87}SignInternal`,
`mlDsa{44,65,87}VerifyInternal`.

Pipeline gotchas discovered:

- **`ml-dsa` API is bigger and trickier than `ml-kem`.** Three traits (`KeyGen`,
  `signature::Keypair`, plus the inherent methods) plus two key types
  (`SigningKey` and `ExpandedSigningKey`) overlap with subtle differences. The
  right pattern is: call `KeyGen::from_seed` to get a `SigningKey`, then
  `.signing_key()` to get the embedded `ExpandedSigningKey`, which is what owns
  `sign_internal` and `verifying_key`.
- **`ExpandedSigningKey::to_expanded` and `from_expanded` are deprecated.** But
  they're the FIPS 204 sk encoding that NIST ACVP test vectors compare against.
  The deprecation recommends `to_seed` / `from_seed` (32-byte form) but that
  doesn't match ACVP's expected output. Used `#[allow(deprecated)]` with a note.
  If ml-dsa removes these in the future we'll need to roll our own FIPS 204
  §6.4.2 encoding/decoding.
- **`sign_internal` takes `&[&[u8]]` (multipart).** Pass `&[message]` for the
  single-message case.
- **Signature is parsed via `Signature::decode(&EncodedSignature)`** which
  returns `Option<Self>` — invalid signatures get caught here before reaching
  `verify_internal`.

The ACVP sigGen tests have `deterministic: bool` per group. When `true`, FIPS
204 §5.2 specifies `rnd = 0^32`, so the test cases omit the `rnd` field. The
audit suite supplies a constant zero `rnd` for these cases.

### Result: Pass

**Rust:** 6/6 unit tests pass (round-trip across all three parameter sets,
deterministic signing reproducibility, tampered-signature rejection, input
validation). `cargo check` and `wasm-pack build --target bundler` both clean.

**WASM size:** 189KB raw, 252KB after base64 inlining. About 2.1× the size of
`@webbuf/mlkem`, which is expected — ML-DSA is a significantly more complex
algorithm with more code paths (signing rejection sampling, hint
encoding/decoding, etc.). Still well within budget for synchronous-load
TypeScript packages.

**TypeScript:** typecheck passes, `pnpm run build` produces a clean `dist/`, and
the test suite reports:

```
✓ test/index.test.ts (6 tests) 19ms
✓ test/audit.test.ts (180 tests) 127ms

Test Files  2 passed (2)
     Tests  186 passed (186)
```

The 180 audit tests exercise the official NIST ACVP-Server FIPS 204 vectors
(commit `65370b8`):

- **keyGen**: 25 tests × 3 parameter sets = 75 tests. All pk and sk match.
- **sigGen**: 10 tests × 2 variants (deterministic and hedged) × 3 parameter
  sets = 60 tests. All signatures match exactly.
- **sigVer**: 15 tests × 3 parameter sets = 45 tests. All `testPassed`
  expectations match — both valid signatures verify and tampered/invalid ones
  reject.

**All 180 NIST vectors match exactly.** Total runtime 127ms (slower than
ML-KEM's 25ms because signing involves rejection sampling, but still fast).

The pipeline holds up for ML-DSA. Pinning `=0.1.0-rc.8` is currently working;
we'll need to bump as new rc releases land. The deprecated
`to_expanded`/`from_expanded` is a sword of Damocles — if it's removed in 0.1.0
final, we'll need to either implement FIPS 204 sk encoding ourselves or switch
to the seed-form sk and have downstream consumers re-derive expanded form on
demand.

Next experiment: scaffold `@webbuf/slhdsa` (SLH-DSA / FIPS 205) using the same
template. SLH-DSA has 12 parameter sets (small/fast × SHA2/SHAKE × 3 security
levels).

## Experiment 5: Scaffold `@webbuf/slhdsa` and verify against NIST vectors

### Goal

Same shape as Experiments 3 and 4, applied to SLH-DSA / FIPS 205:

1. `rs/webbuf_slhdsa` Rust crate compiles cleanly to `wasm32-unknown-unknown`.
2. `ts/npm-webbuf-slhdsa` TypeScript wrapper builds via the existing pipeline.
3. The wrapper produces output matching official NIST ACVP test vectors for all
   12 FIPS 205 parameter sets.

### The 12 parameter sets

FIPS 205 specifies twelve named parameter sets, indexed across three axes:

| Axis           | Values                                        |
| -------------- | --------------------------------------------- |
| Hash family    | `SHA2`, `SHAKE`                               |
| Security level | `128`, `192`, `256` (categories 1/3/5)        |
| Tradeoff       | `s` (small sig, slow) / `f` (fast sig, large) |

Names: `SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}`.

Sizes:

| Set           | n   | pk  | sk  | sig (s) | sig (f) |
| ------------- | --- | --- | --- | ------- | ------- |
| 128 / SLH-DSA | 16  | 32  | 64  | 7,856   | 17,088  |
| 192 / SLH-DSA | 24  | 48  | 96  | 16,224  | 35,664  |
| 256 / SLH-DSA | 32  | 64  | 128 | 29,792  | 49,856  |

Keys are tiny (32–128 bytes — far smaller than ML-DSA's 1.3–4.9KB) but
signatures are huge (8KB – 50KB). This is the point of SLH-DSA: hash-based
security at the cost of signature size.

### Ship all 12

WebBuf is a primitives library; consumers should choose. The macro pattern from
Experiments 3 and 4 scales fine — 12 `slhdsa_impl!` invocations produce 36
wasm-bindgen functions with no per-set hand coding. WASM size will grow but
SLH-DSA is hash-based, so the implementation reuses SHA-2 / SHAKE primitives
across parameter sets — actual code duplication is modest.

### API surface

For each parameter set: `keypair`, `sign_internal`, `verify_internal`.

- **Keypair** takes three n-byte seeds (`sk_seed`, `sk_prf`, `pk_seed`) per FIPS
  205 SLH-Keygen-internal. Outputs `pk || sk` concatenated.
- **Sign internal** takes `sk`, message, optional n-byte `addrnd`. Per FIPS 205
  §10.2, `addrnd = None` is the deterministic variant (uses pk_seed as the
  randomizer); `addrnd = Some(rnd)` is the hedged variant.
- **Verify internal** takes `pk`, message, signature.

The seed sizes are parameter-set-dependent (16/24/32 bytes) — unlike ML-KEM and
ML-DSA where everything is 32-byte seeds.

### Plan

1. Look at the `slh-dsa` 0.2.0-rc.4 source for `slh_keygen_internal` /
   `slh_sign_internal` / `slh_verify_internal` signatures.
2. Write `rs/webbuf_slhdsa/Cargo.toml`
   (`default-features = false, features = ["alloc"]` — skip `pkcs8`) and
   `src/lib.rs` with a macro emitting 36 functions.
3. Round-trip Rust tests for one parameter set per security level.
4. Build WASM; check size.
5. Scaffold `ts/npm-webbuf-slhdsa/` mirroring the previous packages.
6. Vendor NIST ACVP-Server FIPS 205 vectors (keyGen, sigGen, sigVer).
7. Audit suite iterating all three test types across all 12 parameter sets.
8. Run; record results, WASM size, gotchas.

### Implementation

Built `rs/webbuf_slhdsa` (~125 lines of Rust + ~95 lines of round-trip tests via
12 macro invocations) and `ts/npm-webbuf-slhdsa` (~470 lines of TypeScript —
necessarily verbose to expose 36 typed functions). The macro pattern continues
to scale; each parameter set adds five lines of macro invocation.

Pipeline gotchas discovered:

- **slh-dsa requires its default features.** Trying
  `default-features = false, features = ["alloc"]` fails to compile because the
  crate has unconditional `EncodePrivateKey` impls referencing
  `der::SecretDocument`, which requires `der/alloc + der/zeroize`. The
  `pkcs8/alloc` feature in slh-dsa's defaults pulls in the right transitive
  features. Just use defaults — they're fine for our purposes.
- **`slh_sign_internal` panics on wrong-length `opt_rand`.** The docstring warns
  about it explicitly. Validated `opt_rand.len() == n` (or empty) before passing
  through to avoid crashing the WASM module.
- **NIST ACVP sigVer vectors include wrong-size signatures.** Our wrapper uses
  `FixedBuf<sigSize>` typed at the API boundary, which throws on size mismatch.
  The audit suite catches this and treats it as a failed verification, matching
  `testPassed: false` for negative-test vectors.
- **NIST vectors don't cover all 12 parameter sets.** The ACVP-Server publishes
  only a subset (4 in keyGen, 5 in sigGen, 5 in sigVer). The audit runs whatever
  vectors are provided; the rest of the parameter sets rely on round-trip
  self-test only.
- **NIST ACVP sigGen "deterministic = true" tests don't include `rnd`.** Per
  FIPS 205, deterministic uses `pkSeed` as the randomizer; our wrapper treats
  empty `opt_rand` as the deterministic variant. This matches the `slh-dsa`
  crate's behavior.

The `s` (small signature) variants are genuinely slow — SLH-DSA-SHAKE-192s takes
~1.3 seconds per signing operation in WASM. The `f` (fast) variants are an order
of magnitude faster. This is expected from the algorithm design and matches FIPS
205's published performance characteristics.

### Result: Pass

**Rust:** 6/6 unit tests pass (round-trip across SHA2-128f, SHAKE-192s,
SHA2-256f, plus deterministic-signing reproducibility, tampered-signature
rejection, input validation). `cargo check` and
`wasm-pack build --target bundler` both clean.

**WASM size:** 336KB raw, 448KB after base64 inlining. The largest of the three
PQC packages — expected, since 12 parameter sets × 3 functions = 36 exposed
functions, plus SHA-2 / SHAKE primitives. Still acceptable for a
synchronous-load TypeScript package; `@webbuf/slhdsa` is the assumption-
diversity hedge package, not the everyday default, so size is less critical.

**TypeScript:** typecheck passes, `pnpm run build` produces a clean `dist/`, and
the test suite reports:

```
✓ test/index.test.ts (4 tests) 1472ms
✓ test/audit.test.ts (177 tests)

Test Files  2 passed (2)
     Tests  181 passed (181)
Duration  ~30s
```

The 177 audit tests exercise the official NIST ACVP-Server FIPS 205 vectors
(commit `65370b8`):

- **keyGen**: 4 parameter sets × 10 = 40 tests. All pk and sk match.
- **sigGen**: 5 parameter sets × 2 variants (deterministic, hedged) × varying
  counts = 92 tests. All signatures match exactly.
- **sigVer**: 5 parameter sets × 9 = 45 tests. All `testPassed` expectations
  match.

**All 177 NIST vectors match exactly.** Total runtime ~30s, dominated by the
slow `s` (small signature) variants which take ~1.3s per signing operation —
characteristic of SLH-DSA, not a wrapper issue.

## Conclusion

All three NIST-finalized PQC algorithms are now packaged in WebBuf:

| Package          | Algorithm | WASM (raw) | NIST vectors | Notes                                        |
| ---------------- | --------- | ---------- | ------------ | -------------------------------------------- |
| `@webbuf/mlkem`  | ML-KEM    | 89KB       | 180/180 ✓    | KEM, lattice, fastest                        |
| `@webbuf/mldsa`  | ML-DSA    | 189KB      | 180/180 ✓    | Signatures, lattice, default general-purpose |
| `@webbuf/slhdsa` | SLH-DSA   | 336KB      | 177/177 ✓    | Signatures, hash-based, conservative hedge   |

The Rust → WASM → base64-inline → TypeScript pipeline scales to PQC. All three
algorithms wrap RustCrypto crates with no per-algorithm engineering beyond the
standard webbuf template. NIST ACVP coverage is complete for ML-KEM and ML-DSA;
SLH-DSA coverage is limited to the parameter sets NIST chose to publish vectors
for (4 of 12 in keyGen, 5 of 12 in sig{Gen,Ver}).

The known caveats remain those identified in Experiment 2:

1. **No public independent audit** of any Rust PQC implementation.
2. **`ml-dsa` advisory cluster** (Dec 2025 – Mar 2026) requires staying on rc.8
   or later and tracking RUSTSEC.
3. **Pre-1.0 API churn** — all three crates are at `0.x.0-rc.N`. We pin exact
   versions (`=0.2.3` for `ml-kem`, `=0.1.0-rc.8` for `ml-dsa`, `=0.2.0-rc.4`
   for `slh-dsa`) to avoid surprise upgrades.
4. **Deprecated `to_expanded`/`from_expanded`** in `ml-dsa` is still needed for
   FIPS 204 sk encoding / NIST ACVP compatibility.

The original issue Goal — "Add post-quantum signature and key-encapsulation
primitives to WebBuf, packaged the same way as the existing primitives" — is
met. All NIST-finalized PQC algorithms ship as `@webbuf/mlkem`, `@webbuf/mldsa`,
and `@webbuf/slhdsa`. KeyPears and other downstream consumers can now build
hybrid post-quantum cryptography on top of WebBuf primitives.

Future WebBuf work (deferred to a follow-up issue):

- Hybrid packages combining classical (P-256) with PQC: `@webbuf/p256-mlkem` for
  KEM-side hybrid, `@webbuf/p256-mldsa` for signature-side hybrid.
- FN-DSA (Falcon) when FIPS 206 publishes.
- HQC when its FIPS standard publishes.
- Bumping pinned versions as RustCrypto crates reach 1.0 stable releases.
