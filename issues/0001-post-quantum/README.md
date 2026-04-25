+++
status = "open"
opened = "2026-04-25"
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
