+++
status = "open"
opened = "2026-04-25"
+++

# Post-quantum cryptography for WebBuf

## Goal

Add post-quantum signature and key-encapsulation primitives to WebBuf, packaged
the same way as the existing primitives: Rust → WASM → base64-inlined → TS
wrapper. The downstream consumer is KeyPears, which needs to migrate off P-256
ECDSA and ECDH (see `keypears/issues/0026-post-quantum`).

Concretely: ship `@webbuf/mlkem` and `@webbuf/mldsa` as drop-in companions to
`@webbuf/secp256k1` (and the eventual `@webbuf/p256`).

## Background

### The threat

Google Quantum AI published a paper on April 17, 2026 ("Securing Elliptic Curve
Cryptocurrencies against Quantum Vulnerabilities," Babbush et al.,
[arXiv:2603.28846](https://arxiv.org/abs/2603.28846)) demonstrating that
breaking 256-bit ECDLP requires only ~1,200 logical qubits and ~90 million
Toffoli gates — ~9 minutes on a 500,000 physical-qubit superconducting machine.
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

### Algorithm choice

KeyPears needs one signature algorithm and one KEM. The choices, after reviewing
the field:

- **KEM: ML-KEM-768.** Only standardized KEM. Category 3 security (AES-192
  equivalent). What Signal (PQXDH) and Chrome (TLS) deploy.
- **Signatures: ML-DSA-65.** Standardized; widely implemented; most studied.
  3.3KB signatures and 1.9KB public keys are large but manageable.

Rejected alternatives:

- **SLH-DSA-128s**: 7.9KB signatures kill the auth URL flow and bloat every
  message.
- **FN-DSA-512**: smallest signatures (666 bytes) but not a final FIPS standard,
  and discrete Gaussian sampling has known side-channel pitfalls.

Both chosen algorithms are Module-LWE — a single assumption family. The hybrid
scheme (P-256 + ML-DSA, P-256 + ML-KEM) that KeyPears will deploy mitigates the
single-family risk: a structural break against Module-LWE still leaves the
classical primitive standing during the transition.

### Available Rust implementations

Three RustCrypto crates cover everything we need:

| Algorithm | Crate     | Notes                                         |
| --------- | --------- | --------------------------------------------- |
| ML-KEM    | `ml-kem`  | Pure Rust, ~1.1M downloads, unaudited         |
| ML-DSA    | `ml-dsa`  | Pure Rust, early versions, unaudited          |
| SLH-DSA   | `slh-dsa` | Pure Rust, all 12 parameter sets (not needed) |

All three compile cleanly to `wasm32-unknown-unknown`, no C FFI, and fit the
existing webbuf pipeline. The `pqcrypto-*` crates wrap PQClean C code via FFI
and would require additional work to compile to WASM — not chosen.

For ML-DSA, the "early versions" status is the most uncertain piece and is the
first thing to verify in Experiment 1.

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

A combined hybrid package (analogous to `@webbuf/acb3dh`, wrapping P-256 +
ML-KEM for KEM and P-256 + ML-DSA for signatures) is out of scope for this issue
— that lives in KeyPears or in a follow-up webbuf issue once the primitives are
proven.

## Plan

1. Survey the RustCrypto ML-KEM and ML-DSA crates: current versions, API shape,
   WASM build cleanliness, output sizes, basic perf.
2. Build `webbuf_mlkem` Rust crate and `@webbuf/mlkem` TS wrapper.
3. Build `webbuf_mldsa` Rust crate and `@webbuf/mldsa` TS wrapper.
4. Verify with NIST test vectors.
5. Measure WASM bundle size and runtime performance.
