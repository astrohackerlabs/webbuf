+++
status = "open"
opened = "2026-04-25"
+++

# Hybrid post-quantum encryption packages

## Goal

Add high-level encryption packages that combine AES-GCM with ML-KEM key
encapsulation, following the same pattern as the existing
`@webbuf/aesgcm-p256dh` package. The immediate downstream consumer is KeyPears,
which needs to migrate message encryption from P-256 ECDH to a quantum-resistant
scheme.

## Background

### Existing combined packages

WebBuf already ships high-level packages that combine symmetric encryption with
key exchange:

- `@webbuf/aesgcm-p256dh` — AES-256-GCM + P-256 ECDH shared secret
- `@webbuf/acb3p256dh` — AES-CBC + BLAKE3 MAC + P-256 ECDH
- `@webbuf/acs2p256dh` — AES-CBC + SHA-256 HMAC + P-256 ECDH

These take a private key + public key, derive a shared secret, and
encrypt/decrypt in one call. The P-256 ECDH shared secret is hashed with SHA-256
to produce the AES key.

### What's needed

The PQC primitives are ready (`@webbuf/mlkem`, `@webbuf/mldsa`,
`@webbuf/slhdsa`), but there's no high-level package that combines them with
symmetric encryption. Application code has to manually encapsulate, derive a
key, and encrypt — the same multi-step footgun that the classical combined
packages were designed to prevent.

### KEM vs DH

ML-KEM is a key encapsulation mechanism, not a Diffie-Hellman key exchange. The
API shape is different from P-256 ECDH:

**P-256 ECDH (current):**

- Both parties have persistent key pairs (privKey, pubKey)
- Shared secret = ECDH(myPrivKey, theirPubKey)
- Either party can compute the same shared secret independently
- Encryption: `encrypt(myPrivKey, theirPubKey, plaintext)`
- Decryption: `decrypt(myPrivKey, theirPubKey, ciphertext)`

**ML-KEM (post-quantum):**

- Recipient has a key pair (encapsulationKey, decapsulationKey)
- Sender encapsulates:
  `(ciphertext, sharedSecret) = encapsulate(recipientEncapKey)`
- Recipient decapsulates: `sharedSecret = decapsulate(decapKey, ciphertext)`
- The ciphertext must be transmitted alongside the encrypted message
- Encryption is asymmetric: only the sender generates the ciphertext, only the
  recipient can decapsulate it

This means the combined package has a different API shape than `aesgcm-p256dh`.
The encrypt function produces both the KEM ciphertext and the AES ciphertext.
The decrypt function takes both.

### Hybrid approach

For defense-in-depth during the transition, a hybrid package should combine both
P-256 ECDH and ML-KEM. The AES key is derived from both shared secrets (e.g.
`SHA-256(ecdhSecret || kemSecret)`). An attacker must break both P-256 and
ML-KEM to recover the key.

This is the Signal PQXDH approach: combine X25519 (classical) with ML-KEM
(post-quantum) so the scheme is secure against both classical and quantum
attacks.

### Packages to build

1. **`@webbuf/aesgcm-mlkem`** — AES-256-GCM with ML-KEM-768 key encapsulation.
   Pure post-quantum encryption. The sender encapsulates to the recipient's
   ML-KEM encapsulation key, derives an AES key from the shared secret via
   SHA-256, encrypts with AES-GCM. Output is the KEM ciphertext concatenated
   with the AES ciphertext.

2. **`@webbuf/aesgcm-p256dh-mlkem`** — Hybrid: AES-256-GCM with both P-256 ECDH
   and ML-KEM-768. The AES key is derived from both shared secrets:
   `SHA-256(ecdhSecret || kemSecret)`. The sender needs the recipient's P-256
   public key AND ML-KEM encapsulation key. Output is the KEM ciphertext
   concatenated with the AES ciphertext. This is the recommended migration path
   — secure against both classical and quantum attacks.

### API sketch

**`@webbuf/aesgcm-mlkem`:**

```typescript
// Encrypt: encapsulate + AES-GCM encrypt
export function aesgcmMlkemEncrypt(
  recipientEncapKey: FixedBuf<1184>, // ML-KEM-768 encapsulation key
  plaintext: WebBuf,
): WebBuf; // kemCiphertext (1088 bytes) || aesCiphertext (iv + ct + tag)

// Decrypt: decapsulate + AES-GCM decrypt
export function aesgcmMlkemDecrypt(
  decapKey: FixedBuf<2400>, // ML-KEM-768 decapsulation key
  ciphertext: WebBuf, // kemCiphertext || aesCiphertext
): WebBuf;
```

**`@webbuf/aesgcm-p256dh-mlkem`:**

```typescript
// Encrypt: ECDH + KEM + AES-GCM
export function aesgcmP256dhMlkemEncrypt(
  senderPrivKey: FixedBuf<32>, // P-256 private key
  recipientPubKey: FixedBuf<33>, // P-256 public key (compressed)
  recipientEncapKey: FixedBuf<1184>, // ML-KEM-768 encapsulation key
  plaintext: WebBuf,
): WebBuf; // kemCiphertext (1088 bytes) || aesCiphertext

// Decrypt: ECDH + decapsulate + AES-GCM
export function aesgcmP256dhMlkemDecrypt(
  recipientPrivKey: FixedBuf<32>, // P-256 private key
  senderPubKey: FixedBuf<33>, // P-256 public key
  decapKey: FixedBuf<2400>, // ML-KEM-768 decapsulation key
  ciphertext: WebBuf, // kemCiphertext || aesCiphertext
): WebBuf;
```

### Key derivation

For the hybrid scheme, the AES-256 key is derived as:

```
aesKey = SHA-256(ecdhSecret || kemSharedSecret)
```

Where `ecdhSecret` is the P-256 ECDH shared secret (32 bytes, already SHA-256
hashed per the existing `aesgcm-p256dh` pattern) and `kemSharedSecret` is the
ML-KEM-768 shared secret (32 bytes).

For the pure ML-KEM scheme:

```
aesKey = SHA-256(kemSharedSecret)
```

The raw-SHA-256-of-concatenated-secrets approach matches the existing
`@webbuf/aesgcm-p256dh` pattern but is informal compared to the IETF/NIST
standard combiners (HKDF-SHA-256 with explicit info/salt strings, per RFC 5869,
NIST SP 800-56C, and `draft-ietf-tls-hybrid-design`). Experiment 1 will settle
this before implementation rather than locking in a possibly non-standard key
schedule.

## Constraints

### Synchronous WASM model

The new packages must fit WebBuf's existing model: synchronous Rust → WASM →
base64-inlined → TypeScript. Randomness comes from the platform CSPRNG via
`FixedBuf.fromRandom`, not from a Rust-side RNG. No async initialization, no
top-level await.

### No new Rust crates

These are composition packages, not new primitives. The encrypt/decrypt logic
should live entirely in the TypeScript wrapper, composing existing WebBuf
packages:

- `@webbuf/aesgcm` for symmetric authenticated encryption
- `@webbuf/sha256` (or a new `@webbuf/hkdf-sha256` if Experiment 1 picks HKDF)
  for key derivation
- `@webbuf/p256` for P-256 ECDH (hybrid only)
- `@webbuf/mlkem` for ML-KEM key encapsulation

No `rs/webbuf_aesgcm_mlkem` or similar crate. Adding new primitives in Rust
would be premature — these are pure compositions.

### Standards alignment

The key schedule should match a published standard or near-standard where
practical. Candidates:

- **NIST SP 800-56C Rev. 2** (Two-Step Key Derivation) — extract-then- expand
  using HMAC-SHA-256.
- **RFC 5869 HKDF** — the underlying primitive used by SP 800-56C and the TLS /
  HPKE / PQXDH key schedules.
- **`draft-ietf-tls-hybrid-design`** — concrete combiner for hybrid KEM shared
  secrets in TLS 1.3.
- **Signal PQXDH** — `KDF(DH1 || DH2 || DH3 || DH4 || PQKEM_SS)` using
  HKDF-SHA-256 with a protocol-specific info string.

The choice should not be invented by WebBuf. Experiment 1 will pick one and
justify it.

### Wire format

The output of encryption must be unambiguously parseable. The KEM ciphertext is
fixed-size (1088 bytes for ML-KEM-768), so a simple "first 1088 bytes are KEM
ct, remainder is AES output" rule works for the pure-PQC package. The hybrid
package may need a different framing because the P-256 ephemeral public key (33
bytes) also has to be transmitted.

A version byte at the start (`0x01`) leaves room for future format evolution
without silently corrupting old ciphertexts. Experiment 1 should pin the exact
wire format.

### Backwards compatibility

`@webbuf/aesgcm-p256dh` continues to exist unchanged. The new packages are
additive. KeyPears or any other consumer chooses which to use.

### Out of scope

- **Hybrid signatures.** Combining P-256 ECDSA with ML-DSA in a single
  `@webbuf/p256-mldsa` style package is a separate concern. Encryption and
  signing have different threat models and different upstream primitives. This
  issue covers KEM hybrid only.
- **ML-KEM-512 / ML-KEM-1024 variants.** ML-KEM-768 was chosen in issue 0001
  (Category 3, what Signal PQXDH and Chrome TLS use). Other security levels can
  be added in a follow-up if a consumer needs them; for now the ergonomic
  high-level wrapper targets the recommended parameter set.
- **Other KEMs** (HQC etc.) — defer until those algorithms reach FIPS
  finalization.

### Testing

- **Round-trip:** encrypt + decrypt recovers the plaintext for both packages.
- **Wrong-recipient rejection:** decrypting with the wrong decapsulation key
  fails (via AES-GCM authentication-tag mismatch — the recovered shared secret
  is wrong, so the AES key is wrong, so the GCM tag fails).
- **Tampered KEM ciphertext rejected:** flipping a byte in the KEM ciphertext
  portion causes decapsulation to produce a different shared secret, which then
  fails AES-GCM authentication.
- **Tampered AES ciphertext rejected:** flipping a byte in the AES ciphertext /
  tag portion fails AES-GCM authentication directly.
- **Hybrid security:** for the hybrid package, manually breaking either the ECDH
  shared secret or the KEM shared secret (e.g. by replacing one with random
  bytes during decryption) causes decryption to fail — confirming both shared
  secrets are needed.
- **Wire format stability:** capture a known (recipient key, plaintext,
  randomness) → ciphertext mapping; assert it stays stable across refactors.

## Experiment 1: Pin the hybrid KEM key schedule

### Goal

Decide the key derivation function and wire format for the new packages before
any TypeScript wrapper code is written. Output a concrete specification: which
KDF, which info/salt strings, exactly how the ciphertext is laid out on the
wire, exactly which bytes are concatenated in which order to compute the AES
key.

### Why this experiment first

The Background section's `aesKey = SHA-256(ecdhSecret || kemSecret)` sketch is
informal. Two concrete risks:

1. **Raw SHA-256 of concatenated secrets is not the standard combiner.** IETF
   and NIST standards use HKDF-SHA-256 with explicit info/salt binding. Shipping
   a non-standard combiner now means having to migrate downstream consumers
   later if interop becomes important.
2. **Concatenation order, framing, and version bytes are interface contracts.**
   Decisions made in code without a written spec become harder to change once
   consumers ship.

Settling these in a focused experiment is cheaper than discovering them during
implementation review.

### Questions to answer

- **KDF choice.** HKDF-SHA-256, raw SHA-256 (matching existing `aesgcm-p256dh`),
  or NIST SP 800-56C Two-Step? Trade-offs: standards conformance vs. ecosystem
  consistency vs. complexity.
- **Info/salt strings.** If HKDF, what info / salt provides domain separation?
  Per-package literals like `b"webbuf:aesgcm-mlkem v1"`?
- **Concatenation order.** For the hybrid combiner: ECDH first then KEM, or the
  reverse? IETF `draft-ietf-tls-hybrid-design` and PQXDH both have specific
  orderings — match one of them.
- **Wire format.** Version byte yes/no? Field ordering? Length prefix on
  variable-size pieces?
- **AES-GCM IV strategy.** Random 12-byte IV prepended to the AES ciphertext
  (matching `aesgcm-p256dh`) is the obvious choice. Confirm it's appropriate
  when the AES key is derived per-message from a fresh KEM shared secret.
- **Backwards compatibility with `aesgcm-p256dh`.** If we want the
  pure-classical and hybrid variants to share a key schedule, the hybrid
  combiner has to degrade cleanly when the KEM contribution is fixed/empty.
  Probably not worth doing — the packages are intended to be wire-incompatible —
  but state the decision.

### Method

1. Read the relevant standards/drafts: RFC 5869 (HKDF), NIST SP 800-56C Rev. 2,
   `draft-ietf-tls-hybrid-design`, Signal PQXDH spec.
2. Compare the proposed combiners and pick the one most aligned with WebBuf's
   ecosystem (synchronous, primitive-composing, browser-friendly).
3. Sketch the exact byte-for-byte wire format for both packages.
4. Write the resulting design into this issue as the Plan for the subsequent
   implementation experiments.

### Deliverable

A pinned design including:

- Exact KDF and info/salt strings.
- Exact concatenation order for the hybrid combiner.
- Exact wire format for both packages, with byte offsets.
- A short rationale referencing the standards consulted.
- A note on whether the existing `@webbuf/aesgcm-p256dh` should be considered
  "legacy" or remain the recommended classical option.

### Success criteria

This experiment passes if it produces a wire-format-and-KDF spec detailed enough
that the next experiment can implement `@webbuf/aesgcm-mlkem` without
re-debating any of these questions.

## Plan

Pin the key schedule and wire format first (Experiment 1, above), then build the
packages incrementally. Each experiment is designed, implemented, and concluded
before the next one is designed; outcomes inform what comes next.
