+++
status = "closed"
opened = "2026-04-25"
closed = "2026-04-25"
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

### Findings

#### RFC 5869 (HKDF)

Two-step pattern: `HKDF-Extract(salt, IKM) → PRK` (32 bytes, the HMAC-SHA-256
output length) and `HKDF-Expand(PRK, info, L) → OKM`. The `salt` parameter
strengthens the construction by ensuring independence across uses; if absent, a
zero-filled string of HashLen bytes is the documented default. `info` should
bind protocol identifiers and algorithm specifics for domain separation. RFC
5869 does not directly prescribe how to combine multiple shared secrets — that
responsibility falls to higher-level standards.

#### NIST SP 800-56C Rev. 2

Specifies the same Two-Step Key Derivation pattern as HKDF, with HMAC-SHA-256 as
the recommended PRF. WebBuf's `@webbuf/sha256` already exposes HMAC-SHA-256, so
HKDF is implementable in pure TypeScript on top of it (Extract = 1 HMAC call,
Expand for L=32 bytes = 1 HMAC call, total 2 HMAC calls per derivation).

#### `draft-ietf-tls-hybrid-design-16`

Section 3.3 specifies the combiner as **simple concatenation** of the classical
and post-quantum shared secrets, with the concatenated value fed into TLS 1.3's
existing HKDF-Extract stage. Section 3.2 fixes the order: **classical first,
post-quantum second**, matching the NamedGroup definition. No length prefixes;
lengths are fixed once the algorithm is fixed. Tampered-KEM-ciphertext detection
relies on the AEAD authentication tag and the IND-CCA2 properties of the
component KEMs (a tampered KEM ciphertext yields a different shared secret,
which yields a different derived key, which fails AEAD verification).

#### Signal PQXDH

Section 2.2 uses HKDF with a hash parameter (SHA-256 or SHA-512), salt = HashLen
zero bytes, and `info` = a literal ASCII string identifying the protocol, hash,
curve, and KEM (e.g. `"MyProtocol_CURVE25519_SHA-512_CRYSTALS-KYBER-1024"`).
Section 3.3 prepends a 32-byte (or 57-byte) `0xFF` prefix `F` to the IKM:
`IKM = F || (DH1 || DH2 || DH3 || ... || SS)`. DH outputs come first; the KEM
shared secret comes last. Wire format is "implementation defined, must be
unambiguous" — no specific bytes prescribed.

#### Synthesis

Both real-world PQ-hybrid standards (TLS hybrid-design and PQXDH) use
HKDF-SHA-256 and put the classical secret(s) before the PQ secret in the IKM.
They differ on info/salt/prefix conventions because their host protocols differ:

- TLS relies on its own multi-stage key schedule for context binding, so the
  hybrid combiner is bare concatenation feeding into the existing HKDF-Extract
  step.
- PQXDH is its own protocol, so its KDF call carries an explicit
  protocol-identifier `info` string and a `0xFF` prefix `F` (the prefix serves
  the same role in X3DH and is preserved in PQXDH).

WebBuf's combined packages aren't wrapped in a larger protocol that provides
context, so we follow PQXDH's pattern of putting the binding into the HKDF call
directly: explicit `info` string per package, zero-byte salt, classical-first
IKM concatenation. We skip the `0xFF` prefix `F` — it's specific to X3DH/PQXDH's
identity-key authenticated handshake and adds no security to a self-contained
encryption primitive. The `info` string alone provides the domain separation we
need.

The choice to use HKDF (rather than raw SHA-256, which the existing
`@webbuf/aesgcm-p256dh` uses) is driven by interop and standards alignment, not
by a security flaw in raw SHA-256 of concatenated secrets. For a one-shot
encryption with fresh per-message KEM material, both constructions are secure
under standard assumptions. HKDF wins because it's the published standard and
the cost of using it is negligible (2 extra HMAC calls in TypeScript).

### Decision

#### KDF

**HKDF-SHA-256** (RFC 5869), implemented in TypeScript on top of the existing
`@webbuf/sha256` HMAC-SHA-256 primitive. No new Rust crate needed. The
implementation is approximately 20 lines:

```typescript
// Extract: PRK = HMAC-SHA-256(salt, IKM)
const prk = hmacSha256(salt, ikm);
// Expand for L=32: OKM = HMAC-SHA-256(PRK, info || 0x01)[0..32]
const t1 = hmacSha256(prk, concat(info, [0x01]));
const aesKey = t1.slice(0, 32);
```

#### Salt

**32-byte zero salt** (`FixedBuf.alloc(32)`). Matches PQXDH and the RFC 5869
default. Fixed across all WebBuf hybrid-PQ packages.

#### Info strings (per package, exact UTF-8 bytes)

| Package                       | Info string                     |
| ----------------------------- | ------------------------------- |
| `@webbuf/aesgcm-mlkem`        | `webbuf:aesgcm-mlkem v1`        |
| `@webbuf/aesgcm-p256dh-mlkem` | `webbuf:aesgcm-p256dh-mlkem v1` |

The trailing `v1` lets us version the schedule independently of the package
version. If we ever revise the KDF, info string, or wire format, we bump to `v2`
and the version byte changes — old ciphertexts decrypt under the old scheme, new
ones under the new.

#### IKM concatenation order

For `@webbuf/aesgcm-mlkem`:

```
IKM = kemSharedSecret  (32 bytes)
```

For `@webbuf/aesgcm-p256dh-mlkem`:

```
IKM = ecdhSharedSecret || kemSharedSecret  (32 + 32 = 64 bytes)
```

Where:

- `ecdhSharedSecret` is the raw 32-byte X-coordinate produced by P-256 scalar
  multiplication — the SEC1 X9.63 "Z" value used as input to a KDF in NIST SP
  800-56A §5.7.1.2 and the IETF hybrid drafts. **We do not** apply the SHA-256
  hashing that `@webbuf/aesgcm-p256dh` performs internally, and we **do not**
  use the SEC1 compressed-point encoding (33 bytes with a 0x02/0x03 prefix byte)
  that `@webbuf/p256`'s current `p256SharedSecret` returns. Both would be
  WebBuf-specific deviations from how SP 800-56C and
  `draft-ietf-tls-hybrid- design-16` feed IKM.
- `kemSharedSecret` is the 32-byte ML-KEM-768 shared secret returned by
  `decapsulate` / the second element of `encapsulate`'s output.

Classical first, PQ second — matches both TLS hybrid-design and PQXDH.

##### Required prerequisite: `p256SharedSecretRaw` helper

The current `@webbuf/p256` API exposes:

```typescript
export function p256SharedSecret(
  privKey: FixedBuf<32>,
  pubKey: FixedBuf<33>,
): FixedBuf<33>; // SEC1-compressed point: 0x02/0x03 prefix || X-coord (32 bytes)
```

The compressed-point output includes a 1-byte prefix that is deterministic given
the X-coordinate, so it carries no extra entropy and stripping it is a trivial
slice. But for IKM input we want the bare 32-byte X-coordinate, both for
standards conformance and so that any independent implementation of this scheme
produces the same ciphertexts.

Before Experiment 2 can begin, `@webbuf/p256` must expose a new helper:

```typescript
export function p256SharedSecretRaw(
  privKey: FixedBuf<32>,
  pubKey: FixedBuf<33>,
): FixedBuf<32>; // raw X-coordinate (32 bytes), the SEC1 X9.63 Z value
```

The underlying RustCrypto `p256` crate already produces this value before SEC1
encoding (via `elliptic_curve::ecdh::diffie_hellman` returning a `SharedSecret`
whose `.raw_secret_bytes()` is the X-coord). Adding the helper is small: one new
exported function in `rs/webbuf_p256/src/p256_curve.rs` (roughly 10 lines), one
new wasm-bindgen export, and one new TS wrapper.

This work is a prerequisite to Experiment 2 — we'll either land it as a small
preliminary commit before Experiment 2 or fold it into the start of Experiment
2's implementation work. Calling it out explicitly here so the spec is grounded
in an API that exists.

#### AES key length and IV

**AES-256-GCM**, so HKDF-Expand outputs L=32 bytes for the AES key.

**12-byte random IV** per encryption, generated via `FixedBuf.fromRandom(12)`,
prepended to the AES-GCM ciphertext. Matches `@webbuf/aesgcm-p256dh`'s existing
convention. Since the AES key itself is fresh per message (derived from the
unique-per-message KEM shared secret), the IV uniqueness requirement is
automatically satisfied; the random IV is defense-in-depth.

#### Wire format

##### `@webbuf/aesgcm-mlkem` (scheme byte `0x01`)

| Offset   | Length | Field                                                    |
| -------- | ------ | -------------------------------------------------------- |
| 0        | 1      | Version byte: `0x01`                                     |
| 1        | 1088   | ML-KEM-768 ciphertext (fixed)                            |
| 1089     | 12     | AES-GCM IV (fixed)                                       |
| 1101     | N      | AES-GCM ciphertext (variable, equal to plaintext length) |
| 1101 + N | 16     | AES-GCM authentication tag (fixed)                       |

Total fixed overhead: **1117 bytes** per message.

##### `@webbuf/aesgcm-p256dh-mlkem` (scheme byte `0x02`)

| Offset   | Length | Field                              |
| -------- | ------ | ---------------------------------- |
| 0        | 1      | Version byte: `0x02`               |
| 1        | 1088   | ML-KEM-768 ciphertext (fixed)      |
| 1089     | 12     | AES-GCM IV (fixed)                 |
| 1101     | N      | AES-GCM ciphertext (variable)      |
| 1101 + N | 16     | AES-GCM authentication tag (fixed) |

Total fixed overhead: **1117 bytes** per message.

The hybrid package uses the same wire layout but a different scheme byte
(`0x02`) and a different HKDF IKM (32 + 32 bytes instead of 32). The
classical-side ECDH inputs (`senderPrivKey`, `recipientPubKey`) are out-of-band
— sender and recipient must know each other's persistent P-256 keys, matching
`@webbuf/aesgcm-p256dh`'s static-static pattern. No ephemeral P-256 public key
on the wire; if forward secrecy on the classical side is desired, that's a
separate scheme (likely `@webbuf/aesgcm-p256dhe-mlkem` later).

The version byte doubles as a scheme identifier: feeding a `0x02` ciphertext
into `aesgcmMlkemDecrypt` (which expects `0x01`) fails fast with a clear error
rather than a silent AEAD-tag mismatch.

#### `@webbuf/aesgcm-p256dh` legacy status

Remains unchanged and supported. The new packages are not drop-in replacements;
they have a different KDF, different wire format, and the hybrid variant has
different security properties. Documenting the choice as a deliberate fork
rather than a successor is correct.

### Test vectors

A complete spec needs at least one byte-level known-answer test vector per
package, captured at this stage and embedded here as the contract that
Experiment 2's implementation must reproduce. Without KATs, "implementable
without re-debating" leaves room for an implementer to interpret the spec in a
way that diverges from intent.

The KATs below were generated by
`ts/npm-webbuf/scripts/capture-issue-0004-kats.ts`, which uses only the existing
WebBuf primitives (`@webbuf/mlkem`, `@webbuf/p256` with the new
`p256SharedSecretRaw` helper, `@webbuf/sha256`'s HMAC, `@webbuf/aesgcm`) plus a
6-line inline HKDF-SHA-256 implementation matching the spec above. Each KAT
records all inputs, key intermediate values, ciphertext length, and SHA-256 of
the full ciphertext as a compact assertion target. Implementation tests assert
that `sha256Hash(ciphertext).toHex()` matches the captured hash; mismatch means
divergence from the spec.

#### `@webbuf/aesgcm-mlkem` v1 KAT

| Field                 | Value (hex)                                                        |
| --------------------- | ------------------------------------------------------------------ |
| ML-KEM-768 d (seed 1) | `0000000000000000000000000000000000000000000000000000000000000000` |
| ML-KEM-768 z (seed 2) | `1111111111111111111111111111111111111111111111111111111111111111` |
| ML-KEM-768 m (encap)  | `2222222222222222222222222222222222222222222222222222222222222222` |
| Plaintext (UTF-8)     | `"hello, post-quantum"`                                            |
| Plaintext (hex)       | `68656c6c6f2c20706f73742d7175616e74756d`                           |
| AES-GCM IV            | `333333333333333333333333`                                         |
| ML-KEM sharedSecret   | `14da7607fb7793b34534cd5adfba9db862a2eb8b4599462809c1354f07aeedef` |
| Derived AES key       | `7222f04bc5e90a65248eaf8f9401d2813843fa33bd6aa7444248b684a88bbed1` |
| Ciphertext length     | 1136 bytes                                                         |
| SHA-256(ciphertext)   | `680beaa6d06d2324db4bf1545814f85fcc5f60ca7790ed5702779f497f8ef240` |

Full ciphertext (hex, 2272 chars):

```
012afd05db59114a15615e8a2fcd9a9621836cffdecec7736f58fbe67ddf314e55ae2e428
5f09ce2a6ccb06a7f4c36708559165e6a6b0d28cb457087b26fdd86fef9c3eaf7148eb3a7
31980d5990562e61790a51b751422bc7ea8a97ec7e3d3b94562ee7323a59e78888af8386d
0ace205d1c08896b047ffef2866fd6fd774ef5d2358e8750bf6301683cc972d1240abf035
c3fc7d6161c08bae98475b462cefa6d7e1e0604aa84279f41b8ed2ff1455dc640c23d7470
dba0b3473ea504bd1a8807f13a83f233c5a2398e5eb122312964c018404a7b9e9e9c18fe6
51b2f0c6a6352d0d9ecb0dbdeabbc02a10f074999df109e8b9eaa5b8357590b3e77ee834d
717fb054e097e4d860a813dbdd98fc8c79dbbb0e43484e7169369197a58bbdbd59fd9b289
070088958f90bba7e1044b170870415c33907cf388472b89c93503e72c905e9fd409dcf73
c2e8f89c2c5199645635fc9ee9b57354649470340ae3bc23bedc4c5b80ba3ced3b778c108
61dcd5737399faafe39b4e1d0bccc4875879d69905db22dbcc8198e54a0c07fbd7ce61c5c
e9b73251d6bb91f3596ce790741b7eab0f86e80fa8d917d0abbeee12cec328636d8db2c39
9d6915cd606ef35f59b1530f2b464771ea791e2a739389ef98236d8ac6bd88d8c92267a80
e223b483542368231a077188562c7559b95bad3af4551065435f2554159d45c47f3955b66
baf47e0c306070b6c9554b7fceefde54476be76c43b6779300ca0f87ab88e5a3af483e86f
e99411b3b9638f2f86715b7763cb7934e748b2db657cf167129b23eb902f1299e3da6f220
7cc879e1b16f26f202847be504c69950e8a68cdb8d362769bb7a1958e628b02df1a51fd13
5592a8ca0a825c426706cc0e9110c9305d47f178f3749bdc9a39fa124e0821ca3282a7c71
8319dca738cc1aa714a111bf117f4ca8f16edaf2ab8077c28f924da144ac42ac0c2585ed4
6e63ef6fd8c107f6e5832c3ea92261a0df3134107811e3804c54f13772c88e1d60d133d0a
f28d053a44dc2a04fbeab80c2fa2c94738850cc5799fda8758d0f79d0361f309dd97ec73f
18e221424695d1a4a4594914912b129d049293eb0acebf4c7cf8f6e42b67a7037bfe73e12
b0ffbce8547f316665a1609bb12c57a9c3de911301a2fcf394c588b6fc9dc37a67b6e5fd6
d3ed5ab30330a7a985680c5dea5974c008f0537c9ca20e22f68b2687e74abd1d1975ef52f
16c8c0ca0b905983adfbd186aa91dc8893badf6e29792a689504cfd133f6cb4725c3dd8db
ae9d0c8e305d49b5f68abb41f9af6fa5dca816fa99e280c3c21a8c28e7bdb0f1aafdeb4ea
e5880a62a2e07f59b7bfe004b3c1a3f3ce9407c78782a3b08ff2a5f445fe28e3ed0b85569
e72953485d6f4d6c7e59cff0dc3c250a9bbbc8a2b084b1dac36759118ed180c1e73404fc3
73eb365f1d31c364663b72ff6cdba98f642a64c51210f5fb7d8fc62460cb9268fe61f4ad3
de7a64906ff16ba082a0a84c61054dec384df44d3dc8ae83cb03c649039e2333333333333
3333333333334ad627950b83d0a3e55d9005b60bae98a820de56568833e51c0e3cfa32ea9
58d314bcc
```

#### `@webbuf/aesgcm-p256dh-mlkem` v1 KAT

| Field                       | Value (hex)                                                          |
| --------------------------- | -------------------------------------------------------------------- |
| Sender P-256 priv           | `4444444444444444444444444444444444444444444444444444444444444444`   |
| Recipient P-256 priv        | `5555555555555555555555555555555555555555555555555555555555555555`   |
| Recipient P-256 pub (33B)   | `0257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34` |
| Recipient ML-KEM d (seed 1) | `6666666666666666666666666666666666666666666666666666666666666666`   |
| Recipient ML-KEM z (seed 2) | `7777777777777777777777777777777777777777777777777777777777777777`   |
| ML-KEM m (encap randomness) | `8888888888888888888888888888888888888888888888888888888888888888`   |
| Plaintext (UTF-8)           | `"hybrid"`                                                           |
| Plaintext (hex)             | `687962726964`                                                       |
| AES-GCM IV                  | `999999999999999999999999`                                           |
| ECDH raw X-coordinate       | `f05172058ca0efd6258338b6d64a4efaf0ecf7e65e9d6c51337e3aa3017dc7ed`   |
| ML-KEM sharedSecret         | `9ad302f203e4c31efbda3b1e1030407ff89ecb8e20500d093636558983675870`   |
| Derived AES key             | `5d77954fa6f4f074f2dfa01f392538e620f096a9079c1bf7566416cab7fcaacc`   |
| Ciphertext length           | 1123 bytes                                                           |
| SHA-256(ciphertext)         | `c689ccce3ad0194c00377441af4f89c4d8aa48f530b451216e7b26f566a02b6d`   |

Full ciphertext (hex, 2246 chars):

```
02dbfdf2752836f80974a7b95a15126887e7955179e25633619f73f7705e49163b0b8e7fc5
669f5570e97c3622cf5686f4d4ab6e57823ab60e123ac42be124f06becc4008a801da2aed7
f5178733c98651e86fdc3788df13c28bf200463af2a551ccc9fc5fcc5cbf92b5f5c3466dea
91935812e2193540d50a426f0d5e1d3a9bd21b4096ed0a675e52f44ebcfbcae1ca887c8ace
f241a56ed6a3d13862d288444eae1b8da0c4de254d27a27e4a6b631976ffc7e6099b1c0d6e
a7efff3aae1d996838f3d1b81ba27356afb9419620c42ab6531b172d0d9fb4ccc7da98edb9
3aeb10f04930a03eff99b0062df1270e033ec058a19ce31fdd263faceebd7522ddda35a11c
183bdc83f08944bdb6a22719b1f94be981d66527d86e65570568bbd2d3e20405cc2fa0025f
d536bcc3f98f3c4897682cb3e0bfaac6e822c089ba69690041cec8a9c5258a8e9cd6552973
34f2befbef1dca5910158db0023f7131d4287a83e7ee54e6a8128488f8ec8a1081086e7379
0b65879e953aa94c92c598cbefdc47672238960521a430718a07e655d9b3ca2ea7205729a2
04fc820f6f8bdaf2338080338a5bb8b66c84372c093009bc2cbda9f7c0dcefb6ae102bcb7d
a9b1955bd8dabe439bd75b3f62800d557d7022dbc47d1f9abec92d441b9a0f313cdaf5be1e
4a60c5922d825db463c997715d2aca0e206396d60fe0fcbf3dd78cf2fa3efa03c906af58c8
3fa11d3633878b837c21e1385c6e5798a086652da86dc6ebec43fae09ff222951c36446c56
d44ffaaf0b9821eb3f92a8229f8b1500e02187c6b1391731ba4029724f810ee4dc771f968e
d3164f90521294c914b3d8ed3d8a93005b9a1df341574c1c61ec5af8ff6b18d39b411d5919
e52382ff7abe4022926ed73025f649ab66e860ac7af4019d5097fced1870f0c627f362b3a9
c05521a8220cb575aaccf6086aaa57c3a238b111044481d3a52d9e637cc57a18246e5313d9
9404fee56ff86dca1a11d69de027a81de8d59854011f1fab8b7fdef4865d661ea220a6dfed
3e9d28f4b7f96a8f2003ef9a5dd6873ca3fb3d1ee063f11c4064cfd8a37f33287f2e725daf
eb9134fb0c114022e80fa14c542d4a45db4c11f535334ee1a1e85079599fd26227ec78b10c
970dc8f6d3017406db0cf28c472ef940422aa47117d58dc1f52e652c18e1f13265f48a1b92
e613828ceb7cdaeab965c22ea521067de6fd66dab63487ea07c267da2c32e37ccf2391b69f
4b6e15dbf2801d75b4196c7d8870868b7dc441c2eb4f796270597f8d3635569d0c1d7577fc
0043d9fb2d0a15cc8941972dbe4b327d3f6c0aec7d9bf224cb3d84238fa2002bfd37a1137e
e231999679a18c8f0fde0f5e4230237313c3d02256410c17823f8cbee08c2544e4fc303ed9
56fffd310ab2c759c1f5551986744f9844337ca400c013ce947a09de2f6020e833bf3b122c
02d000c160ce3dcb5a4e9401b998e703be2bea7d1e51c21cf4928ae97def64629470d81bd7
1de56cf1e4af734c6b3d9e394a943c3d99999999999999999999999918f6813d48eb540332
36aa7140cdea40b1e77bbc1418
```

The KAT inputs are all-deterministic — every randomness source is fixed — so the
output is fully reproducible. The capture script is preserved at
`ts/npm-webbuf/scripts/capture-issue-0004-kats.ts` for re-derivation if anything
in the dependency chain needs to be re-validated.

### Result: Pass

Experiment 1 produced a complete, byte-precise spec backed by working
prerequisite code and concrete known-answer vectors. The next experiment can
implement `@webbuf/aesgcm-mlkem` directly from this issue with no remaining
design questions.

**Pinned:**

- **HKDF-SHA-256** (RFC 5869, NIST SP 800-56C Rev. 2) — implementable in
  TypeScript over `@webbuf/sha256`'s HMAC primitive.
- **Zero salt** (32 bytes), **per-package info string** with `v1` suffix —
  PQXDH-style domain separation.
- **Classical-first IKM concatenation** — matches TLS hybrid-design and PQXDH.
- **IKM input shape:** raw 32-byte ECDH X-coordinate (NOT the SEC1-compressed
  33-byte form, NOT the existing `aesgcm-p256dh`'s pre-hashed value),
  concatenated with the 32-byte ML-KEM shared secret.
- **AES-256-GCM** with 32-byte HKDF-Expand output and **random 12-byte IV** per
  encryption — matches existing `@webbuf/aesgcm-p256dh`.
- **Wire format:** version byte (`0x01` or `0x02`) || ML-KEM ciphertext (1088)
  || IV (12) || AES-GCM ct+tag. Total fixed overhead 1117 bytes.
- **Distinct version bytes** for fast scheme-mismatch detection.
- **`@webbuf/aesgcm-p256dh` legacy status:** unchanged, supported, not a
  predecessor.

**Prerequisite landed:**

- **`p256SharedSecretRaw(privKey: FixedBuf<32>, pubKey: FixedBuf<33>) → FixedBuf<32>`**
  added to `@webbuf/p256`. Returns the bare 32-byte ECDH X-coordinate (SEC1
  X9.63 Z value), no SHA-256 hashing, no SEC1 prefix. Three Rust tests + two
  TypeScript tests cover the helper: cross-implementation equivalence with
  `p256SharedSecret`, symmetry across the two parties, input validation. WASM
  rebuilt; full p256 test suite (55 tests including 48 ACVP-style audit vectors)
  green.

**KATs captured:**

- Two byte-precise known-answer test vectors (one per package) embedded above
  with all inputs, intermediate values, ciphertext lengths, and SHA-256 of the
  full ciphertext. Generated by
  `ts/npm-webbuf/scripts/capture-issue-0004-kats.ts` — committed with this
  experiment so the derivation is reproducible.

**Verification:**

- `cargo test -p webbuf_p256 --release` — 23 Rust tests pass (3 new for
  `shared_secret_raw`).
- `pnpm test` in `ts/npm-webbuf-p256` — 55 tests pass (2 new).
- `pnpm exec tsx scripts/capture-issue-0004-kats.ts` in `ts/npm-webbuf` — KAT
  outputs match the values embedded in this issue.

The next experiment is `@webbuf/aesgcm-mlkem`. Build it first because it's the
simpler of the two packages and validates the HKDF helper, the wire format, and
the test infrastructure before the hybrid combiner adds a second moving piece.

## Experiment 2: Implement `@webbuf/aesgcm-mlkem`

### Goal

Build the pure-PQC encryption package per the Experiment 1 spec. Ship a
TypeScript-only package that takes an ML-KEM-768 encapsulation key and a
plaintext, performs ML-KEM encapsulation + HKDF-SHA-256 key derivation +
AES-256-GCM encryption, and produces a wire format matching the captured KAT
byte-for-byte.

### Why this experiment is small and well-defined

All the design questions were settled in Experiment 1:

- KDF, salt, info string, IKM shape (just `kemSharedSecret` for the pure-PQ
  package), AES key length, IV strategy, wire format, version byte — all pinned
  with concrete byte values.
- The KAT (`SHA-256(ciphertext) = 680beaa6…8ef240`) is the load-bearing test
  contract. If the implementation produces a different hash for the same inputs,
  something has diverged.
- The composition primitives (`@webbuf/mlkem`, `@webbuf/sha256`,
  `@webbuf/aesgcm`) all exist and the capture script demonstrates that the spec
  composes through them correctly.

The implementation is therefore straightforward and the test bar is unambiguous.

### Plan

#### Package scaffold

Create `ts/npm-webbuf-aesgcm-mlkem/` mirroring the existing TypeScript-only
package layout (e.g. compare against an existing TS-only package; if there isn't
one, follow the structure of the WASM packages but omit `build-inline-wasm.ts`,
`sync:from-rust`, `build:wasm`, and the `src/rs-*-bundler` /
`src/rs-*-inline-base64` directories).

Required files:

- `package.json` with peer deps on `@webbuf/webbuf`, `@webbuf/fixedbuf`,
  `@webbuf/mlkem`, `@webbuf/sha256`, `@webbuf/aesgcm`. No Rust deps.
- `tsconfig.json` and `tsconfig.build.json` matching the conventions in the
  other packages.
- `vitest.config.ts` (default).
- `LICENSE` (copy from another package).
- `README.md` documenting:
  - Preferred high-level API (one encrypt + one decrypt function).
  - Wire format byte-offset table (copy from issue 0004).
  - Reference to issue 0004 and FIPS 203 / RFC 5869 / NIST SP 800-56C.
  - Audit-posture caveat (no public audit of any Rust PQC crate).

#### Internal HKDF helper

Inside `src/hkdf.ts` (or inlined in `src/index.ts` if small enough):

```typescript
// HKDF-SHA-256 (RFC 5869) for output length L = 32 bytes.
// Implements Extract + Expand in two HMAC-SHA-256 calls.
export function hkdfSha256L32(
  salt: FixedBuf<32>,
  ikm: WebBuf,
  info: WebBuf,
): FixedBuf<32> {
  const prk = sha256Hmac(salt.buf, ikm);
  const t1Input = WebBuf.concat([info, WebBuf.fromArray([0x01])]);
  return sha256Hmac(prk.buf, t1Input);
}
```

Constants:

```typescript
const ZERO_SALT = FixedBuf.alloc(32);
const INFO = WebBuf.fromUtf8("webbuf:aesgcm-mlkem v1");
const VERSION = 0x01;
const KEM_CT_SIZE = 1088;
const IV_SIZE = 12;
const TAG_SIZE = 16;
const FIXED_OVERHEAD = 1 + KEM_CT_SIZE + IV_SIZE + TAG_SIZE; // 1117
```

#### Public API

```typescript
export function aesgcmMlkemEncrypt(
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
): WebBuf;

export function aesgcmMlkemDecrypt(
  decapKey: FixedBuf<2400>,
  ciphertext: WebBuf,
): WebBuf;
```

Encrypt body (~15 lines):

1. `m = FixedBuf.fromRandom<32>(32)`
2. `{ ciphertext: kemCt, sharedSecret } = mlKem768Encapsulate(recipientEncapKey, m)`
3. `aesKey = hkdfSha256L32(ZERO_SALT, sharedSecret.buf, INFO)`
4. `iv = FixedBuf.fromRandom<12>(12)`
5. `aesPart = aesgcmEncrypt(plaintext, aesKey, iv)` // returns iv || ct || tag
6. Return `WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart])`

Note: `aesgcmEncrypt` already prepends the IV to its output, so step 5 gives us
the iv || ct || tag bytes directly. We don't need to manually prepend the IV
again.

Decrypt body (~20 lines):

1. Validate `ciphertext.length >= FIXED_OVERHEAD`. If not, throw.
2. Validate `ciphertext[0] === VERSION` (`0x01`). If not, throw with a clear
   message naming the unexpected version byte.
3. `kemCt = FixedBuf.fromBuf<1088>(1088, ciphertext.subarray(1, 1 + KEM_CT_SIZE))`
4. `aesPart = ciphertext.subarray(1 + KEM_CT_SIZE)` // iv || ct || tag
5. `sharedSecret = mlKem768Decapsulate(decapKey, kemCt)`
6. `aesKey = hkdfSha256L32(ZERO_SALT, sharedSecret.buf, INFO)`
7. `aesgcmDecrypt(aesPart, aesKey)` // also handles iv extraction internally per
   `@webbuf/aesgcm`'s API; verify in implementation.
8. Return the plaintext.

If `aesgcmDecrypt` doesn't handle iv extraction, do it manually:
`iv = aesPart.subarray(0, 12)`, `ctTag = aesPart.subarray(12)`, then pass `iv`
explicitly. Verify the actual API in implementation.

#### Wire it into the umbrella package

Add `@webbuf/aesgcm-mlkem` as a dep in `ts/npm-webbuf/package.json` and
re-export from `ts/npm-webbuf/src/index.ts`.

### Test plan

#### Unit tests (`test/index.test.ts`)

1. **Round-trip with random inputs:** generate a fresh ML-KEM keypair, pick a
   random plaintext, encrypt, decrypt, assert plaintext matches.
2. **Round-trip with empty plaintext:** `WebBuf.alloc(0)` round-trips.
3. **Round-trip with large plaintext:** 64 KiB random buffer round-trips.
4. **Default encryption is non-deterministic:** two calls with the same key +
   plaintext produce different ciphertexts (because `m` and the AES IV are
   randomized).
5. **Wire format size:** ciphertext length is exactly `1117 + plaintext.length`.
6. **Version byte present:** `ciphertext[0] === 0x01`.
7. **Wrong recipient rejected:** encrypt to recipient A, attempt decrypt with
   recipient B's decapsulation key, expect throw (AES-GCM tag mismatch).
8. **Tampered KEM ciphertext rejected:** flip a byte in `ciphertext[1..1089]`,
   expect throw.
9. **Tampered AES ciphertext rejected:** flip a byte in `ciphertext[1101..]`,
   expect throw.
10. **Tampered IV rejected:** flip a byte in `ciphertext[1089..1101]`, expect
    throw.
11. **Wrong version byte rejected:** replace `ciphertext[0]` with `0x02`, expect
    throw with a clear "unexpected version byte" message.
12. **Truncated ciphertext rejected:** truncate to 100 bytes, expect throw.

#### KAT regression (`test/audit.test.ts` or similar)

13. **KAT 1 from Experiment 1:** reproduce the inputs in the issue's
    "`@webbuf/aesgcm-mlkem` v1 KAT" section. Use `mlKem768KeyPairDeterministic`
    and a deterministic `m`. Encrypt with a fixed IV (the test will need a way
    to inject the IV — see below). Assert
    `sha256Hash(ciphertext).toHex() === "680beaa6d06d2324db4bf1545814f85fcc5f60ca7790ed5702779f497f8ef240"`.

The KAT test requires the implementation to expose a way to inject deterministic
randomness, since the public API generates `m` and `iv` internally. Options:

- **Test-only internal export:** export an
  `_aesgcmMlkemEncryptDeterministic(encapKey, plaintext, m, iv)` not documented
  as public API but available for vector tests.
- **Drop the KAT test:** rely solely on round-trip and the capture script's
  external check.

Recommend the test-only export. It's the same pattern `@webbuf/mldsa` uses
(`SignDeterministic` aliases) and lets the implementation prove spec-compliance
against the captured KAT. The exported function is explicitly named with a `_`
prefix or in a separate `internal` module to discourage application use.

### Success criteria

- `pnpm test` passes all unit and KAT tests in `ts/npm-webbuf-aesgcm-mlkem`.
- `pnpm run typecheck` clean.
- `pnpm run build` produces a clean `dist/`.
- Umbrella package re-exports the new functions and `pnpm test` /
  `pnpm run typecheck` in `ts/npm-webbuf` stay green.
- The KAT regression test asserts the exact SHA-256 hash from Experiment 1's
  captured KAT.
- Round-trip works across all three ML-KEM-768 keypairs (random, deterministic,
  and one captured KAT keypair).

### Risks

1. **`@webbuf/aesgcm` API mismatch.** The current `aesgcmEncrypt` prepends the
   IV to its output but `aesgcmDecrypt` may or may not handle IV extraction
   internally. Need to verify during implementation; if not, parse the IV
   manually in our decrypt path.
2. **Type-level FixedBuf size on subarray.** Slicing `ciphertext` to produce a
   `FixedBuf<1088>` requires the right API; if `subarray` returns plain
   `WebBuf`, may need `FixedBuf.fromBuf(1088, ...)` to re-tag. Mechanical.
3. **HKDF info-string encoding.** Must be exactly `"webbuf:aesgcm-mlkem v1"` as
   UTF-8. The capture script uses `WebBuf.fromUtf8` and the KAT matches; the
   implementation must use the same encoding.

### Out of scope for this experiment

- Hybrid encryption (Experiment 3).
- Other ML-KEM security levels (ML-KEM-512, ML-KEM-1024).
- Forward-secrecy variants.
- A standalone `@webbuf/hkdf-sha256` package (defer until a second consumer
  needs it).

### Implementation

Built `ts/npm-webbuf-aesgcm-mlkem/` as a TypeScript-only package — no new Rust
crate, mirroring the layout of `@webbuf/rw` (the only other TS-only package in
the monorepo).

**Source (`src/index.ts`, ~115 lines):**

- 6-line `hkdfSha256L32(salt, ikm, info)` helper using `@webbuf/sha256`'s
  `sha256Hmac`. Two HMAC calls: Extract gives the PRK, Expand gives the L=32
  output (one HMAC iteration, since SHA-256 output already equals L).
- `aesgcmMlkemEncrypt(encapKey, plaintext)` — calls `mlKem768Encapsulate` (which
  generates `m` randomly via `FixedBuf.fromRandom` per `@webbuf/mlkem`'s issue
  0002 high-level API), derives the AES key, encrypts via `aesgcmEncrypt` (which
  generates the IV randomly and prepends it), prepends the version byte and KEM
  ciphertext, returns the assembled `WebBuf`.
- `_aesgcmMlkemEncryptDeterministic(encapKey, plaintext, m, iv)` — same shape
  but takes caller-supplied `m` and `iv` for the KAT regression test.
  Underscore-prefixed name signals "test-only / unsafe for application use".
- `aesgcmMlkemDecrypt(decapKey, ciphertext)` — validates the minimum length and
  version byte, slices out the KEM ciphertext (fixed 1088 bytes) and the AES
  portion (`iv || ct || tag`), decapsulates, derives the AES key, decrypts via
  `aesgcmDecrypt` (which extracts the IV from its input internally — confirmed
  by reading `@webbuf/aesgcm`'s source before scaffolding).
- Exported `AESGCM_MLKEM` constants object with `versionByte`,
  `kemCiphertextSize`, `ivSize`, `tagSize`, `fixedOverhead`, `hkdfInfo`.

**Tests (15 total, all pass):**

- `test/index.test.ts` — 13 unit tests:
  - Round-trip with random / empty / 64 KiB plaintexts.
  - Default encryption is non-deterministic (two consecutive calls produce
    different ciphertexts).
  - Ciphertext length equals `1117 + plaintext.length` for several sizes (0, 1,
    16, 100, 1024, 65535).
  - Ciphertext starts with `0x01`.
  - Wrong recipient (different keypair) throws.
  - Tampered KEM ciphertext, tampered AES ciphertext, tampered IV all throw.
  - Wrong version byte (`0x02`) throws with a `/version byte/` regex match.
  - Truncated ciphertext (100 bytes) throws with `/too short/`.
  - Issue-0004-Experiment-1 KAT seeds produce a usable keypair (sanity check;
    the byte-precise assertion lives in `audit.test.ts`).
- `test/audit.test.ts` — 2 audit tests:
  - **Load-bearing KAT regression:** reproduces Experiment 1's deterministic
    inputs (`d = 0x00..00`, `z = 0x11..11`, `m = 0x22..22`, `iv = 0x33..33`,
    plaintext = `"hello, post-quantum"`), encrypts via
    `_aesgcmMlkemEncryptDeterministic`, asserts
    `sha256Hash(ciphertext).toHex() === "680beaa6...8ef240"`.
  - Asserts the version byte (`0x01`), the KEM ciphertext prefix bytes, and the
    IV at the expected offset (1089).

The KAT regression matched on the first run — implementation matches the spec
byte-for-byte.

**Umbrella package:** added `@webbuf/aesgcm-mlkem` to
`ts/npm-webbuf/package.json`'s peer deps and `export *` from
`ts/npm-webbuf/src/index.ts`. Umbrella `pnpm run typecheck` and
`pnpm run build:typescript` both clean.

**Pipeline gotchas discovered:**

- `@webbuf/aesgcm`'s `aesgcmEncrypt` already prepends the IV to its output
  (`return WebBuf.concat([iv.buf, encrypted])`), so step 5 of the encrypt path
  is a single call — no manual IV prepending needed. Same for `aesgcmDecrypt`:
  it slices the IV from the front of its input. The decrypt path can pass
  `iv || ct || tag` straight through.
- `WebBuf.subarray` returns a `WebBuf` (which extends `Uint8Array`), so feeding
  it back into `FixedBuf.fromBuf(KEM_CT_SIZE, ...)` works cleanly without an
  extra `WebBuf.fromUint8Array` wrap. The wrap is still present for
  explicitness.
- The package has zero `peerDependencies` violations: all five peer deps
  (`webbuf`, `fixedbuf`, `mlkem`, `sha256`, `aesgcm`) are workspace links and
  present in the umbrella tree.

### Result: Pass

- `pnpm run typecheck` clean in `ts/npm-webbuf-aesgcm-mlkem`.
- `pnpm test` reports 15/15 tests pass:
  ```
  ✓ test/audit.test.ts  (2 tests) — KAT regression matches
  ✓ test/index.test.ts (13 tests) — round-trip, rejection, invariants
  ```
- `pnpm run build` produces a clean `dist/`.
- Umbrella `pnpm run typecheck` and `pnpm run build:typescript` clean.
- KAT SHA-256 matches Experiment 1's captured value
  (`680beaa6d06d2324db4bf1545814f85fcc5f60ca7790ed5702779f497f8ef240`)
  byte-for-byte on the first run — implementation faithfully matches the spec.

The pure-PQ encryption package is shippable. The next experiment builds
`@webbuf/aesgcm-p256dh-mlkem` using the same scaffold plus the hybrid IKM
(classical X-coord || KEM shared secret) and a different version byte (`0x02`)
and info string (`webbuf:aesgcm-p256dh-mlkem v1`).

## Experiment 3: Implement `@webbuf/aesgcm-p256dh-mlkem`

### Goal

Build the hybrid classical+PQC encryption package per Experiment 1's spec,
combining P-256 ECDH and ML-KEM-768 shared secrets into a single AES key via
HKDF-SHA-256. The hybrid scheme is the recommended migration path: an attacker
must break **both** P-256 and ML-KEM to recover the AES key, so the package is
secure against both classical adversaries (today's threat) and quantum
adversaries (the harvest-now-decrypt-later threat).

### Why this experiment is mostly mechanical

Experiment 2 validated the scaffold pattern, the HKDF helper, the wire format,
and the test infrastructure. Experiment 1 captured a byte-precise KAT
(`SHA-256(ciphertext) = c689ccce...a02b6d`) that the implementation must
reproduce. The deltas from Experiment 2 are small and well-defined:

| Aspect           | aesgcm-mlkem (Exp 2)       | aesgcm-p256dh-mlkem (Exp 3)                        |
| ---------------- | -------------------------- | -------------------------------------------------- |
| Version byte     | `0x01`                     | `0x02`                                             |
| HKDF info string | `"webbuf:aesgcm-mlkem v1"` | `"webbuf:aesgcm-p256dh-mlkem v1"`                  |
| IKM              | `kemSharedSecret` (32B)    | `ecdhRawX \|\| kemSharedSecret` (64B)              |
| Encrypt arity    | `(encapKey, plaintext)`    | `(senderPriv, recipientPub, encapKey, plaintext)`  |
| Decrypt arity    | `(decapKey, ciphertext)`   | `(recipientPriv, senderPub, decapKey, ciphertext)` |
| Wire format      | identical layout           | identical layout, different version byte           |
| KAT to assert    | `680beaa6...8ef240`        | `c689ccce...a02b6d`                                |

Everything else — package layout, HKDF helper, AES-GCM composition, test
structure — copies directly from Experiment 2.

### Plan

#### Package scaffold

Create `ts/npm-webbuf-aesgcm-p256dh-mlkem/` mirroring
`ts/npm-webbuf-aesgcm-mlkem/`. One additional peer dep: `@webbuf/p256`
(workspace).

#### Constants and helpers

```typescript
const VERSION = 0x02;
const KEM_CT_SIZE = ML_KEM_768.ciphertextSize; // 1088
const IV_SIZE = 12;
const TAG_SIZE = 16;
const FIXED_OVERHEAD = 1 + KEM_CT_SIZE + IV_SIZE + TAG_SIZE; // 1117

const ZERO_SALT = FixedBuf.alloc(32);
const INFO = WebBuf.fromUtf8("webbuf:aesgcm-p256dh-mlkem v1");
```

The `hkdfSha256L32` helper is identical to Experiment 2's. Future refactor
opportunity: extract to a shared internal module. For now duplicate the 6 lines
— composition over premature abstraction.

#### Public API

```typescript
export function aesgcmP256dhMlkemEncrypt(
  senderPrivKey: FixedBuf<32>,
  recipientPubKey: FixedBuf<33>,
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
): WebBuf;

export function aesgcmP256dhMlkemDecrypt(
  recipientPrivKey: FixedBuf<32>,
  senderPubKey: FixedBuf<33>,
  decapKey: FixedBuf<2400>,
  ciphertext: WebBuf,
): WebBuf;
```

Encrypt body (~18 lines):

1. `ecdhRaw = p256SharedSecretRaw(senderPrivKey, recipientPubKey)` — 32 bytes.
2. `{ ciphertext: kemCt, sharedSecret: kemSS } = mlKem768Encapsulate(recipientEncapKey)`.
3. `ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf])` — 64 bytes.
4. `aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO)`.
5. `aesPart = aesgcmEncrypt(plaintext, aesKey)` — random IV prepended
   internally.
6. Return `WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart])`.

Decrypt body (~22 lines):

1. Validate length and version byte (`0x02`).
2. Slice out `kemCt`, then `aesPart`.
3. `ecdhRaw = p256SharedSecretRaw(recipientPrivKey, senderPubKey)`.
4. `kemSS = mlKem768Decapsulate(decapKey, kemCt)`.
5. `ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf])`.
6. `aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO)`.
7. `aesgcmDecrypt(aesPart, aesKey)`.

Test-only
`_aesgcmP256dhMlkemEncryptDeterministic(senderPriv, recipientPub, encapKey, plaintext, m, iv)`
for the KAT regression.

### Tests

#### Unit tests (`test/index.test.ts`)

1. Round-trip with random plaintext (small, empty, 64 KiB).
2. Default encryption is non-deterministic.
3. Ciphertext length equals `1117 + plaintext.length`.
4. Version byte is `0x02`.
5. **Wrong recipient ML-KEM key** (different decapKey) fails.
6. **Wrong recipient P-256 key** (decrypter uses wrong privKey) fails.
7. **Wrong sender P-256 key** (decrypter uses wrong senderPub) fails.
8. Tampered KEM ciphertext rejected.
9. Tampered AES ciphertext rejected.
10. Tampered IV rejected.
11. Wrong version byte (`0x01` from a sibling-package ciphertext) rejected.
12. Truncated ciphertext rejected.

#### Hybrid defense-in-depth test

13. **Both shared secrets are load-bearing.** Encrypt with the correct inputs.
    Then attempt to decrypt with a derivative-but-wrong setup: keep the KEM
    keypair right but swap to a different sender P-256 keypair. Confirm the
    decrypt fails. This proves the ECDH contribution actually feeds into the key
    — if the implementation accidentally only used `kemSS` as IKM (forgetting
    the ECDH part), this test would still succeed and we'd have shipped a
    non-hybrid masquerading as a hybrid. The test catches that bug class.

#### KAT regression (`test/audit.test.ts`)

14. Reproduce Experiment 1's hybrid KAT inputs:
    - sender P-256 priv = `0x44 * 32`
    - recipient P-256 priv = `0x55 * 32` (recipient pub derived)
    - ML-KEM seeds d/z = `0x66 * 32` / `0x77 * 32`
    - ML-KEM m = `0x88 * 32`
    - AES IV = `0x99 * 12`
    - plaintext = `"hybrid"`

    Encrypt via `_aesgcmP256dhMlkemEncryptDeterministic`. Assert
    `sha256Hash(ciphertext).toHex() === "c689ccce3ad0194c00377441af4f89c4d8aa48f530b451216e7b26f566a02b6d"`
    and `ciphertext.length === 1123`.

### Wire into umbrella

Add `@webbuf/aesgcm-p256dh-mlkem` to `ts/npm-webbuf/package.json` peer deps and
`export *` from `ts/npm-webbuf/src/index.ts`.

### Success criteria

- `pnpm test` passes all 14 tests in `ts/npm-webbuf-aesgcm-p256dh-mlkem`.
- KAT SHA-256 matches `c689ccce...a02b6d` byte-for-byte.
- `pnpm run typecheck` and `pnpm run build` clean in the new package.
- Umbrella `pnpm run typecheck` and `pnpm run build:typescript` clean.

After this experiment passes, issue 0004 is complete and can be closed with a
top-level Conclusion summarizing the two new packages, the spec they implement,
and the captured test vectors.

### Implementation

Built `ts/npm-webbuf-aesgcm-p256dh-mlkem/` mirroring the `@webbuf/aesgcm-mlkem`
scaffold from Experiment 2, with one additional peer dep on `@webbuf/p256` and
the hybrid IKM logic. About 130 lines of TypeScript total.

The encrypt path computes the raw 32-byte ECDH X-coordinate via
`p256SharedSecretRaw` (the helper landed in Experiment 1's prerequisite work),
encapsulates a fresh ML-KEM-768 shared secret, concatenates the two as IKM
(`ecdhRaw || kemSS`, 64 bytes total), derives the AES-256 key via the same
HKDF-SHA-256 helper used in Experiment 2 — but with the hybrid info string
`webbuf:aesgcm-p256dh-mlkem v1` — and encrypts with AES-GCM. The wire format
uses version byte `0x02` so a stray `@webbuf/aesgcm-mlkem` ciphertext (which
uses `0x01`) is rejected clearly rather than silently failing AES-GCM
authentication.

The HKDF helper is duplicated from `@webbuf/aesgcm-mlkem` (6 lines — not worth a
shared package yet; revisit if a third consumer appears).

### Result: Pass

**Tests:** 19/19 pass on the first run.

```
✓ test/audit.test.ts (3 tests) — KAT regression matches
✓ test/index.test.ts (16 tests) — round-trip, rejection, hybrid defense
```

The 16 unit tests cover round-trip across plaintext sizes (small, empty, 64
KiB), wire-format invariants (length, version byte), non-determinism, and seven
rejection paths: wrong recipient ML-KEM key, wrong recipient P-256 priv, wrong
sender P-256 pub, tampered KEM ciphertext, tampered AES ciphertext, tampered IV,
wrong version byte, truncation. Plus two **hybrid defense-in-depth tests** that
explicitly verify both shared secrets are load-bearing — one breaks only the
ML-KEM contribution and confirms decryption fails, the other breaks only the
P-256 contribution and confirms decryption fails. If the implementation
accidentally fed only one secret as IKM, one of these tests would catch it.

The 3 audit tests reproduce Experiment 1's deterministic hybrid KAT inputs
(`senderPriv = 0x44 * 32`, `recipientPriv = 0x55 * 32`, ML-KEM seeds `0x66 * 32`
/ `0x77 * 32`, encap rand `0x88 * 32`, IV `0x99 * 12`, plaintext `"hybrid"`) and
assert
`sha256Hash(ciphertext).toHex() === "c689ccce3ad0194c00377441af4f89c4d8aa48f530b451216e7b26f566a02b6d"`
— matched on the first run, byte-for-byte. The recipient public key derivation
also matches the captured value
(`0257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34`), and the
wire-format prefix bytes (KEM ct prefix, IV at offset 1089) match the captured
ciphertext.

**Build:**

- `pnpm run typecheck` clean.
- `pnpm run build` produces a clean `dist/`.
- Umbrella `pnpm run typecheck` and `pnpm run build:typescript` clean.

Both PQC encryption packages are now shippable.

## Conclusion

Issue 4 is complete. WebBuf now exposes high-level post-quantum authenticated
encryption packages alongside the classical `@webbuf/aesgcm-p256dh`:

- **`@webbuf/aesgcm-mlkem`** — pure post-quantum encryption with ML-KEM-768 +
  AES-256-GCM, version byte `0x01`.
- **`@webbuf/aesgcm-p256dh-mlkem`** — hybrid classical + post-quantum encryption
  combining P-256 ECDH with ML-KEM-768, version byte `0x02`. Recommended for
  transitional deployments.

Both packages share a single design pinned in Experiment 1:

- HKDF-SHA-256 (RFC 5869, NIST SP 800-56C Rev. 2) for key derivation, with a
  32-byte zero salt and a per-package info string carrying domain separation and
  a `v1` version suffix.
- AES-256-GCM with random 12-byte IV per encryption — the AES key is fresh per
  message because the underlying KEM shared secret is.
- Wire format: version byte || ML-KEM-768 ciphertext (1088) || IV (12) ||
  AES-GCM ciphertext + tag, with 1117 bytes of fixed overhead per message.

The hybrid package's IKM concatenates the raw 32-byte P-256 ECDH X-coordinate
with the 32-byte ML-KEM shared secret in classical-first order, matching the
conventions of `draft-ietf-tls-hybrid-design-16` and Signal PQXDH. An attacker
must break both P-256 and ML-KEM to recover the AES key, providing defense in
depth during the post-quantum transition.

Both KATs are embedded byte-for-byte in this issue — full ciphertext hex,
intermediate values, and SHA-256 assertion targets — so an independent
implementation can verify spec conformance from the issue alone. The capture
script lives at `ts/npm-webbuf/scripts/capture-issue-0004-kats.ts` for
re-derivation.

A new helper `p256SharedSecretRaw` was added to `@webbuf/p256` along the way,
exposing the bare ECDH X-coordinate (the SEC1 X9.63 Z value) for
standards-compliant KDF input. It's the recommended ECDH-output helper for any
future package building on top of `@webbuf/p256` that feeds into HKDF.

The umbrella `webbuf` package re-exports both new packages, so
`import { aesgcmMlkemEncrypt, aesgcmP256dhMlkemEncrypt } from "webbuf"` works.

WebBuf's post-quantum suite is now complete:

| Package                       | Algorithm                     | Type                 |
| ----------------------------- | ----------------------------- | -------------------- |
| `@webbuf/mlkem`               | ML-KEM (FIPS 203)             | KEM primitive        |
| `@webbuf/mldsa`               | ML-DSA (FIPS 204)             | Signature primitive  |
| `@webbuf/slhdsa`              | SLH-DSA (FIPS 205)            | Hash-based signature |
| `@webbuf/aesgcm-mlkem`        | AES-GCM + ML-KEM              | Pure-PQ encryption   |
| `@webbuf/aesgcm-p256dh-mlkem` | AES-GCM + P-256 ECDH + ML-KEM | Hybrid encryption    |

Downstream consumers like KeyPears now have a complete post-quantum-ready
encryption story available as TypeScript primitives.
