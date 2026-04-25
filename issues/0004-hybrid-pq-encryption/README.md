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

The trailing ` v1` lets us version the schedule independently of the package
version. If we ever revise the KDF, info string, or wire format, we bump to
` v2` and the version byte changes — old ciphertexts decrypt under the old
scheme, new ones under the new.

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

These are intentionally placeholder values. They will be filled in once the
prerequisite `p256SharedSecretRaw` helper exists — the helper is needed both for
the hybrid KAT and for the implementation, so capturing the KAT and adding the
helper happen together.

#### `@webbuf/aesgcm-mlkem` v1 KAT (placeholder)

| Field                 | Value (hex)             |
| --------------------- | ----------------------- |
| ML-KEM-768 d (seed 1) | `_to be captured_`      |
| ML-KEM-768 z (seed 2) | `_to be captured_`      |
| ML-KEM-768 m (encap)  | `_to be captured_`      |
| Plaintext (UTF-8)     | `"hello, post-quantum"` |
| AES-GCM IV            | `_to be captured_`      |
| Output ciphertext     | `_to be captured_`      |

#### `@webbuf/aesgcm-p256dh-mlkem` v1 KAT (placeholder)

| Field                       | Value (hex)        |
| --------------------------- | ------------------ |
| Sender P-256 priv           | `_to be captured_` |
| Recipient P-256 priv        | `_to be captured_` |
| Recipient P-256 pub (33B)   | `_derived_`        |
| Recipient ML-KEM d (seed 1) | `_to be captured_` |
| Recipient ML-KEM z (seed 2) | `_to be captured_` |
| ML-KEM m (encap randomness) | `_to be captured_` |
| Plaintext (UTF-8)           | `"hybrid"`         |
| AES-GCM IV                  | `_to be captured_` |
| Output ciphertext           | `_to be captured_` |

The KAT inputs include all randomness sources (deterministic seeds for keypair
generation, fixed `m` for encapsulation, fixed AES-GCM IV) so the output is
deterministic given the inputs. Experiment 2's implementation will hold these
constant in a test and assert against the captured output.

### Result: Partial

Experiment 1 settled the core design questions but left the classical-side IKM
input under-specified relative to the actual `@webbuf/p256` API. The delta below
summarizes what's pinned and what blocks the upgrade to a clean `Pass`.

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

**Open (blocking promotion to `Pass`):**

1. **`p256SharedSecretRaw` helper** does not yet exist in `@webbuf/p256`. The
   current `p256SharedSecret` returns a 33-byte compressed point. The spec is
   grounded in a 32-byte raw-X-coord input that no current API exposes. Need to
   add the helper (small Rust + TS change) before the hybrid package can be
   implemented to spec.
2. **KAT byte vectors** are placeholders. Capturing them requires the helper
   above (for the hybrid KAT) and a one-shot capture run for the pure-PQ KAT.
   Once captured, Experiment 2 can use them as a test contract.

**Promotion criterion:** Experiment 1 closes as `Pass` when the
`p256SharedSecretRaw` helper has landed in `@webbuf/p256` with tests, and the
two KAT tables above are filled in with concrete hex values. Both items are
mechanical follow-up work; neither requires further design deliberation.
Expected effort: ~1 hour for the helper, ~30 minutes to capture and embed both
KATs.

These two items will be folded into the start of Experiment 2 rather than
spawning a separate experiment, since they're prerequisites for the
implementation work and don't change the design.

## Plan

Pin the key schedule and wire format first (Experiment 1, above), then build the
packages incrementally. Each experiment is designed, implemented, and concluded
before the next one is designed; outcomes inform what comes next.
