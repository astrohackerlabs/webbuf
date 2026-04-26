# @webbuf/ed25519

Ed25519 PureEdDSA digital signatures (RFC 8032) for WebBuf, optimized with
Rust/WASM.

Ed25519 is the standard signature primitive used by Signal, OpenSSH, OpenPGP,
age, Tor, and increasingly Web PKI. It pairs with `@webbuf/x25519` for ECDH and
with `@webbuf/mldsa` for post-quantum hybrid signatures.

## Installation

```bash
npm install @webbuf/ed25519
```

## Usage

```typescript
import {
  ed25519PublicKeyCreate,
  ed25519Sign,
  ed25519Verify,
} from "@webbuf/ed25519";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Each party generates a 32-byte seed and derives the public key.
const priv = FixedBuf.fromRandom<32>(32);
const pub = ed25519PublicKeyCreate(priv);

// Sign a message.
const message = WebBuf.fromUtf8("hello, ed25519");
const signature = ed25519Sign(priv, message);

// Verify it.
const ok = ed25519Verify(pub, message, signature); // true
```

## Seed semantics

The 32-byte `privKey` parameter is the **seed** (RFC 8032 §5.1.5 secret key) —
NOT the 64-byte expanded form some libraries expose as the "secret key." The
seed is what's stored on disk in OpenSSH, OpenPGP, and most consumer key
formats. Internally, the seed is hashed with SHA-512 to produce the (clamped)
signing scalar plus the 32-byte prefix used by the signing nonce.

`ed25519-dalek 2.x`'s `SigningKey::to_bytes()` also returns the seed (not the
expanded form), so round-tripping through serialization works as expected.

## PureEdDSA only

This package implements **PureEdDSA** per RFC 8032 §5.1.6 / §5.1.7. The signer
consumes the raw message bytes directly — no prehash, no Ed25519ph variant.

PureEdDSA preserves the collision-resilience guarantee that RFC 8032 calls out:
even if the hash function used internally (SHA-512) had a collision, signing two
distinct messages with the same key would not yield interchangeable signatures.

Consumers who want to sign a digest should hash externally and pass the digest
as the `message` argument; the primitive itself never prehashes.

## Determinism

PureEdDSA signing is deterministic per RFC 8032: the same `(privKey, message)`
pair always produces the same signature. WebBuf does not opt into the hedged-
signing variant added in `ed25519-dalek 2.x` (which would require pulling RNG
into the WASM build). If you need hedged signing for side-channel resistance,
use a different primitive or layer your own hedging on top.

## Strict verification (RFC 8032 §5.1.7)

`ed25519Verify` returns `boolean`. Failed verification is **not an exception**:

- Wrong key, tampered message, tampered signature, non-canonical `S`,
  small-order `R`, malformed point bytes — all return `false`.
- Only **input-length errors** (private key not 32 bytes, signature not 64
  bytes, etc.) throw.

The underlying Rust crate has `legacy_compatibility` **disabled** and the
wrapper calls `VerifyingKey::verify_strict` (not the cofactored `verify`). That
means strict RFC 8032 §5.1.7 verification is enforced: signatures with
non-canonical `S` (i.e. `S >= L`) are rejected, signatures with non-canonical
`R` are rejected, and **small-order public keys are rejected**. This is what
most modern Ed25519 consumers expect.

Strict verification matters: without it, a malicious peer presenting the
Curve25519 identity element as their public key combined with an identity-R /
zero-S signature would produce a universal forgery accepting any message.
WebBuf's verifier rejects this case explicitly; a regression test asserts it.

## API

| Function                                                                                 | Description                                                             |
| ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `ed25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32>`                            | Derive public key from a 32-byte seed                                   |
| `ed25519Sign(privKey: FixedBuf<32>, message: WebBuf): FixedBuf<64>`                      | PureEdDSA sign — returns 64-byte `(R \|\| S)` signature                 |
| `ed25519Verify(pubKey: FixedBuf<32>, message: WebBuf, signature: FixedBuf<64>): boolean` | PureEdDSA verify — returns `true`/`false`; throws on length errors only |

## Audit posture

The `curve25519-dalek` and `subtle` crates received a security audit by
**Quarkslab in 2019** (commissioned by Tari Labs). That audit covered the
pre-1.0 codebase. The current `curve25519-dalek 4.x` and `ed25519-dalek 2.x`
lines are **not under** the 2019 audit, but the pinned versions (`=4.1.3` and
`=2.2.0`) include fixes for:

- **RUSTSEC-2022-0093** (`ed25519-dalek` Double Public Key Signing Function
  Oracle Attack, fixed in 2.0.0 by the `SigningKey` / `VerifyingKey` API
  redesign).
- **RUSTSEC-2024-0344** (`curve25519-dalek` `Scalar29::sub` / `Scalar52::sub`
  LLVM-inserted timing leak, fixed in 4.1.3).

WebBuf pins these crates exactly. Cargo will not silently upgrade across
RUSTSEC-fix points without an intentional bump in WebBuf's `Cargo.toml`.

See
[`issues/0007-curve25519-hybrid-pq`](../../issues/0007-curve25519-hybrid-pq/README.md)
for the full crate-survey rationale and pinned-version decisions.

## Tests

- 13 Rust tests: four RFC 8032 §7.1 KATs (TEST 1 empty, TEST 2 1-byte, TEST 3
  2-byte, TEST SHA(abc)), determinism, round-trip, tampered-message rejection,
  tampered-signature rejection (R and S separately), wrong-public-key rejection,
  malformed-public-key graceful rejection, all-zero-signature rejection,
  input-length error wording, and small-order-public-key universal-forgery
  rejection (asserts that the identity-element pub key + identity-R / zero-S
  signature is rejected for any message — this is what `verify_strict` buys us
  over the cofactored `verify`).
- 25 TypeScript tests: round-trip on random keys, length invariants,
  deterministic public-key + signature derivation, empty-message + 64 KiB
  message round-trip, all seven rejection paths (including the matching
  universal-forgery regression), plus the four RFC 8032 §7.1 audit KATs each
  asserting public-key derivation, signature production, and verification.

```bash
pnpm test
```

## License

MIT
