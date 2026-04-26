# @webbuf/x25519

X25519 elliptic-curve Diffie-Hellman (RFC 7748) for WebBuf, optimized with
Rust/WASM.

X25519 is the standard ECDH primitive used by Signal, WireGuard, TLS 1.3, SSH,
and the Chrome `X25519MLKEM768` post-quantum hybrid handshake.

## Installation

```bash
npm install @webbuf/x25519
```

## Usage

```typescript
import { x25519PublicKeyCreate, x25519SharedSecretRaw } from "@webbuf/x25519";
import { FixedBuf } from "@webbuf/fixedbuf";

// Each party generates a 32-byte private key and computes its public key.
const alicePriv = FixedBuf.fromRandom<32>(32);
const alicePub = x25519PublicKeyCreate(alicePriv);

const bobPriv = FixedBuf.fromRandom<32>(32);
const bobPub = x25519PublicKeyCreate(bobPriv);

// Each side computes the same shared secret independently.
const aliceSS = x25519SharedSecretRaw(alicePriv, bobPub);
const bobSS = x25519SharedSecretRaw(bobPriv, alicePub);
// aliceSS.toHex() === bobSS.toHex()
```

## Output format

Public keys and shared secrets are 32-byte u-coordinates per RFC 7748 §5 — not
the 33-byte SEC1-compressed shape used by `@webbuf/p256` or `@webbuf/secp256k1`.
The shared secret is the raw 32-byte scalar-mult output; consumers that need an
AES key should run it through HKDF-SHA-256 (or use the higher-level
`@webbuf/aesgcm-x25519dh-mlkem` package once it lands).

## Clamping

X25519 requires private-key bit-clamping per RFC 7748 §5 (`decodeScalar25519`)
before scalar multiplication. **Clamping is applied internally** by
`x25519PublicKeyCreate` and `x25519SharedSecretRaw`. Callers can pass any
32-byte private key — the clamping happens transparently inside the WASM
boundary, matching `x25519-dalek`'s `StaticSecret::from([u8; 32])` behavior.
There's no need (and no API surface) to pre-clamp.

The Rust test `clamping_is_internal` proves this empirically: two private keys
that differ only in clamped bits produce the same public key.

## Small-order rejection

`x25519SharedSecretRaw` **throws** if the resulting shared secret is
non-contributory — i.e. if the peer's public key is small-order. This protects
hybrid encryption schemes from being collapsed to PQ-only by a malicious peer's
small-order public key. The error message is stable:

```
X25519 shared secret is non-contributory (small-order public key)
```

The seven canonical small-order Curve25519 u-coordinates (Cremers & Jackson,
"Prime, Order Please!" 2019) are exercised in both the Rust and TypeScript test
suites.

RFC 7748 §6.1 says implementations may abort on a zero shared secret. WebBuf
takes the conservative position: the primitive itself enforces, every consumer
inherits the protection.

## API

| Function                                                                           | Description                                                               |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `x25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32>`                       | Compute public key from a 32-byte private key (clamped internally)        |
| `x25519SharedSecretRaw(privKey: FixedBuf<32>, pubKey: FixedBuf<32>): FixedBuf<32>` | Compute raw 32-byte ECDH shared secret; throws on non-contributory result |

## Audit posture

The `curve25519-dalek` and `subtle` crates received a security audit by
**Quarkslab in 2019** (commissioned by Tari Labs). That audit covered the
pre-1.0 codebase. The current `curve25519-dalek 4.x` and `x25519-dalek 2.x`
lines are **not under** the 2019 audit, but the pinned versions (`=4.1.3` and
`=2.0.1`) include the fix for **RUSTSEC-2024-0344** (`Scalar29::sub` /
`Scalar52::sub` LLVM-inserted timing leak, fixed in `curve25519-dalek 4.1.3`).
There are no open advisories against `x25519-dalek` itself.

WebBuf pins these crates exactly. Cargo will not silently upgrade across
RUSTSEC-fix points without an intentional bump in WebBuf's `Cargo.toml`.

See
[`issues/0007-curve25519-hybrid-pq`](../../issues/0007-curve25519-hybrid-pq/README.md)
for the full crate-survey rationale and pinned-version decisions.

## Tests

- 6 Rust tests: RFC 7748 §6.1 worked example, §5.2 single-iteration vector,
  small-order rejection across all seven canonical u-coordinates, clamping
  invariance, hard-coded round-trip, input-length error wording.
- TypeScript tests: round-trip on random keys, length invariants, deterministic
  public-key derivation, all-seven small-order rejections, the RFC 7748 §6.1 +
  §5.2 audit KATs.

```bash
pnpm test
```

## License

MIT
