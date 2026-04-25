# @webbuf/p256

Elliptic curve P-256 (NIST) for ECDSA signatures and Diffie-Hellman, optimized
with Rust/WASM.

## Installation

```bash
npm install @webbuf/p256
```

## Usage

### Key Generation

```typescript
import {
  p256PublicKeyCreate,
  p256PrivateKeyVerify,
  p256PublicKeyVerify,
} from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";

// Generate random private key
const privKey = FixedBuf.fromRandom<32>(32);

// Verify private key is valid
p256PrivateKeyVerify(privKey); // true

// Derive public key (compressed, 33 bytes)
const pubKey = p256PublicKeyCreate(privKey);

// Verify public key
p256PublicKeyVerify(pubKey); // true
```

### Signing and Verification

```typescript
import { p256Sign, p256Verify, p256PublicKeyCreate } from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";

const privKey = FixedBuf.fromRandom<32>(32);
const pubKey = p256PublicKeyCreate(privKey);

// Message hash (must be 32 bytes)
const messageHash = FixedBuf.fromRandom<32>(32);

// Nonce k (use RFC 6979 in production!)
const k = FixedBuf.fromRandom<32>(32);

// Sign: returns 64-byte signature
const signature = p256Sign(messageHash, privKey, k);

// Verify signature
p256Verify(signature, messageHash, pubKey); // true
```

### Diffie-Hellman Key Exchange

Two helpers compute an ECDH shared secret. Pick the one that matches what your
downstream consumer expects.

#### `p256SharedSecret` — SEC1-compressed point (33 bytes)

Returns the SEC1 X9.62 compressed-point encoding: a 1-byte sign prefix (`0x02`
or `0x03`) followed by the 32-byte X-coordinate. This is what
`@webbuf/aesgcm-p256dh` and the existing combined packages feed into their key
derivation.

```typescript
import { p256SharedSecret, p256PublicKeyCreate } from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";

const alicePriv = FixedBuf.fromRandom<32>(32);
const bobPriv = FixedBuf.fromRandom<32>(32);

const alicePub = p256PublicKeyCreate(alicePriv);
const bobPub = p256PublicKeyCreate(bobPriv);

// Both derive the same shared secret (33-byte SEC1 compressed point)
const secretA = p256SharedSecret(alicePriv, bobPub);
const secretB = p256SharedSecret(bobPriv, alicePub);
// secretA equals secretB
```

#### `p256SharedSecretRaw` — raw 32-byte X-coordinate

Returns the bare X-coordinate of the shared point, without the SEC1 prefix. This
is the X9.63 "Z" value used as IKM input in the standard KDFs — NIST SP 800-56A
§5.7.1.2, RFC 5869 HKDF-Extract, and the IETF hybrid-KEM combiners
(`draft-ietf-tls-hybrid-design`, Signal PQXDH).

Use this helper when feeding the ECDH output into HKDF or another key-derivation
function that expects the raw curve output. The prefix byte that
`p256SharedSecret` includes is deterministic given the X-coordinate, so
stripping it does not lose entropy — it just matches the standard input format.

```typescript
import { p256SharedSecretRaw, p256PublicKeyCreate } from "@webbuf/p256";

const alicePub = p256PublicKeyCreate(alicePriv);
const bobPub = p256PublicKeyCreate(bobPriv);

// 32-byte raw X-coordinate, suitable as IKM for HKDF-SHA-256
const rawA = p256SharedSecretRaw(alicePriv, bobPub);
const rawB = p256SharedSecretRaw(bobPriv, alicePub);
// rawA equals rawB
// rawA equals p256SharedSecret(alicePriv, bobPub).buf.slice(1, 33)
```

If you are building a new package on top of `@webbuf/p256` and want to follow
standards-compliant key derivation, prefer `p256SharedSecretRaw` and feed it
into HKDF rather than `p256SharedSecret`.

### Key Addition

```typescript
import {
  p256PrivateKeyAdd,
  p256PublicKeyAdd,
  p256PublicKeyCreate,
} from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";

const priv1 = FixedBuf.fromRandom<32>(32);
const priv2 = FixedBuf.fromRandom<32>(32);

// Add private keys (mod curve order)
const combinedPriv = p256PrivateKeyAdd(priv1, priv2);

// Add public keys (point addition)
const pub1 = p256PublicKeyCreate(priv1);
const pub2 = p256PublicKeyCreate(priv2);
const combinedPub = p256PublicKeyAdd(pub1, pub2);
```

### Web Crypto Interop

Convert webbuf's compressed storage format to/from the Web Crypto API
(`crypto.subtle`).

```typescript
import {
  p256PublicKeyToJwk,
  p256PrivateKeyToJwk,
  p256PublicKeyFromJwk,
  p256PublicKeyCreate,
} from "@webbuf/p256";

const priv = FixedBuf.fromRandom<32>(32);
const pub = p256PublicKeyCreate(priv);

// Import public key into Web Crypto (for verify or ECDH)
const pubJwk = p256PublicKeyToJwk(pub);
const verifyKey = await crypto.subtle.importKey(
  "jwk",
  pubJwk,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["verify"],
);

// Import private key into Web Crypto (for sign or ECDH)
// p256PrivateKeyToJwk derives the public x/y coordinates internally,
// since Web Crypto requires them alongside d.
const privJwk = p256PrivateKeyToJwk(priv);
const signKey = await crypto.subtle.importKey(
  "jwk",
  privJwk,
  { name: "ECDSA", namedCurve: "P-256" },
  false,
  ["sign"],
);

// Convert Web Crypto JWK back to compressed storage format
const exported = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
const compressed = p256PublicKeyFromJwk(exported);
```

## API

| Function                                                   | Description                          |
| ---------------------------------------------------------- | ------------------------------------ |
| `p256PrivateKeyVerify(key: FixedBuf<32>): boolean`         | Check if private key is valid        |
| `p256PublicKeyVerify(key: FixedBuf<33>): boolean`          | Check if public key is valid         |
| `p256PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<33>` | Derive public key                    |
| `p256PrivateKeyAdd(key1, key2): FixedBuf<32>`              | Add two private keys                 |
| `p256PublicKeyAdd(key1, key2): FixedBuf<33>`               | Add two public keys                  |
| `p256Sign(hash, privKey, k): FixedBuf<64>`                 | Sign with nonce k                    |
| `p256Verify(sig, hash, pubKey): boolean`                   | Verify signature                     |
| `p256SharedSecret(privKey, pubKey): FixedBuf<33>`          | ECDH shared secret (SEC1 compressed) |
| `p256SharedSecretRaw(privKey, pubKey): FixedBuf<32>`       | ECDH shared secret (raw X-coord)     |
| `p256PublicKeyDecompress(c: FixedBuf<33>): FixedBuf<65>`   | 33-byte → 65-byte SEC1               |
| `p256PublicKeyCompress(u: FixedBuf<65>): FixedBuf<33>`     | 65-byte → 33-byte SEC1               |
| `p256PublicKeyToJwk(c: FixedBuf<33>): P256PublicKeyJwk`    | Compressed → JWK                     |
| `p256PrivateKeyToJwk(p: FixedBuf<32>): P256PrivateKeyJwk`  | Scalar → JWK (with x, y)             |
| `p256PublicKeyFromJwk(jwk): FixedBuf<33>`                  | JWK → compressed                     |

## License

MIT
