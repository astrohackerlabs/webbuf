# @webbuf/p256

Elliptic curve P-256 (NIST) for ECDSA signatures and Diffie-Hellman, optimized with Rust/WASM.

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

```typescript
import { p256SharedSecret, p256PublicKeyCreate } from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";

const alicePriv = FixedBuf.fromRandom<32>(32);
const bobPriv = FixedBuf.fromRandom<32>(32);

const alicePub = p256PublicKeyCreate(alicePriv);
const bobPub = p256PublicKeyCreate(bobPriv);

// Both derive the same shared secret
const secretA = p256SharedSecret(alicePriv, bobPub);
const secretB = p256SharedSecret(bobPriv, alicePub);
// secretA equals secretB
```

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

## API

| Function                                                  | Description                   |
| --------------------------------------------------------- | ----------------------------- |
| `p256PrivateKeyVerify(key: FixedBuf<32>): boolean`        | Check if private key is valid |
| `p256PublicKeyVerify(key: FixedBuf<33>): boolean`         | Check if public key is valid  |
| `p256PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<33>`| Derive public key             |
| `p256PrivateKeyAdd(key1, key2): FixedBuf<32>`             | Add two private keys          |
| `p256PublicKeyAdd(key1, key2): FixedBuf<33>`              | Add two public keys           |
| `p256Sign(hash, privKey, k): FixedBuf<64>`                | Sign with nonce k             |
| `p256Verify(sig, hash, pubKey): boolean`                  | Verify signature              |
| `p256SharedSecret(privKey, pubKey): FixedBuf<33>`         | ECDH shared secret            |

## License

MIT
