# @webbuf/secp256k1

Elliptic curve secp256k1 for ECDSA signatures and Diffie-Hellman, optimized with Rust/WASM.

## Installation

```bash
npm install @webbuf/secp256k1
```

## Usage

### Key Generation

```typescript
import { publicKeyCreate, privateKeyVerify, publicKeyVerify } from "@webbuf/secp256k1";
import { FixedBuf } from "@webbuf/fixedbuf";

// Generate random private key
const privKey = FixedBuf.fromRandom<32>(32);

// Verify private key is valid
privateKeyVerify(privKey); // true

// Derive public key (compressed, 33 bytes)
const pubKey = publicKeyCreate(privKey);

// Verify public key
publicKeyVerify(pubKey); // true
```

### Signing and Verification

```typescript
import { sign, verify, publicKeyCreate } from "@webbuf/secp256k1";
import { FixedBuf } from "@webbuf/fixedbuf";

const privKey = FixedBuf.fromRandom<32>(32);
const pubKey = publicKeyCreate(privKey);

// Message hash (must be 32 bytes)
const messageHash = FixedBuf.fromRandom<32>(32);

// Nonce k (use RFC 6979 in production!)
const k = FixedBuf.fromRandom<32>(32);

// Sign: returns 64-byte signature
const signature = sign(messageHash, privKey, k);

// Verify signature
verify(signature, messageHash, pubKey); // true
```

### Diffie-Hellman Key Exchange

```typescript
import { sharedSecret, publicKeyCreate } from "@webbuf/secp256k1";
import { FixedBuf } from "@webbuf/fixedbuf";

const alicePriv = FixedBuf.fromRandom<32>(32);
const bobPriv = FixedBuf.fromRandom<32>(32);

const alicePub = publicKeyCreate(alicePriv);
const bobPub = publicKeyCreate(bobPriv);

// Both derive the same shared secret
const secretA = sharedSecret(alicePriv, bobPub);
const secretB = sharedSecret(bobPriv, alicePub);
// secretA equals secretB
```

### Key Addition

```typescript
import { privateKeyAdd, publicKeyAdd, publicKeyCreate } from "@webbuf/secp256k1";
import { FixedBuf } from "@webbuf/fixedbuf";

const priv1 = FixedBuf.fromRandom<32>(32);
const priv2 = FixedBuf.fromRandom<32>(32);

// Add private keys (mod curve order)
const combinedPriv = privateKeyAdd(priv1, priv2);

// Add public keys (point addition)
const pub1 = publicKeyCreate(priv1);
const pub2 = publicKeyCreate(priv2);
const combinedPub = publicKeyAdd(pub1, pub2);
```

## API

| Function | Description |
|----------|-------------|
| `privateKeyVerify(key: FixedBuf<32>): boolean` | Check if private key is valid |
| `publicKeyVerify(key: FixedBuf<33>): boolean` | Check if public key is valid |
| `publicKeyCreate(privKey: FixedBuf<32>): FixedBuf<33>` | Derive public key |
| `privateKeyAdd(key1, key2): FixedBuf<32>` | Add two private keys |
| `publicKeyAdd(key1, key2): FixedBuf<33>` | Add two public keys |
| `sign(hash, privKey, k): FixedBuf<64>` | Sign with nonce k |
| `verify(sig, hash, pubKey): boolean` | Verify signature |
| `sharedSecret(privKey, pubKey): FixedBuf<33>` | ECDH shared secret |

## License

MIT
