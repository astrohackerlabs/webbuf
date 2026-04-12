# @webbuf/aesgcm-p256dh

Authenticated encryption with P-256 ECDH key exchange and AES-GCM.

A fully NIST-approved construction: P-256 ECDH + SHA-256 key derivation + AES-256-GCM.

## Installation

```bash
npm install @webbuf/aesgcm-p256dh
```

## Usage

```typescript
import { aesgcmP256dhEncrypt, aesgcmP256dhDecrypt } from "@webbuf/aesgcm-p256dh";
import { p256PublicKeyCreate } from "@webbuf/p256";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Alice and Bob generate key pairs
const alicePrivKey = FixedBuf.fromRandom<32>(32);
const alicePubKey = p256PublicKeyCreate(alicePrivKey);

const bobPrivKey = FixedBuf.fromRandom<32>(32);
const bobPubKey = p256PublicKeyCreate(bobPrivKey);

// Alice encrypts a message to Bob
const plaintext = WebBuf.fromUtf8("Hello Bob!");
const ciphertext = aesgcmP256dhEncrypt(alicePrivKey, bobPubKey, plaintext);

// Bob decrypts the message from Alice
const decrypted = aesgcmP256dhDecrypt(bobPrivKey, alicePubKey, ciphertext);
console.log(decrypted.toUtf8()); // "Hello Bob!"
```

## How It Works

1. Derives shared secret using P-256 ECDH: `p256SharedSecret(privKey, pubKey)`
2. Hashes the shared secret with SHA-256 to get a 32-byte AES-256 key
3. Encrypts/decrypts using AES-GCM (authenticated, no separate MAC needed)

Both parties derive the same shared secret:

- Alice: `p256SharedSecret(alicePriv, bobPub)`
- Bob: `p256SharedSecret(bobPriv, alicePub)`

## API

| Function | Description |
| -------- | ----------- |
| `aesgcmP256dhEncrypt(privKey, pubKey, plaintext, iv?)` | Encrypt with ECDH-derived key |
| `aesgcmP256dhDecrypt(privKey, pubKey, ciphertext)` | Decrypt with ECDH-derived key |

## License

MIT
