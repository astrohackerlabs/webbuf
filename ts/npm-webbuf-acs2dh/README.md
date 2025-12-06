# @webbuf/acs2dh

Authenticated encryption with ECDH key exchange using SHA-256.

ACS2DH = **A**ES + **C**BC + **S**HA**2**56 HMAC + **D**iffie-**H**ellman

Uses secp256k1 ECDH to derive a shared secret, then encrypts with ACS2.

## Installation

```bash
npm install @webbuf/acs2dh
```

## Usage

```typescript
import { acs2dhEncrypt, acs2dhDecrypt } from "@webbuf/acs2dh";
import { publicKeyCreate } from "@webbuf/secp256k1";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Alice and Bob generate key pairs
const alicePrivKey = FixedBuf.fromRandom<32>(32);
const alicePubKey = publicKeyCreate(alicePrivKey);

const bobPrivKey = FixedBuf.fromRandom<32>(32);
const bobPubKey = publicKeyCreate(bobPrivKey);

// Alice encrypts a message to Bob
const plaintext = WebBuf.fromUtf8("Hello Bob!");
const ciphertext = acs2dhEncrypt(alicePrivKey, bobPubKey, plaintext);

// Bob decrypts the message from Alice
const decrypted = acs2dhDecrypt(bobPrivKey, alicePubKey, ciphertext);
console.log(decrypted.toUtf8()); // "Hello Bob!"
```

## How It Works

1. Derives shared secret using ECDH: `sharedSecret(privKey, pubKey)`
2. Hashes the shared secret with SHA-256 to get the encryption key
3. Encrypts/decrypts using ACS2 (AES-CBC + SHA-256 HMAC)

Both parties can derive the same shared secret:
- Alice: `sharedSecret(alicePriv, bobPub)`
- Bob: `sharedSecret(bobPriv, alicePub)`

## API

| Function | Description |
|----------|-------------|
| `acs2dhEncrypt(privKey, pubKey, plaintext, iv?)` | Encrypt with ECDH-derived key |
| `acs2dhDecrypt(privKey, pubKey, ciphertext)` | Decrypt with ECDH-derived key |

## License

MIT
