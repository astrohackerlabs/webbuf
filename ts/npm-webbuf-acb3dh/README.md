# @webbuf/acb3dh

Authenticated encryption with ECDH key exchange.

ACB3DH = **A**ES + **C**BC + **B**lake**3** MAC + **D**iffie-**H**ellman

Uses secp256k1 ECDH to derive a shared secret, then encrypts with ACB3.

## Installation

```bash
npm install @webbuf/acb3dh
```

## Usage

```typescript
import { acb3dhEncrypt, acb3dhDecrypt } from "@webbuf/acb3dh";
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
const ciphertext = acb3dhEncrypt(alicePrivKey, bobPubKey, plaintext);

// Bob decrypts the message from Alice
const decrypted = acb3dhDecrypt(bobPrivKey, alicePubKey, ciphertext);
console.log(decrypted.toUtf8()); // "Hello Bob!"
```

## How It Works

1. Derives shared secret using ECDH: `sharedSecret(privKey, pubKey)`
2. Hashes the shared secret with BLAKE3 to get the encryption key
3. Encrypts/decrypts using ACB3 (AES-CBC + BLAKE3 MAC)

Both parties can derive the same shared secret:
- Alice: `sharedSecret(alicePriv, bobPub)`
- Bob: `sharedSecret(bobPriv, alicePub)`

## API

| Function | Description |
|----------|-------------|
| `acb3dhEncrypt(privKey, pubKey, plaintext, iv?)` | Encrypt with ECDH-derived key |
| `acb3dhDecrypt(privKey, pubKey, ciphertext)` | Decrypt with ECDH-derived key |

## License

MIT
