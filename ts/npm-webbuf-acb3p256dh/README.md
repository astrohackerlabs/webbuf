# @webbuf/acb3p256dh

Authenticated encryption with P-256 ECDH key exchange.

ACB3P256DH = **A**ES + **C**BC + **B**lake**3** MAC + **P**-**256** **D**iffie-**H**ellman

Uses P-256 (NIST) ECDH to derive a shared secret, then encrypts with ACB3.

## Installation

```bash
npm install @webbuf/acb3p256dh
```

## Usage

```typescript
import { acb3p256dhEncrypt, acb3p256dhDecrypt } from "@webbuf/acb3p256dh";
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
const ciphertext = acb3p256dhEncrypt(alicePrivKey, bobPubKey, plaintext);

// Bob decrypts the message from Alice
const decrypted = acb3p256dhDecrypt(bobPrivKey, alicePubKey, ciphertext);
console.log(decrypted.toUtf8()); // "Hello Bob!"
```

## How It Works

1. Derives shared secret using P-256 ECDH: `p256SharedSecret(privKey, pubKey)`
2. Hashes the shared secret with BLAKE3 to get the encryption key
3. Encrypts/decrypts using ACB3 (AES-CBC + BLAKE3 MAC)

Both parties can derive the same shared secret:

- Alice: `p256SharedSecret(alicePriv, bobPub)`
- Bob: `p256SharedSecret(bobPriv, alicePub)`

## API

| Function                                              | Description                   |
| ----------------------------------------------------- | ----------------------------- |
| `acb3p256dhEncrypt(privKey, pubKey, plaintext, iv?)`  | Encrypt with ECDH-derived key |
| `acb3p256dhDecrypt(privKey, pubKey, ciphertext)`      | Decrypt with ECDH-derived key |

## License

MIT
