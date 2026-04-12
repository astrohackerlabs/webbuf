# @webbuf/acs2p256dh

Authenticated encryption with P-256 ECDH key exchange.

ACS2P256DH = **A**ES + **C**BC + **S**HA-**2**56 HMAC + **P**-**256** **D**iffie-**H**ellman

Uses P-256 (NIST) ECDH to derive a shared secret, then encrypts with ACS2.

## Installation

```bash
npm install @webbuf/acs2p256dh
```

## Usage

```typescript
import { acs2p256dhEncrypt, acs2p256dhDecrypt } from "@webbuf/acs2p256dh";
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
const ciphertext = acs2p256dhEncrypt(alicePrivKey, bobPubKey, plaintext);

// Bob decrypts the message from Alice
const decrypted = acs2p256dhDecrypt(bobPrivKey, alicePubKey, ciphertext);
console.log(decrypted.toUtf8()); // "Hello Bob!"
```

## How It Works

1. Derives shared secret using P-256 ECDH: `p256SharedSecret(privKey, pubKey)`
2. Hashes the shared secret with SHA-256 to get the encryption key
3. Encrypts/decrypts using ACS2 (AES-CBC + SHA-256 HMAC)

Both parties can derive the same shared secret:

- Alice: `p256SharedSecret(alicePriv, bobPub)`
- Bob: `p256SharedSecret(bobPriv, alicePub)`

## API

| Function                                              | Description                   |
| ----------------------------------------------------- | ----------------------------- |
| `acs2p256dhEncrypt(privKey, pubKey, plaintext, iv?)`  | Encrypt with ECDH-derived key |
| `acs2p256dhDecrypt(privKey, pubKey, ciphertext)`      | Decrypt with ECDH-derived key |

## License

MIT
