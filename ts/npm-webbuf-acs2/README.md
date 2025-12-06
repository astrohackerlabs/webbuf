# @webbuf/acs2

Authenticated encryption using AES-CBC with SHA-256 HMAC.

ACS2 = **A**ES + **C**BC + **S**HA**2**56 HMAC

## Installation

```bash
npm install @webbuf/acs2
```

## Usage

```typescript
import { acs2Encrypt, acs2Decrypt } from "@webbuf/acs2";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// 256-bit key
const key = FixedBuf.fromRandom<32>(32);

// Encrypt with authentication
const plaintext = WebBuf.fromUtf8("Secret message");
const ciphertext = acs2Encrypt(plaintext, key);

// Decrypt and verify
try {
  const decrypted = acs2Decrypt(ciphertext, key);
  console.log(decrypted.toUtf8()); // "Secret message"
} catch (e) {
  console.error("Authentication failed!");
}
```

## How It Works

**Encryption:**
1. Encrypts plaintext with AES-CBC (random IV)
2. Computes SHA-256 HMAC over the ciphertext
3. Returns: `HMAC (32 bytes) || IV (16 bytes) || encrypted data`

**Decryption:**
1. Extracts and verifies the HMAC
2. Throws if HMAC doesn't match (tampered data)
3. Decrypts and returns plaintext

## API

| Function | Description |
|----------|-------------|
| `acs2Encrypt(plaintext, key, iv?)` | Encrypt with HMAC. Optional custom IV. |
| `acs2Decrypt(ciphertext, key)` | Decrypt and verify. Throws on auth failure. |

## License

MIT
