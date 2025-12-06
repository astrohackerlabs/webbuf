# @webbuf/acb3

Authenticated encryption using AES-CBC with BLAKE3 MAC.

ACB3 = **A**ES + **C**BC + **B**lake**3** MAC

## Installation

```bash
npm install @webbuf/acb3
```

## Usage

```typescript
import { acb3Encrypt, acb3Decrypt } from "@webbuf/acb3";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// 256-bit key
const key = FixedBuf.fromRandom<32>(32);

// Encrypt with authentication
const plaintext = WebBuf.fromUtf8("Secret message");
const ciphertext = acb3Encrypt(plaintext, key);

// Decrypt and verify
try {
  const decrypted = acb3Decrypt(ciphertext, key);
  console.log(decrypted.toUtf8()); // "Secret message"
} catch (e) {
  console.error("Authentication failed!");
}
```

## How It Works

**Encryption:**

1. Encrypts plaintext with AES-CBC (random IV)
2. Computes BLAKE3 MAC over the ciphertext
3. Returns: `MAC (32 bytes) || IV (16 bytes) || encrypted data`

**Decryption:**

1. Extracts and verifies the MAC
2. Throws if MAC doesn't match (tampered data)
3. Decrypts and returns plaintext

## API

| Function                           | Description                                 |
| ---------------------------------- | ------------------------------------------- |
| `acb3Encrypt(plaintext, key, iv?)` | Encrypt with MAC. Optional custom IV.       |
| `acb3Decrypt(ciphertext, key)`     | Decrypt and verify. Throws on auth failure. |

## License

MIT
