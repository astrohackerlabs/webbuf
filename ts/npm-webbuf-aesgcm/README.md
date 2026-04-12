# @webbuf/aesgcm

AES-GCM authenticated encryption, optimized with Rust/WASM.

AES-GCM is an AEAD cipher — it provides both confidentiality and integrity in a single operation (no separate MAC needed).

## Installation

```bash
npm install @webbuf/aesgcm
```

## Usage

```typescript
import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

const key = FixedBuf.fromRandom<32>(32); // AES-256
const plaintext = WebBuf.fromUtf8("Hello, AES-GCM!");

// Encrypt (nonce generated automatically)
const ciphertext = aesgcmEncrypt(plaintext, key);

// Decrypt (nonce extracted from ciphertext)
const decrypted = aesgcmDecrypt(ciphertext, key);
console.log(decrypted.toUtf8()); // "Hello, AES-GCM!"
```

## Output Format

`[12-byte nonce] + [ciphertext] + [16-byte auth tag]`

The nonce is prepended automatically on encrypt and extracted automatically on decrypt.

## API

| Function | Description |
| -------- | ----------- |
| `aesgcmEncrypt(plaintext, key, iv?): WebBuf` | Encrypt and authenticate |
| `aesgcmDecrypt(ciphertext, key): WebBuf` | Decrypt and verify auth tag |

**Parameters:**
- `key` - `FixedBuf<16>` (AES-128) or `FixedBuf<32>` (AES-256)
- `iv` - Optional `FixedBuf<12>` nonce (random if not provided)

## License

MIT
