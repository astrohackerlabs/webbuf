# @webbuf/aescbc

AES-CBC encryption and decryption, optimized with Rust/WASM.

> **Note**: This library does not provide message authentication. Use `@webbuf/acb3` for authenticated encryption.

## Installation

```bash
npm install @webbuf/aescbc
```

## Usage

```typescript
import { aescbcEncrypt, aescbcDecrypt } from "@webbuf/aescbc";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// AES-256 key (32 bytes)
const aesKey = FixedBuf.fromRandom<32>(32);

// Optional: custom IV (16 bytes). If not provided, random IV is generated.
const iv = FixedBuf.fromRandom<16>(16);

// Encrypt
const plaintext = WebBuf.fromUtf8("Hello, world!");
const ciphertext = aescbcEncrypt(plaintext, aesKey, iv);
// Note: IV is prepended to ciphertext

// Decrypt
const decrypted = aescbcDecrypt(ciphertext, aesKey);
console.log(decrypted.toUtf8()); // "Hello, world!"
```

## API

| Function | Description |
|----------|-------------|
| `aescbcEncrypt(plaintext, aesKey, iv?)` | Encrypt with AES-CBC. IV prepended to output. |
| `aescbcDecrypt(ciphertext, aesKey)` | Decrypt AES-CBC. Expects IV at start of ciphertext. |

### Key Sizes

- **AES-128**: `FixedBuf<16>`
- **AES-192**: `FixedBuf<24>`
- **AES-256**: `FixedBuf<32>`

## License

MIT
