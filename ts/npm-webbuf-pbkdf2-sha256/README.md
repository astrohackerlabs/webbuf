# @webbuf/pbkdf2-sha256

PBKDF2-HMAC-SHA256 password-based key derivation, optimized with Rust/WASM.

Implements RFC 8018 (PKCS #5 v2.1) with HMAC-SHA256 as the pseudorandom function.

## Installation

```bash
npm install @webbuf/pbkdf2-sha256
```

## Usage

```typescript
import { pbkdf2Sha256 } from "@webbuf/pbkdf2-sha256";
import { WebBuf } from "@webbuf/webbuf";

const password = WebBuf.fromUtf8("my password");
const salt = WebBuf.fromUtf8("random salt");
const iterations = 100_000;
const keyLen = 32;

const derivedKey = pbkdf2Sha256(password, salt, iterations, keyLen);
console.log(derivedKey.toHex()); // 32-byte derived key
```

## API

| Function | Description |
| -------- | ----------- |
| `pbkdf2Sha256(password: WebBuf, salt: WebBuf, iterations: number, keyLen: number): WebBuf` | Derive key from password |

**Parameters:**
- `password` - Password bytes (any length)
- `salt` - Salt bytes (any length, should be random)
- `iterations` - Number of HMAC rounds (higher = slower + more secure)
- `keyLen` - Desired output length in bytes (1-128)

## License

MIT
