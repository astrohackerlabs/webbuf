# webbuf

Convenience package that re-exports all @webbuf packages.

## Installation

```bash
npm install webbuf
```

## Usage

```typescript
import {
  // Core
  WebBuf,
  FixedBuf,

  // Numbers
  U8,
  U16BE,
  U16LE,
  U32BE,
  U32LE,
  U64BE,
  U64LE,
  U128BE,
  U128LE,
  U256BE,
  U256LE,

  // Buffer I/O
  BufReader,
  BufWriter,

  // Hashing
  blake3Hash,
  doubleBlake3Hash,
  blake3Mac,
  sha256Hash,
  doubleSha256Hash,
  sha256Hmac,
  ripemd160Hash,
  doubleRipemd160Hash,

  // Elliptic curves
  sign,
  verify,
  publicKeyCreate,
  publicKeyVerify,
  privateKeyVerify,
  sharedSecret,

  // Encryption
  aescbcEncrypt,
  aescbcDecrypt,
  acb3Encrypt,
  acb3Decrypt,
  acb3dhEncrypt,
  acb3dhDecrypt,
} from "webbuf";
```

## Included Packages

| Package             | Description                                  |
| ------------------- | -------------------------------------------- |
| `@webbuf/webbuf`    | Extended Uint8Array with base64/hex encoding |
| `@webbuf/fixedbuf`  | Fixed-size buffer wrapper                    |
| `@webbuf/numbers`   | Fixed-size unsigned integers                 |
| `@webbuf/rw`        | Buffer reader/writer                         |
| `@webbuf/blake3`    | BLAKE3 hash and MAC                          |
| `@webbuf/sha256`    | SHA-256 hash and HMAC                        |
| `@webbuf/ripemd160` | RIPEMD-160 hash                              |
| `@webbuf/secp256k1` | ECDSA and ECDH                               |
| `@webbuf/aescbc`    | AES-CBC encryption                           |
| `@webbuf/acb3`      | AES-CBC + BLAKE3 MAC                         |
| `@webbuf/acb3dh`    | ACB3 + ECDH key exchange                     |

## License

MIT
