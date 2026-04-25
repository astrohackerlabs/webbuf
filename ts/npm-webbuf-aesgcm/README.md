# @webbuf/aesgcm

AES-GCM authenticated encryption, optimized with Rust/WASM.

AES-GCM is an AEAD cipher — it provides both confidentiality and integrity in a
single operation (no separate MAC needed).

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

The nonce is prepended automatically on encrypt and extracted automatically on
decrypt.

## API

| Function                                           | Description                |
| -------------------------------------------------- | -------------------------- |
| `aesgcmEncrypt(plaintext, key, iv?, aad?): WebBuf` | Encrypt and authenticate   |
| `aesgcmDecrypt(ciphertext, key, aad?): WebBuf`     | Decrypt and verify the tag |

**Parameters:**

- `key` — `FixedBuf<16>` (AES-128) or `FixedBuf<32>` (AES-256)
- `iv` — optional `FixedBuf<12>` nonce (random if not provided)
- `aad` — optional `WebBuf` of Additional Authenticated Data; defaults to empty
  (see below)

## Authenticated context (AAD)

Both `aesgcmEncrypt` and `aesgcmDecrypt` accept an optional trailing `aad`
parameter. AAD is **authenticated** by AES-GCM but **not encrypted** and **not
included in the output bytes** — the recipient must supply the exact same AAD
the sender used, or decryption fails with an authentication-tag error.

```typescript
const aad = WebBuf.fromUtf8("protocol-v1:alice:bob");

// Sender binds context into the tag
const ciphertext = aesgcmEncrypt(plaintext, key, undefined, aad);

// Recipient must rebuild the same AAD bytes; mismatch throws.
const decrypted = aesgcmDecrypt(ciphertext, key, aad);
```

Use AAD to bind any context that should be inseparable from the message:
protocol version, sender / recipient identity, message type, transcript state,
sequence number — anything where mismatch should mean "this isn't the message I
think it is."

**Properties:**

- **Backward-compatible.** Calls with no `aad` argument behave identically to
  before (empty AAD is mathematically equivalent to no AAD in AES-GCM).
- **No wire-format change.** Ciphertext length is unchanged; only the AES-GCM
  authentication tag changes when AAD is non-empty.
- **No key-schedule change.** AAD enters the GHASH computation only, not the AES
  key.

This was added in [issue 0006](../../issues/0006-aad-pq-encryption/README.md).
The same `aad?` parameter is propagated through the post-quantum encryption
packages [`@webbuf/aesgcm-mlkem`](../npm-webbuf-aesgcm-mlkem/README.md) and
[`@webbuf/aesgcm-p256dh-mlkem`](../npm-webbuf-aesgcm-p256dh-mlkem/README.md).

## License

MIT
