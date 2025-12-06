# webbuf_aescbc

AES-CBC encryption and decryption for Rust and WebAssembly.

> **Note**: This library does not provide message authentication. Combine with HMAC or a MAC for authenticated encryption.

## Installation

```toml
[dependencies]
webbuf_aescbc = "0.13"
```

## Usage

```rust
use webbuf_aescbc::aescbc::{aescbc_encrypt, aescbc_decrypt};

// AES-256-CBC encryption
let key = [0u8; 32];  // 32 bytes for AES-256 (or 16 for AES-128, 24 for AES-192)
let iv = [0u8; 16];   // IV must always be 16 bytes
let plaintext = b"Hello, world!";

// Encrypt
let ciphertext = aescbc_encrypt(plaintext, &key, &iv).unwrap();

// Decrypt
let decrypted = aescbc_decrypt(&ciphertext, &key, &iv).unwrap();
assert_eq!(decrypted, plaintext);
```

## API

| Function | Description |
|----------|-------------|
| `aescbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String>` | Encrypt with AES-CBC and PKCS#7 padding |
| `aescbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String>` | Decrypt AES-CBC with PKCS#7 unpadding |

### Key Sizes

- **AES-128**: 16-byte key
- **AES-192**: 24-byte key
- **AES-256**: 32-byte key

The IV must always be 16 bytes.

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_aescbc = { version = "0.13", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/aescbc` on npm.

## License

MIT
