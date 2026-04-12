# webbuf_aesgcm

AES-GCM authenticated encryption for Rust and WebAssembly.

AES-GCM is an AEAD cipher — it provides both confidentiality and integrity in a single operation (no separate MAC needed).

## Installation

```toml
[dependencies]
webbuf_aesgcm = "0.15"
```

## Usage

```rust
use webbuf_aesgcm::aesgcm::{aesgcm_encrypt, aesgcm_decrypt};

let key = [0x01u8; 32]; // 16 or 32 bytes (AES-128 or AES-256)
let iv = [0x02u8; 12];  // 12 bytes (GCM standard nonce)
let plaintext = b"Hello, AES-GCM!";

// Encrypt: returns ciphertext + 16-byte auth tag
let ciphertext = aesgcm_encrypt(plaintext, &key, &iv).unwrap();
assert_eq!(ciphertext.len(), plaintext.len() + 16);

// Decrypt: verifies auth tag and returns plaintext
let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv).unwrap();
assert_eq!(decrypted, plaintext);
```

## API

| Function | Description |
|----------|-------------|
| `aesgcm_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String>` | Encrypt and authenticate |
| `aesgcm_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String>` | Decrypt and verify auth tag |

**Parameters:**
- `key` - 16 bytes (AES-128) or 32 bytes (AES-256)
- `iv` - 12 bytes (GCM nonce)
- Output: `ciphertext || 16-byte tag` (tag appended)

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_aesgcm = { version = "0.15", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/aesgcm` on npm.

## License

MIT
