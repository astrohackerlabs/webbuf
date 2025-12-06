# webbuf_sha256

SHA-256 hash and HMAC-SHA256 for Rust and WebAssembly.

## Installation

```toml
[dependencies]
webbuf_sha256 = "0.13"
```

## Usage

```rust
use webbuf_sha256::{sha256_hash, double_sha256_hash, sha256_hmac};

// SHA-256 hash
let data = b"abc";
let hash = sha256_hash(data).unwrap();
assert_eq!(
    hex::encode(&hash),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);

// Double SHA-256 (used in Bitcoin)
let double_hash = double_sha256_hash(data).unwrap();
assert_eq!(double_hash.len(), 32);

// HMAC-SHA256
let key = b"secret key";
let message = b"message";
let mac = sha256_hmac(key, message).unwrap();
assert_eq!(mac.len(), 32);
```

## API

| Function | Description |
|----------|-------------|
| `sha256_hash(data: &[u8]) -> Result<Vec<u8>, String>` | Compute SHA-256 hash (32 bytes) |
| `double_sha256_hash(data: &[u8]) -> Result<Vec<u8>, String>` | Compute SHA-256(SHA-256(data)) |
| `sha256_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String>` | Compute HMAC-SHA256 |

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_sha256 = { version = "0.13", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/sha256` on npm.

## License

MIT
