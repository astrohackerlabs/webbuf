# webbuf_blake3

BLAKE3 cryptographic hash function for Rust and WebAssembly.

## Installation

```toml
[dependencies]
webbuf_blake3 = "0.13"
```

## Usage

```rust
use webbuf_blake3::{blake3_hash, double_blake3_hash, blake3_mac};

// Hash data
let data = b"Hello, world!";
let hash = blake3_hash(data).unwrap();
assert_eq!(hash.len(), 32);

// Double hash (hash of hash)
let double_hash = double_blake3_hash(data).unwrap();
assert_eq!(double_hash.len(), 32);

// Keyed MAC (key must be exactly 32 bytes)
let key = [0u8; 32];
let mac = blake3_mac(&key, data).unwrap();
assert_eq!(mac.len(), 32);
```

## API

| Function | Description |
|----------|-------------|
| `blake3_hash(data: &[u8]) -> Result<Vec<u8>, String>` | Compute BLAKE3 hash (32 bytes) |
| `double_blake3_hash(data: &[u8]) -> Result<Vec<u8>, String>` | Compute hash of hash |
| `blake3_mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String>` | Compute keyed MAC (key must be 32 bytes) |

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_blake3 = { version = "0.13", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/blake3` on npm.

## License

MIT
