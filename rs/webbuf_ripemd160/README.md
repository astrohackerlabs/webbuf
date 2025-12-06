# webbuf_ripemd160

RIPEMD-160 cryptographic hash function for Rust and WebAssembly.

## Installation

```toml
[dependencies]
webbuf_ripemd160 = "0.13"
```

## Usage

```rust
use webbuf_ripemd160::{ripemd160_hash, double_ripemd160_hash};

// RIPEMD-160 hash
let data = b"Hello, world!";
let hash = ripemd160_hash(data).unwrap();
assert_eq!(hash.len(), 20); // RIPEMD-160 produces 20-byte output

// Double hash (hash of hash)
let double_hash = double_ripemd160_hash(data).unwrap();
assert_eq!(double_hash.len(), 20);
```

## API

| Function | Description |
|----------|-------------|
| `ripemd160_hash(data: &[u8]) -> Result<Vec<u8>, String>` | Compute RIPEMD-160 hash (20 bytes) |
| `double_ripemd160_hash(data: &[u8]) -> Result<Vec<u8>, String>` | Compute hash of hash |

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_ripemd160 = { version = "0.13", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/ripemd160` on npm.

## License

MIT
