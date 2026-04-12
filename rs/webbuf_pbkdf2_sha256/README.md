# webbuf_pbkdf2_sha256

PBKDF2-HMAC-SHA256 password-based key derivation for Rust and WebAssembly.

Implements RFC 8018 (PKCS #5 v2.1) with HMAC-SHA256 as the pseudorandom function.

## Installation

```toml
[dependencies]
webbuf_pbkdf2_sha256 = "0.15"
```

## Usage

```rust
use webbuf_pbkdf2_sha256::pbkdf2_sha256::pbkdf2_sha256;

let password = b"my password";
let salt = b"random salt";
let iterations = 100_000;
let key_len = 32; // output length in bytes (max 128)

let derived_key = pbkdf2_sha256(password, salt, iterations, key_len).unwrap();
assert_eq!(derived_key.len(), 32);
```

## API

| Function | Description |
|----------|-------------|
| `pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, key_len: u32) -> Result<Vec<u8>, String>` | Derive key from password |

**Parameters:**
- `password` - Password bytes (any length)
- `salt` - Salt bytes (any length, should be random)
- `iterations` - Number of HMAC rounds (higher = slower + more secure)
- `key_len` - Desired output length in bytes (1-128)

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_pbkdf2_sha256 = { version = "0.15", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/pbkdf2-sha256` on npm.

## License

MIT
