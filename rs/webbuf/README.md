# webbuf

Fast base64 and hex encoding/decoding for Rust and WebAssembly.

## Installation

```toml
[dependencies]
webbuf = "0.13"
```

## Usage

```rust
use webbuf::{encode_base64, decode_base64, encode_hex, decode_hex};

// Base64 encoding
let data = b"Hello, world!";
let base64_str = encode_base64(data);
assert_eq!(base64_str, "SGVsbG8sIHdvcmxkIQ==");

// Base64 decoding
let decoded = decode_base64(&base64_str).unwrap();
assert_eq!(decoded, data);

// Hex encoding
let hex_str = encode_hex(data);
assert_eq!(hex_str, "48656c6c6f2c20776f726c6421");

// Hex decoding
let decoded = decode_hex(&hex_str).unwrap();
assert_eq!(decoded, data);
```

### Decoding with Whitespace

Use `decode_base64_strip_whitespace` to decode base64 strings that may contain spaces, tabs, or newlines:

```rust
use webbuf::decode_base64_strip_whitespace;

let base64_with_whitespace = "SGVs bG8s\nIHdv cmxk IQ==";
let decoded = decode_base64_strip_whitespace(base64_with_whitespace).unwrap();
assert_eq!(decoded, b"Hello, world!");
```

## API

| Function | Description |
|----------|-------------|
| `encode_base64(data: &[u8]) -> String` | Encode bytes to base64 |
| `decode_base64(encoded: &str) -> Result<Vec<u8>, String>` | Decode base64 to bytes |
| `decode_base64_strip_whitespace(encoded: &str) -> Result<Vec<u8>, String>` | Decode base64, ignoring whitespace |
| `encode_hex(data: &[u8]) -> String` | Encode bytes to hex |
| `decode_hex(encoded: &str) -> Result<Vec<u8>, String>` | Decode hex to bytes |

## WebAssembly

This crate compiles to WebAssembly. The TypeScript wrapper is available as `@webbuf/webbuf` on npm.

## License

MIT
