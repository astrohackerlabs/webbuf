# webbuf_p256

Elliptic curve P-256 (NIST) for ECDSA signatures and Diffie-Hellman key exchange, for Rust and WebAssembly.

## Installation

```toml
[dependencies]
webbuf_p256 = "0.15"
```

## Usage

### Key Generation

```rust
use webbuf_p256::p256_curve::{
    private_key_verify, public_key_verify, public_key_create
};

// Verify a private key (must be 32 bytes, valid scalar)
let priv_key = [0x01u8; 32];
assert!(private_key_verify(&priv_key));

// Derive public key from private key (compressed, 33 bytes)
let pub_key = public_key_create(&priv_key).unwrap();
assert_eq!(pub_key.len(), 33);

// Verify a public key
assert!(public_key_verify(&pub_key));
```

### Signing and Verification

```rust
use webbuf_p256::p256_curve::{sign, verify, public_key_create};

let priv_key = [0x01u8; 32];
let hash = [0x02u8; 32]; // 32-byte message hash
let k = [0x03u8; 32];    // 32-byte nonce (use RFC 6979 in production!)

// Sign: returns 64-byte signature (r || s)
let signature = sign(&hash, &priv_key, &k).unwrap();
assert_eq!(signature.len(), 64);

// Verify signature
let pub_key = public_key_create(&priv_key).unwrap();
assert!(verify(&signature, &hash, &pub_key).is_ok());
```

### Diffie-Hellman Key Exchange

```rust
use webbuf_p256::p256_curve::{shared_secret, public_key_create};

let alice_priv = [0x01u8; 32];
let bob_priv = [0x02u8; 32];

let alice_pub = public_key_create(&alice_priv).unwrap();
let bob_pub = public_key_create(&bob_priv).unwrap();

// Both parties derive the same shared secret
let secret_a = shared_secret(&alice_priv, &bob_pub).unwrap();
let secret_b = shared_secret(&bob_priv, &alice_pub).unwrap();
assert_eq!(secret_a, secret_b);
```

### Key Addition

```rust
use webbuf_p256::p256_curve::{private_key_add, public_key_add, public_key_create};

let priv1 = [0x01u8; 32];
let priv2 = [0x02u8; 32];

// Add private keys (mod curve order)
let combined_priv = private_key_add(&priv1, &priv2).unwrap();

// Add public keys (point addition)
let pub1 = public_key_create(&priv1).unwrap();
let pub2 = public_key_create(&priv2).unwrap();
let combined_pub = public_key_add(&pub1, &pub2).unwrap();
```

## API

| Function | Description |
|----------|-------------|
| `private_key_verify(key: &[u8]) -> bool` | Check if 32-byte key is valid |
| `public_key_verify(key: &[u8]) -> bool` | Check if 33-byte compressed key is valid |
| `public_key_create(priv_key: &[u8]) -> Result<Vec<u8>, String>` | Derive public key |
| `private_key_add(key1: &[u8], key2: &[u8]) -> Result<Vec<u8>, String>` | Add two private keys |
| `public_key_add(key1: &[u8], key2: &[u8]) -> Result<Vec<u8>, String>` | Add two public keys |
| `sign(hash: &[u8], priv_key: &[u8], k: &[u8]) -> Result<Vec<u8>, String>` | Sign hash with nonce k |
| `verify(sig: &[u8], hash: &[u8], pub_key: &[u8]) -> Result<(), String>` | Verify signature |
| `shared_secret(priv_key: &[u8], pub_key: &[u8]) -> Result<Vec<u8>, String>` | ECDH shared secret |

## WebAssembly

Build with the `wasm` feature for WebAssembly support:

```toml
[dependencies]
webbuf_p256 = { version = "0.15", features = ["wasm"] }
```

The TypeScript wrapper is available as `@webbuf/p256` on npm.

## License

MIT
