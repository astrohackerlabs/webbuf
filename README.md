# WebBuf

WebBuf is a modern buffer library for TypeScript/JavaScript with
Rust/WASM-optimized cryptographic operations. It provides a complete toolkit for
binary data manipulation, encoding/decoding, fixed-size buffers, cryptographic
hashing, elliptic curve operations, and authenticated encryption.

## Installation

```bash
npm install webbuf
```

Or install individual packages:

```bash
npm install @webbuf/webbuf @webbuf/fixedbuf @webbuf/sha256 # etc.
```

## Package Overview

| Package                 | Description                                                                   |
| ----------------------- | ----------------------------------------------------------------------------- |
| **Core**                |                                                                               |
| `@webbuf/webbuf`        | Core `WebBuf` class - extended Uint8Array with hex/base64/base32 encoding     |
| `@webbuf/fixedbuf`      | `FixedBuf<N>` - compile-time sized buffer wrapper                             |
| `@webbuf/numbers`       | Fixed-size integers (U8, U16BE, U32LE, U64BE, U128, U256, etc.)               |
| `@webbuf/rw`            | `BufReader` and `BufWriter` for sequential binary I/O                         |
| **Hashing**             |                                                                               |
| `@webbuf/blake3`        | BLAKE3 hash and keyed MAC                                                     |
| `@webbuf/sha256`        | SHA-256 hash and HMAC-SHA256                                                  |
| `@webbuf/ripemd160`     | RIPEMD-160 hash                                                               |
| **Key Derivation**      |                                                                               |
| `@webbuf/pbkdf2-sha256` | PBKDF2-HMAC-SHA256 password-based key derivation                              |
| **Elliptic Curves**     |                                                                               |
| `@webbuf/secp256k1`     | secp256k1 ECDSA signatures and ECDH key exchange                              |
| `@webbuf/p256`          | P-256 (NIST) ECDSA signatures and ECDH key exchange                           |
| **Encryption (CBC)**    |                                                                               |
| `@webbuf/aescbc`        | AES-CBC encryption (no authentication)                                        |
| `@webbuf/acb3`          | AES-CBC + BLAKE3 MAC (authenticated encryption)                               |
| `@webbuf/acs2`          | AES-CBC + SHA-256 HMAC (authenticated encryption)                             |
| `@webbuf/acb3dh`        | ACB3 + secp256k1 ECDH key exchange                                            |
| `@webbuf/acs2dh`        | ACS2 + secp256k1 ECDH key exchange                                            |
| `@webbuf/acb3p256dh`    | ACB3 + P-256 ECDH key exchange                                                |
| `@webbuf/acs2p256dh`    | ACS2 + P-256 ECDH key exchange                                                |
| **Encryption (GCM)**    |                                                                               |
| `@webbuf/aesgcm`        | AES-GCM authenticated encryption (AEAD)                                       |
| `@webbuf/aesgcm-p256dh` | AES-GCM + P-256 ECDH + SHA-256 key derivation (fully NIST-approved)           |
| **Post-Quantum (NIST)** |                                                                               |
| `@webbuf/mlkem`         | ML-KEM (FIPS 203) post-quantum key encapsulation — 512/768/1024               |
| `@webbuf/mldsa`         | ML-DSA (FIPS 204) post-quantum signatures — 44/65/87                          |
| `@webbuf/slhdsa`        | SLH-DSA (FIPS 205) hash-based post-quantum signatures — all 12 parameter sets |

---

## Core Classes

### WebBuf

`WebBuf` extends `Uint8Array` with convenient methods for hex/base64/base32
encoding, concatenation, comparison, and cloning. The encoding methods use
Rust/WASM for performance.

```typescript
import { WebBuf } from "@webbuf/webbuf";

// Creating buffers
const buf1 = WebBuf.alloc(32); // 32 zero bytes
const buf2 = WebBuf.alloc(16, 0xff); // 16 bytes of 0xff
const buf3 = WebBuf.fromHex("deadbeef"); // From hex string
const buf4 = WebBuf.fromBase64("SGVsbG8="); // From base64
const buf5 = WebBuf.fromUtf8("Hello"); // From UTF-8 string
const buf6 = WebBuf.fromArray([1, 2, 3, 4]); // From number array
const buf7 = WebBuf.fromBase32("91JPRV3F"); // From base32 (Crockford default)

// Converting to strings
buf3.toHex(); // "deadbeef"
buf4.toBase64(); // "SGVsbG8="
buf5.toUtf8(); // "Hello"
buf7.toBase32(); // "91JPRV3F" (Crockford default)

// Buffer operations
const combined = WebBuf.concat([buf1, buf2, buf3]);
const cloned = buf1.clone();
const reversed = buf1.toReverse();
const slice = buf1.slice(0, 16);

// Comparison
buf1.equals(buf2); // false
buf1.compare(buf2); // -1, 0, or 1
```

**Key Methods:**

| Static Methods                  | Description                   |
| ------------------------------- | ----------------------------- |
| `WebBuf.alloc(size, fill?)`     | Create buffer of given size   |
| `WebBuf.concat(buffers[])`      | Concatenate multiple buffers  |
| `WebBuf.fromHex(hex)`           | Parse hex string to buffer    |
| `WebBuf.fromBase64(b64)`        | Parse base64 string to buffer |
| `WebBuf.fromBase32(str, opts?)` | Parse base32 string to buffer |
| `WebBuf.fromUtf8(str)`          | Encode UTF-8 string to buffer |
| `WebBuf.fromArray(nums[])`      | Create from number array      |
| `WebBuf.fromUint8Array(arr)`    | Create from Uint8Array        |

| Instance Methods         | Description                   |
| ------------------------ | ----------------------------- |
| `toHex()`                | Convert to hex string         |
| `toBase64()`             | Convert to base64 string      |
| `toBase32(opts?)`        | Convert to base32 string      |
| `toUtf8()`               | Decode as UTF-8 string        |
| `clone()`                | Create a copy                 |
| `toReverse()`            | Create reversed copy          |
| `slice(start?, end?)`    | Get slice (returns WebBuf)    |
| `subarray(start?, end?)` | Get subarray (returns WebBuf) |
| `equals(other)`          | Check equality                |
| `compare(other)`         | Compare (-1, 0, 1)            |

---

### FixedBuf<N>

`FixedBuf<N>` wraps a `WebBuf` with compile-time size enforcement. This is
essential for cryptographic operations where buffer sizes must be exact (32-byte
keys, 64-byte signatures, etc.).

```typescript
import { FixedBuf } from "@webbuf/fixedbuf";

// Creating fixed-size buffers
const key = FixedBuf.alloc<32>(32); // 32 zero bytes
const iv = FixedBuf.alloc<16>(16, 0xff); // 16 bytes of 0xff
const hash = FixedBuf.fromHex<32>(32, "ba7816bf8f01cfea..."); // From hex (must be exactly 32 bytes)
const random = FixedBuf.fromRandom<32>(32); // 32 cryptographically random bytes

// Shortcut
const key = FixedBuf.alloc(32); // 32 zero bytes
const iv = FixedBuf.alloc(16, 0xff); // 16 bytes of 0xff
const hash = FixedBuf.fromHex(32, "ba7816bf8f01cfea..."); // From hex (must be exactly 32 bytes)
const random = FixedBuf.fromRandom(32); // 32 cryptographically random bytes

// Access underlying WebBuf
const webBuf: WebBuf = key.buf;

// Converting to strings
hash.toHex(); // Returns hex string
hash.toBase64(); // Returns base64 string

// Clone and reverse
const cloned = key.clone();
const reversed = key.toReverse();
```

**Key Methods:**

| Static Methods                          | Description                         |
| --------------------------------------- | ----------------------------------- |
| `FixedBuf.alloc<N>(size, fill?)`        | Create fixed buffer of size N       |
| `FixedBuf.fromBuf<N>(size, webBuf)`     | Wrap WebBuf (throws if wrong size)  |
| `FixedBuf.fromHex<N>(size, hex)`        | Parse hex (throws if wrong size)    |
| `FixedBuf.fromBase64(size, b64)`        | Parse base64 (throws if wrong size) |
| `FixedBuf.fromBase32(size, str, opts?)` | Parse base32 (throws if wrong size) |
| `FixedBuf.fromRandom<N>(size)`          | Generate N random bytes             |

| Instance Properties/Methods | Description              |
| --------------------------- | ------------------------ |
| `buf`                       | Get underlying WebBuf    |
| `toHex()`                   | Convert to hex string    |
| `toBase64()`                | Convert to base64 string |
| `toBase32(opts?)`           | Convert to base32 string |
| `clone()`                   | Create a copy            |
| `toReverse()`               | Create reversed copy     |

**Common Fixed Sizes:**

| Size           | Common Use                                           |
| -------------- | ---------------------------------------------------- |
| `FixedBuf<12>` | AES-GCM nonce                                        |
| `FixedBuf<16>` | AES-CBC IV, AES-128 key, UUIDs                       |
| `FixedBuf<20>` | RIPEMD-160 hash                                      |
| `FixedBuf<32>` | SHA-256 hash, BLAKE3 hash, private keys, AES-256 key |
| `FixedBuf<33>` | Compressed public key (secp256k1, P-256)             |
| `FixedBuf<64>` | ECDSA signature                                      |

---

## Numbers (@webbuf/numbers)

Fixed-size unsigned integers with big-endian (BE) and little-endian (LE)
variants. All types follow the same pattern.

```typescript
import {
  U8,
  U16BE,
  U16LE,
  U32BE,
  U32LE,
  U64BE,
  U64LE,
  U128BE,
  U256BE,
} from "@webbuf/numbers";

// Create from number or bigint
const a = U32BE.fromN(1000);
const b = U64BE.fromBn(0x123456789abcdef0n);

// Arithmetic
const sum = a.add(U32BE.fromN(500));
const diff = a.sub(U32BE.fromN(100));
const product = a.mul(U32BE.fromN(2));
const quotient = a.div(U32BE.fromN(10));

// Access value
a.n; // As number
a.bn; // As bigint

// Buffer conversion
const beBuf = a.toBEBuf(); // FixedBuf in big-endian
const leBuf = a.toLEBuf(); // FixedBuf in little-endian
const restored = U32BE.fromBEBuf(beBuf);

// Hex conversion
a.toHex(); // "000003e8"
U32BE.fromHex("000003e8"); // Parse hex
```

**Available Types:**

| Type   | Size     | Variants           |
| ------ | -------- | ------------------ |
| `U8`   | 1 byte   | (no endianness)    |
| `U16`  | 2 bytes  | `U16BE`, `U16LE`   |
| `U32`  | 4 bytes  | `U32BE`, `U32LE`   |
| `U64`  | 8 bytes  | `U64BE`, `U64LE`   |
| `U128` | 16 bytes | `U128BE`, `U128LE` |
| `U256` | 32 bytes | `U256BE`, `U256LE` |

All types have: `fromN()`, `fromBn()`, `fromBEBuf()`, `fromLEBuf()`,
`fromHex()`, `toBEBuf()`, `toLEBuf()`, `toHex()`, `add()`, `sub()`, `mul()`,
`div()`, `.n`, `.bn`

---

## Buffer I/O (@webbuf/rw)

Sequential reading and writing of binary data.

```typescript
import { BufReader, BufWriter } from "@webbuf/rw";

// Writing
const writer = new BufWriter();
writer.writeU8(new U8(255));
writer.writeU32BE(new U32BE(123456));
writer.writeFixed(someFixedBuf);
const result = writer.toBuf();

// Reading
const reader = new BufReader(result);
const u8 = reader.readU8();
const u32 = reader.readU32BE();
const fixed = reader.readFixed<32>(32);
reader.eof(); // true if at end
reader.remainder(); // remaining bytes
```

---

## Hashing

### BLAKE3 (@webbuf/blake3)

```typescript
import { blake3Hash, doubleBlake3Hash, blake3Mac } from "@webbuf/blake3";

const data = WebBuf.fromUtf8("Hello");
const hash = blake3Hash(data); // FixedBuf<32>
const double = doubleBlake3Hash(data); // FixedBuf<32>

const key = FixedBuf.fromRandom<32>(32);
const mac = blake3Mac(key, data); // FixedBuf<32>
```

### SHA-256 (@webbuf/sha256)

```typescript
import { sha256Hash, doubleSha256Hash, sha256Hmac } from "@webbuf/sha256";

const data = WebBuf.fromUtf8("abc");
const hash = sha256Hash(data); // FixedBuf<32>
const double = doubleSha256Hash(data); // FixedBuf<32> (used in Bitcoin)

const key = WebBuf.fromUtf8("secret");
const hmac = sha256Hmac(key, data); // FixedBuf<32>
```

### RIPEMD-160 (@webbuf/ripemd160)

```typescript
import { ripemd160Hash, doubleRipemd160Hash } from "@webbuf/ripemd160";

const data = WebBuf.fromUtf8("Hello");
const hash = ripemd160Hash(data); // FixedBuf<20>
const double = doubleRipemd160Hash(data); // FixedBuf<20>
```

### PBKDF2-HMAC-SHA256 (@webbuf/pbkdf2-sha256)

```typescript
import { pbkdf2Sha256 } from "@webbuf/pbkdf2-sha256";

const password = WebBuf.fromUtf8("my password");
const salt = WebBuf.fromUtf8("random salt");
const derivedKey = pbkdf2Sha256(password, salt, 100_000, 32); // FixedBuf<32>
```

---

## Elliptic Curves

### secp256k1 (@webbuf/secp256k1)

ECDSA signatures and ECDH key exchange on the secp256k1 curve.

```typescript
import {
  privateKeyVerify,
  publicKeyVerify,
  publicKeyCreate,
  privateKeyAdd,
  publicKeyAdd,
  sign,
  verify,
  sharedSecret,
} from "@webbuf/secp256k1";

// Key generation
const privKey = FixedBuf.fromRandom<32>(32);
privateKeyVerify(privKey); // true if valid
const pubKey = publicKeyCreate(privKey); // FixedBuf<33> (compressed)
publicKeyVerify(pubKey); // true if valid

// Key addition (for HD wallets, stealth addresses, etc.)
const combined = privateKeyAdd(privKey1, privKey2); // FixedBuf<32>
const combinedPub = publicKeyAdd(pubKey1, pubKey2); // FixedBuf<33>

// Signing (requires 32-byte hash and 32-byte nonce k)
const messageHash = sha256Hash(WebBuf.fromUtf8("message"));
const k = FixedBuf.fromRandom<32>(32); // Use RFC 6979 in production!
const signature = sign(messageHash, privKey, k); // FixedBuf<64>

// Verification
verify(signature, messageHash, pubKey); // true if valid

// Diffie-Hellman shared secret
const alicePriv = FixedBuf.fromRandom<32>(32);
const bobPriv = FixedBuf.fromRandom<32>(32);
const alicePub = publicKeyCreate(alicePriv);
const bobPub = publicKeyCreate(bobPriv);
const secretA = sharedSecret(alicePriv, bobPub); // FixedBuf<33>
const secretB = sharedSecret(bobPriv, alicePub); // Same as secretA
```

### P-256 / NIST (@webbuf/p256)

ECDSA signatures and ECDH key exchange on the NIST P-256 curve. Same API shape
as secp256k1, with `p256` prefix on all functions.

```typescript
import {
  p256PrivateKeyVerify,
  p256PublicKeyVerify,
  p256PublicKeyCreate,
  p256PrivateKeyAdd,
  p256PublicKeyAdd,
  p256Sign,
  p256Verify,
  p256SharedSecret,
} from "@webbuf/p256";

const privKey = FixedBuf.fromRandom<32>(32);
const pubKey = p256PublicKeyCreate(privKey); // FixedBuf<33>

const signature = p256Sign(messageHash, privKey, k); // FixedBuf<64>
p256Verify(signature, messageHash, pubKey); // true if valid

const shared = p256SharedSecret(alicePriv, bobPub); // FixedBuf<33>
```

---

## Post-Quantum Cryptography

WebBuf ships all three NIST-finalized post-quantum algorithms (FIPS 203, 204,
205, finalized August 13, 2024). All three wrap the corresponding RustCrypto
crates (`ml-kem`, `ml-dsa`, `slh-dsa`) and validate against the official NIST
ACVP-Server test vectors.

> **Audit posture:** No Rust PQC implementation has received a public
> independent audit yet. The packages are appropriate for early adoption,
> hybrid-with-classical deployments, and post-quantum readiness work — be aware
> of the unaudited status if you ship them as the sole protection on sensitive
> material.

### ML-KEM (@webbuf/mlkem)

Key encapsulation mechanism per FIPS 203 (formerly CRYSTALS-Kyber). Lattice-
based; replaces ECDH for post-quantum key exchange. Three parameter sets:
ML-KEM-512 (Category 1), ML-KEM-768 (Category 3), ML-KEM-1024 (Category 5).

```typescript
import {
  mlKem768KeyPair,
  mlKem768Encapsulate,
  mlKem768Decapsulate,
  ML_KEM_768,
} from "@webbuf/mlkem";

// Generate keypair
const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
// encapsulationKey: FixedBuf<1184>, decapsulationKey: FixedBuf<2400>

// Encapsulate (sender side)
const { ciphertext, sharedSecret } = mlKem768Encapsulate(encapsulationKey);
// ciphertext: FixedBuf<1088>, sharedSecret: FixedBuf<32>

// Decapsulate (recipient side) — recovers the same shared secret
const recovered = mlKem768Decapsulate(decapsulationKey, ciphertext);
// recovered.toHex() === sharedSecret.toHex()
```

ML-KEM-512 and ML-KEM-1024 follow the same shape with `mlKem512*` / `mlKem1024*`
and the corresponding `ML_KEM_512` / `ML_KEM_1024` size constants.
Use `mlKem*KeyPairDeterministic` and `mlKem*EncapsulateDeterministic` when you
need reproducible FIPS 203 / ACVP vector behavior with caller-supplied seeds.

### ML-DSA (@webbuf/mldsa)

Digital signatures per FIPS 204 (formerly CRYSTALS-Dilithium). Lattice-based;
the default general-purpose post-quantum signature scheme. Three parameter sets:
ML-DSA-44, ML-DSA-65, ML-DSA-87.

```typescript
import {
  mlDsa65KeyPair,
  mlDsa65Sign,
  mlDsa65Verify,
  ML_DSA_65,
} from "@webbuf/mldsa";

const message = WebBuf.fromUtf8("authenticated message");
const context = WebBuf.fromUtf8("example domain");

// KeyGen
const { verifyingKey, signingKey } = mlDsa65KeyPair();
// verifyingKey: FixedBuf<1952>, signingKey: FixedBuf<4032>

// Sign (hedged by default using platform CSPRNG randomness)
const signature = mlDsa65Sign(signingKey, message, context);
// signature: FixedBuf<3309>

// Verify
mlDsa65Verify(verifyingKey, message, signature, context); // true
```

ML-DSA-44 and ML-DSA-87 use the same API shape with `mlDsa44*` / `mlDsa87*`.
Use `mlDsa*SignDeterministic` for reproducible message-level signatures and
`mlDsa*SignInternal` / `mlDsa*VerifyInternal` only for ACVP vectors or low-level
FIPS 204 conformance work.

### SLH-DSA (@webbuf/slhdsa)

Hash-based digital signatures per FIPS 205 (formerly SPHINCS+). Security rests
only on hash function strength — the conservative hedge against any structural
break in lattice cryptography. All 12 parameter sets are exposed: SHA2 / SHAKE ×
128 / 192 / 256-bit security × `s` (small signature, slow) / `f` (fast signing,
larger signature).

```typescript
import {
  slhDsaSha2_128fKeyPair,
  slhDsaSha2_128fSign,
  slhDsaSha2_128fVerify,
  SLH_DSA_SHA2_128F,
} from "@webbuf/slhdsa";

const message = WebBuf.fromUtf8("hash-based signature");
const context = WebBuf.fromUtf8("example domain");

const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPair();
// verifyingKey: FixedBuf<32>, signingKey: FixedBuf<64>

// Sign (hedged by default using platform CSPRNG randomness)
const signature = slhDsaSha2_128fSign(signingKey, message, context);
// signature: FixedBuf<17088>

slhDsaSha2_128fVerify(verifyingKey, message, signature, context); // true
```

The other 11 parameter sets follow the same `slhDsa{Sha2,Shake}_{NNN}{s,f}*`
naming with corresponding size constants (`SLH_DSA_{SHA2,SHAKE}_{NNN}{S,F}`).
Use `slhDsa*SignDeterministic` for reproducible message-level signatures and
`slhDsa*SignInternal` / `slhDsa*VerifyInternal` only for ACVP vectors or
low-level FIPS 205 conformance work.

**Tradeoffs at a glance:**

| Variant           | Sig size  | Speed        | When to use                             |
| ----------------- | --------- | ------------ | --------------------------------------- |
| `s` (small)       | 7.9–30 KB | slow signing | Storage-constrained verifiers           |
| `f` (fast)        | 17–50 KB  | fast signing | Bandwidth-constrained signers           |
| 128 vs 192 vs 256 | varies    | varies       | Match to AES-equivalent security target |

---

## Encryption

### AES-CBC (@webbuf/aescbc)

Low-level AES-CBC. **No authentication** - use `@webbuf/acb3` for authenticated
encryption.

```typescript
import { aescbcEncrypt, aescbcDecrypt } from "@webbuf/aescbc";

const key = FixedBuf.fromRandom<32>(32); // AES-256
const iv = FixedBuf.fromRandom<16>(16); // Optional, random if not provided
const plaintext = WebBuf.fromUtf8("Secret");

const ciphertext = aescbcEncrypt(plaintext, key, iv); // IV prepended
const decrypted = aescbcDecrypt(ciphertext, key); // Extracts IV automatically
```

### ACB3 - Authenticated Encryption (@webbuf/acb3)

AES-CBC + BLAKE3 MAC. Provides both encryption and authentication.

```typescript
import { acb3Encrypt, acb3Decrypt } from "@webbuf/acb3";

const key = FixedBuf.fromRandom<32>(32);
const plaintext = WebBuf.fromUtf8("Secret message");

const ciphertext = acb3Encrypt(plaintext, key);

try {
  const decrypted = acb3Decrypt(ciphertext, key);
  // Success - data is authentic
} catch (e) {
  // Authentication failed - data was tampered
}
```

### ACB3DH - Authenticated Encryption with Key Exchange (@webbuf/acb3dh)

Combines ECDH key derivation with ACB3 encryption.

```typescript
import { acb3dhEncrypt, acb3dhDecrypt } from "@webbuf/acb3dh";
import { publicKeyCreate } from "@webbuf/secp256k1";

const alicePriv = FixedBuf.fromRandom<32>(32);
const alicePub = publicKeyCreate(alicePriv);
const bobPriv = FixedBuf.fromRandom<32>(32);
const bobPub = publicKeyCreate(bobPriv);

// Alice encrypts to Bob
const ciphertext = acb3dhEncrypt(
  alicePriv,
  bobPub,
  WebBuf.fromUtf8("Hello Bob!"),
);

// Bob decrypts from Alice
const plaintext = acb3dhDecrypt(bobPriv, alicePub, ciphertext);
```

### ACS2 - Authenticated Encryption (@webbuf/acs2)

AES-CBC encryption with SHA-256 HMAC authentication. Uses the Encrypt-then-MAC
pattern for secure authenticated encryption.

```typescript
import { acs2Encrypt, acs2Decrypt } from "@webbuf/acs2";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

const key = FixedBuf.fromRandom<32>(32);
const plaintext = WebBuf.fromUtf8("Secret message");

// Encrypt (IV generated automatically if not provided)
const ciphertext = acs2Encrypt(plaintext, key);

// Decrypt with authentication verification
try {
  const decrypted = acs2Decrypt(ciphertext, key);
  // Success - data is authentic
} catch (e) {
  // Authentication failed - data was tampered
}
```

### ACS2DH - Authenticated Encryption with Key Exchange (@webbuf/acs2dh)

Combines ECDH key derivation with ACS2 encryption. The shared secret is hashed
with SHA-256 to derive the encryption key.

```typescript
import { acs2dhEncrypt, acs2dhDecrypt } from "@webbuf/acs2dh";
import { publicKeyCreate } from "@webbuf/secp256k1";

const alicePriv = FixedBuf.fromRandom<32>(32);
const alicePub = publicKeyCreate(alicePriv);
const bobPriv = FixedBuf.fromRandom<32>(32);
const bobPub = publicKeyCreate(bobPriv);

// Alice encrypts to Bob
const ciphertext = acs2dhEncrypt(
  alicePriv,
  bobPub,
  WebBuf.fromUtf8("Hello Bob!"),
);

// Bob decrypts from Alice
const plaintext = acs2dhDecrypt(bobPriv, alicePub, ciphertext);
```

### P-256 DH Variants (@webbuf/acb3p256dh, @webbuf/acs2p256dh)

Same as ACB3DH and ACS2DH, but using the P-256 (NIST) curve instead of
secp256k1.

```typescript
import { acb3p256dhEncrypt, acb3p256dhDecrypt } from "@webbuf/acb3p256dh";
import { acs2p256dhEncrypt, acs2p256dhDecrypt } from "@webbuf/acs2p256dh";
import { p256PublicKeyCreate } from "@webbuf/p256";

const alicePriv = FixedBuf.fromRandom<32>(32);
const alicePub = p256PublicKeyCreate(alicePriv);
const bobPriv = FixedBuf.fromRandom<32>(32);
const bobPub = p256PublicKeyCreate(bobPriv);

const ciphertext = acb3p256dhEncrypt(
  alicePriv,
  bobPub,
  WebBuf.fromUtf8("Hello!"),
);
const plaintext = acb3p256dhDecrypt(bobPriv, alicePub, ciphertext);
```

### AES-GCM (@webbuf/aesgcm)

AES-GCM authenticated encryption (AEAD). No separate MAC needed.

```typescript
import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";

const key = FixedBuf.fromRandom<32>(32); // AES-256
const plaintext = WebBuf.fromUtf8("Secret");

const ciphertext = aesgcmEncrypt(plaintext, key); // Nonce prepended, tag appended
const decrypted = aesgcmDecrypt(ciphertext, key); // Verifies auth tag
```

### AES-GCM + P-256 DH (@webbuf/aesgcm-p256dh)

Fully NIST-approved construction: P-256 ECDH + SHA-256 key derivation +
AES-256-GCM.

```typescript
import {
  aesgcmP256dhEncrypt,
  aesgcmP256dhDecrypt,
} from "@webbuf/aesgcm-p256dh";
import { p256PublicKeyCreate } from "@webbuf/p256";

const alicePriv = FixedBuf.fromRandom<32>(32);
const alicePub = p256PublicKeyCreate(alicePriv);
const bobPriv = FixedBuf.fromRandom<32>(32);
const bobPub = p256PublicKeyCreate(bobPriv);

const ciphertext = aesgcmP256dhEncrypt(
  alicePriv,
  bobPub,
  WebBuf.fromUtf8("Hello Bob!"),
);
const plaintext = aesgcmP256dhDecrypt(bobPriv, alicePub, ciphertext);
```

---

## Common Patterns

### Working with Hex Strings

```typescript
// WebBuf: variable-length hex
const buf = WebBuf.fromHex("deadbeef0102030405");
buf.toHex(); // "deadbeef0102030405"

// FixedBuf: fixed-length hex (must match size exactly)
const hash = FixedBuf.fromHex<32>(
  32,
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
);
hash.toHex(); // Same 64-char hex string
```

### Working with Base32

Base32 encoding is useful for human-readable identifiers like UUIDs. It's more
compact than hex (26 chars vs 32 for a UUID) and avoids ambiguous characters.

```typescript
// Base32 encoding (Crockford default - case-insensitive, URL-safe)
const uuid = FixedBuf.fromRandom<16>(16);
uuid.toBase32(); // "5WJPRV3FKZB1M8Q4C6A0ERSN7Y" (26 chars)
uuid.toHex(); // "2d93a6b1f5..." (32 chars)

// Parsing is case-insensitive for Crockford (I/L → 1, O → 0)
WebBuf.fromBase32("5wjprv3f"); // Same as "5WJPRV3F"
WebBuf.fromBase32("O1IL"); // Parsed as "0111"

// Different alphabets
buf.toBase32({ alphabet: "Rfc4648" }); // Standard RFC 4648 (with padding)
buf.toBase32({ alphabet: "Rfc4648", padding: false }); // Without padding
buf.toBase32({ alphabet: "Rfc4648Lower" }); // Lowercase RFC 4648
buf.toBase32({ alphabet: "Z" }); // z-base-32

// Supported alphabets:
// - "Crockford" (default): 0-9 A-Z excluding I L O U, case-insensitive
// - "Rfc4648": A-Z 2-7 with padding
// - "Rfc4648Lower": a-z 2-7 with padding
// - "Rfc4648Hex": 0-9 A-V with padding
// - "Rfc4648HexLower": 0-9 a-v with padding
// - "Z": z-base-32 (optimized for human readability)
```

### Generating Random Data

```typescript
// Fixed-size random (most common for crypto)
const key = FixedBuf.fromRandom<32>(32); // 32-byte key
const iv = FixedBuf.fromRandom<16>(16); // 16-byte IV
const nonce = FixedBuf.fromRandom<32>(32); // 32-byte nonce

// Variable-size random
const random = WebBuf.alloc(64);
crypto.getRandomValues(random);
```

### Type-Safe Cryptographic Operations

```typescript
// Functions enforce correct buffer sizes at compile time
function encryptMessage(
  key: FixedBuf<32>,
  iv: FixedBuf<16>,
  plaintext: WebBuf,
): WebBuf {
  return aescbcEncrypt(plaintext, key, iv);
}

// Hash outputs are always the correct size
const sha256: FixedBuf<32> = sha256Hash(data);
const blake3: FixedBuf<32> = blake3Hash(data);
const ripemd: FixedBuf<20> = ripemd160Hash(data);
```

---

## Repository Structure

```
webbuf/
├── rs/                              # Rust crates (compiled to WASM)
│   ├── webbuf/                      # Base64/hex encoding
│   ├── webbuf_blake3/               # BLAKE3
│   ├── webbuf_sha256/               # SHA-256
│   ├── webbuf_ripemd160/            # RIPEMD-160
│   ├── webbuf_secp256k1/            # secp256k1
│   ├── webbuf_p256/                 # P-256 (NIST)
│   ├── webbuf_aescbc/               # AES-CBC
│   ├── webbuf_aesgcm/               # AES-GCM
│   ├── webbuf_pbkdf2_sha256/        # PBKDF2-HMAC-SHA256
│   ├── webbuf_mlkem/                # ML-KEM (FIPS 203)
│   ├── webbuf_mldsa/                # ML-DSA (FIPS 204)
│   └── webbuf_slhdsa/               # SLH-DSA (FIPS 205)
└── ts/                              # TypeScript packages
    ├── npm-webbuf-webbuf/           # @webbuf/webbuf
    ├── npm-webbuf-fixedbuf/         # @webbuf/fixedbuf
    ├── npm-webbuf-numbers/          # @webbuf/numbers
    ├── npm-webbuf-rw/               # @webbuf/rw
    ├── npm-webbuf-blake3/           # @webbuf/blake3
    ├── npm-webbuf-sha256/           # @webbuf/sha256
    ├── npm-webbuf-ripemd160/        # @webbuf/ripemd160
    ├── npm-webbuf-pbkdf2-sha256/    # @webbuf/pbkdf2-sha256
    ├── npm-webbuf-secp256k1/        # @webbuf/secp256k1
    ├── npm-webbuf-p256/             # @webbuf/p256
    ├── npm-webbuf-aescbc/           # @webbuf/aescbc
    ├── npm-webbuf-aesgcm/           # @webbuf/aesgcm
    ├── npm-webbuf-acb3/             # @webbuf/acb3
    ├── npm-webbuf-acb3dh/           # @webbuf/acb3dh
    ├── npm-webbuf-acb3p256dh/       # @webbuf/acb3p256dh
    ├── npm-webbuf-acs2/             # @webbuf/acs2
    ├── npm-webbuf-acs2dh/           # @webbuf/acs2dh
    ├── npm-webbuf-acs2p256dh/       # @webbuf/acs2p256dh
    ├── npm-webbuf-aesgcm-p256dh/    # @webbuf/aesgcm-p256dh
    ├── npm-webbuf-mlkem/            # @webbuf/mlkem
    ├── npm-webbuf-mldsa/            # @webbuf/mldsa
    ├── npm-webbuf-slhdsa/           # @webbuf/slhdsa
    └── npm-webbuf/                  # webbuf (re-exports all)
```

## Security Audits

The webbuf library undergoes rigorous security auditing to verify correctness of
all cryptographic implementations. Each package is tested against official test
vectors, cross-verified with trusted implementations, and checked for proper
security properties.

| Audit                                      | Date     | Packages | Tests | Bugs Found |
| ------------------------------------------ | -------- | -------- | ----- | ---------- |
| [December 2025](./audits/2025-12-audit.md) | Dec 2025 | 13       | 598   | 2 (fixed)  |

For more information about our audit process and methodology, see the
[audits README](./audits/README.md).

## License

MIT
