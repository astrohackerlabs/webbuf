# Webbuf Cryptographic Audit Plan

This document outlines the audit strategy for all TypeScript packages in the
webbuf repository.

## Package Overview

| Package             | Type       | Audit Approach                                            |
| ------------------- | ---------- | --------------------------------------------------------- |
| `@webbuf/webbuf`    | Core       | Correctness tests, comparison with standard libraries     |
| `@webbuf/fixedbuf`  | Core       | Correctness tests                                         |
| `@webbuf/numbers`   | Core       | Boundary tests, endianness verification                   |
| `@webbuf/rw`        | Core       | Round-trip tests, boundary conditions                     |
| `@webbuf/blake3`    | Hash       | Official BLAKE3 test vectors                              |
| `@webbuf/sha256`    | Hash       | NIST test vectors, RFC 4231 (HMAC), Web Crypto comparison |
| `@webbuf/ripemd160` | Hash       | Official test vectors from original paper                 |
| `@webbuf/secp256k1` | ECC        | Cross-implementation tests, BIP-340 vectors               |
| `@webbuf/aescbc`    | Cipher     | NIST CAVP test vectors                                    |
| `@webbuf/acb3`      | Encryption | Web Crypto interop (requires audited primitives)          |
| `@webbuf/acb3dh`    | Encryption | Depends on acb3 + secp256k1 audits                        |
| `@webbuf/acs2`      | Encryption | Web Crypto interop (requires audited primitives)          |
| `@webbuf/acs2dh`    | Encryption | Depends on acs2 + secp256k1 audits                        |

---

## Audit Checklist

### @webbuf/webbuf

Core buffer type with hex/base64 encoding.

- [x] Verify hex encoding matches standard (compare with Node.js Buffer)
- [x] Verify base64 encoding matches standard (compare with Node.js Buffer)
- [x] Verify UTF-8 encoding/decoding matches standard
- [x] Test round-trip for all encoding types
- [x] Test edge cases: empty buffers, large buffers, special characters

Audit tests: `ts/npm-webbuf-webbuf/test/audit.test.ts` (76 tests)

### @webbuf/fixedbuf

Fixed-size buffer wrapper.

- [x] Verify size enforcement (reject wrong sizes)
- [x] Verify `fromRandom()` produces correct length
- [x] Test `fromBuf()` with exact size, oversized, and undersized inputs

Audit tests: `ts/npm-webbuf-fixedbuf/test/audit.test.ts` (52 tests)

**BUG FIXED:** `clone()` method was creating a shared view instead of an
independent copy. Fixed by changing `WebBuf.from(this._buf)` to
`new WebBuf(this._buf)` in `fixedbuf.ts:56`.

### @webbuf/numbers

Fixed-size unsigned integers with big/little endian support.

- [ ] Verify U8 boundary values (0, 255)
- [ ] Verify U16BE/U16LE byte ordering with known values
- [ ] Verify U32BE/U32LE byte ordering with known values
- [ ] Verify U64BE/U64LE byte ordering with known values
- [ ] Verify U128BE/U128LE byte ordering with known values
- [ ] Verify U256BE/U256LE byte ordering with known values
- [ ] Test max values for each type
- [ ] Test endianness against Node.js DataView or known test vectors

### @webbuf/rw

Buffer reader/writer utilities.

- [ ] Verify BufWriter produces correct output for all types
- [ ] Verify BufReader reads back what BufWriter wrote
- [ ] Test variable-length integer encoding (if applicable)
- [ ] Test boundary conditions (reading past end of buffer)

### @webbuf/blake3

BLAKE3 hash and MAC.

- [ ] Add official BLAKE3 test vectors from
      https://github.com/BLAKE3-team/BLAKE3
- [ ] Test empty input
- [ ] Test various input lengths (1 byte, 64 bytes, 1024 bytes, etc.)
- [ ] Verify keyed hash (MAC) against official test vectors
- [ ] Compare output with reference implementation or another library

### @webbuf/sha256

SHA-256 hash and HMAC.

- [x] Web Crypto comparison tests (already implemented)
- [ ] Add NIST FIPS 180-4 test vectors for SHA-256
  - URL:
    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
- [ ] Add RFC 4231 test vectors for HMAC-SHA256
  - URL: https://datatracker.ietf.org/doc/html/rfc4231
- [ ] Test empty input
- [ ] Test multi-block inputs (>64 bytes)

### @webbuf/ripemd160

RIPEMD-160 hash.

- [ ] Add test vectors from original RIPEMD-160 paper
  - URL: https://homes.esat.kuleuven.be/~boslat/ripemd160.html
- [ ] Compare with Node.js crypto module or another implementation
- [ ] Test empty input
- [ ] Test the standard test string "abc" → known hash
- [ ] Test the standard test string "message digest" → known hash

### @webbuf/secp256k1

ECDSA signatures and ECDH key exchange.

- [ ] Cross-implementation test: compare with `@noble/secp256k1`
- [ ] Add BIP-340 test vectors for Schnorr signatures (if applicable)
- [ ] Verify `publicKeyCreate()` produces valid compressed public keys
- [ ] Verify `sign()` produces valid DER-encoded signatures
- [ ] Verify `verify()` correctly validates signatures
- [ ] Verify `sharedSecret()` matches other ECDH implementations
- [ ] Test with known private key → known public key pairs
- [ ] Test signature verification with invalid signatures (should fail)

### @webbuf/aescbc

AES-CBC encryption.

- [ ] Add NIST CAVP test vectors for AES-CBC
  - URL:
    https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
  - Test AES-128-CBC, AES-192-CBC, AES-256-CBC
- [ ] Web Crypto interop: encrypt with webbuf, decrypt with Web Crypto
- [ ] Web Crypto interop: encrypt with Web Crypto, decrypt with webbuf
- [ ] Verify IV is correctly prepended/extracted
- [ ] Verify PKCS7 padding is correct
- [ ] Test block-aligned and non-block-aligned plaintexts

### @webbuf/acb3

AES-CBC + BLAKE3 MAC (Encrypt-then-MAC).

Construction: `BLAKE3_MAC (32 bytes) || IV (16 bytes) || ciphertext`

- [ ] Verify MAC is computed over `IV || ciphertext` (not just ciphertext)
- [ ] Single-byte modification to MAC portion causes decryption failure
- [ ] Single-byte modification to IV portion causes decryption failure
- [ ] Single-byte modification to ciphertext portion causes decryption failure
- [ ] Truncated ciphertext is rejected
- [ ] Minimum length enforcement works correctly
- [ ] Cross-verify with manual construction using audited primitives

### @webbuf/acb3dh

ACB3 + ECDH key exchange.

- [x] Basic bidirectional encryption test (Alice↔Bob)
- [ ] Verify derived key matches: `BLAKE3(sharedSecret(alicePriv, bobPub))`
      equals `BLAKE3(sharedSecret(bobPriv, alicePub))`
- [ ] Third party (Eve) cannot decrypt messages
- [ ] Different key pairs produce different shared secrets

### @webbuf/acs2

AES-CBC + SHA-256 HMAC (Encrypt-then-MAC).

Construction: `HMAC_SHA256 (32 bytes) || IV (16 bytes) || ciphertext`

- [ ] Web Crypto interop: encrypt with acs2, decrypt with pure Web Crypto
  - Manually parse `HMAC || IV || ciphertext`
  - Verify HMAC with `crypto.subtle.verify()`
  - Decrypt with `crypto.subtle.decrypt()` (AES-CBC)
- [ ] Web Crypto interop: encrypt with pure Web Crypto, decrypt with acs2
  - Encrypt with `crypto.subtle.encrypt()` (AES-CBC)
  - Compute HMAC with `crypto.subtle.sign()`
  - Assemble as `HMAC || IV || ciphertext`
  - Verify acs2 can decrypt
- [ ] Single-byte modification to MAC portion causes decryption failure
- [ ] Single-byte modification to IV portion causes decryption failure
- [ ] Single-byte modification to ciphertext portion causes decryption failure
- [ ] Truncated ciphertext is rejected
- [x] Wrong key causes decryption failure (implemented)
- [x] Tampered ciphertext causes failure (implemented)

### @webbuf/acs2dh

ACS2 + ECDH key exchange.

- [x] Basic bidirectional encryption test (Alice↔Bob)
- [ ] Verify derived key matches: `SHA256(sharedSecret(alicePriv, bobPub))`
      equals `SHA256(sharedSecret(bobPriv, alicePub))`
- [ ] Third party (Eve) cannot decrypt messages
- [ ] Different key pairs produce different shared secrets
- [x] Wrong keys cause decryption failure (implemented)

---

## Standard References

| Standard        | Description                      | URL                                                                       |
| --------------- | -------------------------------- | ------------------------------------------------------------------------- |
| NIST FIPS 180-4 | SHA-256 specification            | https://csrc.nist.gov/publications/detail/fips/180/4/final                |
| NIST CAVP       | AES test vectors                 | https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program |
| RFC 4231        | HMAC-SHA256 test vectors         | https://datatracker.ietf.org/doc/html/rfc4231                             |
| BLAKE3          | Official test vectors            | https://github.com/BLAKE3-team/BLAKE3                                     |
| RIPEMD-160      | Original specification           | https://homes.esat.kuleuven.be/~bosselaers/ripemd160.html                 |
| BIP-340         | Schnorr signatures for secp256k1 | https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki            |

---

## Audit Priority

### High Priority (Security Critical)

1. `@webbuf/sha256` - RFC 4231 HMAC test vectors
2. `@webbuf/aescbc` - NIST test vectors + Web Crypto interop
3. `@webbuf/acs2` - Web Crypto interoperability tests
4. `@webbuf/secp256k1` - Cross-implementation verification

### Medium Priority

5. `@webbuf/blake3` - Official test vectors
6. `@webbuf/ripemd160` - Standard test vectors
7. `@webbuf/acb3` - Property-based tests (primitives covered by blake3/aescbc)
8. `@webbuf/acs2dh` - Depends on acs2 + secp256k1
9. `@webbuf/acb3dh` - Depends on acb3 + secp256k1

### Lower Priority (Non-Cryptographic)

10. `@webbuf/webbuf` - Encoding correctness
11. `@webbuf/fixedbuf` - Size enforcement
12. `@webbuf/numbers` - Endianness verification
13. `@webbuf/rw` - Round-trip correctness

---

## Notes

- Items marked [x] are already implemented
- The "Encrypt-then-MAC" construction used by acb3 and acs2 is a
  well-established secure pattern
- All cryptographic primitives (AES-CBC, HMAC-SHA256, BLAKE3, secp256k1) are
  industry-standard
- Web Crypto interoperability tests provide strong validation since Web Crypto
  is browser-native and widely audited
- Cross-implementation tests catch subtle bugs that standard test vectors might
  miss
