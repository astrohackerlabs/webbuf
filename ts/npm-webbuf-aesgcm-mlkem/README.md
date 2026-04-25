# @webbuf/aesgcm-mlkem

AES-256-GCM authenticated encryption with ML-KEM-768 key encapsulation. Pure
post-quantum encryption: the recipient holds an ML-KEM-768 keypair, the sender
encapsulates a fresh shared secret per message, derives an AES-256 key via
HKDF-SHA-256, and encrypts with AES-GCM.

This package is a **TypeScript-only composition** over the existing WebBuf
primitives — no new Rust crate. See
[`issues/0004-hybrid-pq-encryption`](../../issues/0004-hybrid-pq-encryption/README.md)
for the byte-precise specification and the captured KAT vector.

> **Audit posture:** No Rust PQC implementation has received a public
> independent audit yet. This package inherits that risk through
> `@webbuf/mlkem`. Be aware of the unaudited status if shipping this as the sole
> protection on sensitive material; for transitional deployments prefer the
> hybrid `@webbuf/aesgcm-p256dh-mlkem` package which combines this scheme with
> classical P-256 ECDH.

## Preferred API

```typescript
import { aesgcmMlkemEncrypt, aesgcmMlkemDecrypt } from "@webbuf/aesgcm-mlkem";
import { mlKem768KeyPair } from "@webbuf/mlkem";
import { WebBuf } from "@webbuf/webbuf";

// Recipient generates a keypair (once, persistent)
const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();

// Sender encrypts to recipient's encapsulationKey
const plaintext = WebBuf.fromUtf8("hello, post-quantum");
const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);

// Recipient decrypts using decapsulationKey
const recovered = aesgcmMlkemDecrypt(decapsulationKey, ciphertext);
// recovered.toUtf8() === "hello, post-quantum"
```

`aesgcmMlkemEncrypt` is non-deterministic: each call generates fresh ML-KEM
encapsulation randomness and a fresh AES-GCM IV. Two calls with the same inputs
produce different ciphertexts.

## Wire format

| Offset   | Length | Field                                  |
| -------- | ------ | -------------------------------------- |
| 0        | 1      | Version byte: `0x01`                   |
| 1        | 1088   | ML-KEM-768 ciphertext                  |
| 1089     | 12     | AES-GCM IV                             |
| 1101     | N      | AES-GCM ciphertext (N = plaintext.len) |
| 1101 + N | 16     | AES-GCM authentication tag             |

Total fixed overhead: **1117 bytes** per message.

The version byte (`0x01`) lets future format revisions coexist with old
ciphertexts. Feeding a ciphertext from a different scheme (e.g.
`@webbuf/aesgcm-p256dh-mlkem` which uses `0x02`) into `aesgcmMlkemDecrypt` fails
fast with a clear error rather than a silent AEAD-tag mismatch.

## Key derivation

The AES-256 key is derived from the ML-KEM-768 shared secret via HKDF-SHA-256
(RFC 5869, NIST SP 800-56C Rev. 2):

```
salt = 0^32  (32 zero bytes)
info = UTF-8("webbuf:aesgcm-mlkem v1")
PRK  = HMAC-SHA-256(salt, sharedSecret)
K    = HMAC-SHA-256(PRK, info || 0x01)
```

The trailing ` v1` in the info string lets us version the schedule
independently. If we ever revise the KDF or wire format, we bump the info string
to ` v2` and the version byte to `0x02` (or higher) — old ciphertexts decrypt
under the old scheme, new ones under the new.

## Security properties

The package's authentication relies entirely on AES-GCM's tag:

- **Tampered KEM ciphertext** → ML-KEM decapsulation produces a different shared
  secret (per FIPS 203's implicit-rejection design) → wrong AES key → AES-GCM
  tag fails.
- **Tampered AES ciphertext or IV** → AES-GCM tag fails directly.
- **Wrong recipient (different decapsulation key)** → wrong shared secret →
  wrong AES key → AES-GCM tag fails.

In all rejection cases, `aesgcmMlkemDecrypt` throws.

## Tests

- 13 unit tests covering round-trip, size invariants, version byte,
  non-determinism, and all rejection paths (wrong recipient, tampered
  KEM/AES/IV, wrong version, truncation).
- 2 audit tests asserting the byte-precise KAT from issue 0004 Experiment 1:
  `SHA-256(ciphertext) === 680beaa6...8ef240` for the fixed-input fixture.

```bash
pnpm test
```

## Internal API

`_aesgcmMlkemEncryptDeterministic(encapKey, plaintext, m, iv)` exists for KAT
regression tests and reproducible fixtures. Application code should never call
it directly — the leading underscore is a marker that the function exposes
deterministic randomness, which is unsafe in production. Use
`aesgcmMlkemEncrypt` instead.

## License

MIT
