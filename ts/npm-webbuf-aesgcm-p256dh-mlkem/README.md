# @webbuf/aesgcm-p256dh-mlkem

Hybrid classical + post-quantum authenticated encryption: AES-256-GCM keyed by
an HKDF-SHA-256 derivation over **both** a P-256 ECDH shared secret and an
ML-KEM-768 shared secret. An attacker must break both P-256 and ML-KEM to
recover the AES key — secure against today's classical adversaries and the
harvest-now-decrypt-later quantum threat.

This package is a **TypeScript-only composition** over the existing WebBuf
primitives — no new Rust crate. See
[`issues/0004-hybrid-pq-encryption`](../../issues/0004-hybrid-pq-encryption/README.md)
for the byte-precise specification and the captured KAT vector.

> **When to use which package:**
>
> - `@webbuf/aesgcm-mlkem` — pure post-quantum. Smaller wire format, no
>   classical fallback. Choose when you trust the lattice assumption and want
>   the simpler scheme.
> - `@webbuf/aesgcm-p256dh-mlkem` — hybrid. Defense in depth: the AES key
>   depends on both ECDH and ML-KEM. **Recommended for transitional
>   deployments** while ML-KEM remains pre-1.0 and unaudited in the Rust
>   ecosystem.

## Preferred API

```typescript
import {
  aesgcmP256dhMlkemEncrypt,
  aesgcmP256dhMlkemDecrypt,
} from "@webbuf/aesgcm-p256dh-mlkem";
import { mlKem768KeyPair } from "@webbuf/mlkem";
import { p256PublicKeyCreate } from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

// Both parties have persistent (static-static) P-256 keypairs
const senderPriv = FixedBuf.fromRandom<32>(32);
const senderPub = p256PublicKeyCreate(senderPriv);
const recipientPriv = FixedBuf.fromRandom<32>(32);
const recipientPub = p256PublicKeyCreate(recipientPriv);

// Recipient holds an ML-KEM-768 keypair too
const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();

// Sender encrypts using its own P-256 priv, recipient's P-256 pub,
// recipient's ML-KEM encapsulation key
const plaintext = WebBuf.fromUtf8("hybrid encryption");
const ciphertext = aesgcmP256dhMlkemEncrypt(
  senderPriv,
  recipientPub,
  encapsulationKey,
  plaintext,
);

// Recipient decrypts using its own P-256 priv, sender's P-256 pub,
// own ML-KEM decapsulation key
const recovered = aesgcmP256dhMlkemDecrypt(
  recipientPriv,
  senderPub,
  decapsulationKey,
  ciphertext,
);
```

The static-static design means both parties must already know each other's
persistent P-256 public keys (out-of-band — same as `@webbuf/aesgcm-p256dh`). No
ephemeral key on the wire; if you want forward secrecy on the classical side,
that's a different scheme.

## Wire format

Identical layout to `@webbuf/aesgcm-mlkem`, distinguished by version byte:

| Offset   | Length | Field                                  |
| -------- | ------ | -------------------------------------- |
| 0        | 1      | Version byte: `0x02`                   |
| 1        | 1088   | ML-KEM-768 ciphertext                  |
| 1089     | 12     | AES-GCM IV                             |
| 1101     | N      | AES-GCM ciphertext (N = plaintext.len) |
| 1101 + N | 16     | AES-GCM authentication tag             |

Total fixed overhead: **1117 bytes** per message.

The version byte (`0x02`) lets `aesgcmP256dhMlkemDecrypt` reject a ciphertext
from `@webbuf/aesgcm-mlkem` (which uses `0x01`) with a clear error, instead of
failing silently with an AEAD-tag mismatch.

## Key derivation

The AES-256 key is derived from the concatenation of both shared secrets via
HKDF-SHA-256 (RFC 5869, NIST SP 800-56C Rev. 2):

```
ecdhRaw = raw 32-byte ECDH X-coordinate (NIST SP 800-56A Z value)
kemSS   = ML-KEM-768 shared secret (32 bytes)
ikm     = ecdhRaw || kemSS   (64 bytes; classical first, PQ second)
salt    = 0^32  (32 zero bytes)
info    = UTF-8("webbuf:aesgcm-p256dh-mlkem v1")
PRK     = HMAC-SHA-256(salt, ikm)
K       = HMAC-SHA-256(PRK, info || 0x01)
```

The classical-first IKM ordering matches both Signal PQXDH and the IETF
`draft-ietf-tls-hybrid-design` convention. The trailing ` v1` in the info string
lets us version the schedule independently of the package version.

## Security properties

- **Both shared secrets are required.** The HKDF input concatenates the ECDH
  X-coordinate with the ML-KEM shared secret; an attacker must recover both to
  compute the AES key. This is verified by the defense-in-depth tests:
  - Wrong ML-KEM key with right P-256 keys → fails (proves ML-KEM is
    load-bearing).
  - Right ML-KEM key with wrong P-256 inputs → fails (proves P-256 is
    load-bearing).
- **Tampering authenticated by AES-GCM.** Tampered KEM ciphertext produces a
  wrong shared secret (per FIPS 203 implicit rejection), which produces a wrong
  AES key, which fails the AES-GCM tag. Tampered AES ciphertext or IV fails the
  tag directly.
- **Wrong-recipient and wrong-sender rejection.** Decrypting with the wrong
  P-256 recipient priv, the wrong P-256 sender pub, or the wrong ML-KEM
  decapsulation key all fail with AES-GCM tag errors.

In all rejection cases, `aesgcmP256dhMlkemDecrypt` throws.

## Tests

- 16 unit tests covering round-trip, size invariants, version byte,
  non-determinism, and all rejection paths.
- 1 KAT regression test asserting the byte-precise ciphertext from issue 0004
  Experiment 1: `SHA-256(ciphertext) === c689ccce...a02b6d`.
- 2 hybrid defense-in-depth tests confirming both shared secrets are
  load-bearing.
- 2 audit tests verifying the KAT recipient public-key derivation and the
  wire-format prefix bytes.

```bash
pnpm test
```

## Internal API

`_aesgcmP256dhMlkemEncryptDeterministic(senderPriv, recipientPub, encapKey, plaintext, m, iv)`
exists for KAT regression tests and reproducible fixtures. Application code
should never call it directly — the leading underscore signals deterministic
randomness, which is unsafe in production. Use `aesgcmP256dhMlkemEncrypt`
instead.

## License

MIT
