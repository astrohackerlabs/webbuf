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

## Scope

This package authenticates a ciphertext under the recipient's ML-KEM-768 keypair
using AES-256-GCM. It does not bind any external context — the recipient gets
back the plaintext if and only if they hold the matching decapsulation key, but
no other application-level data is verified.

**What this package binds (AES-GCM tag fails on mismatch):**

- The recipient's ML-KEM encapsulation / decapsulation keys (a wrong
  decapsulation key produces a different shared secret per FIPS 203's implicit
  rejection, which produces a wrong AES key, which fails the AES-GCM tag).
- The KEM ciphertext bytes (tampering causes decapsulation to produce a
  different shared secret, same chain).
- The AES-GCM IV and ciphertext bytes (tampering fails the tag directly).
- The wire-format version byte `0x01` (a `0x02` ciphertext from the hybrid
  `@webbuf/aesgcm-p256dh-mlkem` package is rejected up front with a clear
  error).

**What this package does not bind:**

- Sender's federation identity / address (the encrypter does not have a notion
  of "sender" at all — pure-PQ encrypts to the recipient's encapsulation key,
  full stop).
- Recipient's federation identity / address (only the keypair).
- Application protocol version (beyond the wire-format byte).
- Message type — text vs. signed challenge vs. control vs. vault entry all share
  the same key schedule.
- Any transcript, message-ID, or sequence number.

**If you need those bindings:**

- **Avoid (works, ugly):** prepend your context bytes to the plaintext before
  encryption and parse them off after decryption. The cost is that the
  encrypted-vs-authenticated line gets blurry and every consumer reinvents the
  same framing.
- **Recommended (clean):** use the optional `aad` (Additional Authenticated
  Data) parameter — see
  [Authenticated context (AAD)](#authenticated-context-aad) below.

## Authenticated context (AAD)

`aesgcmMlkemEncrypt` and `aesgcmMlkemDecrypt` accept an optional trailing `aad`
parameter (default: empty `WebBuf`). AAD is **authenticated** by AES-GCM but
**not encrypted** and **not transmitted** — the recipient must supply the exact
same bytes the sender used, and any mismatch fails decryption with an AES-GCM
tag error.

```typescript
const aad = WebBuf.fromUtf8("alice@example.com:bob@example.com:v1");

// Sender binds context into the tag
const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext, aad);

// Recipient must supply the same AAD or decryption throws
const recovered = aesgcmMlkemDecrypt(decapsulationKey, ciphertext, aad);
```

Use AAD to bind any context that should be inseparable from the message: the
protocol version, sender / recipient identity, message type, transcript state,
sequence number, or anything else where mismatch should mean "this isn't the
message I think it is."

**Properties:**

- **Backward-compatible.** Calls with no `aad` argument behave identically to
  before (empty AAD is mathematically equivalent to no AAD in AES-GCM). The
  issue 0004 KAT regression (`SHA-256(ciphertext) === 680beaa6...8ef240`) still
  matches byte-for-byte.
- **No wire-format change.** Ciphertext length is unchanged because AAD is not
  transmitted; only the AES-GCM authentication tag changes when AAD is
  non-empty.
- **No key-schedule change.** The HKDF info string and version byte stay the
  same. AAD enters only the GHASH computation, not the AES key derivation.
- **Symmetric requirement.** Sender and recipient must agree on AAD bytes
  exactly — typically derived from a shared protocol or out-of-band metadata.
  Mismatches throw cleanly.

The change was landed in
[issue 0006](../../issues/0006-aad-pq-encryption/README.md), which also
documents the captured non-empty-AAD KAT
(`SHA-256(ciphertext) === f05197b5...5bafc2ab`) asserted in
`test/audit.test.ts`. See
[issue 0005](../../issues/0005-pq-package-followups/README.md) for the original
Scope-section gap that motivated this.

## Tests

- 17 unit tests covering round-trip, size invariants, version byte,
  non-determinism, all rejection paths (wrong recipient, tampered KEM/AES/IV,
  wrong version, truncation), and AAD round-trip / mismatch / missing / extra
  scenarios.
- 5 audit tests asserting both the byte-precise KAT from issue 0004 Experiment 1
  (`SHA-256(ciphertext) === 680beaa6...8ef240`) and the byte-precise non-empty
  AAD KAT from issue 0006 Experiment 2
  (`SHA-256(ciphertext) === f05197b5...5bafc2ab`), plus invariants confirming
  AAD changes only the tag and the explicit empty-AAD path matches the no-AAD
  default byte-for-byte.

```bash
pnpm test
```

## Internal API

`_aesgcmMlkemEncryptDeterministic(encapKey, plaintext, m, iv, aad?)` exists for
KAT regression tests and reproducible fixtures. Application code should never
call it directly — the leading underscore is a marker that the function exposes
deterministic randomness, which is unsafe in production. Use
`aesgcmMlkemEncrypt` instead.

## License

MIT
