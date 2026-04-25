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

## Scope

This package authenticates a ciphertext under both the sender↔recipient P-256
ECDH static-static pair and the recipient's ML-KEM-768 keypair, using
AES-256-GCM. The AES key is derived from the concatenation of both shared
secrets via HKDF-SHA-256 — an attacker must break **both** P-256 and ML-KEM to
recover it. But the package does not bind any external context beyond the keys
themselves.

**What this package binds (AES-GCM tag fails on mismatch):**

- The sender's and recipient's P-256 keypairs (any wrong key on either side →
  wrong ECDH X-coordinate → wrong AES key → AES-GCM tag fails). Hybrid
  defense-in-depth tests confirm the ECDH contribution is load-bearing.
- The recipient's ML-KEM encapsulation / decapsulation keys (per FIPS 203
  implicit rejection, same chain). Hybrid defense-in-depth tests confirm the
  ML-KEM contribution is also load-bearing.
- The KEM ciphertext bytes.
- The AES-GCM IV and ciphertext bytes.
- The wire-format version byte `0x02` (a `0x01` ciphertext from the pure-PQ
  `@webbuf/aesgcm-mlkem` package is rejected up front).

**What this package does not bind:**

- The mapping between a sender's P-256 keypair and their federation identity /
  address. A keypair could serve multiple addresses, and the package has no way
  to verify which address the sender claims.
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

`aesgcmP256dhMlkemEncrypt` and `aesgcmP256dhMlkemDecrypt` accept an optional
trailing `aad` parameter (default: empty `WebBuf`). AAD is **authenticated** by
AES-GCM but **not encrypted** and **not transmitted** — the recipient must
supply the exact same bytes the sender used, and any mismatch fails decryption
with an AES-GCM tag error.

For consumers like KeyPears that federate across multiple domains and have
multiple message types, the recommended AAD construction binds protocol version,
message type, and the federated sender / recipient addresses:

```typescript
const aad = WebBuf.concat([
  WebBuf.fromArray([PROTOCOL_VERSION]),
  WebBuf.fromArray([MESSAGE_TYPE]),
  WebBuf.fromUtf8(senderAddress),
  WebBuf.fromArray([0]), // NUL separator — `@` cannot appear in addresses, but
  // a separator avoids ambiguity if two addresses
  // concatenated could equal one address verbatim.
  WebBuf.fromUtf8(recipientAddress),
]);

// Sender
const ciphertext = aesgcmP256dhMlkemEncrypt(
  senderPriv,
  recipientPub,
  encapsulationKey,
  plaintext,
  aad,
);

// Recipient must rebuild the same AAD bytes from its own view of the
// protocol; mismatch on any field throws a clean AES-GCM tag error.
const recovered = aesgcmP256dhMlkemDecrypt(
  recipientPriv,
  senderPub,
  decapsulationKey,
  ciphertext,
  aad,
);
```

Use AAD to bind any context that should be inseparable from the message: the
protocol version, sender / recipient identity, message type, transcript state,
sequence number, or anything else where mismatch should mean "this isn't the
message I think it is." The four-field construction above is the worked example
asserted in the test suite.

**Properties:**

- **Backward-compatible.** Calls with no `aad` argument behave identically to
  before (empty AAD is mathematically equivalent to no AAD in AES-GCM). The
  issue 0004 KAT regression (`SHA-256(ciphertext) === c689ccce...a02b6d`) still
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
(`SHA-256(ciphertext) === daae47a9...6ad1595a`) asserted in
`test/audit.test.ts`. See
[issue 0005](../../issues/0005-pin-mlkem-and-scope-docs/README.md) for the
original Scope-section gap that motivated this.

## Tests

- 19 unit tests covering round-trip, size invariants, version byte,
  non-determinism, all rejection paths, AAD round-trip / mismatch scenarios, and
  a KeyPears-style four-field AAD construction with tamper detection.
- 6 audit tests asserting:
  - The byte-precise issue 0004 Experiment 1 KAT
    (`SHA-256(ciphertext) === c689ccce...a02b6d`) and the captured recipient
    P-256 public-key derivation and wire-format prefix bytes.
  - The byte-precise issue 0006 Experiment 2 non-empty-AAD KAT
    (`SHA-256(ciphertext) === daae47a9...6ad1595a`).
  - That the explicit empty-AAD path matches the no-AAD default byte-for-byte.
  - That AAD changes only the AES-GCM tag and not the AES-CTR ciphertext body.
- 2 hybrid defense-in-depth tests confirming both shared secrets are
  load-bearing.

```bash
pnpm test
```

## Internal API

`_aesgcmP256dhMlkemEncryptDeterministic(senderPriv, recipientPub, encapKey, plaintext, m, iv, aad?)`
exists for KAT regression tests and reproducible fixtures. Application code
should never call it directly — the leading underscore signals deterministic
randomness, which is unsafe in production. Use `aesgcmP256dhMlkemEncrypt`
instead.

## License

MIT
