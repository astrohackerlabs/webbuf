# @webbuf/aesgcm-x25519dh-mlkem

Hybrid classical + post-quantum authenticated encryption: AES-256-GCM keyed by
an HKDF-SHA-256 derivation over **both** an X25519 ECDH shared secret and an
ML-KEM-768 shared secret. An attacker must break both X25519 and ML-KEM to
recover the AES key — secure against today's classical adversaries and the
harvest-now-decrypt-later quantum threat.

This package is a **TypeScript-only composition** over the existing WebBuf
primitives — no new Rust crate. It is the **Curve25519-flavored sibling** of
[`@webbuf/aesgcm-p256dh-mlkem`](../npm-webbuf-aesgcm-p256dh-mlkem/README.md).
See
[`issues/0007-curve25519-hybrid-pq`](../../issues/0007-curve25519-hybrid-pq/README.md)
for the byte-precise specification, the captured KATs, and the rationale for
choosing X25519 over P-256 for new construction.

> **When to use which package:**
>
> - `@webbuf/aesgcm-x25519dh-mlkem` (this package) — **recommended**
>   Curve25519-first hybrid. Matches Chrome `X25519MLKEM768`, Signal PQXDH, and
>   the IETF TLS hybrid draft direction. Use this for new work.
> - `@webbuf/aesgcm-p256dh-mlkem` — NIST-curves hybrid. Use when an existing
>   protocol or compliance regime requires P-256 specifically; otherwise prefer
>   this package.
> - `@webbuf/aesgcm-mlkem` — pure post-quantum. No classical fallback. Use when
>   you trust the lattice assumption and want the simpler scheme.

## Preferred API

```typescript
import {
  aesgcmX25519dhMlkemEncrypt,
  aesgcmX25519dhMlkemDecrypt,
} from "@webbuf/aesgcm-x25519dh-mlkem";
import { mlKem768KeyPair } from "@webbuf/mlkem";
import { x25519PublicKeyCreate } from "@webbuf/x25519";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

// Both parties have persistent (static-static) X25519 keypairs.
const senderPriv = FixedBuf.fromRandom<32>(32);
const senderPub = x25519PublicKeyCreate(senderPriv);
const recipientPriv = FixedBuf.fromRandom<32>(32);
const recipientPub = x25519PublicKeyCreate(recipientPriv);

// Recipient holds an ML-KEM-768 keypair too.
const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();

// Sender encrypts using its own X25519 priv, recipient's X25519 pub,
// recipient's ML-KEM encapsulation key.
const plaintext = WebBuf.fromUtf8("hybrid encryption");
const ciphertext = aesgcmX25519dhMlkemEncrypt(
  senderPriv,
  recipientPub,
  encapsulationKey,
  plaintext,
);

// Recipient decrypts using its own X25519 priv, sender's X25519 pub,
// own ML-KEM decapsulation key.
const recovered = aesgcmX25519dhMlkemDecrypt(
  recipientPriv,
  senderPub,
  decapsulationKey,
  ciphertext,
);
```

The static-static design means both parties must already know each other's
persistent X25519 public keys (out-of-band — same as `@webbuf/aesgcm-p256dh` or
`@webbuf/aesgcm-p256dh-mlkem`). No ephemeral key on the wire; if you want
forward secrecy on the classical side, that's a different scheme.

## Wire format

Identical layout to `@webbuf/aesgcm-p256dh-mlkem`, distinguished by version
byte:

| Offset   | Length | Field                                  |
| -------- | ------ | -------------------------------------- |
| 0        | 1      | Version byte: `0x03`                   |
| 1        | 1088   | ML-KEM-768 ciphertext                  |
| 1089     | 12     | AES-GCM IV                             |
| 1101     | N      | AES-GCM ciphertext (N = plaintext.len) |
| 1101 + N | 16     | AES-GCM authentication tag             |

Total fixed overhead: **1117 bytes** per message — same as the P-256 sibling and
the pure-PQ package.

The version byte (`0x03`) lets `aesgcmX25519dhMlkemDecrypt` reject ciphertexts
from `@webbuf/aesgcm-mlkem` (`0x01`) or `@webbuf/aesgcm-p256dh-mlkem` (`0x02`)
with a clear error, instead of failing silently with an AEAD-tag mismatch.

## Public-key shape

X25519 public keys are 32-byte u-coordinates per RFC 7748 § 5 — **not** the
33-byte SEC1-compressed shape used by P-256. The package signatures take
`FixedBuf<32>` for both the sender and recipient X25519 public keys; passing a
P-256 `FixedBuf<33>` won't typecheck, which is exactly the safety we want.

## Key derivation

The AES-256 key is derived from the concatenation of both shared secrets via
HKDF-SHA-256 (RFC 5869, NIST SP 800-56C Rev. 2):

```
ecdhSS = X25519 raw 32-byte scalar-mult output (RFC 7748)
kemSS  = ML-KEM-768 shared secret (32 bytes)
ikm    = ecdhSS || kemSS   (64 bytes; classical first, PQ second)
salt   = 0^32  (32 zero bytes)
info   = UTF-8("webbuf:aesgcm-x25519dh-mlkem v1")
PRK    = HMAC-SHA-256(salt, ikm)
K      = HMAC-SHA-256(PRK, info || 0x01)
```

The classical-first IKM ordering matches the WebBuf-internal convention
established in issue 0004 for `@webbuf/aesgcm-p256dh-mlkem`. (Note: Chrome TLS
X25519MLKEM768 puts ML-KEM first, then X25519; Signal PQXDH puts classical
first; both are valid — the ordering is a domain-separation choice within HKDF,
not a security choice. WebBuf is internally consistent across its hybrid
packages.)

The trailing ` v1` in the info string lets us version the schedule independently
of the package version.

## Small-order rejection

`aesgcmX25519dhMlkemEncrypt` and `aesgcmX25519dhMlkemDecrypt` propagate the
**non-contributory rejection** from `@webbuf/x25519`: `x25519SharedSecretRaw`
throws when the resulting shared secret is all-zero (caused by a small-order
public key). Without this rejection, a malicious peer presenting a small-order
public key would collapse the hybrid scheme to PQ-only — the X25519 contribution
to HKDF would be a fixed all-zero string, defeating the point of "an attacker
must break both X25519 and ML-KEM."

WebBuf rejects this case before HKDF runs. The error message is stable:

```
X25519 shared secret is non-contributory (small-order public key)
```

The seven canonical small-order Curve25519 u-coordinates (Cremers & Jackson,
"Prime, Order Please!" 2019) are exercised in
[`@webbuf/x25519`](../npm-webbuf-x25519/README.md)'s test suite. This package's
tests confirm the rejection propagates through both the encrypt and decrypt code
paths.

## Security properties

- **Both shared secrets are required.** The HKDF input concatenates the X25519
  SS with the ML-KEM SS; an attacker must recover both to compute the AES key.
  This is verified by the defense-in-depth tests:
  - Wrong ML-KEM key with right X25519 keys → fails (proves ML-KEM is
    load-bearing).
  - Right ML-KEM key with wrong X25519 inputs → fails (proves X25519 is
    load-bearing).
- **Tampering authenticated by AES-GCM.** Tampered KEM ciphertext produces a
  wrong shared secret (per FIPS 203 implicit rejection), which produces a wrong
  AES key, which fails the AES-GCM tag. Tampered AES ciphertext or IV fails the
  tag directly.
- **Wrong-recipient and wrong-sender rejection.** Decrypting with the wrong
  X25519 recipient priv, the wrong X25519 sender pub, or the wrong ML-KEM
  decapsulation key all fail with AES-GCM tag errors.
- **Small-order peer pub key rejection.** Encrypt and decrypt both throw before
  HKDF runs; see above.

In all rejection cases (other than small-order-rejection on the encrypt path,
which throws explicitly), `aesgcmX25519dhMlkemDecrypt` throws.

## Authenticated context (AAD)

Both encrypt and decrypt accept an optional trailing `aad` parameter (default:
empty `WebBuf`). AAD is **authenticated** by AES-GCM but **not encrypted** and
**not transmitted** — the recipient must supply the same bytes the sender used;
any mismatch fails decryption.

For consumers like KeyPears that federate across multiple domains and have
multiple message types, the recommended construction binds protocol version,
message type, and federated sender / recipient addresses:

```typescript
const aad = WebBuf.concat([
  WebBuf.fromArray([PROTOCOL_VERSION]),
  WebBuf.fromArray([MESSAGE_TYPE]),
  WebBuf.fromUtf8(senderAddress),
  WebBuf.fromArray([0]), // NUL separator
  WebBuf.fromUtf8(recipientAddress),
]);

const ciphertext = aesgcmX25519dhMlkemEncrypt(
  senderPriv,
  recipientPub,
  encapsulationKey,
  plaintext,
  aad,
);
```

This binding is identical to the recommended pattern in
`@webbuf/aesgcm-p256dh-mlkem` — the AAD layer is curve-agnostic.

**Properties:**

- **Backward-compatible.** Calls with no `aad` argument behave identically to
  AES-GCM with empty AAD. Captured empty-AAD KATs are stable.
- **No wire-format change.** Ciphertext length is unchanged because AAD is not
  transmitted; only the AES-GCM tag changes when AAD is non-empty.
- **No key-schedule change.** AAD enters only the GHASH computation, not the
  HKDF key derivation.

## Audit posture

This package composes Rust/WASM primitives whose audit postures differ:

- **X25519 / Curve25519** (via `@webbuf/x25519` → `x25519-dalek` 2.0.1 +
  `curve25519-dalek` 4.1.3): a 2019 Quarkslab audit covered the pre-1.0
  codebase; the modern 4.x / 2.x lines are not under that audit but include
  RUSTSEC-2024-0344's timing-leak fix. Mature ecosystem with widespread
  production use (Signal, WireGuard, TLS 1.3).
- **ML-KEM** (via `@webbuf/mlkem` → `ml-kem` 0.2.3): no public independent
  audit. The Rust crate is pre-1.0; KEM design itself is FIPS 203 standardized.

The hybrid construction defends against single-primitive failures: an attacker
who fully breaks ML-KEM still has to break X25519, and vice versa. **Recommended
for transitional deployments** where a pure-PQ scheme's audit posture is
uncomfortable but classical-only is no longer acceptable.

## Tests

- 24 unit tests covering round-trip on random / empty / 64 KiB plaintexts,
  non-determinism, length / version-byte invariants, all rejection paths (wrong
  recipient / sender / ML-KEM key, tampered KEM / AES / IV, wrong-version-byte
  rejection for both `0x01` and `0x02`, truncation), hybrid defense-in-depth
  (each shared secret independently load-bearing), small-order rejection on both
  encrypt and decrypt paths, and AAD scenarios including a KeyPears-style
  four-field construction with tamper detection.
- 5 audit tests asserting the byte-precise issue 0007 Experiment 4 KATs: the
  captured recipient X25519 public-key derivation, the empty-AAD KAT
  (`SHA-256(ciphertext) === 81ebae8d...d9c986e1`), the wire-format prefix and IV
  offset, the non-empty-AAD KAT (`SHA-256(ciphertext) === 20ec384a...cea0b9c9`),
  and the AAD-changes-tag-not-body invariant.

```bash
pnpm test
```

## Internal API

`_aesgcmX25519dhMlkemEncryptDeterministic(senderPriv, recipientPub, encapKey, plaintext, m, iv, aad?)`
exists for KAT regression tests and reproducible fixtures. Application code
should never call it directly — the leading underscore signals deterministic
randomness, which is unsafe in production. Use `aesgcmX25519dhMlkemEncrypt`
instead.

## License

MIT
