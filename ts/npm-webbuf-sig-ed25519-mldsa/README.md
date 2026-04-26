# @webbuf/sig-ed25519-mldsa

Composite Ed25519 + ML-DSA-65 signatures: two independent signatures over the
raw message bytes, both required to verify. An attacker must forge **both** the
classical Ed25519 signature **and** the post-quantum ML-DSA-65 signature to
forge the composite — secure against today's classical adversaries and the
harvest-now-decrypt-later quantum threat.

This package is a **TypeScript-only composition** over `@webbuf/ed25519` and
`@webbuf/mldsa` — no new Rust crate. It matches the OpenPGP
`draft-ietf-openpgp-pqc` "MUST" pairing and the LAMPS X.509 `id-Ed25519-MLDSA65`
OID at the **primitive** level. WebBuf does **not** provide Web PKI / X.509 /
OpenPGP framing — the package signs and verifies raw bytes; consumers do their
own packaging.

See
[`issues/0007-curve25519-hybrid-pq`](../../issues/0007-curve25519-hybrid-pq/README.md)
Experiment 5 for the byte-precise specification, the captured KAT, and the
rationale.

## Installation

```bash
npm install @webbuf/sig-ed25519-mldsa
```

## Usage

```typescript
import {
  sigEd25519MldsaSign,
  sigEd25519MldsaVerify,
} from "@webbuf/sig-ed25519-mldsa";
import { ed25519PublicKeyCreate } from "@webbuf/ed25519";
import { mlDsa65KeyPair } from "@webbuf/mldsa";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

// Each party generates two independent keys: a 32-byte Ed25519 seed and an
// ML-DSA-65 keypair.
const ed25519Priv = FixedBuf.fromRandom<32>(32);
const ed25519Pub = ed25519PublicKeyCreate(ed25519Priv);

const { signingKey: mldsaSigningKey, verifyingKey: mldsaVerifyingKey } =
  mlDsa65KeyPair();

// Sign a message — produces a 3374-byte composite signature.
const message = WebBuf.fromUtf8("composite signature");
const signature = sigEd25519MldsaSign(ed25519Priv, mldsaSigningKey, message);

// Verify — both halves must verify against their respective public keys.
const ok = sigEd25519MldsaVerify(
  ed25519Pub,
  mldsaVerifyingKey,
  message,
  signature,
);
// ok === true
```

The composite carries two distinct private keys and two distinct public keys.
WebBuf intentionally does **not** provide a single "composite KeyPair" type —
bundling them into one object would obscure which half is which and break
compatibility if the scheme later adds a third signer (e.g. SLH-DSA). Bundle
them in your application layer if needed.

## Composition

Both signers consume the **raw message bytes** per their RFC-defined interfaces:

- Ed25519: PureEdDSA per RFC 8032 §5.1.6 (no prehash, no Ed25519ph).
- ML-DSA-65: FIPS 204 `Sign` over the message bytes directly.

No `H(message)` indirection. No domain separation in the message. The
construction matches `draft-ietf-openpgp-pqc`'s "MUST" pairing.

The wire format is a fixed 3374 bytes:

| Offset | Length | Field                                  |
| ------ | ------ | -------------------------------------- |
| 0      | 1      | Version byte: `0x01`                   |
| 1      | 64     | Ed25519 PureEdDSA signature (R \|\| S) |
| 65     | 3309   | ML-DSA-65 signature                    |

Total: **3374 bytes**. No length-prefix between the halves — both individual
signature sizes are constant.

The version byte enables future scheme revisions (e.g. switching to ML-DSA-87 or
adding SLH-DSA as a third signer). It lives in its own namespace from the
encryption packages — `0x01` here is distinct from `@webbuf/aesgcm-mlkem`'s
`0x01` because they are consumed by different decoders.

## Determinism

PureEdDSA signing is deterministic per RFC 8032: the same
`(ed25519Priv, message)` pair always produces the same Ed25519 signature.

ML-DSA-65 signing is **hedged by default** in WebBuf (per issue 0003) — each
call mixes in fresh per-call randomness. This is the recommended posture for
fault-attack resistance.

The composite signature is therefore **non-deterministic by default**. The
Ed25519 half (bytes 1–65) is stable for a given `(ed25519Priv, message)`; the
ML-DSA half (bytes 65–3374) varies per call. Two calls to
`sigEd25519MldsaSign(ed25519Priv, mldsaSigningKey, message)` produce two
different signatures, but both verify under the same public keys.

For reproducible test fixtures only, the package exposes
`_sigEd25519MldsaSignDeterministic` (leading underscore signals test-only —
never use in production). It calls `mlDsa65SignDeterministic` under the hood,
which lacks the fault-attack resistance the hedged default provides.

## Strict verification (small-order rejection inherited from Ed25519)

`sigEd25519MldsaVerify` returns `boolean`. Failed verification is **not** an
exception — wrong key on either side, tampered message, tampered signature,
non-canonical Ed25519 S, malformed Ed25519 point, version-byte mismatch all
return `false`. Only top-level input-length errors throw (and the static
`FixedBuf<...>` size discriminators prevent most of those at typecheck time).

The composite verifier inherits **strict Ed25519 verification** from
`@webbuf/ed25519` — the underlying `verify_strict` rejects small-order public
keys, non-canonical S, and non-canonical R. Without this, a malicious peer
presenting the Curve25519 identity element as their Ed25519 public key, combined
with an identity-R / zero-S forgery, could produce a universal forgery against
the Ed25519 half of the composite. WebBuf's verifier rejects this case
explicitly; a regression test asserts it.

## Defense in depth

The whole point of the composite is that **each half must independently
verify**. The test suite asserts this empirically:

- Wrong Ed25519 pub key + correct ML-DSA verifying key → `false` (Ed25519 is
  load-bearing; without its check the hybrid claim collapses to "ML-DSA alone").
- Correct Ed25519 pub + wrong ML-DSA verifying key → `false` (ML-DSA is
  load-bearing).
- Tampering just the Ed25519 half (`signature[1..65]`) → `false`.
- Tampering just the ML-DSA half (`signature[65..3374]`) → `false`.

The composite's security is therefore the **AND** of the two primitives'
securities — an attacker must break both Ed25519 and ML-DSA-65 to forge a
signature.

## Verification timing

Both halves' verifiers run regardless of the other's result; the implementation
does **not** short-circuit on the first failure. Neither primitive's underlying
verifier is constant-time anyway, so the abstraction does not add timing safety
we don't already have at the primitive layer. If your threat model requires
constant-time composite verification, you'll need to use a
side-channel-resistant verifier as the primitive layer first.

## ML-DSA `context` parameter

ML-DSA accepts an optional context byte string that's bound into the signature.
The composite `sigEd25519MldsaSign` does **not** expose this parameter — it's
intentionally kept narrow to match the no-prehash / no-context decision in issue
0007's Decision Log.

If you need ML-DSA context binding for application reasons, call `mlDsa65Sign`
directly from `@webbuf/mldsa` and compose the framing yourself.

## API

| Function                                                                                                                                  | Description                                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `sigEd25519MldsaSign(ed25519Priv: FixedBuf<32>, mldsaSigningKey: FixedBuf<4032>, message: WebBuf): FixedBuf<3374>`                        | Composite sign — hedged ML-DSA, deterministic Ed25519                 |
| `sigEd25519MldsaVerify(ed25519Pub: FixedBuf<32>, mldsaVerifyingKey: FixedBuf<1952>, message: WebBuf, signature: FixedBuf<3374>): boolean` | Composite verify — both halves required; throws on length errors only |

The `SIG_ED25519_MLDSA` constants object exports the wire-format sizes:
`versionByte`, `ed25519SignatureSize`, `mldsaSignatureSize`, `fixedSize`, plus
the underlying primitives' key sizes.

## Audit posture

This package composes Rust/WASM primitives whose audit postures differ:

- **Ed25519 / Curve25519** (via `@webbuf/ed25519` → `ed25519-dalek` 2.2.0 +
  `curve25519-dalek` 4.1.3): a 2019 Quarkslab audit covered the pre-1.0
  codebase; the modern 4.x / 2.x lines are not under that audit but include
  fixes for RUSTSEC-2022-0093 (ed25519-dalek keypair-oracle, fixed in 2.0.0) and
  RUSTSEC-2024-0344 (curve25519-dalek scalar-sub timing leak, fixed in 4.1.3).
- **ML-DSA-65** (via `@webbuf/mldsa` → `ml-dsa` `=0.1.0-rc.8`): no public
  independent audit. The Rust crate is pre-1.0 and pinned exactly per issue 0001
  / 0005's PQC pinning policy.

The hybrid construction defends against single-primitive failures: an attacker
who fully breaks ML-DSA still has to break Ed25519, and vice versa.

## Tests

- 14 unit tests covering round-trip on random / empty / 64 KiB messages, length
  and version-byte invariants, four hybrid defense-in-depth tests (wrong Ed25519
  pub fails, wrong ML-DSA pub fails, tampered Ed25519 half fails, tampered
  ML-DSA half fails), version-byte tampering rejection, tampered-message
  rejection, non-determinism of the default sign with Ed25519-half stability,
  and the strict-Ed25519 universal-forgery rejection inherited from the
  Experiment 3 Codex fix.
- 5 audit tests asserting the byte-precise issue 0007 Experiment 5 KAT: Ed25519
  public-key derivation, ML-DSA-65 verifying-key SHA-256 match,
  composite-signature SHA-256 (`401a517c…47158c53`), wire-format prefix bytes
  (version 0x01 + Ed25519 half + ML-DSA prefix), and end-to-end verification of
  the captured signature.

```bash
pnpm test
```

## Internal API

`_sigEd25519MldsaSignDeterministic(ed25519Priv, mldsaSigningKey, message)`
exists for KAT regression tests and reproducible fixtures. Application code
should never call it directly — the leading underscore signals deterministic
randomness, which is unsafe in production per issue 0003. Use
`sigEd25519MldsaSign` instead.

## License

MIT
