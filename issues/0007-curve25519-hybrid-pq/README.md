+++
status = "open"
opened = "2026-04-26"
+++

# Adopt Curve25519 (X25519, Ed25519) and Curve25519-based hybrid PQ constructions

## Goal

Add Curve25519-family classical primitives to WebBuf — X25519 for ECDH and
Ed25519 for signatures — and build the matching Curve25519-based hybrid
post-quantum constructions:

- `@webbuf/x25519` — X25519 ECDH primitive (Rust → WASM → TS).
- `@webbuf/ed25519` — Ed25519 signature primitive (Rust → WASM → TS).
- `@webbuf/aesgcm-x25519dh-mlkem` — hybrid encryption: AES-256-GCM keyed by
  HKDF-SHA-256 over `(X25519 SS || ML-KEM-768 SS)`. Sibling to the existing
  `@webbuf/aesgcm-p256dh-mlkem` from issue 0004.
- A composite signature package combining Ed25519 + ML-DSA-65 (exact name and
  shape TBD per Experiment N — likely `@webbuf/ed25519-mldsa` or
  `@webbuf/sig-ed25519-mldsa`, modeled on the OpenPGP "MUST" pairing and the
  Signal PQXDH approach).

After this issue, WebBuf has a Curve25519-first answer for both hybrid
encryption and hybrid signatures, matching the direction the entire ecosystem
(Chrome, Cloudflare, AWS, Signal, OpenPGP, the IETF hybrid drafts) is converging
on.

## Background

### What we have today

Issue 0004 landed two hybrid encryption packages keyed on P-256 ECDH:

- `@webbuf/aesgcm-p256dh-mlkem` — hybrid: AES-256-GCM + HKDF-SHA-256 over
  `(P-256 ECDH X-coord || ML-KEM-768 SS)`. Issue 0004's recommended transitional
  scheme.
- `@webbuf/aesgcm-mlkem` — pure-PQ: AES-256-GCM + HKDF-SHA-256 over the
  ML-KEM-768 SS alone.

Both gained AAD support in issue 0006, so context binding is no longer a gap.

For signatures, WebBuf currently exposes ML-DSA (`@webbuf/mldsa`, FIPS 204) and
SLH-DSA (`@webbuf/slhdsa`, FIPS 205) as standalone PQ primitives, plus classical
secp256k1 ECDSA (`@webbuf/secp256k1`) and P-256 ECDSA (`@webbuf/p256`). There is
no hybrid signature package yet.

### Why Curve25519 now

The keypears design discussion concluded:

- Curve25519 is the universal classical choice. X25519 (RFC 7748) is the ECDH
  primitive used by Signal, WireGuard, TLS 1.3, SSH, and the Chrome
  X25519MLKEM768 hybrid (the hybrid that's actually deployed in production
  browsers as of Chrome 124, ~2 years ago). Ed25519 (RFC 8032) is the matching
  signature primitive used in the same systems plus OpenPGP, age, Tor, and
  increasingly Web PKI.
- P-256 is supported but secondary. NIST endorses both; the Curve25519 family
  wins on simplicity, performance, and ecosystem ubiquity. The P-256 hybrid we
  built in issue 0004 is standards-compliant (LAMPS defines
  `id-MLKEM768-ECDH-P256-SHA3-256`) but is the secondary option, not the primary
  one.
- KeyPears is the first consumer and has zero users. There's no migration cost
  to switching to Curve25519 now; staying on P-256 would mean a throwaway
  migration later when consumers expect interop with the wider Curve25519-first
  world.

### Emerging hybrid standards

The hybrid constructions to mirror:

**KEM hybrid (encryption):**

- Chrome `X25519MLKEM768` (TLS, deployed Chrome 124 / 2024): KEM = X25519 +
  ML-KEM-768; combiner = simple concatenation into the TLS HKDF schedule; ML-KEM
  SS first, then X25519 SS (FIPS-approved scheme first per CNSA 2.0 guidance and
  NIST SP 800-227 IPD).
- IETF `draft-ietf-tls-hybrid-design` codifies the same construction.
- Signal PQXDH: hybrid X3DH + ML-KEM, classical SS prepended ahead of PQ SS for
  HKDF input (the opposite ordering from Chrome). Both are valid; the ordering
  is a domain-separation choice within HKDF, not a security choice.

WebBuf's `@webbuf/aesgcm-p256dh-mlkem` from issue 0004 chose **classical first,
PQ second** (matching Signal and IETF TLS hybrid draft). The new
`@webbuf/aesgcm-x25519dh-mlkem` package should keep the same ordering internally
to make audit and review consistent across the two hybrids — even though the
ecosystem is split, the WebBuf-internal convention is what matters for our
consumers.

**Signature hybrid:**

- OpenPGP composite: Ed25519 + ML-DSA-65, two independent signatures over the
  same message digest, both required to verify. RFC drafts:
  `draft-ietf-openpgp-pqc`.
- The X.509 LAMPS work is parallel: `id-Ed25519-MLDSA65` and `id-Ed448-MLDSA87`
  composite OIDs. Still pre-RFC.
- The construction is "sign with both, verify with both" — no exotic key
  derivation, no shared randomness. The cost is roughly the sum of both
  signatures (Ed25519: 64 bytes; ML-DSA-65: 3309 bytes → composite ≈ 3373 bytes
  per signature).

### What KeyPears needs (the urgent driver)

KeyPears is migrating to post-quantum encryption and signatures and wants the
standards-track Curve25519-first answer. Specifically:

- Hybrid message encryption with X25519+ML-KEM (to replace its existing
  classical AES-GCM + P-256 ECDH path).
- Hybrid signatures with Ed25519+ML-DSA (to replace its existing classical
  Ed25519 — actually, KeyPears today uses secp256k1; the migration is a natural
  moment to switch to Ed25519 for the classical half of the hybrid).
- Both with AAD support inherited from issue 0006.

Without these, KeyPears either ships P-256-hybrid (the issue 0004 packages,
which work today but aren't the long-term direction) or waits. KeyPears has zero
users and prefers to wait.

## What's in scope

### `@webbuf/x25519` — classical primitive

Mirror `@webbuf/p256` shape:

- `x25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32>`
- `x25519SharedSecretRaw(privKey: FixedBuf<32>, pubKey: FixedBuf<32>): FixedBuf<32>`
  — RFC 7748 raw 32-byte scalar-mult output, no hashing.
- Underlying Rust crate: RustCrypto `x25519-dalek` or `curve25519-dalek` (one of
  these is a thin wrapper over the other; pick whichever `RustCrypto/x25519`
  re-exports in `0.x` and pin exactly per the issue 0001/0005 PQC pinning
  rationale extended to fresh dependencies).

### `@webbuf/ed25519` — classical primitive

Mirror the secp256k1 / p256 ECDSA shape but with Ed25519's sign/verify
semantics:

- `ed25519KeyPair(): { privKey, pubKey }` and a deterministic
  `ed25519KeyPairFromSeed(seed: FixedBuf<32>)`.
- `ed25519Sign(privKey, message): FixedBuf<64>`.
- `ed25519Verify(pubKey, message, signature): boolean`.
- Underlying Rust: `ed25519-dalek`.

### `@webbuf/aesgcm-x25519dh-mlkem` — hybrid encryption

Sibling to `@webbuf/aesgcm-p256dh-mlkem` from issue 0004, keyed on X25519
instead of P-256:

```
ikm  = x25519SS || mlkemSS  (32 + 32 = 64 bytes; classical first, PQ second)
salt = 0^32
info = UTF-8("webbuf:aesgcm-x25519dh-mlkem v1")
PRK  = HMAC-SHA-256(salt, ikm)
K    = HMAC-SHA-256(PRK, info || 0x01)
```

Wire format identical layout to `@webbuf/aesgcm-p256dh-mlkem` but with a
distinct version byte (likely `0x03` — `0x01` is reserved for `aesgcm-mlkem` and
`0x02` for `aesgcm-p256dh-mlkem`).

AAD support inherited from `@webbuf/aesgcm` (per issue 0006).

A captured byte-precise KAT in `test/audit.test.ts`, mirroring the issue-0004 /
issue-0006 KAT pattern.

### Composite signature package — Ed25519 + ML-DSA-65

The exact API surface and naming will be designed in an experiment, but the
construction is fixed:

- Signing: Ed25519 over `H(message)` and ML-DSA-65 over the same message,
  concatenated with a length prefix.
- Verification: both signatures must verify; failure of either fails the whole.
- Wire format: `version || ed25519_sig (64) || mldsa_sig (3309)` = 3373 + 1 =
  3374 bytes.

The construction matches the OpenPGP composite signature "MUST" pairing
(`draft-ietf-openpgp-pqc`) and the LAMPS `id-Ed25519-MLDSA65` OID. WebBuf's
package will be Web-PKI-agnostic — no X.509, no ASN.1 — but the underlying
sign/verify pair will be the same primitive composition.

## What's out of scope

- Curve448 / Ed448 / X448 (the second tier of Curve25519's siblings; not
  ecosystem-relevant for the workloads WebBuf targets).
- Web PKI integration (X.509, certificate issuance, CA work). LAMPS drafts
  define composite OIDs but no CA issues PQ certificates yet, and KeyPears
  doesn't need a PKI layer — it has its own identity model.
- Replacing the existing P-256 hybrid packages. They stay as-is, marked as the
  secondary classical option in their READMEs.
- Rebuilding `@webbuf/aesgcm-p256dh` (classical-only) on X25519. That's a
  separate package decision; this issue is about the PQ-hybrid path.
- Hybrid encryption / signature constructions involving SLH-DSA. SLH-DSA is
  hash-based, has different size/perf trade-offs (signatures are 8 KB+), and is
  currently positioned as the conservative-fallback signer rather than the
  everyday-use one. Out of scope for this issue.
- Curve25519-based KEMs other than X25519+ML-KEM-768 (e.g. X-Wing). X-Wing is a
  clean composition standard but is still IETF-draft-stage and not yet deployed
  in production browsers; we'll revisit if and when it stabilises.

## Constraints

- **Pin Rust dependencies exactly.** Same pinning rationale as the PQC crates
  from issue 0001/0005: pre-1.0 and just-post-1.0 cryptographic crates have a
  history of CVE-driven point releases, and we want reproducible builds.
  `x25519-dalek` and `ed25519-dalek` are stable but still on `2.x`.
- **Reuse the issue 0004 / 0006 wire-format conventions.** Version byte at
  offset 0; identical layout for `aesgcm-x25519dh-mlkem` as for the P-256 hybrid
  sibling. Make `aesgcmX25519dhMlkemDecrypt` reject ciphertexts from the other
  hybrid packages with a clear error.
- **Reuse the issue 0006 AAD plumbing.** No new AAD design; just thread
  `aad?: WebBuf` through the new hybrid encryption package the same way it
  threads through the existing two.
- **Keep the HKDF info string scheme consistent.** Same `"webbuf:<scheme> v1"`
  pattern. Independent versioning per scheme.
- **Capture byte-precise KATs for every new construction.** Same pattern as
  issue 0004 (raw KAT bytes embedded in the issue + asserted in
  `test/audit.test.ts`).
- **Audit posture.** Both `x25519-dalek` and `ed25519-dalek` have had public
  review (notably the 2017 SLOTH and 2019 fault-injection work) unlike the PQC
  crates. The hybrid construction inherits its PQ-side audit posture from
  `ml-kem` / `ml-dsa`. Document this in the package READMEs.
- **No Web PKI surface.** The composite signature package signs and verifies raw
  bytes. No ASN.1, no X.509, no CMS. Consumers that need Web PKI compatibility
  build it on top.

## Test plan (per package)

- Round-trip encrypt/decrypt (or sign/verify) on random inputs, empty inputs,
  and large inputs (≥ 64 KiB).
- Wrong-key rejection: every component of every key.
- Tamper rejection on every wire-format region (version byte, KEM ciphertext,
  IV, AES ciphertext, AES tag).
- Hybrid defense-in-depth: confirm each shared secret / each signature half is
  independently load-bearing (i.e. tampering with the X25519 half alone or the
  ML-KEM half alone fails decryption; tampering with the Ed25519 sig alone or
  the ML-DSA sig alone fails verification).
- Empty-AAD equivalence vs. no-AAD default.
- Non-empty AAD round-trip + mismatch rejection (encryption package only).
- Byte-precise KAT regression captured in this issue.
- A KeyPears-style worked example (multi-field AAD construction; a composite
  signature over a federation message) where applicable.

## Decision log so far

- **Curve choice:** Curve25519 family over Curve448 / NIST P-256 for new hybrid
  work. P-256 stays as a supported-but-secondary classical option via the
  existing issue 0004 packages.
- **Encryption combiner:** simple HKDF over concatenated shared secrets;
  classical first, PQ second; SHA-256; per-scheme info string. Matches the issue
  0004 `aesgcm-p256dh-mlkem` choice for cross-package consistency.
- **Signature combiner:** OpenPGP-style composite (two independent signatures,
  both required). Concatenation order: Ed25519 first, ML-DSA second (mirrors the
  encryption ordering: classical first, PQ second).
- **Naming:** `aesgcm-x25519dh-mlkem` for the hybrid encryption package (mirrors
  `aesgcm-p256dh-mlkem`). Composite signature naming is open pending Experiment
  N design.
- **Versioning:** new wire-format version byte for each new package (`0x03` for
  `aesgcm-x25519dh-mlkem`); independent HKDF info-string versioning.

## What this unblocks

After this issue closes:

- KeyPears can ship the entire post-quantum messaging migration on the
  Curve25519-first standards track without a future migration to switch curves.
- Future WebBuf consumers wanting Web PKI / OpenPGP / Signal interop have
  primitives that match those ecosystems' direction.
- The `@webbuf/aesgcm-p256dh-mlkem` / classical-NIST track stays maintained for
  consumers that need NIST-curves-everywhere.

Experiments will be designed and recorded incrementally. Likely starting points:

1. Survey the Rust Curve25519 crate ecosystem (`x25519-dalek`, `ed25519-dalek`,
   `curve25519-dalek`) for version pinning and feature selection — the same kind
   of survey issue 0001 did for the PQC crates.
2. Build `@webbuf/x25519` end-to-end (Rust crate → WASM → TS wrapper + tests).
3. Build `@webbuf/ed25519` end-to-end.
4. Build `@webbuf/aesgcm-x25519dh-mlkem` end-to-end with KAT capture and AAD
   plumbing.
5. Design and build the composite Ed25519+ML-DSA signature package.

But these are the natural starting points, not a committed sequence — later
experiments will be designed only after earlier ones land.
