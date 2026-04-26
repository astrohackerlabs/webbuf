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
  same raw message bytes (no external prehash on either side), both required to
  verify. RFC drafts: `draft-ietf-openpgp-pqc`.
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
  — RFC 7748 raw 32-byte scalar-mult output, no hashing. **Rejects all-zero
  shared secrets.** RFC 7748 §6.1 notes implementations may abort when the
  scalar-mult output is all zero (caused by small-order / low-order public
  inputs). WebBuf takes the conservative position: the primitive throws on
  all-zero output, matching `x25519-dalek`'s `SharedSecret::was_contributory()`
  check. This means every consumer (including the hybrid encryption package)
  gets the protection by default — without it, a malicious peer's small-order
  public key could collapse the hybrid scheme to PQ-only.
- Underlying Rust crate: `x25519-dalek` (Dalek-cryptography, not RustCrypto; the
  two ecosystems are distinct). `x25519-dalek` is a thin wrapper around
  `curve25519-dalek`. Pin exactly per the issue 0001 / 0005 PQC pinning
  rationale extended to fresh cryptographic dependencies. The exact version to
  pin and feature flags to enable will be settled in the crate-survey
  experiment.

### `@webbuf/ed25519` — classical primitive

Mirror the secp256k1 / p256 ECDSA shape but with Ed25519's sign/verify
semantics. **PureEdDSA (RFC 8032 §5.1.6 / §5.1.7) only** — no Ed25519ph prehash
variant. The signer consumes the raw message bytes directly, preserving the
collision-resilience guarantee RFC 8032 calls out for PureEdDSA. Consumers who
want to sign a digest can hash externally and pass the digest as the "message" —
but the primitive itself never prehashes.

- `ed25519KeyPair(): { privKey, pubKey }` and a deterministic
  `ed25519KeyPairFromSeed(seed: FixedBuf<32>)`.
- `ed25519Sign(privKey, message): FixedBuf<64>`.
- `ed25519Verify(pubKey, message, signature): boolean`.
- Underlying Rust: `ed25519-dalek` (Dalek-cryptography, not RustCrypto).

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

- Signing: **both signers consume the raw message bytes directly per their
  RFC-defined interfaces.** Ed25519 runs PureEdDSA (RFC 8032 §5.1.6) over the
  message; ML-DSA-65 runs FIPS 204's `Sign` over the same message bytes. No
  external prehashing, no `H(message)` indirection — that would either collapse
  to Ed25519ph (asymmetric pairing rejected by `draft-ietf-openpgp-pqc` for the
  same reason) or break PureEdDSA's collision-resilience.
- Verification: both signatures must verify; failure of either fails the whole.
- Wire format: `version || ed25519_sig (64) || mldsa_sig (3309)` = 3373 + 1 =
  3374 bytes.

This matches the OpenPGP composite signature "MUST" pairing
(`draft-ietf-openpgp-pqc` — both signers over raw message, no prehash) and the
LAMPS `id-Ed25519-MLDSA65` OID. WebBuf's package will be Web-PKI-agnostic — no
X.509, no ASN.1 — but the underlying sign/verify pair will be the same primitive
composition.

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
- **Audit posture.** `curve25519-dalek` (and `subtle`) had a 2019 Quarkslab
  audit covering the pre-1.0 codebase commissioned by Tari Labs. The 2.x line of
  `x25519-dalek` and `ed25519-dalek` is not under that audit. Both crates have a
  RUSTSEC history that must be reflected in the package READMEs:
  `RUSTSEC-2022-0093` (ed25519-dalek keypair-oracle, fixed in 2.0.0) and
  `RUSTSEC-2024-0344` (curve25519-dalek scalar-sub timing leak, fixed in 4.1.3).
  The hybrid construction inherits its PQ-side audit posture from `ml-kem` /
  `ml-dsa`. Document this in the package READMEs.
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
- **X25519 small-order / all-zero rejection.** For `@webbuf/x25519` and the
  hybrid encryption package: feed the seven small-order Curve25519 u-coordinates
  (from Cremers & Jackson, "Prime, Order Please!" 2019, and Adam Langley's
  curves-list notes — **not** RFC 7748, which does not enumerate them, and
  **not** `x25519-dalek`'s upstream tests, which do not cover them either).
  Assert that `x25519SharedSecretRaw` throws and that hybrid encryption /
  decryption refuses to proceed. Without this, a malicious peer's small-order
  public key could collapse the hybrid scheme to PQ-only. WebBuf will hard-code
  the seven u-coordinates in `mod tests`; see Experiment 1's Result section A8
  for the source citations.

## Decision log so far

- **Curve choice:** Curve25519 family over Curve448 / NIST P-256 for new hybrid
  work. P-256 stays as a supported-but-secondary classical option via the
  existing issue 0004 packages.
- **Encryption combiner:** simple HKDF over concatenated shared secrets;
  classical first, PQ second; SHA-256; per-scheme info string. Matches the issue
  0004 `aesgcm-p256dh-mlkem` choice for cross-package consistency.
- **Signature combiner:** OpenPGP-style composite (two independent signatures,
  both required). Concatenation order: Ed25519 first, ML-DSA second (mirrors the
  encryption ordering: classical first, PQ second). **Both signers consume the
  raw message bytes per their RFC interfaces** — PureEdDSA for Ed25519 (RFC 8032
  §5.1.6, no prehash), FIPS 204 `Sign` for ML-DSA-65 — matching
  `draft-ietf-openpgp-pqc`. No `H(message)` indirection.
- **X25519 small-order rejection:** `x25519SharedSecretRaw` throws on all-zero
  scalar-mult output (RFC 7748 §6.1). Conservative position: the primitive
  itself enforces, every consumer inherits the protection.
- **Crate ecosystem:** Dalek-cryptography (`x25519-dalek`, `ed25519-dalek`,
  built on `curve25519-dalek`), not RustCrypto. The two ecosystems are distinct;
  audit posture, maintenance, and feature flags differ.
- **Naming:** `aesgcm-x25519dh-mlkem` for the hybrid encryption package (mirrors
  `aesgcm-p256dh-mlkem`). Composite signature naming is open pending the
  experiment that designs it.
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

Experiments will be designed and recorded incrementally — one at a time, with
each experiment's outcome shaping the next. No experiment sequence is committed
upfront.

## Experiment 1: Dalek-cryptography crate survey

### Goal

Survey the `dalek-cryptography` ecosystem and decide — before writing any Rust —
exactly which crates, versions, and feature flags WebBuf will pin for
`@webbuf/x25519` and `@webbuf/ed25519`. Mirrors the survey work that issue 0001
/ 0002 did for the post-quantum crates: cheap insurance against picking the
wrong dependency or the wrong feature mix and discovering it mid-build.

This experiment writes no Rust code and ships no package. Output is a filled-in
**Result** section below with concrete decisions: crate name, exact version
(`= "x.y.z"`), enabled features, disabled defaults, WASM build notes, and any
gotchas to document in the eventual TS package README.

### Why a survey first

Issue 0001 surveyed the RustCrypto PQC ecosystem before touching code, and that
work paid off twice:

- It surfaced the `ml-dsa` rc.8 cluster of CVE-class advisories before WebBuf
  depended on the crate, which fed into the exact-pin policy documented in issue
  0001's conclusion.
- Issue 0005 tightened that pin further after Codex caught a `^` range slip —
  the survey set the precedent and the mistake was caught.

The Dalek crates are more mature than the PQC crates (the v1.0 audit landed in
2019), but the ecosystem still has decisions worth making deliberately:

- Two ed25519 worlds — the trait-defining `ed25519` crate (RustCrypto ecosystem)
  and the implementing `ed25519-dalek` crate. They interop but are not the same.
- `x25519-dalek` is a thin layer over `curve25519-dalek`; we want to know
  whether to depend on the high-level crate, the low-level crate, or both.
- The crates have rapidly-changing feature flags — `static_secrets`,
  `precomputed-tables`, `zeroize`, `reusable_secrets`, `serde`, `digest`,
  `rand_core`, `legacy_compatibility`. Picking the wrong combination costs
  binary size, build time, or correctness.
- WASM compatibility with `wasm32-unknown-unknown` requires careful `getrandom`
  / `rand_core` configuration. WebBuf's build pipeline (`wasm-pack` → bundler →
  base64-inline → TS) has specific expectations and failures here are easy to
  misdiagnose.

### Plan

Answer each of the questions below by reading crate documentation, `Cargo.toml`,
the `dalek-cryptography` GitHub README, the RUSTSEC advisory database, and the
existing WebBuf packages that wrap similar crates. Record one decision per
question in the **Result** section.

Use the `Plan` agent (or a focused subagent) to parallelize where the questions
are independent.

#### Q1: Which crate(s) for `@webbuf/x25519`?

- Compare `x25519-dalek` (high-level X25519) and `curve25519-dalek` (low-level
  field/group operations). Confirm `x25519-dalek` exposes the API we need
  (`PublicKey`, `StaticSecret`, `EphemeralSecret`,
  `SharedSecret::was_contributory()`).
- Confirm `x25519-dalek` is the right dependency layer (high-level) rather than
  reaching into `curve25519-dalek` directly.
- Pick the **exact** latest stable version on crates.io. As of writing the line
  is `x25519-dalek = "2.x"`. Find the most-recent point release with no open
  RUSTSEC advisories.

#### Q2: Which crate(s) for `@webbuf/ed25519`?

- Compare `ed25519-dalek` (Dalek implementation) and `ed25519` (RustCrypto trait
  crate that `ed25519-dalek` interops with).
- Confirm we depend only on `ed25519-dalek`. The `ed25519` trait crate is
  interesting for downstream consumers but adds a dependency for no benefit if
  WebBuf isn't exposing the trait surface.
- Pick the exact latest stable version. The line is `ed25519-dalek = "2.x"`.

#### Q3: Feature flags — what to enable, what to disable

For each of `x25519-dalek` and `ed25519-dalek`, decide:

- `default-features = false` — almost certainly yes, to avoid pulling in
  unwanted defaults. Confirm by listing what defaults are.
- `zeroize` — yes; matches WebBuf's existing posture on private-key crates (the
  secp256k1 wrapper enables zeroization).
- `static_secrets` (x25519-dalek) — needed to expose `StaticSecret` alongside
  `EphemeralSecret`. WebBuf's API takes a private key in hand, so static is the
  right shape.
- `reusable_secrets` (x25519-dalek) — probably no; `EphemeralSecret` is
  single-use by design and reusable secrets are a footgun.
- `precomputed-tables` (curve25519-dalek; transitively important) — trades
  binary size for performance. WebBuf's WASM pipeline has been
  binary-size-conscious historically; defer the decision to a measured
  comparison in Experiment 2 if size matters more than speed for our consumers.
- `digest` / `rand_core` (ed25519-dalek) — investigate whether PureEdDSA signing
  requires either. Pin versions if pulled transitively.
- `serde` — no. WebBuf serializes through `WebBuf` / `FixedBuf`, not serde.
- `legacy_compatibility` (ed25519-dalek) — no, unless we have a consumer
  demanding pre-RFC-8032 verification semantics. KeyPears doesn't.

For each, record the chosen flag list and the rationale.

#### Q4: WASM target compatibility

- Confirm `x25519-dalek` and `ed25519-dalek` compile to `wasm32-unknown-unknown`
  with `wasm-pack --target bundler`.
- Identify any `getrandom` configuration needed. The crates use
  `rand_core::CryptoRng` for randomness; in WASM the underlying source is
  `getrandom`, which historically requires the `js` feature on `getrandom 0.2.x`
  but that requirement is changing with `getrandom 0.3.x`. Pin or document
  whichever applies.
- Note any `unstable_features` warnings or build-time gotchas.
- Cross-check against the existing PQ packages (`@webbuf/mlkem`,
  `@webbuf/mldsa`) to confirm the pipeline pattern is reusable.

#### Q5: Audit and CVE history

- Pull the public audit history. The 2019 Quarkslab audit (commissioned by Tari
  Labs) covered the pre-1.0 `curve25519-dalek` and `subtle` crates; subsequent
  4.x / 2.x changes are not under that audit. Note this for the `@webbuf/x25519`
  and `@webbuf/ed25519` README audit-posture sections.
- Search RUSTSEC for `x25519-dalek`, `ed25519-dalek`, and `curve25519-dalek`
  advisories. Document any historical CVEs and their fix versions.
- Compare the audit posture to the WebBuf-PQC crates: the Dalek line is
  significantly more mature, which should be reflected in the package README
  warnings (a softer "no recent audit on 2.x" rather than the PQC packages' "no
  public audit at all" wording).

#### Q6: Existing WebBuf parallels

- Read `rs/webbuf_p256/Cargo.toml`, `rs/webbuf_p256/src/lib.rs`,
  `rs/webbuf_p256/wasm-pack-bundler.zsh`, and the corresponding TypeScript
  wrapper to understand the established patterns for signature / ECDH primitives
  in WebBuf.
- Read `rs/webbuf_secp256k1/Cargo.toml` and source for the same reason — the
  long-standing wrapper for an elliptic curve crate.
- Read `rs/webbuf_mlkem/Cargo.toml` to confirm the exact-pin pattern
  (`= "x.y.z"`) and the `wasm` feature gating.
- Document any conventions to copy: how the `wasm` feature is conditionally
  exported via `cfg_attr`, how zeroization is plumbed, how randomness is
  sourced.

#### Q7: KAT and test-vector source

- Identify the official RFC 7748 / RFC 8032 test vectors WebBuf will use to
  validate the eventual `@webbuf/x25519` and `@webbuf/ed25519` implementations.
  Both RFCs include canonical vectors.
- Identify small-order public points for the X25519 all-zero rejection test (RFC
  7748 §6.1 and the cryptographic-frontier literature list eight points;
  `x25519-dalek` has them in test fixtures we can re-use).
- Note these as inputs for the eventual implementation experiments; they don't
  need to be captured in this experiment's output, just pointed at.

### Risks

1. **Picking the wrong feature set surfaces only at build time.** A feature flag
   that pulls in a `std`-requiring transitive dependency can fail the WASM build
   cryptically. Mitigation: explicitly list the feature decisions in the survey
   and run a smoke `cargo check --target wasm32-unknown-unknown` for each crate
   before committing to the choices in Experiment 2.
2. **`getrandom` API churn.** The 0.2.x → 0.3.x transition reshuffled the `js`
   feature requirements; pinning to whichever the latest `x25519-dalek` /
   `ed25519-dalek` transitively pull in needs to match what WebBuf's existing
   WASM pipeline uses. Cross-check against `Cargo.lock` for the existing PQ
   packages.
3. **Audit-posture wording temptation.** The dalek crates' 2019 Quarkslab audit
   (commissioned by Tari Labs, scope: pre-1.0 `curve25519-dalek` + `subtle`)
   might tempt us to write a stronger audit claim than is accurate for the
   current 4.x / 2.x line. Resolve by stating the verifiable fact (auditor +
   year + scope + what's not under the audit) rather than the warmer-sounding
   paraphrase.
4. **Decision creep into Experiment 2.** It's tempting to also pre-decide
   build-pipeline details (the exact `wasm-pack-bundler.zsh` contents, the TS
   wrapper API surface). Resist. Experiment 1 stops at "pinned dependencies and
   feature flags." Experiment 2 will build the package, including the pipeline
   scripts.

### Out of scope for this experiment

- Writing any Rust code.
- Building any wasm artifact.
- Designing the TypeScript wrapper API surface (that lives in the per-package
  experiments — Experiment 2+).
- Designing or implementing `@webbuf/aesgcm-x25519dh-mlkem` or the composite
  signature package.
- Choosing a name for the composite signature package.
- Deciding `precomputed-tables` empirically — that decision wants a measured
  size/perf trade-off comparison, which is appropriate work for Experiment 2
  once we can actually compile.

### Success criteria

The experiment is complete (recorded as **Result: Pass**) when the following are
decided and documented in this issue:

- Pinned exact versions for `x25519-dalek`, `ed25519-dalek`, and (transitively)
  `curve25519-dalek`.
- Feature flag set (enabled / disabled defaults) for each direct dependency.
- Confirmed WASM compatibility with `wasm32-unknown-unknown` plus any required
  `getrandom` / `rand_core` configuration.
- Audit / RUSTSEC summary suitable for verbatim use in the `@webbuf/x25519` and
  `@webbuf/ed25519` README audit-posture sections.
- Pointers to the WebBuf packages whose `Cargo.toml` / `wasm-pack-bundler.zsh`
  patterns we'll copy in Experiment 2.
- Pointers to the RFC 7748 / RFC 8032 official test vectors and the small-order
  points list.

If any question above resolves to "we don't know yet, need to build to find out"
(e.g. `precomputed-tables` size impact), explicitly defer it to Experiment 2 in
the **Result** section rather than guessing.

### Implementation

Research pass executed by reading crate manifests on crates.io, the `docs.rs`
API surfaces, the `dalek-cryptography` GitHub monorepo, the RUSTSEC advisory
database, the Quarkslab 2019 audit blog post and report PDF, and the existing
WebBuf parallels (`rs/webbuf_p256`, `rs/webbuf_secp256k1`, `rs/webbuf_mlkem`).
One decision per question recorded below.

#### A1: `@webbuf/x25519` depends only on `x25519-dalek`

`x25519-dalek` exposes the full surface WebBuf needs: `PublicKey`,
`StaticSecret`, `EphemeralSecret`, `SharedSecret::was_contributory()`. Reaching
directly into `curve25519-dalek` would buy nothing for an X25519 ECDH wrapper.
**`curve25519-dalek` is pulled in transitively and pinned in `Cargo.toml` to
defend against yanks.**

- Latest stable: **`x25519-dalek = "=2.0.1"`** (published 2024-02-07).
- The `3.0.0-pre.N` line is pre-release only; not eligible for pinning.
- Dependency graph at this version: `curve25519-dalek ^4` → `=4.1.3` after the
  WebBuf yank-defense pin (see A3).

#### A2: `@webbuf/ed25519` depends only on `ed25519-dalek`

The RustCrypto `ed25519` trait crate is interesting for downstream trait-driven
consumers, but adds a dependency for no benefit if WebBuf doesn't expose the
trait surface. WebBuf's API is concrete `FixedBuf<32>` / `FixedBuf<64>` bytes in
/ out, so the trait crate is unnecessary.

- Latest stable: **`ed25519-dalek = "=2.2.0"`** (published 2025-07-09).
- API confirmed: `SigningKey: Signer<Signature>` and
  `VerifyingKey: Verifier<Signature>` give PureEdDSA
  `sign(msg: &[u8]) -> Signature` and `verify(msg: &[u8], sig: &Signature)` per
  RFC 8032 §5.1.6, no prehash. Ed25519ph is segregated behind `DigestSigner` /
  `DigestVerifier` and is not used.

#### A3: `curve25519-dalek` is pinned in WebBuf's `Cargo.toml`

Both `x25519-dalek` and `ed25519-dalek` declare `curve25519-dalek = "^4"`
internally. Cargo will resolve to the highest non-yanked 4.x.

- Latest stable: **`curve25519-dalek = "=4.1.3"`** (published 2024-06-18).
- **`curve25519-dalek 4.2.0` is YANKED** (published 2025-07-09, since yanked).
  Without an exact pin, a future yank or a clean lock could shift the version
  unexpectedly. Pin to defend against this.
- 4.1.3 also includes the **RUSTSEC-2024-0344 timing-leak fix** (`Scalar29::sub`
  / `Scalar52::sub` LLVM-inserted branch). Earlier 4.x is vulnerable.

#### A4: Feature flags

**`x25519-dalek 2.0.1` defaults are
`["alloc", "precomputed-tables", "zeroize"]`.** `static_secrets` is **NOT** in
the default set in 2.x — it must be explicitly enabled to get the `StaticSecret`
constructor WebBuf needs (the user supplies the 32 raw private-key bytes; we
don't generate them inside Rust). `getrandom` is gated behind a feature of the
same name and is **off by default** — exactly what we want.

```toml
x25519-dalek = { version = "=2.0.1", default-features = false, features = [
    "static_secrets",        # required for `StaticSecret::from([u8; 32])`
    "zeroize",               # private-key memory zeroized on drop
    "precomputed-tables",    # base-point precomputation (faster ECDH; binary
                             # size impact deferred to Experiment 2 measurement)
] }
```

Disabled: `alloc` (not needed for raw-byte API), `serde`, `reusable_secrets`
(footgun by design), `getrandom` (we pass bytes from JS), `pem`, `pkcs8`.

**`ed25519-dalek 2.2.0` defaults are `["fast", "std", "zeroize"]`** — crucially
**`std` is in the default set**. `std` pulls `sha2/std` which breaks the
`no_std`-friendly WASM build. **Must use `default-features = false`** and re-add
the wanted features explicitly.

```toml
ed25519-dalek = { version = "=2.2.0", default-features = false, features = [
    "fast",                  # = curve25519-dalek/precomputed-tables
    "zeroize",               # private-key memory zeroized on drop
] }
```

Disabled: `std` (would break WASM), `alloc` (not needed for raw-byte API),
`rand_core` (we pass seed bytes from JS), `digest` (Ed25519ph prehash variant —
explicitly out per the issue's PureEdDSA-only constraint), `serde`, `pem`,
`pkcs8`, `legacy_compatibility` (pre-RFC 8032 verification semantics — KeyPears
doesn't need it), `hazmat`, `batch`, `asm`.

#### A5: WASM target compatibility

Both crates compile cleanly to `wasm32-unknown-unknown` with the feature sets
above. Critically:

- **No `getrandom` in the dep graph** when the RNG features are disabled.
  `x25519-dalek 2.0.1` makes `getrandom` strictly opt-in via the `getrandom`
  feature; `ed25519-dalek 2.2.0` makes `rand_core` optional behind a feature of
  the same name. With both off, neither `getrandom 0.2.x` nor `0.3.x` is pulled,
  and the historical `js` / `wasm_js` feature dance is sidestepped entirely.
- The `cpufeatures` dep that `curve25519-dalek` pulls is gated to
  `target_arch = "x86_64"` and is irrelevant on `wasm32`.
- `wasm-pack --target bundler` works the same as for `webbuf_blake3`,
  `webbuf_sha256`, `webbuf_mlkem`. Existing WebBuf bundler scripts
  (`rs/webbuf_*/wasm-pack-bundler.zsh`) can be copy-modified for the new crates
  without changes.

WebBuf's existing `Cargo.lock` already pins `getrandom = "0.2.16"` for the
SLH-DSA path (which uses `rand_core 0.10.1`); the new x25519/ed25519 crates
won't perturb this because they don't pull `getrandom` at all under the chosen
feature set.

#### A6: Audit history and RUSTSEC advisories

- **2019 audit was Quarkslab, not Trail of Bits.** Commissioned by Tari Labs
  (~30 person-days, ~4 weeks, two engineers). Scope: `subtle` and pre-1.0
  `curve25519-dalek` (Rust nightly-2019-06-11). Outcome: minor findings only;
  the most-cited is that `Scalar::from_bits` allows non-canonical `Scalar52`
  construction. Sources: the Quarkslab blog post
  `https://blog.quarkslab.com/security-audit-of-dalek-libraries.html` and the
  report PDF
  `https://blog.quarkslab.com/resources/2019-08-26-audit-dalek-libraries/19-06-594-REP.pdf`.
- The 4.x line of `curve25519-dalek` and the 2.x lines of `x25519-dalek` /
  `ed25519-dalek` are **not under** the Quarkslab audit.

RUSTSEC advisories to surface in the package READMEs:

- **`RUSTSEC-2022-0093` (CVE-2022-50237)** — `ed25519-dalek` "Double Public Key
  Signing Function Oracle Attack." Affected `< 2.0.0`; fixed in `2.0.0` by the
  `SigningKey` / `VerifyingKey` API redesign. Our pinned `=2.2.0` is safe.
- **`RUSTSEC-2024-0344` (CVE-2024-58262)** — `curve25519-dalek` timing
  variability in `Scalar29::sub` / `Scalar52::sub` (LLVM `jns` insertion).
  Affected `< 4.1.3`; fixed in `4.1.3` via volatile-read optimization barrier.
  Our pinned `=4.1.3` is safe.
- **`x25519-dalek`** — no direct advisories on rustsec.org. Inherits the
  curve25519-dalek timing fix transitively.

Audit-posture wording for the package READMEs (verifiable fact formulation, not
paraphrase):

> The `curve25519-dalek` (and `subtle`) crates received a security audit by
> Quarkslab in 2019 (commissioned by Tari Labs). That audit covered the pre-1.0
> codebase. The current `curve25519-dalek 4.x`, `x25519-dalek 2.x`, and
> `ed25519-dalek 2.x` lines are not under the 2019 audit, but the 4.1.3 / 2.0.0
> versions include fixes for two RUSTSEC advisories: RUSTSEC-2022-0093
> (ed25519-dalek keypair-oracle, fixed in 2.0.0) and RUSTSEC-2024-0344
> (curve25519-dalek scalar-sub timing leak, fixed in 4.1.3). WebBuf pins to
> versions that include both fixes.

This is softer than the WebBuf-PQC packages' "no public audit at all" wording,
but more precise than "the dalek crates have been audited" — which would
over-claim coverage of the modern API surface.

#### A7: WebBuf parallels for Experiment 2

Patterns to copy in the implementation experiments:

- **`rs/webbuf_p256/Cargo.toml`** — clean elliptic-curve wrapper using
  `default-features = false, features = ["arithmetic"]` on the underlying
  RustCrypto crate, plus `[features] wasm = ["wasm-bindgen"]` feature gating on
  the WebBuf side.
- **`rs/webbuf_secp256k1/Cargo.toml`** — same shape with `k256`. Both these
  wrappers use `[lib] crate-type = ["cdylib", "rlib"]` which is the WebBuf
  convention.
- **`rs/webbuf_mlkem/Cargo.toml`** — exact-pin precedent for a cryptographic dep
  (`ml-kem = "=0.2.3"`).
- **`rs/webbuf_p256/wasm-pack-bundler.zsh`** — bundler script with `rm` cleanup;
  `rs/webbuf_mlkem/wasm-pack-bundler.zsh` uses the defensive `rm -f` form, which
  is the better pattern for new packages.
- **`#[cfg_attr(feature = "wasm", wasm_bindgen)]`** — the conditional WASM
  export pattern documented in CLAUDE.md and used uniformly across existing
  wrappers.

No conventions diverge from these — Experiment 2 will mechanically mirror them.

#### A8: Test-vector sources for Experiment 2+

- **X25519 (RFC 7748):** §5.2 single-iteration IUT vectors and the 1 / 1,000 /
  1,000,000-iteration ladder tests; §6.1 worked Alice/Bob example with the
  expected 32-byte shared secret. Both are short enough to hard-code in the
  eventual Rust `mod tests`.
- **Ed25519 (RFC 8032):** §7.1 PureEdDSA TEST 1–4 + the 1023-byte test + the
  SHA-512-of-`"abc"` test. The dalek upstream uses Adam Langley's `agl/ed25519`
  `sign.input` superset, which does not trivially align with §7.1 — WebBuf will
  hard-code the §7.1 vectors directly to assert literal RFC conformance.
- **Small-order point list (X25519 all-zero rejection):** **NOT in RFC 7748
  itself.** The canonical reference list of 7 small-order Curve25519
  u-coordinates is in Cremers & Jackson, "Prime, Order Please!" (2019), and in
  Adam Langley's notes
  (`https://moderncrypto.org/mail-archive/curves/2017/000898.html`).
  `x25519-dalek`'s upstream test suite does **not** enumerate them; WebBuf must
  hard-code them and assert that `x25519SharedSecretRaw` rejects each.

These pointers feed Experiment 2+ directly; capturing the actual vectors here
would duplicate them.

### Result: Pass

Concrete pinned dependencies for the X25519 and Ed25519 primitive packages,
ready for Experiment 2 to consume:

```toml
# rs/webbuf_x25519/Cargo.toml
[dependencies]
x25519-dalek = { version = "=2.0.1", default-features = false, features = [
    "static_secrets",
    "zeroize",
    "precomputed-tables",
] }
curve25519-dalek = { version = "=4.1.3", default-features = false, features = [
    "zeroize",
    "precomputed-tables",
] }
wasm-bindgen = { version = "0.2", optional = true }

[features]
wasm = ["wasm-bindgen"]
```

```toml
# rs/webbuf_ed25519/Cargo.toml
[dependencies]
ed25519-dalek = { version = "=2.2.0", default-features = false, features = [
    "fast",
    "zeroize",
] }
curve25519-dalek = { version = "=4.1.3", default-features = false, features = [
    "zeroize",
    "precomputed-tables",
] }
wasm-bindgen = { version = "0.2", optional = true }

[features]
wasm = ["wasm-bindgen"]
```

**Decision summary:**

- Crate ecosystem: **dalek-cryptography** (`x25519-dalek`, `ed25519-dalek`, both
  built on `curve25519-dalek`). Confirmed distinct from RustCrypto; Codex's
  correction on the original issue wording is reflected in the Background's
  Decision Log.
- Pinned versions: `x25519-dalek = "=2.0.1"`, `ed25519-dalek = "=2.2.0"`,
  `curve25519-dalek = "=4.1.3"`. Pinning `curve25519-dalek` directly defends
  against the yanked 4.2.0 and any future yank.
- Feature flags: each crate uses `default-features = false`. For `x25519-dalek`
  we add `static_secrets` (required for `StaticSecret::from([u8; 32])`),
  `zeroize`, `precomputed-tables`. For `ed25519-dalek` we add `fast` (=
  `curve25519-dalek/ precomputed-tables`) and `zeroize`. Critically,
  `ed25519-dalek`'s default `std` feature is **disabled** — it would break the
  `no_std`-friendly WASM build via `sha2/std`.
- WASM compatibility: both crates build cleanly on `wasm32-unknown-unknown` with
  `wasm-pack --target bundler` under the chosen feature set. **No `getrandom` is
  pulled into the dep graph** — the `js` / `wasm_js` feature dance is avoided
  entirely by sourcing randomness from JS and passing raw bytes into Rust,
  matching the existing WebBuf pattern.
- Audit posture: 2019 Quarkslab audit covered pre-1.0 `subtle` +
  `curve25519-dalek`; the 4.x / 2.x lines are not under that audit.
  RUSTSEC-2022-0093 (ed25519-dalek keypair-oracle, fixed 2.0.0) and
  RUSTSEC-2024-0344 (curve25519-dalek scalar-sub timing leak, fixed 4.1.3) are
  both already addressed by the pinned versions. README audit-posture wording
  drafted in A6 above.
- Test-vector sources: RFC 7748 §5.2/§6.1 for X25519, RFC 8032 §7.1 for Ed25519.
  Small-order point list NOT in RFC 7748 — comes from Cremers & Jackson "Prime,
  Order Please!" + Langley notes; WebBuf hard-codes the seven u-coordinates for
  the all-zero rejection test.
- Deferred to Experiment 2: empirical `precomputed-tables` size / performance
  trade-off measurement (we keep the feature on for now; re-evaluate if the
  inlined-WASM base64 grows beyond the existing WebBuf packages' typical sizes).

The next experiment will build `@webbuf/x25519` end-to-end against this
pinned-dependency baseline.

## Experiment 2: Build `@webbuf/x25519` end-to-end

### Goal

Ship the `@webbuf/x25519` package — Rust crate, WASM, TypeScript wrapper, tests,
README — using the dependency pins from Experiment 1. After this experiment
closes, the package can be imported and used by any consumer that needs raw RFC
7748 X25519 ECDH.

This is the smallest end-to-end build in the issue. It validates the
dalek-cryptography pipeline against WebBuf's existing wasm-pack-bundler /
inline-base64 / TypeScript-wrapper conventions before a second package
(`@webbuf/ed25519` in the next experiment) leans on the same pattern, and before
the hybrid encryption package (`@webbuf/aesgcm-x25519dh-mlkem` in a later
experiment) leans on this primitive.

### What this experiment delivers

- A new Rust crate at `rs/webbuf_x25519/` with `Cargo.toml`, `src/lib.rs`,
  `wasm-pack-bundler.zsh`, and `LICENSE`.
- A new TypeScript package at `ts/npm-webbuf-x25519/` with `package.json`,
  `tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts`,
  `build-inline-wasm.ts`, `src/index.ts`, `test/index.test.ts`,
  `test/audit.test.ts`, `README.md`, and the inline-base64 / bundler WASM
  artifact directories.
- The Rust crate added to the `[workspace] members` list in `rs/Cargo.toml`.
- The TypeScript package added to `pnpm-workspace.yaml` (if explicit enumeration
  is used; if it's a glob, no change needed).
- The umbrella `webbuf` package re-exporting the new functions from
  `@webbuf/x25519`, with the dependency added to `ts/npm-webbuf/ package.json`.
- Tests passing at every layer: `cargo test`, `vitest`, and umbrella typecheck +
  build.

### Public API

The TypeScript surface mirrors the established `@webbuf/p256` shape:

```typescript
// ts/npm-webbuf-x25519/src/index.ts
export function x25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32>;

export function x25519SharedSecretRaw(
  privKey: FixedBuf<32>,
  pubKey: FixedBuf<32>,
): FixedBuf<32>;
```

Both functions accept and return 32-byte `FixedBuf` values. **No `FixedBuf<33>`
SEC1-compressed point shape** like P-256; X25519 public keys are 32-byte
u-coordinates per RFC 7748 §5.

`x25519SharedSecretRaw` **throws** if the resulting shared secret is the
all-zero 32-byte value (i.e. `SharedSecret::was_contributory()` returns false).
This is the conservative position pinned in the Decision Log: the primitive
itself enforces, every consumer inherits the protection.

#### Clamping behavior

X25519 requires private-key bit-clamping per RFC 7748 §5 ("decodeScalar25519")
before scalar multiplication. WebBuf's wrapper accepts any 32 raw bytes as the
private key and applies clamping internally — matching what JS callers expect
(they shouldn't have to know about clamping). This is already the behavior of
`x25519-dalek::StaticSecret::from([u8; 32])` under the hood, which calls
`clamp_integer` during the scalar-mult.

The README will explicitly document this so consumers don't double-clamp or
assume otherwise.

### Rust crate

```toml
# rs/webbuf_x25519/Cargo.toml — pinned per Experiment 1's Result
[package]
name = "webbuf_x25519"
description = "X25519 ECDH (RFC 7748) for WebBuf with optional WASM support."
version.workspace = true
edition = "2021"
license = "MIT"
authors = ["Identellica LLC"]
repository = "https://github.com/identellica/webbuf"

[lib]
crate-type = ["cdylib", "rlib"]

[features]
wasm = ["wasm-bindgen"]

[dependencies]
x25519-dalek = { version = "=2.0.1", default-features = false, features = [
    "static_secrets",
    "zeroize",
    "precomputed-tables",
] }
curve25519-dalek = { version = "=4.1.3", default-features = false, features = [
    "zeroize",
    "precomputed-tables",
] }
wasm-bindgen = { version = "0.2", optional = true }

[dev-dependencies]
hex-literal = "0.4.1"
hex = "0.4.3"
```

Rust API surface:

```rust
// rs/webbuf_x25519/src/lib.rs
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn x25519_public_key_create(priv_key: &[u8]) -> Result<Vec<u8>, String> {
    let priv_arr: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn x25519_shared_secret_raw(
    priv_key: &[u8],
    pub_key: &[u8],
) -> Result<Vec<u8>, String> {
    let priv_arr: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be 32 bytes".to_string())?;
    let pub_arr: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;

    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(pub_arr);
    let shared = secret.diffie_hellman(&public);

    if !shared.was_contributory() {
        return Err(
            "X25519 shared secret is non-contributory (small-order public key)"
                .to_string(),
        );
    }

    Ok(shared.as_bytes().to_vec())
}
```

#### Rust tests

In `mod tests`, embedded vectors:

1. **RFC 7748 §6.1 worked example.** Hard-coded Alice/Bob private and public
   keys, expected shared secret. Asserts both `public_key_create` matches the
   published public keys and `shared_secret_raw` matches the published shared
   secret.
2. **RFC 7748 §5.2 single-iteration vector.** The
   `Input scalar / Input u-coordinate / Output u-coordinate` test vector.
   Asserts the X25519 ladder produces the expected output for both directions.
3. **Small-order rejection.** The seven small-order Curve25519 u-coordinates
   from Cremers & Jackson, "Prime, Order Please!" 2019 (and Adam Langley's
   curves-list notes), hard-coded as a slice. For each, assert
   `x25519_shared_secret_raw` returns `Err(...non-contributory...)`. Use a
   non-zero arbitrary private key for the local side.
4. **Clamping invariance.** Generate two private keys that differ only in the
   clamped bits (bit 0, 1, 2 of byte 0; bit 7 of byte 31; bit 6 of byte 31).
   Confirm both produce the same public key — proves clamping is applied
   internally and consumers don't need to pre-clamp.
5. **Round-trip for random keys.** Use `hex_literal!`-canned bytes (no RNG dep)
   for two arbitrary private keys; compute both public keys; compute both shared
   secrets; assert equality. This is a smoke test of the full ECDH cycle
   independent of the RFC vectors.

#### `wasm-pack-bundler.zsh`

Copy the `rs/webbuf_mlkem/wasm-pack-bundler.zsh` shape (it's the most recent /
defensive form). The `rm -f` cleanup pattern handles missing files gracefully.

### TypeScript package

Layout copied from `ts/npm-webbuf-p256/`:

```
ts/npm-webbuf-x25519/
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── vitest.config.ts
├── build-inline-wasm.ts
├── README.md
├── src/
│   ├── index.ts
│   ├── rs-webbuf_x25519-bundler/
│   └── rs-webbuf_x25519-inline-base64/
└── test/
    ├── index.test.ts
    └── audit.test.ts
```

`src/index.ts` skeleton:

```typescript
import { wasm } from "./rs-webbuf_x25519-inline-base64/webbuf_x25519.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function x25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32> {
  const pub = wasm.x25519_public_key_create(privKey.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(pub));
}

export function x25519SharedSecretRaw(
  privKey: FixedBuf<32>,
  pubKey: FixedBuf<32>,
): FixedBuf<32> {
  const ss = wasm.x25519_shared_secret_raw(privKey.buf, pubKey.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(ss));
}
```

Rejected by Rust → throws across the WASM boundary → the TS wrapper re-throws as
a regular `Error`. WebBuf's existing pattern (e.g. in `@webbuf/secp256k1`)
already handles this; copy it verbatim.

#### TypeScript tests

`test/index.test.ts`:

- Round-trip: random `privKey` (via `FixedBuf.fromRandom<32>(32)`) →
  `x25519PublicKeyCreate(priv)` produces a 32-byte public key; both parties
  compute matching shared secrets via `x25519SharedSecretRaw`.
- Length invariants: public key and shared secret are exactly 32 bytes.
- Fixed-keypair determinism: a hard-coded private key always produces the same
  public key.
- All-zero / small-order rejection: each of the seven small-order u-coordinates
  from Cremers & Jackson causes `x25519SharedSecretRaw` to throw with the
  contributory-check error.

`test/audit.test.ts`:

- RFC 7748 §6.1 byte-precise KAT: Alice's private key, Bob's private key
  (hard-coded hex from the RFC), assert both public keys match the published
  values and the shared secret matches.
- RFC 7748 §5.2 single-iteration vector: input scalar + input u-coordinate
  produce the expected output u-coordinate.

Both tests use `hex` literals embedded in the test file; no fixture files.

#### Package README

Mirrors the `@webbuf/p256` README structure. Includes:

- Brief description: "X25519 ECDH (RFC 7748) for WebBuf."
- Usage example with `x25519PublicKeyCreate` and `x25519SharedSecretRaw`.
- An explicit **Clamping** subsection: "Accepts any 32-byte private key.
  Clamping per RFC 7748 §5 is applied internally — consumers don't need to
  pre-clamp."
- A **Small-order rejection** subsection: "`x25519SharedSecretRaw` throws if the
  shared secret is non-contributory (i.e. the peer's public key is small-order).
  This protects hybrid encryption schemes from being collapsed to PQ-only by a
  malicious peer's small-order public key."
- An **Audit posture** subsection using the verifiable-fact wording drafted in
  Experiment 1's A6: Quarkslab 2019 covered pre-1.0; current 4.x / 2.x lines not
  under that audit; RUSTSEC-2024-0344 fix included via the pinned
  `curve25519-dalek = "=4.1.3"`.

### Umbrella `webbuf` package

After the new package builds cleanly, add it to the umbrella:

- `ts/npm-webbuf/package.json`: add `"@webbuf/x25519": "workspace:^"` to
  dependencies.
- `ts/npm-webbuf/src/index.ts`: re-export `x25519PublicKeyCreate`,
  `x25519SharedSecretRaw` alongside the existing primitives.
- Run `pnpm install`, `pnpm run typecheck`, `pnpm run build:typescript` in the
  umbrella to confirm clean.

### Risks

1. **`StaticSecret::from([u8; 32])` clamping behavior.** I've stated it clamps
   internally based on docs.rs. Verify in Rust with the "Clamping invariance"
   test; if dalek's behavior differs from what's documented, the test fails fast
   and I revisit before shipping.
2. **`was_contributory()` semantics on edge inputs.** It detects the all-zero
   shared secret per RFC 7748 §6.1, but I should confirm it triggers for **all
   seven** small-order u-coordinates in Cremers & Jackson's list — some might
   produce non-zero (but non-secret) shared secrets. If `was_contributory()`
   only catches a subset, the primitive needs an additional explicit check on
   the `as_bytes()` output. The Rust small-order test will surface this
   empirically.
3. **`getrandom` sneaking in.** Experiment 1 confirmed neither crate pulls
   `getrandom` under the chosen feature set. Verify by inspecting `Cargo.lock`
   after `cargo build` — if `getrandom` appears for `webbuf_x25519`, something's
   misconfigured.
4. **WASM binary size.** `precomputed-tables` is on. The base64-inline WASM may
   be larger than `webbuf_p256`. Measure after build; if it doubles or worse,
   consider disabling `precomputed-tables` and re-evaluate. Defer the decision
   to actual measurement.
5. **TS-side error message stability.** Rust's `Err(String)` becomes a
   `wasm-bindgen` thrown JS error. The exact error message text on the
   small-order-rejection path becomes a test assertion. Keep the wording stable
   so audit tests don't churn — pick a message in Rust now and don't change it
   later without intent.
6. **The `version.workspace = true` precedent.** The Rust workspace version
   bumps when a release is cut. `webbuf_x25519` will inherit the next bump
   (0.16.0 or whatever is chosen). No special handling needed — same pattern as
   every other crate.

### Out of scope for this experiment

- `@webbuf/ed25519` — Experiment 3.
- `@webbuf/aesgcm-x25519dh-mlkem` (hybrid encryption) — a later experiment.
- Composite Ed25519 + ML-DSA-65 signature package — last experiment in the
  issue.
- Updating the existing `@webbuf/aesgcm-p256dh-mlkem` README to cross-link to
  `@webbuf/aesgcm-x25519dh-mlkem` — happens when the hybrid package lands.
- Empirical `precomputed-tables` size/perf measurement that would decide whether
  to ship without it. Measure now, defer the decision unless the size is
  unacceptable.
- Version bumps on any package. The user is doing the bump pass separately.
- Web Crypto interop helpers (the way `@webbuf/p256` exposes
  `p256PrivKeyToWebCryptoEcKey` / `p256PubKeyFromWebCrypto`). X25519 is
  supported in browsers via `crypto.subtle.importKey({ name: "X25519" })` but
  the API surface is different from P-256 ECDSA's; punt unless KeyPears asks for
  it.

### Success criteria

- `cargo build -p webbuf_x25519` clean.
- `cargo test -p webbuf_x25519 --release` all pass: RFC 7748 §6.1 + §5.2
  vectors, small-order rejection (seven points), clamping invariance,
  round-trip.
- `./wasm-pack-bundler.zsh` produces a clean `build/bundler/`.
- `pnpm install` in `ts/` resolves the new package.
- `pnpm run sync:from-rust && pnpm run build:wasm` in `ts/npm-webbuf-x25519`
  produces clean inline-base64 artifacts.
- `pnpm run typecheck` clean.
- `pnpm test` in `ts/npm-webbuf-x25519` all pass: round-trip, length invariants,
  deterministic public-key derivation, all-seven small-order rejections, RFC
  7748 §6.1 audit KAT, RFC 7748 §5.2 ladder vector.
- Umbrella `ts/npm-webbuf/`: `pnpm run typecheck` and
  `pnpm run build:typescript` clean after the re-export is added.
- `cat rs/Cargo.lock | grep getrandom` returns no `webbuf_x25519` dep-tree entry
  (verifies the Experiment 1 promise of no `getrandom` in the WASM-bound graph).
- Inline-base64 WASM size measured and noted in the **Result** section. If it's
  grossly larger than `@webbuf/p256`, document the trade-off and decide whether
  to ship as-is or disable `precomputed-tables`.

### Implementation

Built `@webbuf/x25519` end-to-end against the Experiment 1 pinned-dependency
baseline. Files created:

- `rs/webbuf_x25519/Cargo.toml` — exact pins per Experiment 1
  (`x25519-dalek = "=2.0.1"`, `curve25519-dalek = "=4.1.3"`,
  `default-features = false`, feature flags `static_secrets`, `zeroize`,
  `precomputed-tables`).
- `rs/webbuf_x25519/src/lib.rs` — two `wasm_bindgen` exports
  (`x25519_public_key_create`, `x25519_shared_secret_raw`) plus six `mod tests`
  cases.
- `rs/webbuf_x25519/wasm-pack-bundler.zsh` — the defensive `rm -f` cleanup
  pattern from `webbuf_mlkem`.
- `rs/webbuf_x25519/LICENSE` (MIT).
- `rs/Cargo.toml` workspace `members` and `[patch.crates-io]` updated.
- `ts/npm-webbuf-x25519/` — `package.json`, `tsconfig.json`,
  `tsconfig.build.json`, `build-inline-wasm.ts`, `src/index.ts`,
  `test/index.test.ts`, `test/audit.test.ts`, `README.md`, `LICENSE`, and the
  bundler / inline-base64 directories populated by the build pipeline.
- `ts/npm-webbuf/package.json` and `ts/npm-webbuf/src/index.ts` updated to
  re-export the new package alongside the other primitives.

The Rust `lib.rs` is intentionally flat (no submodule split) — only two
functions in the WASM-bindgen surface, so the indirection wouldn't earn its
keep. Doc-comments on each exported function call out the clamping behavior and
the contributory-check guarantee.

### Result: Pass

**Tests (6/6 Rust, 15/15 TypeScript):**

- `cargo test -p webbuf_x25519 --release` — 6/6 pass:
  `rfc_7748_6_1_alice_bob_worked_example`,
  `rfc_7748_5_2_single_iteration_vector`, `small_order_public_keys_are_rejected`
  (all seven canonical small-order u-coordinates rejected with the stable
  `non-contributory` error message), `clamping_is_internal`,
  `round_trip_hard_coded_keys`, `input_length_errors`.
- `pnpm test` in `ts/npm-webbuf-x25519` — 15/15 pass: 4 audit (RFC 7748 §6.1
  Alice's pub, Bob's pub, both-direction shared secret; RFC 7748 §5.2
  single-iteration vector) + 11 unit (random round-trip, length invariants,
  deterministic public-key derivation, all seven small-order rejections each as
  a separate `it()`, and a `FixedBuf` length-mismatch sanity check).

**Builds:**

- `cargo build -p webbuf_x25519` clean.
- `./wasm-pack-bundler.zsh` clean.
- `pnpm run typecheck` and `pnpm run build` clean in `ts/npm-webbuf-x25519`.
- `pnpm run typecheck` and `pnpm run build:typescript` clean in the umbrella
  `ts/npm-webbuf` after the re-export was added.

**WASM size — better than expected:**

- `webbuf_x25519_bg.wasm`: **68,185 bytes** (~67 KiB).
- For comparison: `webbuf_p256_bg.wasm` is 79,706 bytes (~78 KiB);
  `webbuf_secp256k1_bg.wasm` is 101,082 bytes (~99 KiB).
- The `precomputed-tables` feature is on and `webbuf_x25519` is still smaller
  than `webbuf_p256`. **Decision: ship with `precomputed-tables` enabled.** The
  Experiment 1 deferred decision is now closed.

**`getrandom` not in the dep graph:**

- `awk '/name = "webbuf_x25519"/,/^$/' rs/Cargo.lock` shows the only direct deps
  are `curve25519-dalek`, `hex`, `hex-literal`, `wasm-bindgen`, `x25519-dalek`.
  No `getrandom`, no `rand_core`, confirming the Experiment 1 promise. The two
  `getrandom` hits elsewhere in `Cargo.lock` belong to `webbuf_slhdsa`.

**Risk outcomes (all six green):**

- Risk #1 (clamping): the `clamping_is_internal` test passes — variants in
  clamped bits produce identical public keys. Confirmed empirically.
- Risk #2 (`was_contributory()` coverage): all seven canonical small-order
  points trigger the contributory-check failure. **No need for an additional
  explicit `as_bytes()` zero check** — `was_contributory()` is sufficient
  against the Cremers & Jackson list.
- Risk #3 (`getrandom` sneak-in): not present in the dep graph, verified via
  lockfile.
- Risk #4 (WASM binary size): smaller than `webbuf_p256`. Non-issue.
- Risk #5 (TS-side error message stability): the
  `non-contributory (small-order public key)` message is asserted in both Rust
  and TS test layers. Locked in.
- Risk #6 (`version.workspace = true`): unchanged behavior — picks up `0.15.1`
  from the workspace; will bump in lockstep with the next release.

**Public API delivered:**

```typescript
import { x25519PublicKeyCreate, x25519SharedSecretRaw } from "@webbuf/x25519";

x25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32>;
x25519SharedSecretRaw(
  privKey: FixedBuf<32>,
  pubKey: FixedBuf<32>,
): FixedBuf<32>; // throws on non-contributory peer pub
```

The umbrella `webbuf` package re-exports both functions alongside the existing
primitives.

The next experiment will build `@webbuf/ed25519` end-to-end against the same
Experiment 1 pinned-dependency baseline. The pipeline is now proven; that build
will be largely mechanical, with the design surface concentrated on the Ed25519
sign/verify API shape and the seed-vs-secret-key distinction.

## Experiment 3: Build `@webbuf/ed25519` end-to-end

### Goal

Ship the `@webbuf/ed25519` package — Rust crate, WASM, TypeScript wrapper,
tests, README — using the dependency pins from Experiment 1 and the build
pipeline proven by Experiment 2. After this experiment closes, `@webbuf/ed25519`
is ready to be paired with `@webbuf/mldsa` in the forthcoming
composite-signature experiment.

### What this experiment delivers

Same shape as Experiment 2 but for Ed25519:

- New Rust crate `rs/webbuf_ed25519/` with `Cargo.toml`, `src/lib.rs`,
  `wasm-pack-bundler.zsh`, `LICENSE`.
- New TypeScript package `ts/npm-webbuf-ed25519/` with the standard
  webbuf-package layout (the Experiment 2 output is the template).
- The Rust crate added to `rs/Cargo.toml` workspace `members` and
  `[patch.crates-io]`.
- Umbrella `webbuf` package re-exporting the new functions.
- Tests passing at every layer, including the RFC 8032 §7.1 audit KATs.

### Public API

The TypeScript surface targets a **flat, seed-only** shape. Three exported
functions, no `KeyPair` object:

```typescript
// ts/npm-webbuf-ed25519/src/index.ts

/** Derive the 32-byte Ed25519 public key from a 32-byte seed (RFC 8032
 *  §5.1.5 secret key). */
export function ed25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32>;

/** Sign a message with PureEdDSA (RFC 8032 §5.1.6). Produces a 64-byte
 *  (R || S) signature. The signer consumes the raw message bytes
 *  directly — no prehash. */
export function ed25519Sign(
  privKey: FixedBuf<32>,
  message: WebBuf,
): FixedBuf<64>;

/** Verify a 64-byte PureEdDSA signature against the public key and
 *  message (RFC 8032 §5.1.7). Returns `true` for a valid signature,
 *  `false` for any rejection (wrong key, tampered message, tampered
 *  signature, non-canonical S, malformed point). Throws only on
 *  malformed-length input. */
export function ed25519Verify(
  pubKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<64>,
): boolean;
```

#### Deviation from the issue's original Scope wording

The issue's outer Scope section originally proposed `ed25519KeyPair()` and
`ed25519KeyPairFromSeed(seed)`. This experiment drops both in favor of the flat
`ed25519PublicKeyCreate(privKey)` shape. Reasons:

- Mirrors `@webbuf/x25519` exactly (`x25519PublicKeyCreate(privKey)`), giving
  consumers a uniform "private key in, public key out" shape across the
  Curve25519 family.
- Random keypair generation is one line in JS:
  `const priv = FixedBuf.fromRandom<32>(32); const pub = ed25519PublicKeyCreate(priv);`.
  A `KeyPair` object would add type surface for nothing.
- The "from seed" naming was redundant with the seed-only API shape; if the only
  input form is a seed, the function name doesn't need to say so.

The Scope section's earlier sketch stays as the original "what we thought"; this
experiment's design is the pinned reality. Past issues followed the same
convention (the Scope section is a sketch; the experiments hold the truth).

#### Seed semantics

Ed25519 has a critical seed-vs-expanded distinction:

- **Seed** (32 bytes) — the input to RFC 8032 §5.1.5's derivation. Hashed with
  SHA-512 to produce the (clamped) signing scalar plus the 32-byte prefix used
  by the signing nonce. **This is what RFC 8032 calls the "secret key"** and
  what is stored on disk in OpenSSH, OpenPGP, and KeyPears.
- **Expanded signing key** (64 bytes internally) — the (clamped scalar ||
  prefix-hash) pair. Some libraries expose this as the "secret key" surface,
  which causes interop bugs.

`@webbuf/ed25519` standardizes on **seed-only** for `privKey`. Internally,
`ed25519-dalek 2.x`'s `SigningKey::from_bytes(&[u8; 32])` takes a seed and
expands it on every call; that's exactly what we want.

The README will explicitly document this so consumers don't pass a 64-byte
expanded form by mistake.

#### Verification semantics

`ed25519Verify` returns `boolean`. Failed verification is **not an exception**:

- Wrong key, tampered message, tampered signature, non-canonical `S`,
  small-order public key, malformed point bytes — all return `false`.
- Only **input-length errors** (private key not 32 bytes, signature not 64
  bytes, etc.) throw. The error message text is stable and asserted in tests.

This matches the pattern in `@webbuf/secp256k1` and `@webbuf/p256`'s ECDSA
verify — verification failure is a value, not an error.

The Rust crate has `legacy_compatibility` **disabled** (per Experiment 1's
feature-flag decisions). That means strict RFC 8032 §5.1.7 verification
semantics: signatures with non-canonical `S` are rejected, signatures with
small-order `R` are rejected. This is a **feature**, not a quirk; document it in
the README's verification subsection.

### Rust crate

```toml
# rs/webbuf_ed25519/Cargo.toml — pinned per Experiment 1's Result
[package]
name = "webbuf_ed25519"
description = "Ed25519 PureEdDSA (RFC 8032) for WebBuf with optional WASM support."
version.workspace = true
edition = "2021"
license = "MIT"
authors = ["Identellica LLC"]
repository = "https://github.com/identellica/webbuf"

[lib]
crate-type = ["cdylib", "rlib"]

[features]
wasm = ["wasm-bindgen"]

[dependencies]
ed25519-dalek = { version = "=2.2.0", default-features = false, features = [
    "fast",
    "zeroize",
] }
curve25519-dalek = { version = "=4.1.3", default-features = false, features = [
    "zeroize",
    "precomputed-tables",
] }
wasm-bindgen = { version = "0.2", optional = true }

[dev-dependencies]
hex-literal = "0.4.1"
hex = "0.4.3"
```

Rust API surface:

```rust
// rs/webbuf_ed25519/src/lib.rs
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn ed25519_public_key_create(priv_key: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key.verifying_key().as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn ed25519_sign(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn ed25519_verify(
    pub_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let pub_arr: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes".to_string())?;
    let sig_arr: [u8; 64] = signature
        .try_into()
        .map_err(|_| "signature must be exactly 64 bytes".to_string())?;

    // VerifyingKey::from_bytes can fail for non-decompressible points;
    // treat that as a verification failure (return false), not a length
    // error.
    let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let signature = Signature::from_bytes(&sig_arr);

    Ok(verifying_key.verify(message, &signature).is_ok())
}
```

#### Rust tests

In `mod tests`, embedded vectors:

1. **RFC 8032 §7.1 TEST 1.** Empty message. Hard-coded seed, public key,
   expected signature. Asserts `ed25519_public_key_create` matches and
   `ed25519_sign` produces the published signature.
2. **RFC 8032 §7.1 TEST 2.** 1-byte message `0x72`.
3. **RFC 8032 §7.1 TEST 3.** 2-byte message `0xaf 0x82`.
4. **RFC 8032 §7.1 TEST 1024.** The long-message vector (1023 bytes).
5. **RFC 8032 §7.1 TEST SHA(abc).** SHA-512(`"abc"`) as the message.
6. **Round-trip on hard-coded seed.** Sign, then verify, returns true.
7. **Verify rejects tampered message.** Sign a message; flip a byte;
   `ed25519_verify` returns `false`.
8. **Verify rejects tampered signature.** Sign; flip a byte in `R` and in `S`
   (separately); both return `false`.
9. **Verify rejects wrong public key.** Sign with seed A; verify with pub-key
   from seed B; returns `false`.
10. **Verify rejects malformed public key gracefully.** Pass 32 bytes that
    aren't a valid Ed25519 point (e.g. all `0xff`); verify returns `false`, not
    an error.
11. **Verify input-length errors.** Wrong-length pub key / signature throw with
    stable error messages.

#### WASM size expectation

Bigger than `webbuf_x25519` because of the SHA-512 prefix-hash that
`ed25519-dalek` pulls in via `sha2`. Estimate: 100–150 KB. The Result section
will record actual numbers.

### TypeScript package

Layout copied from `ts/npm-webbuf-x25519/` (i.e. the Experiment 2 output):

```
ts/npm-webbuf-ed25519/
├── package.json
├── tsconfig.json
├── tsconfig.build.json
├── build-inline-wasm.ts
├── README.md
├── LICENSE
├── src/
│   ├── index.ts
│   ├── rs-webbuf_ed25519-bundler/
│   └── rs-webbuf_ed25519-inline-base64/
└── test/
    ├── index.test.ts
    └── audit.test.ts
```

`src/index.ts` skeleton:

```typescript
import {
  ed25519_public_key_create,
  ed25519_sign,
  ed25519_verify,
} from "./rs-webbuf_ed25519-inline-base64/webbuf_ed25519.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function ed25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32> {
  const pub = ed25519_public_key_create(privKey.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(pub));
}

export function ed25519Sign(
  privKey: FixedBuf<32>,
  message: WebBuf,
): FixedBuf<64> {
  const sig = ed25519_sign(privKey.buf, message);
  return FixedBuf.fromBuf(64, WebBuf.fromUint8Array(sig));
}

export function ed25519Verify(
  pubKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<64>,
): boolean {
  return ed25519_verify(pubKey.buf, message, signature.buf);
}
```

#### TypeScript tests

`test/index.test.ts`:

- Round-trip: random `privKey` → derive public → sign + verify random message
  returns `true`.
- Length invariants: pub key 32 bytes, signature 64 bytes.
- Deterministic public-key derivation: fixed seed always produces same public
  key.
- Verify false on tampered message.
- Verify false on tampered signature.
- Verify false on wrong public key.
- Verify false on a public key that's not a valid Ed25519 point (all `0xff`
  bytes).

`test/audit.test.ts`:

- RFC 8032 §7.1 TEST 1 + 2 + 3 + 1024 + SHA(abc) — five byte-precise KAT
  regressions, each asserting the published public key and the published
  signature.

### Package README

Mirrors `@webbuf/x25519`'s structure, with adjustments for the sign/verify
shape:

- Brief: "Ed25519 PureEdDSA (RFC 8032) for WebBuf."
- Usage example showing keypair derivation, sign, verify.
- **Seed semantics** subsection: 32-byte seed, NOT a 64-byte expanded form. Cite
  RFC 8032 §5.1.5.
- **PureEdDSA only** subsection: no Ed25519ph; consumers wanting a prehash
  should hash externally and pass the digest as the "message." Cite the issue
  0007 Decision Log entry.
- **Strict verification** subsection: `legacy_compatibility` is OFF; signatures
  with non-canonical `S` and small-order `R` are rejected. This is the modern
  RFC 8032 §5.1.7 behavior.
- **Audit posture** subsection: same Quarkslab-2019 wording as `@webbuf/x25519`,
  plus the **RUSTSEC-2022-0093** note (ed25519-dalek keypair-oracle, fixed in
  2.0.0; pinned `=2.2.0` is safe).
- API table.
- Tests summary.
- License.

### Umbrella `webbuf` package

Same pattern as Experiment 2:

- `ts/npm-webbuf/package.json`: add `"@webbuf/ed25519": "workspace:^"`.
- `ts/npm-webbuf/src/index.ts`: add `export * from "@webbuf/ed25519";` alongside
  `@webbuf/x25519`.
- Verify with `pnpm install && pnpm run typecheck && pnpm run build:typescript`.

### Risks

1. **Seed vs. expanded confusion.** If a future consumer passes a 64-byte
   SigningKey output by mistake, our 32-byte API rejects it with a length error
   — good failure mode, but the README must make the seed convention explicit.
   Also document that `SigningKey::to_bytes()` in dalek 2.x returns the seed
   (not the expanded form), so round-tripping through serialization works as
   expected.
2. **Signature determinism vs. hedging.** PureEdDSA is deterministic per RFC
   8032; the same seed + message always produces the same signature. WebBuf does
   not opt into the hedged-signing variant added in `ed25519-dalek` 2.x (which
   requires the `rand_core` feature, which is off). This is consistent with
   KeyPears's audit model. Document the determinism in the README.
3. **`VerifyingKey::from_bytes` failure handling.** Some 32-byte values aren't
   valid Ed25519 points (encoding parity issues). The Rust wrapper turns this
   into `Ok(false)` rather than `Err`, matching the "verify failure is a value,
   not an exception" contract. Test this explicitly with all-`0xff` bytes.
4. **WASM size growth.** `sha2` is pulled in via `ed25519-dalek`. The
   inline-base64 string in the TS package will be larger than `@webbuf/x25519`.
   Probably acceptable — every cryptographic package has a fixed ~50 KB tax for
   the WASM glue plus the algorithm-specific code. Measure and decide.
5. **`Signature::from_bytes` infallibility.** In `ed25519-dalek 2.x`,
   `Signature::from_bytes(&[u8; 64])` is infallible — any 64 bytes parse into a
   `Signature` struct, and validation happens in `verify()`. The wrapper is
   correct on this; the test for tampered signatures still works because
   `verify()` rejects them.
6. **Test-vector formatting.** RFC 8032 §7.1 vectors include a 1023-byte
   message; copy carefully. Use `hex_literal!` and `concat!`-style breaking
   across multiple lines to keep the source readable. Verify the byte length
   matches the RFC's claim before running tests.

### Out of scope for this experiment

- `@webbuf/aesgcm-x25519dh-mlkem` — a later experiment. Once both primitives are
  landed, the hybrid encryption package is largely a copy of
  `aesgcm-p256dh-mlkem` with X25519 substituted for P-256.
- Composite Ed25519 + ML-DSA-65 signature package — last experiment in the
  issue. The Ed25519 sign/verify API delivered here is what the composite
  package will compose with.
- Ed25519ph prehash variant — locked out by the Decision Log.
- Hedged signing variant — out of scope; `rand_core` feature is off.
- Web Crypto interop helpers — punt.
- Updating issue 0006 / 0005 / 0004 cross-references — those issues are closed
  and immutable.

### Success criteria

- `cargo build -p webbuf_ed25519` clean.
- `cargo test -p webbuf_ed25519 --release` all pass: five RFC 8032 §7.1 KATs
  (TEST 1, 2, 3, 1024, SHA(abc)), round-trip, tampered-message rejection,
  tampered-signature rejection, wrong-public-key rejection, malformed-pub-key
  rejection, input-length errors.
- `./wasm-pack-bundler.zsh` clean.
- TS package: `pnpm install`, `pnpm run sync:from-rust && pnpm run build:wasm`,
  `pnpm run typecheck`, `pnpm test`, `pnpm run build` — all clean.
- Umbrella `webbuf`: `pnpm run typecheck` and `pnpm run build:typescript` clean
  after the re-export is added.
- `awk '/name = "webbuf_ed25519"/,/^$/' rs/Cargo.lock` shows no `getrandom`
  direct or transitive dep.
- WASM size measured and noted in the **Result** section.

### Implementation

_(To be filled in when the experiment is run.)_

### Result

_(To be filled in. Mark **Result: Pass** once the success-criteria checks all
green, with notable observations — RFC 8032 KAT outcomes, WASM size, any
feature-flag adjustments — recorded.)_
