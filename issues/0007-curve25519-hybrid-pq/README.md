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
- **X25519 small-order / all-zero rejection.** For `@webbuf/x25519` and the
  hybrid encryption package: feed the documented small-order Curve25519 public
  points (the eight points listed in RFC 7748 §6.1 / Cryptographic Frontier and
  `x25519-dalek`'s test vectors) and assert that `x25519SharedSecretRaw` throws
  and that hybrid encryption / decryption refuses to proceed. Without this, a
  malicious peer's small-order public key could collapse the hybrid scheme to
  PQ-only.

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

- Pull the public audit history. The 2019 Trail of Bits audit covered v1.0 of
  the dalek crates; subsequent v2.x changes are not under that audit. Note this
  for the `@webbuf/x25519` and `@webbuf/ed25519` README audit-posture sections.
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
3. **Audit-posture wording temptation.** The dalek crates' 2019 v1.0 audit might
   tempt us to write a stronger audit claim than is accurate for the current 2.x
   line. Resolve by stating the verifiable fact ("v1.0 audited by Trail of Bits
   in 2019; 2.x not under that audit") rather than the warmer-sounding
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

_(To be filled in when the experiment is run. The implementation is a research
pass — read crate docs, Cargo manifests, RUSTSEC advisories, existing WebBuf
packages — and record the decisions per question below.)_

### Result

_(To be filled in. Expected shape:_

```toml
# Pinned dependencies for @webbuf/x25519 and @webbuf/ed25519
x25519-dalek    = { version = "= X.Y.Z", default-features = false, features = ["..."] }
ed25519-dalek   = { version = "= A.B.C", default-features = false, features = ["..."] }
# Plus transitively-pinned curve25519-dalek if not implied.
```

_followed by audit-posture text and any gotchas. Mark **Result: Pass** once
recorded.)_
