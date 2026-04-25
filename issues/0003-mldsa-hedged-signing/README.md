+++
status = "open"
opened = "2026-04-25"
+++

# ML-DSA hedged signing default

## Goal

Make `mlDsa*Sign` hedged by default — generating per-signature randomness via
the platform CSPRNG — so that the high-level ML-DSA API matches both SLH-DSA's
high-level API and FIPS 204's recommended deployment posture.

The deterministic message-level variant should remain available under the
explicit `mlDsa*SignDeterministic` aliases that already exist, so callers who
need reproducibility (test vectors, protocol code with externally managed
randomness) keep that option.

## Background

Issue 0002 hardened the high-level post-quantum APIs by adding message-level
`Sign` / `Verify` functions with FIPS-aligned context separation. SLH-DSA ended
up hedged by default — `slhDsaSha2_128fSign(sk, msg)` generates `addrnd` in the
TypeScript wrapper via `FixedBuf.fromRandom(seedSize)` and forwards it through
to `try_sign_with_context`. Two calls with identical inputs produce different
signatures.

ML-DSA ended up deterministic by default. `mlDsa65Sign(sk, msg)` calls
`sign_deterministic(M, ctx)` in the underlying RustCrypto crate. Two calls with
identical inputs produce identical signatures. Issue 0002 Experiment 3 documents
this as deferred work:

> "Randomized or hedged ML-DSA signing was not added in this experiment. The
> preferred API uses the standardized deterministic ML-DSA.Sign variant because
> it is available from the pinned crate without adding RNG plumbing to the Rust
> WASM boundary. A future experiment can evaluate enabling upstream `rand_core`
> and passing TypeScript-generated randomness into a randomized signing export."

This issue is that future work.

### Why this matters

The asymmetry is surprising at the call site. Both functions look identical:

```typescript
slhDsaSha2_128fSign(signingKey, message); // hedged — different sigs each call
mlDsa65Sign(signingKey, message); // deterministic — identical sigs
```

A reader who knows SLH-DSA is hedged can reasonably assume ML-DSA is too. The
README does call this out, but design-by-disclaimer is weaker than
design-by-consistency.

### FIPS 204 guidance

FIPS 204 §3.6 (Choosing between hedged and deterministic ML-DSA) recommends the
hedged variant when a good random-bit source is available, citing defense
against fault and side-channel attacks. The deterministic variant exists for
environments without trusted RNGs.

WebBuf is not such an environment — it runs in browsers, Node, Deno, and Bun,
all of which expose `crypto.getRandomValues`. `FixedBuf.fromRandom` already
wraps that source for keypair generation, encapsulation, and SLH-DSA signing.
The same source should drive ML-DSA hedged signing.

### What needs to change

The pinned `ml-dsa` crate (`=0.1.0-rc.8`) already exposes
`ExpandedSigningKey::sign_randomized`, which takes an `&mut impl TryCryptoRng`
plus a message and a context. The Rust WASM boundary needs:

- a new function per parameter set (e.g. `ml_dsa_44_sign_hedged`,
  `ml_dsa_65_sign_hedged`, `ml_dsa_87_sign_hedged`) that accepts the expanded
  sk, message, context, and a 32-byte randomness buffer;
- a small RNG adapter that wraps the caller-supplied randomness so the
  RustCrypto trait bound is satisfied without enabling the upstream `rand_core`
  feature.

The TypeScript wrapper changes:

- `mlDsa*Sign(sk, message, context?)` switches from calling `*_sign_context`
  (deterministic) to calling `*_sign_hedged` with `FixedBuf.fromRandom(32)` for
  the randomness;
- `mlDsa*SignDeterministic(sk, message, context?)` keeps its current behavior
  unchanged — it remains the explicit deterministic alias;
- `mlDsa*SignInternal(sk, message, rnd)` is unchanged — still the FIPS 204
  internal primitive used by ACVP vectors.

This mirrors the SLH-DSA pattern: hedged by default, deterministic as an
explicit alias, internal as a primitive.

### Compatibility

This is a behavioral change to `mlDsa*Sign`. Callers who were relying on
deterministic output from `mlDsa*Sign` will see different bytes after the
change. Mitigations:

1. The new behavior matches FIPS 204 best practice and SLH-DSA's existing
   default — most callers should welcome the change.
2. `mlDsa*SignDeterministic` already exists and produces the previous bytes. Any
   caller relying on determinism can switch to that name in one line.
3. ACVP vector tests use `mlDsa*SignInternal`, not `mlDsa*Sign`, so vector
   coverage is unaffected.

The change is appropriate as a default-behavior fix rather than a
backwards-compatibility break — `mlDsa*Sign` is a new function from issue 0002
(April 2026); the deterministic-by-default behavior has not had time to lock in
across downstream consumers.

### Constraints

- **WASM model unchanged.** Synchronous Rust → WASM → base64 → TypeScript.
  Randomness sourced from the TypeScript layer via `FixedBuf.fromRandom`. No
  async initialization, no Rust-side `getrandom` plumbing.
- **No new RustCrypto features.** Avoid enabling `rand_core` /
  `signature/rand_core` on the pinned crate, since those pull in extra
  dependencies and the `TryCryptoRng` adapter pattern is small.
- **Crate pin unchanged.** `ml-dsa = "=0.1.0-rc.8"` stays.
- **ACVP vector coverage intact.** No changes to `*_sign_internal` or its test
  suite.

### Test plan

- `mlDsa*Sign(sk, msg)` produces different signatures on consecutive calls with
  identical inputs (hedged behavior).
- `mlDsa*SignDeterministic(sk, msg, ctx)` continues to produce identical
  signatures on consecutive calls with identical inputs.
- `mlDsa*SignDeterministic` output equals the pre-change `mlDsa*Sign` output for
  the same inputs (regression check).
- Both variants produce signatures verifiable by `mlDsa*Verify`.
- `mlDsa*VerifyInternal` continues to reject message-level signatures (no domain
  separator).
- Existing ACVP `audit.test.ts` continues to pass unchanged.
