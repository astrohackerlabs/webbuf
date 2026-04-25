+++
status = "closed"
opened = "2026-04-25"
closed = "2026-04-25"
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

## Experiment 1: Hedge ML-DSA `Sign` via existing `sign_internal`

### Goal

Make `mlDsa*Sign` hedged by default without enabling the `rand_core` feature on
the pinned `ml-dsa = "=0.1.0-rc.8"` crate and without adding new Rust
dependencies. Use the public `sign_internal(Mp, rnd)` primitive that's already
exported, with a manually constructed FIPS 204 external `M'` prefix and a
TypeScript-supplied `rnd`.

### Key technical insight

`ml-dsa` 0.1.0-rc.8 gates `sign_randomized` (and `sign_mu_randomized`) behind
`#[cfg(feature = "rand_core")]`. Enabling that feature pulls in `rand_core` and
`signature/rand_core`. Both are avoidable.

Reading the upstream source:

- `sign_internal(Mp, rnd)` — public, ungated — calls
  `MuBuilder::internal(tr, Mp)` then `raw_sign_mu(&mu, rnd)`.
- `sign_randomized(M, ctx, rng)` — gated — calls
  `MuBuilder::new(tr, ctx).message(&[M])`, generates `rnd` from `rng`, then
  `raw_sign_mu(&mu, &rnd)`.

`MuBuilder::internal` absorbs `tr`, then each segment of `Mp` in order.
`MuBuilder::new(...).message(...)` absorbs `tr`, `[0]`, `[ctx_len_byte]`, `ctx`,
then each segment of `M`. SHAKE-256 absorption is byte-streaming, so the
resulting μ is fully determined by the absorbed byte sequence.

Therefore, calling `sign_internal(Mp = &[&[0u8], &[ctx_len_byte], ctx, M], rnd)`
produces a signature byte-identical to
`sign_randomized(M, ctx, rng_yielding_rnd)`. Both paths converge on the same
`raw_sign_mu(&mu, &rnd)` call.

This gives us hedged ML-DSA signing through code we already have access to. The
only new piece is reformatting `M'` per FIPS 204 §5.4 in the Rust wrapper.

### Plan

**Rust (`rs/webbuf_mldsa/src/lib.rs`):** add a sixth function per parameter set
in the `mldsa_impl!` macro:

```rust
pub fn $sign_hedged_fn(
    sk_bytes: &[u8],
    message: &[u8],
    context: &[u8],
    addrnd: &[u8],
) -> Result<Vec<u8>, String>
```

Behavior:

1. Validate `sk_bytes.len() == ExpandedSigningKeyBytes<P>::size()`.
2. Validate `context.len() <= 255` (FIPS 204 §5.4 limit).
3. Validate `addrnd.len() == 32`.
4. Decode `ExpandedSigningKey::from_expanded(...)` (deprecation already
   suppressed elsewhere in the crate).
5. Build `Mp = &[&[0u8], &[context.len() as u8], context, message]`.
6. Convert `addrnd` to `B32`.
7. Call `sk.sign_internal(Mp, &rnd_b32)`.
8. Return `sig.encode().to_vec()`.

**TypeScript (`ts/npm-webbuf-mldsa/src/index.ts`):** rewire
`mlDsa{44,65,87}Sign` to call the new hedged Rust export with
`FixedBuf.fromRandom(32)`. Keep `mlDsa*SignDeterministic` calling the existing
`ml_dsa_*_sign` (which still uses `sign_deterministic`). Keep
`mlDsa*SignInternal` unchanged.

The wrapper looks like:

```typescript
export function mlDsa65Sign(
  signingKey: FixedBuf<4032>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<3309> {
  const out = ml_dsa_65_sign_hedged(
    signingKey.buf,
    message,
    defaultContext(context),
    randomSeed().buf,
  );
  return FixedBuf.fromBuf(3309, WebBuf.fromUint8Array(out));
}
```

### Tests

**Rust:** in `#[cfg(test)] mod tests` add:

- `test_ml_dsa_*_hedged_round_trip` for all three parameter sets — verify that
  `sign_hedged` output verifies via `verify_with_context`.
- `test_ml_dsa_65_hedged_differs_from_deterministic` — same sk, msg, ctx with
  non-zero rnd produces a different signature than rnd = 0.
- `test_ml_dsa_65_hedged_with_zero_rnd_matches_deterministic` — sanity check
  that rnd = 0^32 reproduces `sign_deterministic` output.
- `test_ml_dsa_65_hedged_rejects_bad_inputs` — wrong `addrnd` length, ctx
  > 255, malformed sk all return `Err(...)`.

**TypeScript:** add to `ts/npm-webbuf-mldsa/test/index.test.ts`:

- `default sign is hedged` — two consecutive `mlDsa65Sign(sk, msg)` calls
  produce different signatures.
- `hedged signature verifies via mlDsa*Verify` — round-trip check.
- `mlDsa*SignDeterministic still reproducible` — kept from existing tests;
  assert behavior unchanged.
- `hedged signature is rejected by mlDsa*VerifyInternal` — confirms
  domain-separator semantics.
- `regression: deterministic alias matches captured fixture` — capture one
  `mlDsa65SignDeterministic(sk, msg, ctx)` output today (hex), assert it still
  matches after the change. This guards against any unintended drift in the
  deterministic path.

**ACVP:** no change to `test/audit.test.ts`. Re-run to confirm 180 vectors still
pass.

### Risks

1. **`MuBuilder::internal` semantics change in a future ml-dsa version.**
   Mitigation: exact version pin (already in place); the Rust round-trip test
   (`hedged_with_zero_rnd_matches_deterministic`) catches any divergence by
   comparing against `sign_deterministic`. If a future bump breaks this, the
   test fails loudly.
2. **M' formatting bug.** If we mis-format the FIPS 204 prefix (wrong byte
   order, wrong domain separator), signatures will not verify under the FIPS 204
   external interface. The TS-side `mlDsa*Verify` test catches this immediately.
3. **`sign_internal` is marked `// TODO(RLB) Only expose based on a feature` in
   the upstream source.** A future ml-dsa version may gate it behind a feature
   flag. Our exact-version pin contains this risk; we'd need to bump pin and
   potentially enable the feature when we upgrade.

### Success criteria

- `cargo test -p webbuf_mldsa` passes (existing 5 + new tests).
- `pnpm test` in `ts/npm-webbuf-mldsa` passes (existing 191 + ~3 new).
- ACVP `audit.test.ts` still passes unchanged.
- `mlDsa*Sign(sk, msg)` produces different signatures on consecutive calls.
- `mlDsa*SignDeterministic` regression fixture matches captured value.
- WASM size delta is small (one new function per parameter set, all thin).

### Implementation

Extended the `mldsa_impl!` macro in `rs/webbuf_mldsa/src/lib.rs` with a seventh
function per parameter set: `ml_dsa_*_sign_hedged`. The implementation manually
constructs `M' = 0x00 || ctx_len || ctx || M` per FIPS 204 §5.4 as a 4-segment
slice and calls the existing `ExpandedSigningKey::sign_internal(Mp, &rnd_b32)`
with the TS-supplied `addrnd`. No `rand_core` feature enabled, no new Rust
dependencies, crate pin (`ml-dsa = "=0.1.0-rc.8"`) unchanged.

The TypeScript wrapper (`ts/npm-webbuf-mldsa/src/index.ts`) was re-pointed:
`mlDsa44Sign`, `mlDsa65Sign`, `mlDsa87Sign` now call the new
`ml_dsa_*_sign_hedged` exports with `randomSeed().buf` for the randomness.
`mlDsa*SignDeterministic` continues to call the existing `ml_dsa_*_sign`
(deterministic). `mlDsa*SignInternal` is unchanged.

**Subtle finding:** the captured-fixture regression test in the original plan
turned out unnecessary at the TypeScript level. The Rust test
`test_hedged_with_zero_rnd_matches_deterministic` directly compares
`sign_internal(Mp = [0x00, ctx_len, ctx, M], rnd = 0^32)` against
`sign_deterministic(M, ctx)` and asserts byte equality. That test is the
load-bearing regression check for "did `MuBuilder::internal` semantics drift?" —
capturing a 6,618-character hex fixture in TS would just be a derivative of the
same equivalence and would add brittleness without adding signal. Replaced the
old "deterministic sign aliases produce identical signatures" TS test with two
new ones: `default sign is hedged` and `SignDeterministic is reproducible`.

### Result: Pass

**Rust:** all 15 tests pass (`cargo test -p webbuf_mldsa --release`), including:

- Three round-trip tests (one per parameter set) for `sign_hedged`.
- `test_hedged_differs_from_deterministic` — same key/msg/ctx, non-zero rnd
  produces different sig than `sign_deterministic`.
- **`test_hedged_with_zero_rnd_matches_deterministic`** — the load-bearing
  regression check. `sign_internal` with manually constructed `M'` and
  `rnd = 0^32` produces the exact same bytes as `sign_deterministic(M, ctx)`.
  This validates that `MuBuilder::internal(tr, [0x00, ctx_len, ctx, M])` ≡
  `MuBuilder::new(tr, ctx).message([M])` byte-for-byte in `ml-dsa = 0.1.0-rc.8`.
- `test_hedged_with_empty_context_matches_zero_rnd_no_ctx` — same check with
  empty context.
- `test_hedged_bad_inputs` — wrong addrnd length, ctx > 255, malformed sk all
  return `Err(...)`.

**WASM size:** 189 KB → 201 KB (+12 KB for three new sign_hedged functions).
Within budget.

**TypeScript:** `pnpm test` reports 192/192 pass:

```
✓ test/index.test.ts (12 tests) 41ms
✓ test/audit.test.ts (180 tests) 127ms
```

The ACVP audit suite (180 vectors across keyGen, sigGen, sigVer × 3 parameter
sets) is unchanged from the previous state. The 12 high-level tests now include
explicit checks that `mlDsa*Sign` is hedged (different bytes per call) and that
`mlDsa*SignDeterministic` remains reproducible.

**Umbrella package:** `pnpm run typecheck` and `pnpm run build:typescript` in
`ts/npm-webbuf` both clean — re-exports still resolve correctly.

**Verification commands:**

- `cargo test -p webbuf_mldsa --release` in `rs`
- `./wasm-pack-bundler.zsh` in `rs/webbuf_mldsa`
- `pnpm run sync:from-rust` in `ts/npm-webbuf-mldsa`
- `pnpm run build:wasm` in `ts/npm-webbuf-mldsa`
- `pnpm run typecheck` in `ts/npm-webbuf-mldsa`
- `pnpm test` in `ts/npm-webbuf-mldsa`
- `pnpm run build` in `ts/npm-webbuf-mldsa`
- `pnpm run typecheck` in `ts/npm-webbuf`
- `pnpm run build:typescript` in `ts/npm-webbuf`

All passed.

## Conclusion

Issue 3 is complete. ML-DSA's high-level `mlDsa*Sign` API now matches SLH-DSA's
high-level signing posture: hedged by default, with explicit `SignDeterministic`
aliases for callers who need reproducibility, and the FIPS 204 internal
primitives still exposed under `*SignInternal` / `*VerifyInternal` for ACVP
vector tests and advanced users.

The implementation avoided enabling the `rand_core` feature on the pinned
`ml-dsa` crate by directly calling the public `sign_internal` primitive with a
manually constructed FIPS 204 `M'` prefix. The load-bearing regression test
`test_hedged_with_zero_rnd_matches_deterministic` confirms the byte-equivalence
between our shortcut and `sign_deterministic`, and will fail loudly if a future
`ml-dsa` upgrade changes `MuBuilder::internal` semantics.

The asymmetry observed during the issue 0002 audit — `slhDsaSha2_128fSign` was
hedged while `mlDsa65Sign` was deterministic — is now resolved. Same call site,
same behavior: hedged by default, FIPS 204 §3.6 best practice applied.

Crate pin (`ml-dsa = "=0.1.0-rc.8"`) unchanged. ACVP coverage intact. WASM grew
by 12 KB. No new Rust dependencies. No new TypeScript dependencies.
