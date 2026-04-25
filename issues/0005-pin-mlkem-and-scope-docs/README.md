+++
status = "closed"
opened = "2026-04-25"
closed = "2026-04-25"
+++

# Pin ml-kem exactly and clarify PQ encryption scope docs

## Goal

Two small, mechanical fixes prompted by an external review of the post-quantum
work landed in issues 0001–0004:

1. Tighten the `ml-kem` crate dependency from `version = "0.2.3"` to
   `version = "=0.2.3"` so the pin policy stated in issue 0001 is actually
   enforced.
2. Add a "Scope" subsection to the `@webbuf/aesgcm-mlkem` and
   `@webbuf/aesgcm-p256dh-mlkem` package READMEs documenting exactly what the
   packages bind into the derived key and AEAD, and what they do not. This makes
   the absence of context binding (sender identity, protocol version,
   application AAD) explicit so consumers can compensate at the application
   layer until issue 0006 lands.

## Background

### The pin slip

Issue 0001's Experiment 2 documented a deliberate exact-version pin on all three
RustCrypto PQC crates:

> **Pre-1.0 API churn** — all three crates are at `0.x.0-rc.N`. We pin exact
> versions (`=0.2.3` for `ml-kem`, `=0.1.0-rc.8` for `ml-dsa`, `=0.2.0-rc.4` for
> `slh-dsa`) to avoid surprise upgrades.

The rationale: even at a stable 0.2.x, a future patch release could change
behavior, fix a bug, or introduce a regression. The whole point of pinning all
three was to make crate updates a deliberate, reviewed action.

`ml-dsa` and `slh-dsa` actually ship with the `=` form:

- `rs/webbuf_mldsa/Cargo.toml`: `ml-dsa = "=0.1.0-rc.8"`
- `rs/webbuf_slhdsa/Cargo.toml`: `slh-dsa = "=0.2.0-rc.4"`

But `ml-kem` shipped with the loose form:

- `rs/webbuf_mlkem/Cargo.toml`:
  `ml-kem = { version = "0.2.3", features = ["deterministic"] }`

Per Cargo's semver rules, `version = "0.2.3"` is equivalent to `>=0.2.3, <0.3.0`
— a `cargo update` would silently pull in any future 0.2.x release. This
contradicts the documented pin policy and is a real defect, not a stylistic
inconsistency.

The fix is one line:

```toml
ml-kem = { version = "=0.2.3", features = ["deterministic"] }
```

Verify `Cargo.lock` is unchanged, run the test suite, done.

### The scope-docs gap

Issue 0004 shipped two encryption packages whose key schedules bind the
underlying P-256 + ML-KEM keys but **do not bind**:

- Sender identity (other than via the P-256 keypair itself)
- Recipient identity (other than via the keypair)
- Protocol version
- Message type
- Application context / transcript bytes

The README for `@webbuf/aesgcm-p256dh-mlkem` describes the schedule honestly:

```
ikm  = ecdhRaw || kemSS
salt = 0^32
info = "webbuf:aesgcm-p256dh-mlkem v1"
```

But it doesn't make the absence of identity/context binding explicit or give
consumers guidance on how to compensate. A reader could reasonably assume that
calling `aesgcmP256dhMlkemEncrypt(senderPriv, recipientPub, ...)` automatically
binds the sender's address into the encryption — it doesn't.

Issue 0006 will add an `aad` parameter to address this properly. In the
meantime, this issue makes the gap explicit in the package READMEs so consumers
can decide whether to wait for AAD support or work around it (e.g. by prepending
context bytes to the plaintext).

## What's in scope

1. Change `ml-kem` dependency declaration from `"0.2.3"` to `"=0.2.3"` in
   `rs/webbuf_mlkem/Cargo.toml`.
2. Re-run `cargo build`, `cargo test -p webbuf_mlkem`, and the TS test suite to
   confirm nothing breaks.
3. Add a `## Scope` section to:
   - `ts/npm-webbuf-aesgcm-mlkem/README.md`
   - `ts/npm-webbuf-aesgcm-p256dh-mlkem/README.md`
4. The Scope section should:
   - Enumerate exactly what is cryptographically bound (the keys, the fact that
     decapsulation will only succeed with the matching decapsulation key,
     AES-GCM authentication of the ciphertext + IV).
   - Enumerate exactly what is **not** bound (sender's federation identity,
     recipient's federation identity, protocol version, message type,
     application context, transcript state).
   - Direct consumers who need those bindings to either: (a) prepend context
     bytes to the plaintext, or (b) wait for issue 0006's AAD parameter.
5. Add a brief note to issue 0001's Experiment 2 acknowledging the `ml-kem` pin
   slip was caught and corrected here. Issue 0001 is closed and immutable, so
   this means a single-line forward reference, nothing more — but it's worth
   knowing the pin claim in the closed issue had a known exception that got
   fixed in 0005.

## What's out of scope

- Adding AAD support to the encryption packages (issue 0006).
- Adding identity binding to the HKDF info string or IKM (more invasive than
  AAD; would change the wire format and require a version-byte bump and KAT
  recapture; not justified when AAD covers the same threat).
- Pin-form audits of any other dependency. Only the three PQC crates are
  policy-pinned; `aesgcm`, `sha256`, `p256` etc. follow the general WebBuf
  convention and don't need exact pins.

## Constraints

- **No behavioral changes.** The `=0.2.3` pin matches the version currently
  installed; the test suite and KAT regressions must continue to pass unchanged.
- **No API changes.** Scope sections are documentation only.
- **No new dependencies.** Cargo and TypeScript changes are configuration-only.

## Experiment 1: Pin and document in one pass

### Goal

Land both fixes together with one verification cycle. The two changes are
independent (one Cargo, one Markdown) but small enough that splitting them into
separate experiments would add ceremony without value.

### Plan

1. **Pin the dependency.** Edit `rs/webbuf_mlkem/Cargo.toml` to change
   `ml-kem = { version = "0.2.3", features = ["deterministic"] }` to
   `ml-kem = { version = "=0.2.3", features = ["deterministic"] }`.
2. **Verify nothing moves.** Run `cargo build -p webbuf_mlkem` and confirm
   `Cargo.lock`'s `ml-kem` entry stays at `0.2.3` (no surprise downgrade or
   upgrade — the pin matches what's already locked).
3. **Re-run the test suites that exercise `ml-kem`** to confirm zero behavioral
   change:
   - `cargo test -p webbuf_mlkem --release` (5 round-trip tests).
   - `pnpm test` in `ts/npm-webbuf-mlkem` (189 tests including 180 NIST ACVP
     vectors).
4. **Add `## Scope` sections** to:
   - `ts/npm-webbuf-aesgcm-mlkem/README.md`
   - `ts/npm-webbuf-aesgcm-p256dh-mlkem/README.md`

   Each Scope section has the same shape:
   - Two-sentence intro stating the package authenticates ciphertext under the
     given keys but does not bind external context.
   - **What the package binds** — bullet list: ML-KEM keys (and P-256 keys for
     the hybrid package), KEM ciphertext + IV via AES-GCM, the wire-format
     version byte (which differs per package, providing fast cross-package
     mismatch detection).
   - **What the package does not bind** — bullet list: sender's federation
     identity, recipient's federation identity, protocol version (beyond the
     wire-format byte), message type, application transcript / message-ID /
     sequence number.
   - **What to do if you need those bindings** — two options: (a) prepend
     context bytes to the plaintext (works today, ugly, blurs the
     encrypted-vs-authenticated line); (b) wait for issue 0006's `aad` parameter
     (clean, supports authenticated-but-not- encrypted context).

5. **Re-run typecheck and build** on both encryption packages to confirm the
   README changes don't affect anything (they shouldn't — READMEs aren't
   compiled — but the smoke check is free).

6. **Index check.** Issues README stays consistent (regenerate via
   `scripts/build-issues-index.sh`).

The forward-reference note to issue 0001 mentioned in "What's in scope" item 5
is intentionally **not done** in this experiment. Issue 0001 is closed and
immutable per the workflow, and a forward reference embedded in a closed issue
would itself be a modification. The pin slip is documented in this issue (0005)
and that's enough — anyone reading 0001's pin claim and checking the actual
Cargo.toml today will see the `=` form and find their way to 0005 via the issues
README.

### Test plan

- `cargo build -p webbuf_mlkem` succeeds with the new pin.
- `cargo test -p webbuf_mlkem --release` reports 5/5 pass (unchanged).
- `pnpm test` in `ts/npm-webbuf-mlkem` reports 189/189 pass (unchanged).
- `pnpm run typecheck` and `pnpm run build` clean in both encryption packages
  (they should be — the only change is the README).
- `Cargo.lock` diff is empty (or only unrelated lines change).
- The two Scope sections render correctly in the formatted Markdown and contain
  the bullet-list structure described above.

### Success criteria

- Pin in `Cargo.toml` is `=0.2.3`.
- All four test suites stay green with no behavioral change.
- Both PQ encryption package READMEs include a Scope section documenting bound
  vs. not-bound and pointing at issue 0006 for the AAD-based fix.

This experiment closes issue 0005. Both items in "What's in scope" land in one
commit; the issue's Conclusion will be a one-paragraph restatement of "pin
tightened, scope documented" plus the verification log.

### Implementation

**Cargo pin** (`rs/webbuf_mlkem/Cargo.toml`):

```diff
-ml-kem = { version = "0.2.3", features = ["deterministic"] }
+ml-kem = { version = "=0.2.3", features = ["deterministic"] }
```

`Cargo.lock` was unchanged (the pinned `=0.2.3` matches the version already
locked).

**Scope sections** added to `ts/npm-webbuf-aesgcm-mlkem/README.md` and
`ts/npm-webbuf-aesgcm-p256dh-mlkem/README.md`. Each Scope section follows the
planned structure:

1. Two-sentence intro stating the package authenticates ciphertext under the
   keys but does not bind external context.
2. **What the package binds** bullet list — KEM keypair, KEM ct + IV via
   AES-GCM, version byte (with cross-package mismatch detection note). The
   hybrid package additionally lists the P-256 keypair and notes the
   defense-in-depth tests that confirm both contributions are load-bearing.
3. **What the package does not bind** bullet list — federation identities,
   protocol version (beyond the wire-format byte), message type, transcript /
   message-ID / sequence.
4. **If you need those bindings** — two options (plaintext-prefix workaround
   today vs. issue 0006's `aad` parameter soon), with a forward link to
   issue 0006.

The hybrid package's Scope section additionally includes a worked example of the
AAD construction a federated system like KeyPears would use (protocol version
byte || message type byte || sender address || separator || recipient address)
so the issue 0006 forward reference is concrete rather than abstract.

### Result: Pass

**Verification:**

- `cargo build -p webbuf_mlkem` — builds, `ml-kem v0.2.3` selected.
- `Cargo.lock` diff for the change is empty.
- `cargo test -p webbuf_mlkem --release` — 5/5 pass.
- `pnpm test` in `ts/npm-webbuf-mlkem` — 189/189 pass (9 unit + 180 NIST ACVP) —
  unchanged from before the pin tightening.
- `pnpm run typecheck` and `pnpm run build` clean in both
  `ts/npm-webbuf-aesgcm-mlkem` and `ts/npm-webbuf-aesgcm-p256dh-mlkem` after the
  README updates.

The pin is now exact, matching the policy stated in issue 0001 and matching the
form already used by `ml-dsa` and `slh-dsa`. The Scope sections make explicit
what the PQ encryption packages do and don't bind, with a clear forward path to
issue 0006's AAD support for consumers (notably KeyPears) that need identity /
version / message- type binding.

## Conclusion

Issue 5 is complete. The `ml-kem` Cargo dependency now uses the exact version
pin `=0.2.3`, matching the policy stated in issue 0001 and the form already in
use for `ml-dsa` and `slh-dsa`. A future `cargo update` will no longer silently
pull in any 0.2.x release.

Both post-quantum encryption package READMEs gained a `## Scope` section that
enumerates exactly what is and isn't cryptographically bound, and points
consumers at issue 0006 for the AAD-based fix that will let them add identity /
protocol-version / message-type binding without changing the wire format. The
hybrid package's Scope section includes a concrete AAD-construction example
aimed at federated consumers like KeyPears.

No code paths changed; all tests still pass; KATs from issue 0004 still match
byte-for-byte. The issue closes the gap Codex identified without modifying the
closed issues 0001–0004 (per the workflow's immutability rule for closed
issues).
