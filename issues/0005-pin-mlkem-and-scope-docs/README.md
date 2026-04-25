+++
status = "open"
opened = "2026-04-25"
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
