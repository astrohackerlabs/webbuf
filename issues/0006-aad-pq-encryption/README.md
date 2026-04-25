+++
status = "open"
opened = "2026-04-25"
+++

# AAD support for AES-GCM and post-quantum encryption packages

## Goal

Add an optional `aad` (Additional Authenticated Data) parameter to
`@webbuf/aesgcm`, then propagate it through the two new post-quantum encryption
packages built in issue 0004:

- `@webbuf/aesgcm-mlkem`
- `@webbuf/aesgcm-p256dh-mlkem`

Callers can then bind protocol version, sender/recipient identity, message type,
transcript state, or any other context bytes into the AES-GCM authentication
tag. AAD is authenticated but not encrypted — the recipient sees the same
context bytes the sender used, and any mismatch causes AES-GCM verification to
fail.

The change is additive and backward-compatible. Existing callers (empty AAD,
default) get identical behavior; existing KATs continue to match. Callers that
opt in to AAD get a stronger threat model without giving up anything.

## Background

### What the current packages bind

`@webbuf/aesgcm-mlkem` and `@webbuf/aesgcm-p256dh-mlkem` derive their AES key
from an HKDF-SHA-256 over the relevant shared secret(s) plus a static,
package-wide info string (e.g. `"webbuf:aesgcm-mlkem v1"`). The wire format is
`version || kemCt || iv || aesCt || tag`.

This binds:

- The sender + recipient cryptographic keys (any wrong key → wrong shared secret
  → wrong AES key → AES-GCM tag fails).
- The KEM ciphertext and IV (tampering → AES-GCM tag fails).
- The AES ciphertext and tag themselves.

This does **not** bind:

- Sender's federation identity / address (a sender's keypair could serve
  multiple addresses, or be re-used across protocol versions).
- Recipient's federation identity / address.
- Protocol version (cross-version replay would be cryptographically
  indistinguishable; the version byte is part of the wire format but not part of
  the authenticated key derivation).
- Message type (text vs. control vs. vault entry vs. signature challenge — same
  key, same ciphertext format).
- Any transcript / message-ID / sequence number.

This was an explicit design choice for issue 0004: keep the packages narrowly
scoped to "authenticated KEM + AES-GCM" and let consumers layer their own
context. Issue 0005 documents the gap in the package READMEs.

### Why this matters now: the KeyPears migration

KeyPears is the first real consumer of these packages and is migrating from
classical P-256 ECDH + AES-GCM to hybrid `aesgcm-p256dh-mlkem`. Their existing
classical message format also doesn't bind context — which means today they have
an existing weakness, not a regression from our packages. But the migration is
the natural moment to fix it:

- KeyPears stores encrypted messages indefinitely in the database.
- They federate across multiple domains, with multiple addresses potentially
  served by the same keypair.
- They have multiple message types (text, vault entries, signed auth challenges)
  that would benefit from cross-type domain separation.
- They are about to re-issue every encrypted message under new keys.

If the WebBuf packages don't support AAD, KeyPears either:

1. Inherits the existing context-binding gap into the post-quantum era. A future
   migration would need to add binding, costing another full message
   re-encryption pass.
2. Hacks context binding by prepending bytes to the plaintext before encryption.
   Works, but every consumer reinvents this and the "what's authenticated
   context vs. what's secret content" line gets blurry.
3. Waits for AAD before migrating. Delays the post-quantum push.

Adding AAD now lets KeyPears bind:

```typescript
const aad = WebBuf.concat([
  WebBuf.fromArray([PROTOCOL_VERSION]),
  WebBuf.fromArray([MESSAGE_TYPE]),
  WebBuf.fromUtf8(senderAddress),
  WebBuf.fromArray([0]),
  WebBuf.fromUtf8(recipientAddress),
]);
```

cleanly into the encryption call, with no plaintext framing tricks and no
key-schedule changes.

### Why AAD over HKDF info-string customization

Two ways to bind context cryptographically:

1. **AAD into AES-GCM.** Authenticated, not part of the key. Wire format
   unchanged (the AAD is not transmitted — the recipient must already know it).
   Simple, additive, backward-compatible.
2. **Variable info string into HKDF.** Bound into the _key_. Wire format changes
   (the info string or its inputs would need to be transmitted or otherwise
   known on both sides), version byte bumps, KATs recapture.

Option 1 covers the same threat model — an attacker who tampers with AAD context
fails authentication just as surely as one who tampers with the key inputs.
Option 2 is more invasive for no marginal security benefit when AAD is
available.

This issue chooses option 1.

## What's in scope

### `@webbuf/aesgcm` Rust + TS

The underlying primitive package needs to expose AAD first.

Currently:

```typescript
aesgcmEncrypt(plaintext, aesKey, iv?) → WebBuf  // iv || ct || tag
aesgcmDecrypt(ciphertext, aesKey)     → WebBuf
```

Target:

```typescript
aesgcmEncrypt(plaintext, aesKey, iv?, aad?) → WebBuf  // iv || ct || tag
aesgcmDecrypt(ciphertext, aesKey, aad?)     → WebBuf
```

`aad` defaults to an empty `WebBuf`. The Rust crate's underlying `aes-gcm` crate
already supports `Aead::encrypt`'s payload struct with `msg` and `aad`; the
wasm-bindgen exports need to be extended.

The wire format does not change — AAD is authenticated but not included in the
ciphertext bytes.

### Propagate to PQ encryption packages

Both `@webbuf/aesgcm-mlkem` and `@webbuf/aesgcm-p256dh-mlkem` add an optional
trailing `aad` parameter to encrypt and decrypt:

```typescript
aesgcmMlkemEncrypt(encapKey, plaintext, aad?) → WebBuf
aesgcmMlkemDecrypt(decapKey, ciphertext, aad?) → WebBuf

aesgcmP256dhMlkemEncrypt(senderPriv, recipientPub, encapKey, plaintext, aad?) → WebBuf
aesgcmP256dhMlkemDecrypt(recipientPriv, senderPub, decapKey, ciphertext, aad?) → WebBuf
```

`aad` is passed straight through to `aesgcmEncrypt` / `aesgcmDecrypt`. No
HKDF/key-schedule changes; the package version bytes (`0x01`, `0x02`) and info
strings (`"webbuf:aesgcm-mlkem v1"`, `"webbuf:aesgcm-p256dh-mlkem v1"`) stay the
same.

### Captured KATs

Issue 0004's KATs use empty AAD implicitly. After this change:

- The empty-AAD path produces identical bytes to the existing KAT (since AES-GCM
  with empty AAD === AES-GCM with no AAD argument). The existing
  `SHA-256(ciphertext)` assertions stay valid.
- A new KAT per package should be captured with non-empty AAD (e.g.
  `aad = WebBuf.fromUtf8("test-aad")`), embedded in the issue, and asserted in
  `test/audit.test.ts`. This proves the AAD is actually authenticated.

### KeyPears integration guidance

The package READMEs should document an example `aad` construction matching what
KeyPears (and similar federated systems) would use: protocol version byte ||
message type byte || sender address || separator || recipient address. Make the
example explicit so consumers can copy-paste a sane default.

## What's out of scope

- HKDF info-string customization or IKM-level identity binding.
- AAD support on the classical `@webbuf/aesgcm-p256dh` package (separate
  decision; that package's KATs and consumers are different, and it can stay
  narrow).
- AAD on the `@webbuf/acb3*` and `@webbuf/acs2*` AES-CBC packages.
- Schema/storage changes in any consumer (KeyPears or otherwise).

## Constraints

- **Backward-compatible default.** Empty AAD must produce identical bytes to the
  current behavior. Existing KATs in issue 0004 must continue to match without
  modification.
- **No wire format changes.** AAD is authenticated but not transmitted; the
  version byte / KEM ct / IV / tag layout is fixed.
- **No new Rust dependencies.** AAD support comes from the existing `aes-gcm`
  crate; only the wasm-bindgen surface area changes.
- **No HKDF / key-schedule changes.** `info` strings and IKM stay the same, so
  the derived keys are identical for the same key material regardless of whether
  AAD is used.

## Test plan

For each affected package:

- **Empty-AAD regression:** existing KAT still matches byte-for-byte. The
  captured `SHA-256(ciphertext)` from issue 0004 is unchanged.
- **Non-empty AAD round-trip:** encrypt with `aad = X`, decrypt with `aad = X`,
  plaintext recovers.
- **AAD mismatch rejection:** encrypt with `aad = X`, decrypt with `aad = Y`,
  expect throw (AES-GCM tag fails).
- **AAD missing on decrypt:** encrypt with `aad = X`, decrypt with default empty
  AAD, expect throw.
- **AAD captured KAT:** capture a deterministic KAT with non-empty AAD, embed in
  the issue, assert in `test/audit.test.ts`.
- **AAD does not change ciphertext bytes when empty:** encrypt with
  `aad = WebBuf.alloc(0)` and assert byte-equality with encrypt without the
  `aad` argument.

For the `@webbuf/aesgcm` package itself, also test AAD round-trip directly
without the KEM layer.

## Experiment 1: Add AAD to `@webbuf/aesgcm`

### Goal

Land the foundational change first: extend `@webbuf/aesgcm` (the Rust crate plus
its TypeScript wrapper) with an optional `aad` parameter on encrypt and decrypt.
The PQ encryption packages built on top of it (`@webbuf/aesgcm-mlkem`,
`@webbuf/aesgcm-p256dh-mlkem`) are out of scope for this experiment — they are
pure-TS pass-through layers and become mechanical work once the underlying
primitive supports AAD.

### Why this experiment is small and well-defined

The underlying RustCrypto `aes-gcm` crate already supports AAD via the
`Aead::encrypt(payload: Payload)` API where `Payload` is `{ msg, aad }`. Adding
AAD to `webbuf_aesgcm` is a small Rust change:

- Extend the `aesgcm_encrypt` and `aesgcm_decrypt` wasm-bindgen exports to
  accept an additional `aad: &[u8]` parameter.
- Use `cipher.encrypt(nonce, Payload { msg, aad })` instead of
  `cipher.encrypt(nonce, msg)`.
- Same for decrypt.

The wire format does not change — AAD is authenticated by the AES-GCM tag but
not transmitted. Recipient must supply the same AAD bytes the sender used. Empty
AAD = current behavior (AES-GCM with no AAD argument is mathematically
equivalent to AES-GCM with empty AAD).

### Plan

#### Rust (`rs/webbuf_aesgcm/src/lib.rs`)

Inspect the current implementation. The `aes-gcm` crate's `Aead` trait exposes:

```rust
fn encrypt<'msg, 'aad>(&self, nonce: &Nonce<Self::NonceSize>, plaintext: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>, Error>
fn decrypt<'msg, 'aad>(&self, nonce: &Nonce<Self::NonceSize>, ciphertext: impl Into<Payload<'msg, 'aad>>) -> Result<Vec<u8>, Error>

pub struct Payload<'msg, 'aad> {
    pub msg: &'msg [u8],
    pub aad: &'aad [u8],
}
```

Currently `webbuf_aesgcm` calls something like
`cipher.encrypt(nonce, plaintext)` which uses the `From<&[u8]>` conversion to
`Payload { msg: plaintext, aad: &[] }`. Switching to explicit `Payload` lets us
pass non-empty AAD.

Updated function signatures:

```rust
pub fn aesgcm_encrypt(
    plaintext: &[u8],
    aes_key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String>;

pub fn aesgcm_decrypt(
    ciphertext: &[u8],
    aes_key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String>;
```

The argument count grows by one. This is a breaking change at the Rust WASM
boundary, but the TypeScript wrapper preserves backward compatibility by
defaulting `aad` to an empty `WebBuf` (see below).

#### TypeScript (`ts/npm-webbuf-aesgcm/src/index.ts`)

Add an optional `aad` parameter with a default of empty WebBuf:

```typescript
const EMPTY_AAD = WebBuf.alloc(0);

export function aesgcmEncrypt(
  plaintext: WebBuf,
  aesKey: FixedBuf<16> | FixedBuf<32>,
  iv: FixedBuf<12> = FixedBuf.fromRandom(12),
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  const encrypted = aesgcm_encrypt(plaintext, aesKey.buf, iv.buf, aad);
  return WebBuf.concat([iv.buf, WebBuf.fromUint8Array(encrypted)]);
}

export function aesgcmDecrypt(
  ciphertext: WebBuf,
  aesKey: FixedBuf<16> | FixedBuf<32>,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  if (ciphertext.length < 28) {
    throw new Error("Data must be at least 28 bytes (12 nonce + 16 tag)");
  }
  const iv = FixedBuf.fromBuf(12, ciphertext.slice(0, 12));
  const encryptedData = ciphertext.slice(12);
  return WebBuf.fromUint8Array(
    aesgcm_decrypt(encryptedData, aesKey.buf, iv.buf, aad),
  );
}
```

Existing callers that don't pass `aad` continue to work unchanged.

#### Tests

`test/index.test.ts` adds:

1. **Empty-AAD equivalence:** `aesgcmEncrypt(p, k, iv)` (no AAD) and
   `aesgcmEncrypt(p, k, iv, WebBuf.alloc(0))` (explicit empty AAD) produce
   byte-identical ciphertext. Confirms the default doesn't change behavior.
2. **Non-empty AAD round-trip:** encrypt with `aad = "context"`, decrypt with
   `aad = "context"`, plaintext recovers.
3. **AAD mismatch on decrypt:** encrypt with `aad = "ctx-A"`, decrypt with
   `aad = "ctx-B"`, expect throw (AES-GCM tag fails).
4. **AAD missing on decrypt:** encrypt with `aad = "ctx"`, decrypt without AAD
   argument, expect throw.
5. **AAD added on decrypt:** encrypt without AAD, decrypt with `aad = "ctx"`,
   expect throw.
6. **Multiple AADs distinguish ciphertexts:** same `(p, k, iv)` with different
   AADs produces different ciphertext-tag combos (the IV is the same, the body
   bytes are the same modulo AES-CTR with the same counter, but the **tag**
   differs because AAD changes the GHASH input). Confirm this empirically.

If `@webbuf/aesgcm` has any existing audit/KAT tests, run them unchanged — empty
AAD must keep them passing.

### Risks

1. **TS argument-position drift.** The current `aesgcmEncrypt` takes
   `(plaintext, aesKey, iv?)`. Adding `aad` as the 4th positional arg is
   consistent with the current style but means callers can't pass AAD without
   also providing IV. Acceptable — almost all callers want random IV anyway, and
   the rare KAT/test caller already passes an explicit IV.
2. **Rust function-arity change.** The wasm-bindgen export now has 4 args
   instead of 3. The TS wrapper bridges this. Anyone who imports the raw
   `aesgcm_encrypt` from the inline-base64 module would break — but that's an
   internal artifact, not a documented surface.
3. **Cargo.lock churn.** None expected. The `aes-gcm` crate already provides the
   `Payload` API; no version bumps needed.

### Out of scope for this experiment

- Propagating `aad` through `@webbuf/aesgcm-mlkem` and
  `@webbuf/aesgcm-p256dh-mlkem`. Those packages are pure-TS pass-through layers;
  once the underlying primitive supports AAD they need a small signature change
  and a new captured KAT each. Defer to the next experiment.
- Updating `@webbuf/aesgcm-p256dh` (classical hybrid that uses raw SHA-256, not
  HKDF) — explicitly out of scope per issue 0006's out-of-scope list.
- Updating `@webbuf/acb3*` and `@webbuf/acs2*` AES-CBC packages.

### Success criteria

- `cargo build -p webbuf_aesgcm` clean.
- `cargo test -p webbuf_aesgcm` passes (existing tests + new AAD round-trip
  tests).
- `wasm-pack build --target bundler` clean.
- `pnpm test` in `ts/npm-webbuf-aesgcm` passes (existing tests + new AAD tests).
- Empty-AAD equivalence test confirms backward-compatible default.
- AAD mismatch tests confirm authentication failure.

### Implementation

**Rust (`rs/webbuf_aesgcm/src/aesgcm.rs`):** added `aad: &[u8]` parameter to
both `aesgcm_encrypt` and `aesgcm_decrypt`. Switched from
`cipher.encrypt(nonce, plaintext)` (which uses the `From<&[u8]>` conversion to a
`Payload` with empty `aad`) to explicit
`cipher.encrypt(nonce, Payload { msg, aad })` from the `aes_gcm::aead` module.
Same for decrypt. No new dependencies — `Payload` was already re-exported by
`aes_gcm`.

Updated all 18 existing Rust tests to pass `NO_AAD: &[u8] = &[]` through the new
parameter. Added 8 new AAD-specific Rust tests: empty-AAD round-trip,
non-empty-AAD round-trip, AAD mismatch on decrypt, AAD missing on decrypt, AAD
added on decrypt, AAD-changes- tag-not-body (verifies AES-CTR keystream identity
and GHASH tag divergence empirically), AAD with AES-128, and large 4 KiB AAD
with tamper detection.

**TypeScript (`ts/npm-webbuf-aesgcm/src/index.ts`):** extended both
`aesgcmEncrypt` and `aesgcmDecrypt` with an optional `aad: WebBuf` parameter
defaulting to a shared `EMPTY_AAD = WebBuf.alloc(0)`. The existing positional
argument order is preserved (`plaintext, aesKey, iv?, aad?`), so existing
callers compile and run unchanged. JSDoc explains the AAD semantics and the
implication that recipients must supply matching context bytes.

Added 8 new TypeScript tests covering: default-equals-explicit-empty byte
equivalence, non-empty round-trip, mismatch rejection, missing- on-decrypt
rejection, added-on-decrypt rejection, AAD-changes-tag- not-body with explicit
byte slicing, large 4 KiB AAD with tamper detection, and a worked
**KeyPears-style AAD construction** (protocol version byte || message type byte
|| sender address || NUL || recipient address) that round-trips and rejects a
wrong recipient address in AAD.

**Cross-package check:** the boundary change in the Rust function arity didn't
break anything downstream because no consumer reaches the inline-base64 raw
`aesgcm_encrypt` / `aesgcm_decrypt` exports directly — they all go through the
TypeScript wrapper, which absorbs the new parameter via its default. Verified by
running the full test suites for the packages that depend on `@webbuf/aesgcm`:

- `@webbuf/aesgcm-mlkem`: 15/15 pass.
- `@webbuf/aesgcm-p256dh-mlkem`: 19/19 pass.
- `@webbuf/aesgcm-p256dh` (classical): 21/21 pass.
- Umbrella `webbuf` typecheck: clean.

### Result: Pass

**Verification:**

- `cargo build -p webbuf_aesgcm` — clean.
- `cargo test -p webbuf_aesgcm --release` — 26/26 pass (18 existing + 8 new AAD
  tests).
- `./wasm-pack-bundler.zsh` — clean.
- `pnpm run sync:from-rust` and `pnpm run build:wasm` in `ts/npm-webbuf-aesgcm`
  — clean.
- `pnpm run typecheck` in `ts/npm-webbuf-aesgcm` — clean.
- `pnpm test` in `ts/npm-webbuf-aesgcm` — 34/34 pass (12 unit + 22 audit). Audit
  suite untouched and green.
- Downstream consumers (`@webbuf/aesgcm-mlkem`, `@webbuf/aesgcm-p256dh-mlkem`,
  `@webbuf/aesgcm-p256dh`) and the umbrella `webbuf` package all stay green.
- Empty-AAD equivalence test passes byte-for-byte: `aesgcmEncrypt(p, k, iv)` and
  `aesgcmEncrypt(p, k, iv, WebBuf.alloc(0))` produce identical output.
- AAD mismatch / missing / extra all throw cleanly via AES-GCM authentication
  failure.

The foundational change is done. The next experiment will propagate the optional
`aad` parameter through `@webbuf/aesgcm-mlkem` and `@webbuf/aesgcm-p256dh-mlkem`
as a passthrough to this primitive. The existing KATs in issue 0004 will
continue to match (empty-AAD default), and a new captured KAT-with-non-empty-AAD
per package will prove the AAD is actually authenticated end-to-end.
