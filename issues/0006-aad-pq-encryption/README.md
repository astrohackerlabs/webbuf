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
