/* tslint:disable */
/* eslint-disable */

/**
 * Derive the 32-byte Ed25519 public key from a 32-byte seed
 * (RFC 8032 §5.1.5 secret key).
 */
export function ed25519_public_key_create(priv_key: Uint8Array): Uint8Array;

/**
 * PureEdDSA signing per RFC 8032 §5.1.6. Produces a 64-byte (R || S)
 * signature. The signer consumes the raw message bytes directly — no
 * prehash.
 */
export function ed25519_sign(priv_key: Uint8Array, message: Uint8Array): Uint8Array;

/**
 * PureEdDSA verification per RFC 8032 §5.1.7. Returns `Ok(true)` for a
 * valid signature, `Ok(false)` for any rejection (wrong key, tampered
 * message, tampered signature, non-canonical S, malformed point).
 * Returns `Err` only on malformed-length input. Error message text is
 * intentionally stable so audit tests can pin against it.
 *
 * `legacy_compatibility` is disabled at the crate level, so this enforces
 * strict RFC 8032 §5.1.7 semantics: signatures with non-canonical S and
 * signatures with small-order R are rejected.
 */
export function ed25519_verify(pub_key: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
