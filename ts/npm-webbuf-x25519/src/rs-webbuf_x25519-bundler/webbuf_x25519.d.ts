/* tslint:disable */
/* eslint-disable */

/**
 * Compute the X25519 public key (RFC 7748 §5) for a 32-byte private key.
 *
 * Any 32 bytes are accepted; clamping per RFC 7748 §5
 * ("decodeScalar25519") is applied internally by `x25519-dalek` —
 * callers do not need to pre-clamp.
 */
export function x25519_public_key_create(priv_key: Uint8Array): Uint8Array;

/**
 * Compute the raw 32-byte X25519 ECDH shared secret (RFC 7748 §6.1) for
 * a 32-byte private key and a 32-byte peer public key.
 *
 * Returns an error if the resulting shared secret is non-contributory
 * (i.e. the peer's public key is small-order — see RFC 7748 §6.1 and
 * Cremers & Jackson 2019). This protects hybrid encryption schemes from
 * being collapsed to PQ-only by a malicious peer's small-order public
 * key.
 *
 * The error message text is intentionally stable so audit tests can
 * pin against it.
 */
export function x25519_shared_secret_raw(priv_key: Uint8Array, pub_key: Uint8Array): Uint8Array;
