/* tslint:disable */
/* eslint-disable */

/**
 * Deterministically generate a keypair from a 32-byte seed.
 *
 * Returns `vk || sk` (concatenated public key + expanded secret key
 * per FIPS 204).
 */
export function ml_dsa_44_keypair(seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 204 message-level ML-DSA.Sign
 * deterministic variant with context separation.
 */
export function ml_dsa_44_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 204 internal sign primitive.
 *
 * `sk_bytes` is the expanded FIPS 204 secret key encoding,
 * `message` is the raw message bytes (no context, no domain
 * separation), and `rnd` is the 32-byte randomness per FIPS 204
 * §6.2 ML-DSA.Sign_internal.
 */
export function ml_dsa_44_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, rnd: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 204 message-level ML-DSA.Verify
 * algorithm with context separation.
 *
 * Returns true if the signature is valid for the message, context,
 * and verifying key. Invalid keys, signatures, or contexts return
 * false.
 */
export function ml_dsa_44_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 204 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise. Never errors — invalid keys or
 * signatures simply produce false.
 */
export function ml_dsa_44_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from a 32-byte seed.
 *
 * Returns `vk || sk` (concatenated public key + expanded secret key
 * per FIPS 204).
 */
export function ml_dsa_65_keypair(seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 204 message-level ML-DSA.Sign
 * deterministic variant with context separation.
 */
export function ml_dsa_65_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 204 internal sign primitive.
 *
 * `sk_bytes` is the expanded FIPS 204 secret key encoding,
 * `message` is the raw message bytes (no context, no domain
 * separation), and `rnd` is the 32-byte randomness per FIPS 204
 * §6.2 ML-DSA.Sign_internal.
 */
export function ml_dsa_65_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, rnd: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 204 message-level ML-DSA.Verify
 * algorithm with context separation.
 *
 * Returns true if the signature is valid for the message, context,
 * and verifying key. Invalid keys, signatures, or contexts return
 * false.
 */
export function ml_dsa_65_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 204 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise. Never errors — invalid keys or
 * signatures simply produce false.
 */
export function ml_dsa_65_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from a 32-byte seed.
 *
 * Returns `vk || sk` (concatenated public key + expanded secret key
 * per FIPS 204).
 */
export function ml_dsa_87_keypair(seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 204 message-level ML-DSA.Sign
 * deterministic variant with context separation.
 */
export function ml_dsa_87_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 204 internal sign primitive.
 *
 * `sk_bytes` is the expanded FIPS 204 secret key encoding,
 * `message` is the raw message bytes (no context, no domain
 * separation), and `rnd` is the 32-byte randomness per FIPS 204
 * §6.2 ML-DSA.Sign_internal.
 */
export function ml_dsa_87_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, rnd: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 204 message-level ML-DSA.Verify
 * algorithm with context separation.
 *
 * Returns true if the signature is valid for the message, context,
 * and verifying key. Invalid keys, signatures, or contexts return
 * false.
 */
export function ml_dsa_87_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 204 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise. Never errors — invalid keys or
 * signatures simply produce false.
 */
export function ml_dsa_87_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;
