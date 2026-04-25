/* tslint:disable */
/* eslint-disable */

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_sha2_128f_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_sha2_128f_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_sha2_128f_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_sha2_128f_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_sha2_128f_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_sha2_128s_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_sha2_128s_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_sha2_128s_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_sha2_128s_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_sha2_128s_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_sha2_192f_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_sha2_192f_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_sha2_192f_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_sha2_192f_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_sha2_192f_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_sha2_192s_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_sha2_192s_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_sha2_192s_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_sha2_192s_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_sha2_192s_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_sha2_256f_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_sha2_256f_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_sha2_256f_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_sha2_256f_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_sha2_256f_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_sha2_256s_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_sha2_256s_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_sha2_256s_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_sha2_256s_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_sha2_256s_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_shake_128f_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_shake_128f_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_shake_128f_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_shake_128f_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_shake_128f_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_shake_128s_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_shake_128s_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_shake_128s_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_shake_128s_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_shake_128s_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_shake_192f_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_shake_192f_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_shake_192f_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_shake_192f_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_shake_192f_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_shake_192s_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_shake_192s_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_shake_192s_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_shake_192s_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_shake_192s_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_shake_256f_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_shake_256f_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_shake_256f_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_shake_256f_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_shake_256f_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 */
export function slh_dsa_shake_256s_keypair(sk_seed: Uint8Array, sk_prf: Uint8Array, pk_seed: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 */
export function slh_dsa_shake_256s_sign(sk_bytes: Uint8Array, message: Uint8Array, context: Uint8Array, addrnd: Uint8Array): Uint8Array;

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 */
export function slh_dsa_shake_256s_sign_internal(sk_bytes: Uint8Array, message: Uint8Array, opt_rand: Uint8Array): Uint8Array;

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 */
export function slh_dsa_shake_256s_verify(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array, context: Uint8Array): boolean;

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 */
export function slh_dsa_shake_256s_verify_internal(vk_bytes: Uint8Array, message: Uint8Array, sig_bytes: Uint8Array): boolean;
