let wasm;
export function __wbg_set_wasm(val) {
    wasm = val;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let WASM_VECTOR_LEN = 0;

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_128f_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128f_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_128f_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128f_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_128f_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128f_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_sha2_128f_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128f_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_sha2_128f_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128f_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_128s_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128s_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_128s_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128s_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_128s_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128s_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_sha2_128s_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128s_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_sha2_128s_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_128s_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_192f_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192f_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_192f_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192f_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_192f_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192f_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_sha2_192f_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192f_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_sha2_192f_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192f_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_192s_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192s_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_192s_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192s_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_192s_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192s_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_sha2_192s_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192s_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_sha2_192s_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_192s_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_256f_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256f_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_256f_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256f_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_256f_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256f_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_sha2_256f_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256f_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_sha2_256f_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256f_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_256s_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256s_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_256s_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256s_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_sha2_256s_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256s_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_sha2_256s_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256s_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_sha2_256s_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_sha2_256s_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_128f_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128f_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_128f_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128f_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_128f_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128f_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_shake_128f_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128f_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_shake_128f_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128f_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_128s_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128s_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_128s_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128s_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_128s_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128s_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_shake_128s_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128s_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_shake_128s_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_128s_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_192f_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192f_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_192f_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192f_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_192f_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192f_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_shake_192f_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192f_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_shake_192f_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192f_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_192s_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192s_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_192s_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192s_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_192s_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192s_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_shake_192s_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192s_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_shake_192s_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_192s_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_256f_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256f_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_256f_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256f_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_256f_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256f_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_shake_256f_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256f_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_shake_256f_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256f_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from three n-byte seeds.
 *
 * Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
 * Returns `pk || sk` concatenated.
 * @param {Uint8Array} sk_seed
 * @param {Uint8Array} sk_prf
 * @param {Uint8Array} pk_seed
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_256s_keypair(sk_seed, sk_prf, pk_seed) {
    const ptr0 = passArray8ToWasm0(sk_seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sk_prf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pk_seed, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256s_keypair(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 205 SLH-DSA.Sign algorithm with
 * context separation.
 *
 * `addrnd` is either empty for deterministic signing or exactly n
 * bytes for hedged signing.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @param {Uint8Array} addrnd
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_256s_sign(sk_bytes, message, context, addrnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(addrnd, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256s_sign(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Sign a message using the FIPS 205 internal sign primitive.
 *
 * `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
 * raw message bytes. `opt_rand` is either empty (deterministic
 * variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
 * variant: caller-provided randomizer).
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} opt_rand
 * @returns {Uint8Array}
 */
export function slh_dsa_shake_256s_sign_internal(sk_bytes, message, opt_rand) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(opt_rand, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256s_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 205 SLH-DSA.Verify algorithm
 * with context separation.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function slh_dsa_shake_256s_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256s_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 205 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function slh_dsa_shake_256s_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.slh_dsa_shake_256s_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

export function __wbindgen_cast_2241b6af4c4b2941(arg0, arg1) {
    // Cast intrinsic for `Ref(String) -> Externref`.
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
};

export function __wbindgen_init_externref_table() {
    const table = wasm.__wbindgen_externrefs;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
};
