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
 * Deterministically generate a keypair from a 32-byte seed.
 *
 * Returns `vk || sk` (concatenated public key + expanded secret key
 * per FIPS 204).
 * @param {Uint8Array} seed
 * @returns {Uint8Array}
 */
export function ml_dsa_44_keypair(seed) {
    const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_44_keypair(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Sign a message using the FIPS 204 message-level ML-DSA.Sign
 * deterministic variant with context separation.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @returns {Uint8Array}
 */
export function ml_dsa_44_sign(sk_bytes, message, context) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_44_sign(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 204 internal sign primitive.
 *
 * `sk_bytes` is the expanded FIPS 204 secret key encoding,
 * `message` is the raw message bytes (no context, no domain
 * separation), and `rnd` is the 32-byte randomness per FIPS 204
 * §6.2 ML-DSA.Sign_internal.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} rnd
 * @returns {Uint8Array}
 */
export function ml_dsa_44_sign_internal(sk_bytes, message, rnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(rnd, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_44_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 204 message-level ML-DSA.Verify
 * algorithm with context separation.
 *
 * Returns true if the signature is valid for the message, context,
 * and verifying key. Invalid keys, signatures, or contexts return
 * false.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function ml_dsa_44_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_44_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 204 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise. Never errors — invalid keys or
 * signatures simply produce false.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function ml_dsa_44_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_44_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from a 32-byte seed.
 *
 * Returns `vk || sk` (concatenated public key + expanded secret key
 * per FIPS 204).
 * @param {Uint8Array} seed
 * @returns {Uint8Array}
 */
export function ml_dsa_65_keypair(seed) {
    const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_65_keypair(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Sign a message using the FIPS 204 message-level ML-DSA.Sign
 * deterministic variant with context separation.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @returns {Uint8Array}
 */
export function ml_dsa_65_sign(sk_bytes, message, context) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_65_sign(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 204 internal sign primitive.
 *
 * `sk_bytes` is the expanded FIPS 204 secret key encoding,
 * `message` is the raw message bytes (no context, no domain
 * separation), and `rnd` is the 32-byte randomness per FIPS 204
 * §6.2 ML-DSA.Sign_internal.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} rnd
 * @returns {Uint8Array}
 */
export function ml_dsa_65_sign_internal(sk_bytes, message, rnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(rnd, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_65_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 204 message-level ML-DSA.Verify
 * algorithm with context separation.
 *
 * Returns true if the signature is valid for the message, context,
 * and verifying key. Invalid keys, signatures, or contexts return
 * false.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function ml_dsa_65_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_65_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 204 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise. Never errors — invalid keys or
 * signatures simply produce false.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function ml_dsa_65_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_65_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Deterministically generate a keypair from a 32-byte seed.
 *
 * Returns `vk || sk` (concatenated public key + expanded secret key
 * per FIPS 204).
 * @param {Uint8Array} seed
 * @returns {Uint8Array}
 */
export function ml_dsa_87_keypair(seed) {
    const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_87_keypair(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Sign a message using the FIPS 204 message-level ML-DSA.Sign
 * deterministic variant with context separation.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} context
 * @returns {Uint8Array}
 */
export function ml_dsa_87_sign(sk_bytes, message, context) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_87_sign(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Sign a message using the FIPS 204 internal sign primitive.
 *
 * `sk_bytes` is the expanded FIPS 204 secret key encoding,
 * `message` is the raw message bytes (no context, no domain
 * separation), and `rnd` is the 32-byte randomness per FIPS 204
 * §6.2 ML-DSA.Sign_internal.
 * @param {Uint8Array} sk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} rnd
 * @returns {Uint8Array}
 */
export function ml_dsa_87_sign_internal(sk_bytes, message, rnd) {
    const ptr0 = passArray8ToWasm0(sk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(rnd, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_87_sign_internal(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Verify a signature using the FIPS 204 message-level ML-DSA.Verify
 * algorithm with context separation.
 *
 * Returns true if the signature is valid for the message, context,
 * and verifying key. Invalid keys, signatures, or contexts return
 * false.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @param {Uint8Array} context
 * @returns {boolean}
 */
export function ml_dsa_87_verify(vk_bytes, message, sig_bytes, context) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(context, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_87_verify(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    return ret !== 0;
}

/**
 * Verify a signature using the FIPS 204 internal verify primitive.
 *
 * Returns true if the signature is valid for the message and
 * verifying key, false otherwise. Never errors — invalid keys or
 * signatures simply produce false.
 * @param {Uint8Array} vk_bytes
 * @param {Uint8Array} message
 * @param {Uint8Array} sig_bytes
 * @returns {boolean}
 */
export function ml_dsa_87_verify_internal(vk_bytes, message, sig_bytes) {
    const ptr0 = passArray8ToWasm0(vk_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(sig_bytes, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.ml_dsa_87_verify_internal(ptr0, len0, ptr1, len1, ptr2, len2);
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
