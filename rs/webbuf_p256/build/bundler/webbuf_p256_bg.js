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
 * @param {Uint8Array} priv_key_buf_1
 * @param {Uint8Array} priv_key_buf_2
 * @returns {Uint8Array}
 */
export function private_key_add(priv_key_buf_1, priv_key_buf_2) {
    const ptr0 = passArray8ToWasm0(priv_key_buf_1, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(priv_key_buf_2, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.private_key_add(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * @param {Uint8Array} priv_key_buf
 * @returns {boolean}
 */
export function private_key_verify(priv_key_buf) {
    const ptr0 = passArray8ToWasm0(priv_key_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.private_key_verify(ptr0, len0);
    return ret !== 0;
}

/**
 * @param {Uint8Array} pub_key_buf_1
 * @param {Uint8Array} pub_key_buf_2
 * @returns {Uint8Array}
 */
export function public_key_add(pub_key_buf_1, pub_key_buf_2) {
    const ptr0 = passArray8ToWasm0(pub_key_buf_1, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(pub_key_buf_2, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.public_key_add(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * @param {Uint8Array} uncompressed
 * @returns {Uint8Array}
 */
export function public_key_compress(uncompressed) {
    const ptr0 = passArray8ToWasm0(uncompressed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.public_key_compress(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {Uint8Array} priv_key_buf
 * @returns {Uint8Array}
 */
export function public_key_create(priv_key_buf) {
    const ptr0 = passArray8ToWasm0(priv_key_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.public_key_create(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {Uint8Array} compressed
 * @returns {Uint8Array}
 */
export function public_key_decompress(compressed) {
    const ptr0 = passArray8ToWasm0(compressed, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.public_key_decompress(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {Uint8Array} pub_key_buf
 * @returns {boolean}
 */
export function public_key_verify(pub_key_buf) {
    const ptr0 = passArray8ToWasm0(pub_key_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.public_key_verify(ptr0, len0);
    return ret !== 0;
}

/**
 * @param {Uint8Array} priv_key_buf
 * @param {Uint8Array} pub_key_buf
 * @returns {Uint8Array}
 */
export function shared_secret(priv_key_buf, pub_key_buf) {
    const ptr0 = passArray8ToWasm0(priv_key_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(pub_key_buf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.shared_secret(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Diffie-Hellman shared secret, returned as the raw 32-byte X-coordinate.
 *
 * This is the SEC1 X9.63 "Z" value used as input to a KDF in NIST SP
 * 800-56A §5.7.1.2 and the IETF hybrid KEM combiners. Equivalent to
 * `shared_secret` with the SEC1 prefix byte stripped — the prefix is
 * deterministic given the X-coordinate, so removing it loses no entropy.
 * @param {Uint8Array} priv_key_buf
 * @param {Uint8Array} pub_key_buf
 * @returns {Uint8Array}
 */
export function shared_secret_raw(priv_key_buf, pub_key_buf) {
    const ptr0 = passArray8ToWasm0(priv_key_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(pub_key_buf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.shared_secret_raw(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * @param {Uint8Array} hash_buf
 * @param {Uint8Array} priv_key_buf
 * @param {Uint8Array} k_buf
 * @returns {Uint8Array}
 */
export function sign(hash_buf, priv_key_buf, k_buf) {
    const ptr0 = passArray8ToWasm0(hash_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(priv_key_buf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(k_buf, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sign(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * @param {Uint8Array} sig_buf
 * @param {Uint8Array} hash_buf
 * @param {Uint8Array} pub_key_buf
 */
export function verify(sig_buf, hash_buf, pub_key_buf) {
    const ptr0 = passArray8ToWasm0(sig_buf, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(hash_buf, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pub_key_buf, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.verify(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
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
