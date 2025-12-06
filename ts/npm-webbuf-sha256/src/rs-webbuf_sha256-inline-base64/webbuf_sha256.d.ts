/* tslint:disable */
/* eslint-disable */
/**
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function sha256_hash(data: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function double_sha256_hash(data: Uint8Array): Uint8Array;
/**
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Uint8Array}
 */
export function sha256_hmac(key: Uint8Array, data: Uint8Array): Uint8Array;
