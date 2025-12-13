/* tslint:disable */
/* eslint-disable */

/**
 * Decode a Crockford base32 string into a byte vector
 */
export function decode_base32_crockford(encoded: string): Uint8Array;

/**
 * Decode an RFC4648 base32 string into a byte vector
 */
export function decode_base32_rfc4648(encoded: string, padding: boolean): Uint8Array;

/**
 * Decode an RFC4648 hex base32 string into a byte vector
 */
export function decode_base32_rfc4648_hex(encoded: string, padding: boolean): Uint8Array;

/**
 * Decode an RFC4648 hex lowercase base32 string into a byte vector
 */
export function decode_base32_rfc4648_hex_lower(encoded: string, padding: boolean): Uint8Array;

/**
 * Decode an RFC4648 lowercase base32 string into a byte vector
 */
export function decode_base32_rfc4648_lower(encoded: string, padding: boolean): Uint8Array;

/**
 * Decode a z-base-32 string into a byte vector
 */
export function decode_base32_z(encoded: string): Uint8Array;

export function decode_base64(encoded: string): Uint8Array;

/**
 * Decode a base64 string into a byte vector
 * Returns an error string if decoding fails
 */
export function decode_base64_strip_whitespace(encoded: string): Uint8Array;

/**
 * Decode a hex string into a byte vector
 * Returns an error string if decoding fails
 */
export function decode_hex(encoded: string): Uint8Array;

/**
 * Encode a byte slice into a Crockford base32 string
 */
export function encode_base32_crockford(data: Uint8Array): string;

/**
 * Encode a byte slice into an RFC4648 base32 string
 */
export function encode_base32_rfc4648(data: Uint8Array, padding: boolean): string;

/**
 * Encode a byte slice into an RFC4648 hex base32 string
 */
export function encode_base32_rfc4648_hex(data: Uint8Array, padding: boolean): string;

/**
 * Encode a byte slice into an RFC4648 hex lowercase base32 string
 */
export function encode_base32_rfc4648_hex_lower(data: Uint8Array, padding: boolean): string;

/**
 * Encode a byte slice into an RFC4648 lowercase base32 string
 */
export function encode_base32_rfc4648_lower(data: Uint8Array, padding: boolean): string;

/**
 * Encode a byte slice into a z-base-32 string
 */
export function encode_base32_z(data: Uint8Array): string;

/**
 * Encode a byte slice into a base64 string using the default engine
 */
export function encode_base64(data: Uint8Array): string;

/**
 * Encode a byte slice into a hex string
 */
export function encode_hex(data: Uint8Array): string;
