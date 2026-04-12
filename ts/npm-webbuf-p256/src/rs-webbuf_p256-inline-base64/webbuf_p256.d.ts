/* tslint:disable */
/* eslint-disable */

export function private_key_add(priv_key_buf_1: Uint8Array, priv_key_buf_2: Uint8Array): Uint8Array;

export function private_key_verify(priv_key_buf: Uint8Array): boolean;

export function public_key_add(pub_key_buf_1: Uint8Array, pub_key_buf_2: Uint8Array): Uint8Array;

export function public_key_compress(uncompressed: Uint8Array): Uint8Array;

export function public_key_create(priv_key_buf: Uint8Array): Uint8Array;

export function public_key_decompress(compressed: Uint8Array): Uint8Array;

export function public_key_verify(pub_key_buf: Uint8Array): boolean;

export function shared_secret(priv_key_buf: Uint8Array, pub_key_buf: Uint8Array): Uint8Array;

export function sign(hash_buf: Uint8Array, priv_key_buf: Uint8Array, k_buf: Uint8Array): Uint8Array;

export function verify(sig_buf: Uint8Array, hash_buf: Uint8Array, pub_key_buf: Uint8Array): void;
