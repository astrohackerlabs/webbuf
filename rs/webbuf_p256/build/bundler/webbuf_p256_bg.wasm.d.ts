/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const private_key_add: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const private_key_verify: (a: number, b: number) => number;
export const public_key_add: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const public_key_create: (a: number, b: number) => [number, number, number, number];
export const public_key_verify: (a: number, b: number) => number;
export const shared_secret: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const sign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_start: () => void;
