/* tslint:disable */
/* eslint-disable */

export class Blake3Hasher {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Create a new incremental BLAKE3 hasher.
   */
  constructor();
  /**
   * Reset the hasher to its initial state, allowing reuse.
   */
  reset(): void;
  /**
   * Feed data into the hasher. Can be called multiple times.
   */
  update(data: Uint8Array): void;
  /**
   * Finalize the hash and return the 32-byte digest.
   * This does NOT consume the hasher — you can continue calling `update` and
   * `finalize` again to get an extended hash of the data fed so far.
   */
  finalize(): Uint8Array;
  /**
   * Create a new incremental BLAKE3 keyed hasher (for MAC).
   * Key must be exactly 32 bytes.
   */
  static new_keyed(key: Uint8Array): Blake3Hasher;
}

export function blake3_hash(data: Uint8Array): Uint8Array;

export function blake3_mac(key: Uint8Array, data: Uint8Array): Uint8Array;

export function double_blake3_hash(data: Uint8Array): Uint8Array;
