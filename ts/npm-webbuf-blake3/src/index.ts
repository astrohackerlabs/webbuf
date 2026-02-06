import {
  blake3_hash,
  double_blake3_hash,
  blake3_mac,
  Blake3Hasher as WasmBlake3Hasher,
} from "./rs-webbuf_blake3-inline-base64/webbuf_blake3.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function blake3Hash(buf: WebBuf): FixedBuf<32> {
  const hash = blake3_hash(buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(hash));
}

export function doubleBlake3Hash(buf: WebBuf): FixedBuf<32> {
  const hash = double_blake3_hash(buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(hash));
}

export function blake3Mac(key: FixedBuf<32>, message: WebBuf): FixedBuf<32> {
  const mac = blake3_mac(key.buf, message);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(mac));
}

/**
 * Incremental BLAKE3 hasher that maintains state across multiple `update` calls.
 * Useful for hashing large files in chunks without loading the entire content
 * into memory.
 *
 * @example
 * ```ts
 * const hasher = new Blake3Hasher();
 * hasher.update(chunk1);
 * hasher.update(chunk2);
 * const hash = hasher.finalize();
 * hasher.dispose(); // free WASM memory
 * ```
 */
export class Blake3Hasher {
  private inner: WasmBlake3Hasher;

  constructor() {
    this.inner = new WasmBlake3Hasher();
  }

  /**
   * Create a new keyed (MAC) incremental hasher.
   * Key must be exactly 32 bytes.
   */
  static newKeyed(key: FixedBuf<32>): Blake3Hasher {
    const hasher = Object.create(Blake3Hasher.prototype) as Blake3Hasher;
    hasher.inner = WasmBlake3Hasher.new_keyed(key.buf);
    return hasher;
  }

  /**
   * Feed data into the hasher. Can be called multiple times.
   */
  update(data: WebBuf): this {
    this.inner.update(data);
    return this;
  }

  /**
   * Finalize and return the 32-byte BLAKE3 digest.
   * This does NOT consume the hasher — you can continue calling `update` and
   * `finalize` again to get the hash of all data fed so far.
   */
  finalize(): FixedBuf<32> {
    const hash = this.inner.finalize();
    return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(hash));
  }

  /**
   * Reset the hasher to its initial state for reuse.
   */
  reset(): this {
    this.inner.reset();
    return this;
  }

  /**
   * Free the underlying WASM memory. Call this when done with the hasher.
   */
  dispose(): void {
    this.inner.free();
  }

  [Symbol.dispose](): void {
    this.dispose();
  }
}

/**
 * Create a new incremental BLAKE3 hasher.
 */
export function createBlake3Hasher(): Blake3Hasher {
  return new Blake3Hasher();
}

/**
 * Create a new keyed (MAC) incremental BLAKE3 hasher.
 * Key must be exactly 32 bytes.
 */
export function createBlake3KeyedHasher(key: FixedBuf<32>): Blake3Hasher {
  return Blake3Hasher.newKeyed(key);
}
