import { WebBuf, type Base32Options } from "@webbuf/webbuf";

export class FixedBuf<N extends number> {
  public _buf: WebBuf;
  public _size: N;

  constructor(size: N, buf: WebBuf) {
    if (buf.length !== size) {
      throw new Error("invalid size error");
    }
    this._buf = buf;
    this._size = size;
  }

  get buf(): WebBuf {
    return this._buf;
  }

  static fromBuf<N extends number>(size: N, buf: WebBuf): FixedBuf<N> {
    return new FixedBuf(size, buf);
  }

  static alloc<N extends number>(size: N, fill?: number): FixedBuf<N> {
    const buf = WebBuf.alloc(size, fill);
    return FixedBuf.fromBuf(size, buf);
  }

  static fromHex<N extends number>(size: N, hex: string): FixedBuf<N> {
    const buf = WebBuf.from(hex, "hex");
    return FixedBuf.fromBuf(size, buf);
  }

  toHex(): string {
    return this._buf.toString("hex");
  }

  static fromBase64(size: number, base64: string): FixedBuf<number> {
    try {
      const buf = WebBuf.from(base64, "base64");
      return FixedBuf.fromBuf(size, buf);
    } catch {
      throw new Error("invalid encoding");
    }
  }

  toBase64(): string {
    return this._buf.toString("base64");
  }

  /**
   * Encode this buffer as a base32 string.
   *
   * @param options - Options for encoding
   * @param options.alphabet - The alphabet to use (default: "Crockford")
   * @param options.padding - Whether to use padding for Rfc4648* alphabets (default: true)
   * @returns The base32 encoded string
   */
  toBase32(options?: Base32Options): string {
    return this._buf.toBase32(options);
  }

  /**
   * Create a FixedBuf from a base32 encoded string.
   *
   * @param size - The expected size of the decoded buffer
   * @param str - The base32 encoded string
   * @param options - Options for decoding
   * @param options.alphabet - The alphabet to use (default: "Crockford")
   * @param options.padding - Whether the string uses padding for Rfc4648* alphabets (default: true)
   * @returns The decoded FixedBuf
   */
  static fromBase32<N extends number>(
    size: N,
    str: string,
    options?: Base32Options,
  ): FixedBuf<N> {
    const buf = WebBuf.fromBase32(str, options);
    return FixedBuf.fromBuf(size, buf);
  }

  static fromRandom<N extends number>(size: N): FixedBuf<N> {
    const buf = crypto.getRandomValues(WebBuf.alloc(size));
    return FixedBuf.fromBuf(size, buf);
  }

  clone(): FixedBuf<N> {
    return FixedBuf.fromBuf(this._size, new WebBuf(this._buf));
  }

  toReverse(): FixedBuf<N> {
    const cloneedReverse = this._buf.toReverse();
    return FixedBuf.fromBuf(this._size, cloneedReverse);
  }

  /**
   * Securely wipe the buffer by filling it with zeros.
   *
   * Call this method before releasing references to buffers containing
   * sensitive data (keys, passwords, etc.) to minimize the window where
   * sensitive data remains in memory.
   *
   * Note: This is a best-effort security measure. JavaScript's JIT compiler
   * may optimize away the write if it detects the buffer isn't read afterward,
   * and copies of the data may exist elsewhere in memory.
   */
  wipe(): void {
    this._buf.fill(0);
  }
}
