import { WebBuf } from "@webbuf/webbuf";

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
    } catch (err) {
      throw new Error("invalid encoding");
    }
  }

  toBase64(): string {
    return this._buf.toString("base64");
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
