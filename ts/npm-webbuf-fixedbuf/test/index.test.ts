import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "../src/index.js";

describe("Index", () => {
  it("should encode and decode base64", () => {
    const myStr = "Hello, World!";
    const buf = WebBuf.from(myStr);
    const base64 = buf.toString("base64");
    const decoded = WebBuf.from(base64, "base64");
    expect(decoded.toUtf8()).toBe(myStr);
  });

  it("should encode and decode hex", () => {
    const myStr = "Hello, World!";
    const buf = WebBuf.from(myStr);
    const hex = buf.toString("hex");
    const decoded = WebBuf.from(hex, "hex");
    expect(decoded.toUtf8()).toBe(myStr);
  });
});

describe("wipe", () => {
  it("should zero all bytes in a FixedBuf", () => {
    const buf = FixedBuf.fromHex<8>(8, "deadbeef01020304");
    expect(buf.toHex()).toBe("deadbeef01020304");
    buf.wipe();
    expect(buf.toHex()).toBe("0000000000000000");
  });

  it("should work on a single-byte FixedBuf", () => {
    const buf = FixedBuf.fromHex<1>(1, "ff");
    buf.wipe();
    expect(buf.toHex()).toBe("00");
  });

  it("should work on a 32-byte key-sized FixedBuf", () => {
    const buf = FixedBuf.alloc<32>(32, 0xff);
    expect(buf.buf[0]).toBe(0xff);
    expect(buf.buf[31]).toBe(0xff);
    buf.wipe();
    for (let i = 0; i < 32; i++) {
      expect(buf.buf[i]).toBe(0);
    }
  });

  it("should wipe the underlying WebBuf", () => {
    const buf = FixedBuf.fromHex<4>(4, "aabbccdd");
    const underlying = buf.buf;
    buf.wipe();
    // Verify the underlying WebBuf is also zeroed
    expect(underlying.toHex()).toBe("00000000");
  });
});
