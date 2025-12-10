import { describe, it, expect } from "vitest";
import { WebBuf } from "../src/index.js";

describe("Index", () => {
  it("should encode and decode base64", () => {
    const myStr = "Hello, World!";
    const buf = WebBuf.fromUtf8(myStr);
    const base64 = buf.toString("base64");
    const decoded = WebBuf.from(base64, "base64");
    expect(decoded.toUtf8()).toBe(myStr);
  });

  it("should encode and decode hex", () => {
    const myStr = "Hello, World!";
    const buf = WebBuf.fromUtf8(myStr);
    const hex = buf.toString("hex");
    const decoded = WebBuf.from(hex, "hex");
    expect(decoded.toUtf8()).toBe(myStr);
  });
});

describe("wipe", () => {
  it("should zero all bytes in a buffer", () => {
    const buf = WebBuf.fromHex("deadbeef01020304");
    expect(buf.toHex()).toBe("deadbeef01020304");
    buf.wipe();
    expect(buf.toHex()).toBe("0000000000000000");
  });

  it("should work on an empty buffer", () => {
    const buf = new WebBuf(0);
    buf.wipe();
    expect(buf.length).toBe(0);
  });

  it("should work on a single-byte buffer", () => {
    const buf = WebBuf.fromHex("ff");
    buf.wipe();
    expect(buf.toHex()).toBe("00");
  });

  it("should work on a large buffer", () => {
    const buf = WebBuf.alloc(1024, 0xff);
    expect(buf[0]).toBe(0xff);
    expect(buf[1023]).toBe(0xff);
    buf.wipe();
    for (let i = 0; i < buf.length; i++) {
      expect(buf[i]).toBe(0);
    }
  });
});
