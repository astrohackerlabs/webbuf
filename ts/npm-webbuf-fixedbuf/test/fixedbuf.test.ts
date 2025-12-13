import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "../src/fixedbuf.js";

describe("FixedBuf", () => {
  describe("to/from hex", () => {
    it("should convert to and from hex", () => {
      const hex = "deadbeef";
      const buf = FixedBuf.fromHex(4, hex);
      expect(buf.toHex()).toBe(hex);
    });
  });

  describe("to/from base64", () => {
    it("should convert to and from base64", () => {
      const base64 = "3q2+7w==";
      const buf = FixedBuf.fromBase64(4, base64);
      expect(buf.toBase64()).toBe(base64);
    });
  });

  describe("create new buffer", () => {
    it("should create a new buffer", () => {
      const buf = FixedBuf.alloc(4);
      expect(buf.buf.length).toBe(4);
    });

    it("should create a new FixedBuf from a WebBuf", () => {
      const buf = WebBuf.alloc(4);
      const fixedBuf = FixedBuf.fromBuf(4, buf);
      expect(fixedBuf.buf.length).toBe(4);
    });

    it("should not create a new FixedBuf from a WebBuf with the wrong size", () => {
      const buf = WebBuf.alloc(4);
      expect(() => FixedBuf.fromBuf(5, buf)).toThrow();
    });
  });

  describe("to/from base32", () => {
    it("should convert to and from Crockford base32 (default)", () => {
      const buf = FixedBuf.fromHex(4, "deadbeef");
      const encoded = buf.toBase32();
      const decoded = FixedBuf.fromBase32(4, encoded);
      expect(decoded.toHex()).toBe("deadbeef");
    });

    it("should convert to and from RFC4648 base32 with padding", () => {
      const buf = FixedBuf.fromHex(4, "deadbeef");
      const encoded = buf.toBase32({ alphabet: "Rfc4648" });
      const decoded = FixedBuf.fromBase32(4, encoded, { alphabet: "Rfc4648" });
      expect(decoded.toHex()).toBe("deadbeef");
    });

    it("should convert to and from RFC4648 base32 without padding", () => {
      const buf = FixedBuf.fromHex(4, "deadbeef");
      const encoded = buf.toBase32({ alphabet: "Rfc4648", padding: false });
      const decoded = FixedBuf.fromBase32(4, encoded, {
        alphabet: "Rfc4648",
        padding: false,
      });
      expect(decoded.toHex()).toBe("deadbeef");
    });

    it("should throw on wrong size from base32", () => {
      const buf = FixedBuf.fromHex(4, "deadbeef");
      const encoded = buf.toBase32();
      expect(() => FixedBuf.fromBase32(5, encoded)).toThrow();
    });

    it("should handle 32-byte buffers (common for hashes)", () => {
      const hex =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
      const buf = FixedBuf.fromHex(32, hex);
      const encoded = buf.toBase32();
      const decoded = FixedBuf.fromBase32(32, encoded);
      expect(decoded.toHex()).toBe(hex);
    });
  });
});
