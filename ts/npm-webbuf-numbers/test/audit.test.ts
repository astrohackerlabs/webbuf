/**
 * Audit tests for @webbuf/numbers
 *
 * These tests verify correct byte ordering (endianness) and boundary values
 * by comparing against DataView, which is the standard JavaScript API for
 * reading/writing multi-byte numbers with explicit endianness.
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import {
  U8,
  U16BE,
  U16LE,
  U32BE,
  U32LE,
  U64BE,
  U64LE,
  U128BE,
  U128LE,
  U256BE,
  U256LE,
} from "../src/index.js";

describe("Audit: U8 boundary values", () => {
  it("should handle minimum value (0)", () => {
    const u8 = U8.fromN(0);
    expect(u8.n).toBe(0);
    expect(u8.toHex()).toBe("00");
  });

  it("should handle maximum value (255)", () => {
    const u8 = U8.fromN(255);
    expect(u8.n).toBe(255);
    expect(u8.toHex()).toBe("ff");
  });

  it("should reject values above 255", () => {
    expect(() => U8.fromN(256)).toThrow();
  });

  it("should reject negative values", () => {
    expect(() => U8.fromN(-1)).toThrow();
  });

  it("should match DataView for all byte values", () => {
    for (let i = 0; i <= 255; i++) {
      const u8 = U8.fromN(i);
      const buf = new Uint8Array(1);
      buf[0] = i;
      expect(u8.buf.buf[0]).toBe(buf[0]);
    }
  });
});

describe("Audit: U16 endianness verification", () => {
  describe("U16BE (Big Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u16 = U16BE.fromN(0);
      expect(u16.n).toBe(0);
      expect(u16.toHex()).toBe("0000");
    });

    it("should handle maximum value (65535)", () => {
      const u16 = U16BE.fromN(65535);
      expect(u16.n).toBe(65535);
      expect(u16.toHex()).toBe("ffff");
    });

    it("should match DataView big-endian byte ordering", () => {
      const testValues = [0, 1, 255, 256, 0x0102, 0x1234, 0xabcd, 65535];

      for (const value of testValues) {
        const u16 = U16BE.fromN(value);
        const buf = new ArrayBuffer(2);
        const view = new DataView(buf);
        view.setUint16(0, value, false); // false = big-endian

        expect(u16.buf.buf[0]).toBe(new Uint8Array(buf)[0]);
        expect(u16.buf.buf[1]).toBe(new Uint8Array(buf)[1]);
      }
    });

    it("should encode 0x0102 as [01, 02]", () => {
      const u16 = U16BE.fromN(0x0102);
      expect(u16.buf.buf[0]).toBe(0x01);
      expect(u16.buf.buf[1]).toBe(0x02);
    });
  });

  describe("U16LE (Little Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u16 = U16LE.fromN(0);
      expect(u16.n).toBe(0);
      expect(u16.toHex()).toBe("0000");
    });

    it("should handle maximum value (65535)", () => {
      const u16 = U16LE.fromN(65535);
      expect(u16.n).toBe(65535);
      expect(u16.toHex()).toBe("ffff");
    });

    it("should match DataView little-endian byte ordering", () => {
      const testValues = [0, 1, 255, 256, 0x0102, 0x1234, 0xabcd, 65535];

      for (const value of testValues) {
        const u16 = U16LE.fromN(value);
        const buf = new ArrayBuffer(2);
        const view = new DataView(buf);
        view.setUint16(0, value, true); // true = little-endian

        expect(u16.buf.buf[0]).toBe(new Uint8Array(buf)[0]);
        expect(u16.buf.buf[1]).toBe(new Uint8Array(buf)[1]);
      }
    });

    it("should encode 0x0102 as [02, 01]", () => {
      const u16 = U16LE.fromN(0x0102);
      expect(u16.buf.buf[0]).toBe(0x02);
      expect(u16.buf.buf[1]).toBe(0x01);
    });
  });

  describe("U16BE vs U16LE byte order difference", () => {
    it("should produce reversed byte order for same value", () => {
      const value = 0x1234;
      const be = U16BE.fromN(value);
      const le = U16LE.fromN(value);

      // BE: [12, 34], LE: [34, 12]
      expect(be.buf.buf[0]).toBe(0x12);
      expect(be.buf.buf[1]).toBe(0x34);
      expect(le.buf.buf[0]).toBe(0x34);
      expect(le.buf.buf[1]).toBe(0x12);
    });
  });
});

describe("Audit: U32 endianness verification", () => {
  describe("U32BE (Big Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u32 = U32BE.fromN(0);
      expect(u32.n).toBe(0);
      expect(u32.toHex()).toBe("00000000");
    });

    it("should handle maximum value (4294967295)", () => {
      const u32 = U32BE.fromN(4294967295);
      expect(u32.n).toBe(4294967295);
      expect(u32.toHex()).toBe("ffffffff");
    });

    it("should match DataView big-endian byte ordering", () => {
      const testValues = [
        0,
        1,
        255,
        256,
        65535,
        65536,
        0x01020304,
        0x12345678,
        0xdeadbeef,
        4294967295,
      ];

      for (const value of testValues) {
        const u32 = U32BE.fromN(value);
        const buf = new ArrayBuffer(4);
        const view = new DataView(buf);
        view.setUint32(0, value, false); // false = big-endian

        const expected = new Uint8Array(buf);
        expect(u32.buf.buf[0]).toBe(expected[0]);
        expect(u32.buf.buf[1]).toBe(expected[1]);
        expect(u32.buf.buf[2]).toBe(expected[2]);
        expect(u32.buf.buf[3]).toBe(expected[3]);
      }
    });

    it("should encode 0x01020304 as [01, 02, 03, 04]", () => {
      const u32 = U32BE.fromN(0x01020304);
      expect(u32.buf.buf[0]).toBe(0x01);
      expect(u32.buf.buf[1]).toBe(0x02);
      expect(u32.buf.buf[2]).toBe(0x03);
      expect(u32.buf.buf[3]).toBe(0x04);
    });
  });

  describe("U32LE (Little Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u32 = U32LE.fromN(0);
      expect(u32.n).toBe(0);
      expect(u32.toHex()).toBe("00000000");
    });

    it("should handle maximum value (4294967295)", () => {
      const u32 = U32LE.fromN(4294967295);
      expect(u32.n).toBe(4294967295);
      expect(u32.toHex()).toBe("ffffffff");
    });

    it("should match DataView little-endian byte ordering", () => {
      const testValues = [
        0,
        1,
        255,
        256,
        65535,
        65536,
        0x01020304,
        0x12345678,
        0xdeadbeef,
        4294967295,
      ];

      for (const value of testValues) {
        const u32 = U32LE.fromN(value);
        const buf = new ArrayBuffer(4);
        const view = new DataView(buf);
        view.setUint32(0, value, true); // true = little-endian

        const expected = new Uint8Array(buf);
        expect(u32.buf.buf[0]).toBe(expected[0]);
        expect(u32.buf.buf[1]).toBe(expected[1]);
        expect(u32.buf.buf[2]).toBe(expected[2]);
        expect(u32.buf.buf[3]).toBe(expected[3]);
      }
    });

    it("should encode 0x01020304 as [04, 03, 02, 01]", () => {
      const u32 = U32LE.fromN(0x01020304);
      expect(u32.buf.buf[0]).toBe(0x04);
      expect(u32.buf.buf[1]).toBe(0x03);
      expect(u32.buf.buf[2]).toBe(0x02);
      expect(u32.buf.buf[3]).toBe(0x01);
    });
  });

  describe("U32BE vs U32LE byte order difference", () => {
    it("should produce reversed byte order for same value", () => {
      const value = 0x12345678;
      const be = U32BE.fromN(value);
      const le = U32LE.fromN(value);

      // BE: [12, 34, 56, 78], LE: [78, 56, 34, 12]
      expect(be.buf.buf[0]).toBe(0x12);
      expect(be.buf.buf[1]).toBe(0x34);
      expect(be.buf.buf[2]).toBe(0x56);
      expect(be.buf.buf[3]).toBe(0x78);
      expect(le.buf.buf[0]).toBe(0x78);
      expect(le.buf.buf[1]).toBe(0x56);
      expect(le.buf.buf[2]).toBe(0x34);
      expect(le.buf.buf[3]).toBe(0x12);
    });
  });
});

describe("Audit: U64 endianness verification", () => {
  describe("U64BE (Big Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u64 = U64BE.fromBn(0n);
      expect(u64.bn).toBe(0n);
      expect(u64.toHex()).toBe("0000000000000000");
    });

    it("should handle maximum value (2^64 - 1)", () => {
      const max = 2n ** 64n - 1n;
      const u64 = U64BE.fromBn(max);
      expect(u64.bn).toBe(max);
      expect(u64.toHex()).toBe("ffffffffffffffff");
    });

    it("should match DataView big-endian byte ordering", () => {
      const testValues = [
        0n,
        1n,
        255n,
        256n,
        65535n,
        65536n,
        0x0102030405060708n,
        0x123456789abcdef0n,
        2n ** 64n - 1n,
      ];

      for (const value of testValues) {
        const u64 = U64BE.fromBn(value);
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        view.setBigUint64(0, value, false); // false = big-endian

        const expected = new Uint8Array(buf);
        for (let i = 0; i < 8; i++) {
          expect(u64.buf.buf[i]).toBe(expected[i]);
        }
      }
    });

    it("should encode 0x0102030405060708 correctly", () => {
      const u64 = U64BE.fromBn(0x0102030405060708n);
      expect(u64.buf.buf[0]).toBe(0x01);
      expect(u64.buf.buf[1]).toBe(0x02);
      expect(u64.buf.buf[2]).toBe(0x03);
      expect(u64.buf.buf[3]).toBe(0x04);
      expect(u64.buf.buf[4]).toBe(0x05);
      expect(u64.buf.buf[5]).toBe(0x06);
      expect(u64.buf.buf[6]).toBe(0x07);
      expect(u64.buf.buf[7]).toBe(0x08);
    });
  });

  describe("U64LE (Little Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u64 = U64LE.fromBn(0n);
      expect(u64.bn).toBe(0n);
      expect(u64.toHex()).toBe("0000000000000000");
    });

    it("should handle maximum value (2^64 - 1)", () => {
      const max = 2n ** 64n - 1n;
      const u64 = U64LE.fromBn(max);
      expect(u64.bn).toBe(max);
      expect(u64.toHex()).toBe("ffffffffffffffff");
    });

    it("should match DataView little-endian byte ordering", () => {
      const testValues = [
        0n,
        1n,
        255n,
        256n,
        65535n,
        65536n,
        0x0102030405060708n,
        0x123456789abcdef0n,
        2n ** 64n - 1n,
      ];

      for (const value of testValues) {
        const u64 = U64LE.fromBn(value);
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        view.setBigUint64(0, value, true); // true = little-endian

        const expected = new Uint8Array(buf);
        for (let i = 0; i < 8; i++) {
          expect(u64.buf.buf[i]).toBe(expected[i]);
        }
      }
    });

    it("should encode 0x0102030405060708 correctly", () => {
      const u64 = U64LE.fromBn(0x0102030405060708n);
      expect(u64.buf.buf[0]).toBe(0x08);
      expect(u64.buf.buf[1]).toBe(0x07);
      expect(u64.buf.buf[2]).toBe(0x06);
      expect(u64.buf.buf[3]).toBe(0x05);
      expect(u64.buf.buf[4]).toBe(0x04);
      expect(u64.buf.buf[5]).toBe(0x03);
      expect(u64.buf.buf[6]).toBe(0x02);
      expect(u64.buf.buf[7]).toBe(0x01);
    });
  });

  describe("U64BE vs U64LE byte order difference", () => {
    it("should produce reversed byte order for same value", () => {
      const value = 0x0102030405060708n;
      const be = U64BE.fromBn(value);
      const le = U64LE.fromBn(value);

      // Bytes should be reversed
      for (let i = 0; i < 8; i++) {
        expect(be.buf.buf[i]).toBe(le.buf.buf[7 - i]);
      }
    });
  });
});

describe("Audit: U128 endianness verification", () => {
  describe("U128BE (Big Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u128 = U128BE.fromBn(0n);
      expect(u128.bn).toBe(0n);
      expect(u128.toHex()).toBe("00000000000000000000000000000000");
    });

    it("should handle maximum value (2^128 - 1)", () => {
      const max = 2n ** 128n - 1n;
      const u128 = U128BE.fromBn(max);
      expect(u128.bn).toBe(max);
      expect(u128.toHex()).toBe("ffffffffffffffffffffffffffffffff");
    });

    it("should encode known value correctly (big-endian)", () => {
      // 0x0102030405060708090a0b0c0d0e0f10
      const value = 0x0102030405060708090a0b0c0d0e0f10n;
      const u128 = U128BE.fromBn(value);

      expect(u128.buf.buf[0]).toBe(0x01);
      expect(u128.buf.buf[1]).toBe(0x02);
      expect(u128.buf.buf[2]).toBe(0x03);
      expect(u128.buf.buf[3]).toBe(0x04);
      expect(u128.buf.buf[4]).toBe(0x05);
      expect(u128.buf.buf[5]).toBe(0x06);
      expect(u128.buf.buf[6]).toBe(0x07);
      expect(u128.buf.buf[7]).toBe(0x08);
      expect(u128.buf.buf[8]).toBe(0x09);
      expect(u128.buf.buf[9]).toBe(0x0a);
      expect(u128.buf.buf[10]).toBe(0x0b);
      expect(u128.buf.buf[11]).toBe(0x0c);
      expect(u128.buf.buf[12]).toBe(0x0d);
      expect(u128.buf.buf[13]).toBe(0x0e);
      expect(u128.buf.buf[14]).toBe(0x0f);
      expect(u128.buf.buf[15]).toBe(0x10);
    });

    it("should round-trip through hex encoding", () => {
      const testValues = [
        0n,
        1n,
        2n ** 64n,
        2n ** 127n,
        2n ** 128n - 1n,
        0x123456789abcdef0123456789abcdef0n,
      ];

      for (const value of testValues) {
        const u128 = U128BE.fromBn(value);
        const hex = u128.toHex();
        const restored = U128BE.fromHex(hex);
        expect(restored.bn).toBe(value);
      }
    });
  });

  describe("U128LE (Little Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u128 = U128LE.fromBn(0n);
      expect(u128.bn).toBe(0n);
      expect(u128.toHex()).toBe("00000000000000000000000000000000");
    });

    it("should handle maximum value (2^128 - 1)", () => {
      const max = 2n ** 128n - 1n;
      const u128 = U128LE.fromBn(max);
      expect(u128.bn).toBe(max);
      expect(u128.toHex()).toBe("ffffffffffffffffffffffffffffffff");
    });

    it("should encode known value correctly (little-endian)", () => {
      // 0x0102030405060708090a0b0c0d0e0f10
      const value = 0x0102030405060708090a0b0c0d0e0f10n;
      const u128 = U128LE.fromBn(value);

      // Little-endian: least significant byte first
      expect(u128.buf.buf[0]).toBe(0x10);
      expect(u128.buf.buf[1]).toBe(0x0f);
      expect(u128.buf.buf[2]).toBe(0x0e);
      expect(u128.buf.buf[3]).toBe(0x0d);
      expect(u128.buf.buf[4]).toBe(0x0c);
      expect(u128.buf.buf[5]).toBe(0x0b);
      expect(u128.buf.buf[6]).toBe(0x0a);
      expect(u128.buf.buf[7]).toBe(0x09);
      expect(u128.buf.buf[8]).toBe(0x08);
      expect(u128.buf.buf[9]).toBe(0x07);
      expect(u128.buf.buf[10]).toBe(0x06);
      expect(u128.buf.buf[11]).toBe(0x05);
      expect(u128.buf.buf[12]).toBe(0x04);
      expect(u128.buf.buf[13]).toBe(0x03);
      expect(u128.buf.buf[14]).toBe(0x02);
      expect(u128.buf.buf[15]).toBe(0x01);
    });

    it("should round-trip through hex encoding", () => {
      const testValues = [
        0n,
        1n,
        2n ** 64n,
        2n ** 127n,
        2n ** 128n - 1n,
        0x123456789abcdef0123456789abcdef0n,
      ];

      for (const value of testValues) {
        const u128 = U128LE.fromBn(value);
        const hex = u128.toHex();
        const restored = U128LE.fromHex(hex);
        expect(restored.bn).toBe(value);
      }
    });
  });

  describe("U128BE vs U128LE byte order difference", () => {
    it("should produce reversed byte order for same value", () => {
      const value = 0x0102030405060708090a0b0c0d0e0f10n;
      const be = U128BE.fromBn(value);
      const le = U128LE.fromBn(value);

      // Bytes should be reversed
      for (let i = 0; i < 16; i++) {
        expect(be.buf.buf[i]).toBe(le.buf.buf[15 - i]);
      }
    });
  });
});

describe("Audit: U256 endianness verification", () => {
  describe("U256BE (Big Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u256 = U256BE.fromBn(0n);
      expect(u256.bn).toBe(0n);
      expect(u256.toHex()).toBe(
        "0000000000000000000000000000000000000000000000000000000000000000",
      );
    });

    it("should handle maximum value (2^256 - 1)", () => {
      const max = 2n ** 256n - 1n;
      const u256 = U256BE.fromBn(max);
      expect(u256.bn).toBe(max);
      expect(u256.toHex()).toBe(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      );
    });

    it("should encode known value correctly (big-endian)", () => {
      // Create a value where each byte is different for easy verification
      let value = 0n;
      for (let i = 1; i <= 32; i++) {
        value = (value << 8n) | BigInt(i);
      }

      const u256 = U256BE.fromBn(value);

      for (let i = 0; i < 32; i++) {
        expect(u256.buf.buf[i]).toBe(i + 1);
      }
    });

    it("should handle powers of 2", () => {
      const testCases = [
        { power: 0, expected: 1n },
        { power: 8, expected: 256n },
        { power: 16, expected: 65536n },
        { power: 32, expected: 4294967296n },
        { power: 64, expected: 2n ** 64n },
        { power: 128, expected: 2n ** 128n },
        { power: 255, expected: 2n ** 255n },
      ];

      for (const { power, expected } of testCases) {
        const u256 = U256BE.fromBn(expected);
        expect(u256.bn).toBe(expected);
      }
    });

    it("should round-trip through hex encoding", () => {
      const testValues = [
        0n,
        1n,
        2n ** 64n,
        2n ** 128n,
        2n ** 255n,
        2n ** 256n - 1n,
      ];

      for (const value of testValues) {
        const u256 = U256BE.fromBn(value);
        const hex = u256.toHex();
        const restored = U256BE.fromHex(hex);
        expect(restored.bn).toBe(value);
      }
    });
  });

  describe("U256LE (Little Endian)", () => {
    it("should handle minimum value (0)", () => {
      const u256 = U256LE.fromBn(0n);
      expect(u256.bn).toBe(0n);
      expect(u256.toHex()).toBe(
        "0000000000000000000000000000000000000000000000000000000000000000",
      );
    });

    it("should handle maximum value (2^256 - 1)", () => {
      const max = 2n ** 256n - 1n;
      const u256 = U256LE.fromBn(max);
      expect(u256.bn).toBe(max);
      expect(u256.toHex()).toBe(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      );
    });

    it("should encode known value correctly (little-endian)", () => {
      // Create a value where each byte is different for easy verification
      let value = 0n;
      for (let i = 1; i <= 32; i++) {
        value = (value << 8n) | BigInt(i);
      }

      const u256 = U256LE.fromBn(value);

      // Little-endian: bytes should be reversed
      for (let i = 0; i < 32; i++) {
        expect(u256.buf.buf[i]).toBe(32 - i);
      }
    });

    it("should round-trip through hex encoding", () => {
      const testValues = [
        0n,
        1n,
        2n ** 64n,
        2n ** 128n,
        2n ** 255n,
        2n ** 256n - 1n,
      ];

      for (const value of testValues) {
        const u256 = U256LE.fromBn(value);
        const hex = u256.toHex();
        const restored = U256LE.fromHex(hex);
        expect(restored.bn).toBe(value);
      }
    });
  });

  describe("U256BE vs U256LE byte order difference", () => {
    it("should produce reversed byte order for same value", () => {
      // Create a value where each byte is different
      let value = 0n;
      for (let i = 1; i <= 32; i++) {
        value = (value << 8n) | BigInt(i);
      }

      const be = U256BE.fromBn(value);
      const le = U256LE.fromBn(value);

      // Bytes should be reversed
      for (let i = 0; i < 32; i++) {
        expect(be.buf.buf[i]).toBe(le.buf.buf[31 - i]);
      }
    });
  });
});

describe("Audit: Cross-type consistency", () => {
  it("should produce consistent encoding across sizes for same small value", () => {
    const value = 0x12n;

    const u8 = U8.fromN(Number(value));
    const u16be = U16BE.fromN(Number(value));
    const u32be = U32BE.fromN(Number(value));
    const u64be = U64BE.fromBn(value);
    const u128be = U128BE.fromBn(value);
    const u256be = U256BE.fromBn(value);

    // All should encode 0x12 in the least significant byte
    expect(u8.buf.buf[0]).toBe(0x12);
    expect(u16be.buf.buf[1]).toBe(0x12); // Big-endian: value in last byte
    expect(u32be.buf.buf[3]).toBe(0x12);
    expect(u64be.buf.buf[7]).toBe(0x12);
    expect(u128be.buf.buf[15]).toBe(0x12);
    expect(u256be.buf.buf[31]).toBe(0x12);

    // Leading bytes should be zero
    expect(u16be.buf.buf[0]).toBe(0x00);
    expect(u32be.buf.buf[0]).toBe(0x00);
    expect(u64be.buf.buf[0]).toBe(0x00);
    expect(u128be.buf.buf[0]).toBe(0x00);
    expect(u256be.buf.buf[0]).toBe(0x00);
  });

  it("should produce consistent little-endian encoding across sizes", () => {
    const value = 0x12n;

    const u16le = U16LE.fromN(Number(value));
    const u32le = U32LE.fromN(Number(value));
    const u64le = U64LE.fromBn(value);
    const u128le = U128LE.fromBn(value);
    const u256le = U256LE.fromBn(value);

    // Little-endian: value in first byte
    expect(u16le.buf.buf[0]).toBe(0x12);
    expect(u32le.buf.buf[0]).toBe(0x12);
    expect(u64le.buf.buf[0]).toBe(0x12);
    expect(u128le.buf.buf[0]).toBe(0x12);
    expect(u256le.buf.buf[0]).toBe(0x12);

    // Trailing bytes should be zero
    expect(u16le.buf.buf[1]).toBe(0x00);
    expect(u32le.buf.buf[3]).toBe(0x00);
    expect(u64le.buf.buf[7]).toBe(0x00);
    expect(u128le.buf.buf[15]).toBe(0x00);
    expect(u256le.buf.buf[31]).toBe(0x00);
  });
});

describe("Audit: Overflow protection", () => {
  it("should reject U8 overflow", () => {
    expect(() => U8.fromN(256)).toThrow();
    expect(() => U8.fromBn(256n)).toThrow();
  });

  it("should reject U16 overflow", () => {
    expect(() => U16BE.fromN(65536)).toThrow();
    expect(() => U16LE.fromN(65536)).toThrow();
    expect(() => U16BE.fromBn(65536n)).toThrow();
    expect(() => U16LE.fromBn(65536n)).toThrow();
  });

  it("should reject U32 overflow", () => {
    expect(() => U32BE.fromN(4294967296)).toThrow();
    expect(() => U32LE.fromN(4294967296)).toThrow();
    expect(() => U32BE.fromBn(4294967296n)).toThrow();
    expect(() => U32LE.fromBn(4294967296n)).toThrow();
  });

  it("should reject U64 overflow", () => {
    const overflow = 2n ** 64n;
    expect(() => U64BE.fromBn(overflow)).toThrow();
    expect(() => U64LE.fromBn(overflow)).toThrow();
  });

  it("should reject U128 overflow", () => {
    const overflow = 2n ** 128n;
    expect(() => U128BE.fromBn(overflow)).toThrow();
    expect(() => U128LE.fromBn(overflow)).toThrow();
  });

  it("should reject U256 overflow", () => {
    const overflow = 2n ** 256n;
    expect(() => U256BE.fromBn(overflow)).toThrow();
    expect(() => U256LE.fromBn(overflow)).toThrow();
  });

  it("should reject negative values", () => {
    expect(() => U8.fromN(-1)).toThrow();
    expect(() => U16BE.fromN(-1)).toThrow();
    expect(() => U32BE.fromN(-1)).toThrow();
    expect(() => U64BE.fromBn(-1n)).toThrow();
    expect(() => U128BE.fromBn(-1n)).toThrow();
    expect(() => U256BE.fromBn(-1n)).toThrow();
  });
});

describe("Audit: Known test vectors", () => {
  describe("Bitcoin-style values", () => {
    it("should correctly encode Bitcoin genesis block timestamp (U32LE)", () => {
      // Bitcoin genesis block timestamp: 1231006505 = 0x495FAB29
      // In little-endian storage (LSB first): [29, AB, 5F, 49]
      // toHex() returns bytes as stored, so: "29ab5f49" would be BE
      // But since U32LE stores as little-endian: "495fab29"
      const timestamp = U32LE.fromN(1231006505);
      // Verify the numeric value round-trips correctly
      expect(timestamp.n).toBe(1231006505);
      // Verify byte order: 0x495FAB29 -> LE storage [0x29, 0xAB, 0x5F, 0x49]
      expect(timestamp.buf.buf[0]).toBe(0x29);
      expect(timestamp.buf.buf[1]).toBe(0xab);
      expect(timestamp.buf.buf[2]).toBe(0x5f);
      expect(timestamp.buf.buf[3]).toBe(0x49);
    });

    it("should correctly encode common satoshi amounts (U64LE)", () => {
      // 1 BTC = 100,000,000 satoshis
      const oneBtc = U64LE.fromBn(100000000n);
      // 100000000 = 0x05F5E100, little-endian
      expect(oneBtc.buf.buf[0]).toBe(0x00);
      expect(oneBtc.buf.buf[1]).toBe(0xe1);
      expect(oneBtc.buf.buf[2]).toBe(0xf5);
      expect(oneBtc.buf.buf[3]).toBe(0x05);

      // 21 million BTC cap = 2,100,000,000,000,000 satoshis
      const maxBtc = U64LE.fromBn(2100000000000000n);
      expect(maxBtc.bn).toBe(2100000000000000n);
    });
  });

  describe("Ethereum-style values", () => {
    it("should correctly encode wei amounts (U256BE)", () => {
      // 1 ETH = 10^18 wei
      const oneEth = 1000000000000000000n;
      const u256 = U256BE.fromBn(oneEth);
      expect(u256.bn).toBe(oneEth);

      // Verify it round-trips
      const restored = U256BE.fromHex(u256.toHex());
      expect(restored.bn).toBe(oneEth);
    });
  });
});

describe("Audit: Buffer conversion consistency", () => {
  it("should convert BE to LE buffer correctly for U16", () => {
    const value = 0x1234;
    const be = U16BE.fromN(value);
    const leBuf = be.toLEBuf();

    // BE buffer: [12, 34]
    // LE buffer should be: [34, 12]
    expect(leBuf.buf[0]).toBe(0x34);
    expect(leBuf.buf[1]).toBe(0x12);
  });

  it("should convert LE to BE buffer correctly for U16", () => {
    const value = 0x1234;
    const le = U16LE.fromN(value);
    const beBuf = le.toBEBuf();

    // LE buffer: [34, 12]
    // BE buffer should be: [12, 34]
    expect(beBuf.buf[0]).toBe(0x12);
    expect(beBuf.buf[1]).toBe(0x34);
  });

  it("should convert BE to LE buffer correctly for U32", () => {
    const value = 0x12345678;
    const be = U32BE.fromN(value);
    const leBuf = be.toLEBuf();

    expect(leBuf.buf[0]).toBe(0x78);
    expect(leBuf.buf[1]).toBe(0x56);
    expect(leBuf.buf[2]).toBe(0x34);
    expect(leBuf.buf[3]).toBe(0x12);
  });

  it("should convert LE to BE buffer correctly for U32", () => {
    const value = 0x12345678;
    const le = U32LE.fromN(value);
    const beBuf = le.toBEBuf();

    expect(beBuf.buf[0]).toBe(0x12);
    expect(beBuf.buf[1]).toBe(0x34);
    expect(beBuf.buf[2]).toBe(0x56);
    expect(beBuf.buf[3]).toBe(0x78);
  });

  it("should convert BE to LE buffer correctly for U64", () => {
    const value = 0x0102030405060708n;
    const be = U64BE.fromBn(value);
    const leBuf = be.toLEBuf();

    for (let i = 0; i < 8; i++) {
      expect(leBuf.buf[i]).toBe(8 - i);
    }
  });

  it("should convert LE to BE buffer correctly for U64", () => {
    const value = 0x0102030405060708n;
    const le = U64LE.fromBn(value);
    const beBuf = le.toBEBuf();

    for (let i = 0; i < 8; i++) {
      expect(beBuf.buf[i]).toBe(i + 1);
    }
  });
});
