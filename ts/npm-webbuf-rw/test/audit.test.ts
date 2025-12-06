/**
 * Audit tests for @webbuf/rw
 *
 * These tests verify that BufWriter and BufReader correctly handle
 * serialization/deserialization round-trips, boundary conditions,
 * and variable-length integer encoding.
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  U8,
  U16BE,
  U32BE,
  U64BE,
  U128BE,
  U256BE,
} from "@webbuf/numbers";
import { BufReader } from "../src/buf-reader.js";
import { BufWriter } from "../src/buf-writer.js";

describe("Audit: Round-trip tests", () => {
  describe("U8 round-trip", () => {
    it("should round-trip minimum value (0)", () => {
      const writer = new BufWriter();
      writer.writeU8(U8.fromN(0));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU8().n).toBe(0);
    });

    it("should round-trip maximum value (255)", () => {
      const writer = new BufWriter();
      writer.writeU8(U8.fromN(255));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU8().n).toBe(255);
    });

    it("should round-trip all byte values", () => {
      const writer = new BufWriter();
      for (let i = 0; i <= 255; i++) {
        writer.writeU8(U8.fromN(i));
      }
      const reader = new BufReader(writer.toBuf());
      for (let i = 0; i <= 255; i++) {
        expect(reader.readU8().n).toBe(i);
      }
      expect(reader.eof()).toBe(true);
    });
  });

  describe("U16BE round-trip", () => {
    it("should round-trip minimum value (0)", () => {
      const writer = new BufWriter();
      writer.writeU16BE(U16BE.fromN(0));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU16BE().n).toBe(0);
    });

    it("should round-trip maximum value (65535)", () => {
      const writer = new BufWriter();
      writer.writeU16BE(U16BE.fromN(65535));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU16BE().n).toBe(65535);
    });

    it("should round-trip various values", () => {
      const testValues = [0, 1, 255, 256, 0x0102, 0x1234, 0xabcd, 65535];
      const writer = new BufWriter();
      for (const value of testValues) {
        writer.writeU16BE(U16BE.fromN(value));
      }
      const reader = new BufReader(writer.toBuf());
      for (const value of testValues) {
        expect(reader.readU16BE().n).toBe(value);
      }
      expect(reader.eof()).toBe(true);
    });
  });

  describe("U32BE round-trip", () => {
    it("should round-trip minimum value (0)", () => {
      const writer = new BufWriter();
      writer.writeU32BE(U32BE.fromN(0));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU32BE().n).toBe(0);
    });

    it("should round-trip maximum value (4294967295)", () => {
      const writer = new BufWriter();
      writer.writeU32BE(U32BE.fromN(4294967295));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU32BE().n).toBe(4294967295);
    });

    it("should round-trip various values", () => {
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
      const writer = new BufWriter();
      for (const value of testValues) {
        writer.writeU32BE(U32BE.fromN(value));
      }
      const reader = new BufReader(writer.toBuf());
      for (const value of testValues) {
        expect(reader.readU32BE().n).toBe(value);
      }
      expect(reader.eof()).toBe(true);
    });
  });

  describe("U64BE round-trip", () => {
    it("should round-trip minimum value (0)", () => {
      const writer = new BufWriter();
      writer.writeU64BE(U64BE.fromBn(0n));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU64BE().bn).toBe(0n);
    });

    it("should round-trip maximum value (2^64 - 1)", () => {
      const max = 2n ** 64n - 1n;
      const writer = new BufWriter();
      writer.writeU64BE(U64BE.fromBn(max));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU64BE().bn).toBe(max);
    });

    it("should round-trip various values", () => {
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
      const writer = new BufWriter();
      for (const value of testValues) {
        writer.writeU64BE(U64BE.fromBn(value));
      }
      const reader = new BufReader(writer.toBuf());
      for (const value of testValues) {
        expect(reader.readU64BE().bn).toBe(value);
      }
      expect(reader.eof()).toBe(true);
    });
  });

  describe("U128BE round-trip", () => {
    it("should round-trip minimum value (0)", () => {
      const writer = new BufWriter();
      writer.writeU128BE(U128BE.fromBn(0n));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU128BE().bn).toBe(0n);
    });

    it("should round-trip maximum value (2^128 - 1)", () => {
      const max = 2n ** 128n - 1n;
      const writer = new BufWriter();
      writer.writeU128BE(U128BE.fromBn(max));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU128BE().bn).toBe(max);
    });

    it("should round-trip various values", () => {
      const testValues = [
        0n,
        1n,
        2n ** 64n,
        2n ** 127n,
        0x0123456789abcdef0123456789abcdefn,
        2n ** 128n - 1n,
      ];
      const writer = new BufWriter();
      for (const value of testValues) {
        writer.writeU128BE(U128BE.fromBn(value));
      }
      const reader = new BufReader(writer.toBuf());
      for (const value of testValues) {
        expect(reader.readU128BE().bn).toBe(value);
      }
      expect(reader.eof()).toBe(true);
    });
  });

  describe("U256BE round-trip", () => {
    it("should round-trip minimum value (0)", () => {
      const writer = new BufWriter();
      writer.writeU256BE(U256BE.fromBn(0n));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU256BE().bn).toBe(0n);
    });

    it("should round-trip maximum value (2^256 - 1)", () => {
      const max = 2n ** 256n - 1n;
      const writer = new BufWriter();
      writer.writeU256BE(U256BE.fromBn(max));
      const reader = new BufReader(writer.toBuf());
      expect(reader.readU256BE().bn).toBe(max);
    });

    it("should round-trip various values", () => {
      const testValues = [
        0n,
        1n,
        2n ** 64n,
        2n ** 128n,
        2n ** 255n,
        2n ** 256n - 1n,
      ];
      const writer = new BufWriter();
      for (const value of testValues) {
        writer.writeU256BE(U256BE.fromBn(value));
      }
      const reader = new BufReader(writer.toBuf());
      for (const value of testValues) {
        expect(reader.readU256BE().bn).toBe(value);
      }
      expect(reader.eof()).toBe(true);
    });
  });
});

describe("Audit: Boundary conditions", () => {
  describe("reading past end of buffer", () => {
    it("should throw when reading U8 from empty buffer", () => {
      const reader = new BufReader(WebBuf.alloc(0));
      expect(() => reader.readU8()).toThrow();
    });

    it("should throw when reading U16BE from 1-byte buffer", () => {
      const reader = new BufReader(WebBuf.alloc(1));
      expect(() => reader.readU16BE()).toThrow();
    });

    it("should throw when reading U32BE from 3-byte buffer", () => {
      const reader = new BufReader(WebBuf.alloc(3));
      expect(() => reader.readU32BE()).toThrow();
    });

    it("should throw when reading U64BE from 7-byte buffer", () => {
      const reader = new BufReader(WebBuf.alloc(7));
      expect(() => reader.readU64BE()).toThrow();
    });

    it("should throw when reading U128BE from 15-byte buffer", () => {
      const reader = new BufReader(WebBuf.alloc(15));
      expect(() => reader.readU128BE()).toThrow();
    });

    it("should throw when reading U256BE from 31-byte buffer", () => {
      const reader = new BufReader(WebBuf.alloc(31));
      expect(() => reader.readU256BE()).toThrow();
    });

    it("should throw when read() exceeds buffer length", () => {
      const reader = new BufReader(WebBuf.alloc(5));
      expect(() => reader.read(10)).toThrow("not enough bytes");
    });

    it("should throw on second read when buffer exhausted", () => {
      const reader = new BufReader(WebBuf.alloc(4));
      reader.readU32BE(); // Consumes all 4 bytes
      expect(() => reader.readU8()).toThrow();
    });
  });

  describe("eof() behavior", () => {
    it("should return true for empty buffer", () => {
      const reader = new BufReader(WebBuf.alloc(0));
      expect(reader.eof()).toBe(true);
    });

    it("should return false for non-empty buffer at start", () => {
      const reader = new BufReader(WebBuf.alloc(1));
      expect(reader.eof()).toBe(false);
    });

    it("should return true after reading all bytes", () => {
      const reader = new BufReader(WebBuf.alloc(4));
      reader.readU32BE();
      expect(reader.eof()).toBe(true);
    });

    it("should return false with remaining bytes", () => {
      const reader = new BufReader(WebBuf.alloc(5));
      reader.readU32BE();
      expect(reader.eof()).toBe(false);
    });
  });

  describe("position tracking", () => {
    it("should start at position 0", () => {
      const reader = new BufReader(WebBuf.alloc(10));
      expect(reader.pos).toBe(0);
    });

    it("should advance position by 1 after readU8", () => {
      const reader = new BufReader(WebBuf.alloc(10));
      reader.readU8();
      expect(reader.pos).toBe(1);
    });

    it("should advance position by 2 after readU16BE", () => {
      const reader = new BufReader(WebBuf.alloc(10));
      reader.readU16BE();
      expect(reader.pos).toBe(2);
    });

    it("should advance position by 4 after readU32BE", () => {
      const reader = new BufReader(WebBuf.alloc(10));
      reader.readU32BE();
      expect(reader.pos).toBe(4);
    });

    it("should advance position by 8 after readU64BE", () => {
      const reader = new BufReader(WebBuf.alloc(10));
      reader.readU64BE();
      expect(reader.pos).toBe(8);
    });

    it("should advance position by requested length after read()", () => {
      const reader = new BufReader(WebBuf.alloc(10));
      reader.read(7);
      expect(reader.pos).toBe(7);
    });

    it("should track cumulative position across multiple reads", () => {
      const reader = new BufReader(WebBuf.alloc(20));
      reader.readU8();
      expect(reader.pos).toBe(1);
      reader.readU16BE();
      expect(reader.pos).toBe(3);
      reader.readU32BE();
      expect(reader.pos).toBe(7);
      reader.readU64BE();
      expect(reader.pos).toBe(15);
    });
  });
});

describe("Audit: VarInt encoding", () => {
  describe("VarInt write/read round-trip", () => {
    it("should encode single-byte values (0-252)", () => {
      const testValues = [0n, 1n, 127n, 252n];
      for (const value of testValues) {
        const writer = new BufWriter();
        writer.writeVarIntU64BE(U64BE.fromBn(value));
        const buf = writer.toBuf();
        expect(buf.length).toBe(1); // Single byte encoding
        expect(buf[0]).toBe(Number(value));

        const reader = new BufReader(buf);
        expect(reader.readVarIntU64BE().bn).toBe(value);
      }
    });

    it("should encode 3-byte values (253-65535)", () => {
      const testValues = [253n, 254n, 255n, 256n, 0xfffdn, 0xfffen, 0xffffn];
      for (const value of testValues) {
        const writer = new BufWriter();
        writer.writeVarIntU64BE(U64BE.fromBn(value));
        const buf = writer.toBuf();
        expect(buf.length).toBe(3); // 0xFD prefix + 2 bytes
        expect(buf[0]).toBe(0xfd);

        const reader = new BufReader(buf);
        expect(reader.readVarIntU64BE().bn).toBe(value);
      }
    });

    it("should encode 5-byte values (65536-4294967295)", () => {
      const testValues = [0x10000n, 0x12345678n, 0xffffffffn];
      for (const value of testValues) {
        const writer = new BufWriter();
        writer.writeVarIntU64BE(U64BE.fromBn(value));
        const buf = writer.toBuf();
        expect(buf.length).toBe(5); // 0xFE prefix + 4 bytes
        expect(buf[0]).toBe(0xfe);

        const reader = new BufReader(buf);
        expect(reader.readVarIntU64BE().bn).toBe(value);
      }
    });

    it("should encode 9-byte values (4294967296 and above)", () => {
      const testValues = [0x100000000n, 0x123456789abcdef0n, 2n ** 64n - 1n];
      for (const value of testValues) {
        const writer = new BufWriter();
        writer.writeVarIntU64BE(U64BE.fromBn(value));
        const buf = writer.toBuf();
        expect(buf.length).toBe(9); // 0xFF prefix + 8 bytes
        expect(buf[0]).toBe(0xff);

        const reader = new BufReader(buf);
        expect(reader.readVarIntU64BE().bn).toBe(value);
      }
    });
  });

  describe("VarInt minimal encoding enforcement", () => {
    it("should reject non-minimal 3-byte encoding", () => {
      // Value 252 encoded as 0xFD 0x00 0xFC is non-minimal
      const buf = WebBuf.from([0xfd, 0x00, 0xfc]);
      const reader = new BufReader(buf);
      expect(() => reader.readVarIntU64BE()).toThrow("non-minimal");
    });

    it("should reject non-minimal 5-byte encoding", () => {
      // Value 0xFFFF encoded as 0xFE 0x00 0x00 0xFF 0xFF is non-minimal
      const buf = WebBuf.from([0xfe, 0x00, 0x00, 0xff, 0xff]);
      const reader = new BufReader(buf);
      expect(() => reader.readVarIntU64BE()).toThrow("non-minimal");
    });

    it("should reject non-minimal 9-byte encoding", () => {
      // Value 0xFFFFFFFF encoded as 0xFF followed by 8 bytes is non-minimal
      const buf = WebBuf.from([0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]);
      const reader = new BufReader(buf);
      expect(() => reader.readVarIntU64BE()).toThrow("non-minimal");
    });
  });

  describe("VarInt boundary values", () => {
    it("should correctly encode/decode boundary at 252/253", () => {
      // 252 = single byte
      const writer1 = new BufWriter();
      writer1.writeVarIntU64BE(U64BE.fromBn(252n));
      expect(writer1.toBuf().length).toBe(1);

      // 253 = 3 bytes (0xFD prefix)
      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromBn(253n));
      expect(writer2.toBuf().length).toBe(3);
    });

    it("should correctly encode/decode boundary at 65535/65536", () => {
      // 65535 = 3 bytes
      const writer1 = new BufWriter();
      writer1.writeVarIntU64BE(U64BE.fromBn(65535n));
      expect(writer1.toBuf().length).toBe(3);

      // 65536 = 5 bytes (0xFE prefix)
      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromBn(65536n));
      expect(writer2.toBuf().length).toBe(5);
    });

    it("should correctly encode/decode boundary at 4294967295/4294967296", () => {
      // 4294967295 = 5 bytes
      const writer1 = new BufWriter();
      writer1.writeVarIntU64BE(U64BE.fromBn(4294967295n));
      expect(writer1.toBuf().length).toBe(5);

      // 4294967296 = 9 bytes (0xFF prefix)
      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromBn(4294967296n));
      expect(writer2.toBuf().length).toBe(9);
    });
  });
});

describe("Audit: Mixed type serialization", () => {
  it("should correctly serialize and deserialize mixed types", () => {
    const writer = new BufWriter();

    // Write various types
    writer.writeU8(U8.fromN(0x12));
    writer.writeU16BE(U16BE.fromN(0x3456));
    writer.writeU32BE(U32BE.fromN(0x789abcde));
    writer.writeU64BE(U64BE.fromBn(0xf0123456789abcden));
    writer.writeVarIntU64BE(U64BE.fromBn(42n));
    writer.writeVarIntU64BE(U64BE.fromBn(1000n));
    writer.writeU128BE(U128BE.fromBn(0x0123456789abcdef0123456789abcdefn));
    writer.writeU256BE(U256BE.fromBn(2n ** 200n));

    const reader = new BufReader(writer.toBuf());

    // Read back in same order
    expect(reader.readU8().n).toBe(0x12);
    expect(reader.readU16BE().n).toBe(0x3456);
    expect(reader.readU32BE().n).toBe(0x789abcde);
    expect(reader.readU64BE().bn).toBe(0xf0123456789abcden);
    expect(reader.readVarIntU64BE().bn).toBe(42n);
    expect(reader.readVarIntU64BE().bn).toBe(1000n);
    expect(reader.readU128BE().bn).toBe(0x0123456789abcdef0123456789abcdefn);
    expect(reader.readU256BE().bn).toBe(2n ** 200n);

    expect(reader.eof()).toBe(true);
  });

  it("should handle complex message structure", () => {
    // Simulate a message with: version (U32), count (VarInt), items (U64[])
    const writer = new BufWriter();
    const version = 1;
    const items = [100n, 200n, 300n];

    writer.writeU32BE(U32BE.fromN(version));
    writer.writeVarIntU64BE(U64BE.fromBn(BigInt(items.length)));
    for (const item of items) {
      writer.writeU64BE(U64BE.fromBn(item));
    }

    const reader = new BufReader(writer.toBuf());
    expect(reader.readU32BE().n).toBe(version);
    const count = Number(reader.readVarIntU64BE().bn);
    expect(count).toBe(items.length);
    for (let i = 0; i < count; i++) {
      expect(reader.readU64BE().bn).toBe(items[i]);
    }
    expect(reader.eof()).toBe(true);
  });
});

describe("Audit: readFixed and readRemainder", () => {
  describe("readFixed", () => {
    it("should read fixed-size buffer", () => {
      const data = WebBuf.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      const reader = new BufReader(data);

      const fixed = reader.readFixed(4);
      expect(fixed.buf.length).toBe(4);
      expect(fixed.toHex()).toBe("01020304");
      expect(reader.pos).toBe(4);
    });

    it("should throw if not enough bytes", () => {
      const data = WebBuf.from([0x01, 0x02]);
      const reader = new BufReader(data);
      expect(() => reader.readFixed(4)).toThrow();
    });
  });

  describe("readRemainder", () => {
    it("should read all remaining bytes", () => {
      const data = WebBuf.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
      const reader = new BufReader(data);
      reader.readU16BE(); // Read 2 bytes

      const remainder = reader.readRemainder();
      expect(remainder.length).toBe(4);
      expect(remainder.toHex()).toBe("03040506");
      expect(reader.eof()).toBe(true);
    });

    it("should return empty buffer when at end", () => {
      const data = WebBuf.from([0x01, 0x02]);
      const reader = new BufReader(data);
      reader.readU16BE();

      const remainder = reader.readRemainder();
      expect(remainder.length).toBe(0);
    });

    it("should return entire buffer when at start", () => {
      const data = WebBuf.from([0x01, 0x02, 0x03]);
      const reader = new BufReader(data);

      const remainder = reader.readRemainder();
      expect(remainder.length).toBe(3);
      expect(remainder.toHex()).toBe("010203");
    });
  });
});

describe("Audit: BufWriter behavior", () => {
  describe("getLength", () => {
    it("should return 0 for empty writer", () => {
      const writer = new BufWriter();
      expect(writer.getLength()).toBe(0);
    });

    it("should return correct cumulative length", () => {
      const writer = new BufWriter();
      writer.writeU8(U8.fromN(1));
      expect(writer.getLength()).toBe(1);
      writer.writeU16BE(U16BE.fromN(1));
      expect(writer.getLength()).toBe(3);
      writer.writeU32BE(U32BE.fromN(1));
      expect(writer.getLength()).toBe(7);
      writer.writeU64BE(U64BE.fromBn(1n));
      expect(writer.getLength()).toBe(15);
    });
  });

  describe("write raw buffer", () => {
    it("should write raw buffer data", () => {
      const writer = new BufWriter();
      writer.write(WebBuf.from([0xde, 0xad, 0xbe, 0xef]));
      expect(writer.toBuf().toHex()).toBe("deadbeef");
    });

    it("should support chaining", () => {
      const writer = new BufWriter();
      writer
        .writeU8(U8.fromN(1))
        .writeU16BE(U16BE.fromN(2))
        .writeU32BE(U32BE.fromN(3));
      expect(writer.getLength()).toBe(1 + 2 + 4);
    });
  });

  describe("constructor with initial buffers", () => {
    it("should accept initial buffers array", () => {
      const initial = [
        WebBuf.from([0x01, 0x02]),
        WebBuf.from([0x03, 0x04]),
      ];
      const writer = new BufWriter(initial);
      expect(writer.getLength()).toBe(4);
      expect(writer.toBuf().toHex()).toBe("01020304");
    });
  });
});

describe("Audit: Data integrity", () => {
  it("should not modify original buffer on read", () => {
    const original = WebBuf.from([0x01, 0x02, 0x03, 0x04]);
    const originalHex = original.toHex();
    const reader = new BufReader(original);

    reader.readU8();
    reader.readU16BE();

    expect(original.toHex()).toBe(originalHex);
  });

  it("should return independent copies from read()", () => {
    const data = WebBuf.from([0x01, 0x02, 0x03, 0x04]);
    const reader = new BufReader(data);

    const chunk1 = reader.read(2);
    chunk1[0] = 0xff; // Modify the returned chunk

    // Original data should be unchanged
    expect(data[0]).toBe(0x01);

    // Reading again should get original values
    const reader2 = new BufReader(data);
    const chunk2 = reader2.read(2);
    expect(chunk2[0]).toBe(0x01);
  });
});

describe("Audit: Known test vectors", () => {
  describe("Bitcoin-style VarInt (big-endian)", () => {
    // Note: This is big-endian VarInt, not Bitcoin's little-endian
    it("should encode small values as single byte", () => {
      const writer = new BufWriter();
      writer.writeVarIntU64BE(U64BE.fromN(0));
      expect(writer.toBuf().toHex()).toBe("00");

      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromN(252));
      expect(writer2.toBuf().toHex()).toBe("fc");
    });

    it("should encode 0xFD prefix for 253-65535", () => {
      const writer = new BufWriter();
      writer.writeVarIntU64BE(U64BE.fromN(253));
      expect(writer.toBuf().toHex()).toBe("fd00fd");

      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromN(0x1234));
      expect(writer2.toBuf().toHex()).toBe("fd1234");
    });

    it("should encode 0xFE prefix for 65536-4294967295", () => {
      const writer = new BufWriter();
      writer.writeVarIntU64BE(U64BE.fromN(0x10000));
      expect(writer.toBuf().toHex()).toBe("fe00010000");

      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromN(0x12345678));
      expect(writer2.toBuf().toHex()).toBe("fe12345678");
    });

    it("should encode 0xFF prefix for >= 4294967296", () => {
      const writer = new BufWriter();
      writer.writeVarIntU64BE(U64BE.fromBn(0x100000000n));
      expect(writer.toBuf().toHex()).toBe("ff0000000100000000");

      const writer2 = new BufWriter();
      writer2.writeVarIntU64BE(U64BE.fromBn(0x123456789abcdef0n));
      expect(writer2.toBuf().toHex()).toBe("ff123456789abcdef0");
    });
  });
});
