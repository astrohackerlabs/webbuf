/**
 * Audit tests for @webbuf/fixedbuf
 *
 * These tests verify that FixedBuf correctly enforces size constraints
 * and properly wraps WebBuf functionality.
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "../src/fixedbuf.js";

describe("Audit: Size Enforcement", () => {
  describe("constructor size validation", () => {
    it("should accept buffer of exact size", () => {
      const buf = WebBuf.alloc(32);
      const fixed = new FixedBuf(32, buf);
      expect(fixed.buf.length).toBe(32);
    });

    it("should reject buffer smaller than specified size", () => {
      const buf = WebBuf.alloc(16);
      expect(() => new FixedBuf(32, buf)).toThrow("invalid size error");
    });

    it("should reject buffer larger than specified size", () => {
      const buf = WebBuf.alloc(64);
      expect(() => new FixedBuf(32, buf)).toThrow("invalid size error");
    });

    it("should accept zero-size buffer when size is 0", () => {
      const buf = WebBuf.alloc(0);
      const fixed = new FixedBuf(0, buf);
      expect(fixed.buf.length).toBe(0);
    });
  });

  describe("fromBuf size validation", () => {
    it("should accept buffer of exact size", () => {
      const buf = WebBuf.alloc(16);
      const fixed = FixedBuf.fromBuf(16, buf);
      expect(fixed.buf.length).toBe(16);
    });

    it("should reject undersized buffer", () => {
      const buf = WebBuf.alloc(8);
      expect(() => FixedBuf.fromBuf(16, buf)).toThrow();
    });

    it("should reject oversized buffer", () => {
      const buf = WebBuf.alloc(32);
      expect(() => FixedBuf.fromBuf(16, buf)).toThrow();
    });
  });

  describe("fromHex size validation", () => {
    it("should accept hex of exact size", () => {
      const fixed = FixedBuf.fromHex(4, "deadbeef"); // 4 bytes
      expect(fixed.buf.length).toBe(4);
    });

    it("should reject hex that decodes to wrong size", () => {
      expect(() => FixedBuf.fromHex(4, "deadbe")).toThrow(); // 3 bytes
      expect(() => FixedBuf.fromHex(4, "deadbeefca")).toThrow(); // 5 bytes
    });

    it("should accept empty hex for size 0", () => {
      const fixed = FixedBuf.fromHex(0, "");
      expect(fixed.buf.length).toBe(0);
    });
  });

  describe("fromBase64 size validation", () => {
    it("should accept base64 of exact size", () => {
      const fixed = FixedBuf.fromBase64(4, "3q2+7w=="); // 4 bytes
      expect(fixed.buf.length).toBe(4);
    });

    it("should reject base64 that decodes to wrong size", () => {
      expect(() => FixedBuf.fromBase64(4, "3q0=")).toThrow(); // 2 bytes
      expect(() => FixedBuf.fromBase64(4, "3q2+7w==AA==")).toThrow(); // invalid
    });

    it("should accept empty base64 for size 0", () => {
      const fixed = FixedBuf.fromBase64(0, "");
      expect(fixed.buf.length).toBe(0);
    });
  });

  describe("common cryptographic sizes", () => {
    const sizes = [
      { name: "AES-128 key / IV", size: 16 },
      { name: "RIPEMD-160 hash", size: 20 },
      { name: "AES-192 key", size: 24 },
      { name: "AES-256 key / SHA-256 hash / BLAKE3 hash", size: 32 },
      { name: "compressed public key", size: 33 },
      { name: "ECDSA signature", size: 64 },
      { name: "uncompressed public key", size: 65 },
    ];

    for (const { name, size } of sizes) {
      it(`should correctly enforce ${name} size (${String(size)} bytes)`, () => {
        // Exact size should work
        const exact = WebBuf.alloc(size);
        const fixed = FixedBuf.fromBuf(size, exact);
        expect(fixed.buf.length).toBe(size);

        // One byte less should fail
        if (size > 0) {
          const smaller = WebBuf.alloc(size - 1);
          expect(() => FixedBuf.fromBuf(size, smaller)).toThrow();
        }

        // One byte more should fail
        const larger = WebBuf.alloc(size + 1);
        expect(() => FixedBuf.fromBuf(size, larger)).toThrow();
      });
    }
  });
});

describe("Audit: fromRandom", () => {
  describe("produces correct length", () => {
    const sizes = [0, 1, 8, 16, 20, 24, 32, 33, 64, 65, 128, 256];

    for (const size of sizes) {
      it(`should produce exactly ${String(size)} bytes`, () => {
        const fixed = FixedBuf.fromRandom(size);
        expect(fixed.buf.length).toBe(size);
        expect(fixed._size).toBe(size);
      });
    }
  });

  describe("produces random data", () => {
    it("should produce different values on each call", () => {
      const a = FixedBuf.fromRandom(32);
      const b = FixedBuf.fromRandom(32);
      const c = FixedBuf.fromRandom(32);

      // Extremely unlikely to be equal if truly random
      expect(a.toHex()).not.toBe(b.toHex());
      expect(b.toHex()).not.toBe(c.toHex());
      expect(a.toHex()).not.toBe(c.toHex());
    });

    it("should produce non-zero data (statistically)", () => {
      // Generate a large random buffer and check it's not all zeros
      const fixed = FixedBuf.fromRandom(1024);
      let hasNonZero = false;
      for (const byte of fixed.buf) {
        if (byte !== 0) {
          hasNonZero = true;
          break;
        }
      }
      expect(hasNonZero).toBe(true);
    });

    it("should use crypto.getRandomValues (statistical distribution check)", () => {
      // Generate many random bytes and check rough distribution
      const fixed = FixedBuf.fromRandom(10000);
      const counts = new Array(256).fill(0) as number[];

      for (const byte of fixed.buf) {
        counts[byte] = (counts[byte] ?? 0) + 1;
      }

      // Each byte value should appear roughly 10000/256 ≈ 39 times
      // Allow for significant variance (10-100 range)
      for (let i = 0; i < 256; i++) {
        expect(counts[i]).toBeGreaterThan(5); // Very loose lower bound
        expect(counts[i]).toBeLessThan(100); // Very loose upper bound
      }
    });
  });

  describe("type safety", () => {
    it("should preserve generic size type", () => {
      const fixed16 = FixedBuf.fromRandom<16>(16);
      const fixed32 = FixedBuf.fromRandom<32>(32);

      expect(fixed16._size).toBe(16);
      expect(fixed32._size).toBe(32);
    });
  });
});

describe("Audit: alloc", () => {
  describe("size and fill", () => {
    it("should allocate with zeros by default", () => {
      const fixed = FixedBuf.alloc(16);
      expect(fixed.buf.length).toBe(16);
      for (let i = 0; i < 16; i++) {
        expect(fixed.buf[i]).toBe(0);
      }
    });

    it("should allocate with specified fill value", () => {
      const fixed = FixedBuf.alloc(16, 0xff);
      expect(fixed.buf.length).toBe(16);
      for (let i = 0; i < 16; i++) {
        expect(fixed.buf[i]).toBe(0xff);
      }
    });

    it("should handle zero size", () => {
      const fixed = FixedBuf.alloc(0);
      expect(fixed.buf.length).toBe(0);
    });
  });
});

describe("Audit: clone and toReverse", () => {
  describe("clone", () => {
    it("should create independent copy", () => {
      const original = FixedBuf.fromHex(4, "deadbeef");
      const cloned = original.clone();

      expect(cloned.toHex()).toBe("deadbeef");
      expect(cloned._size).toBe(4);

      // Modify original, clone should be unaffected
      original.buf[0] = 0x00;
      expect(cloned.buf[0]).toBe(0xde); // Clone is independent
      expect(original.buf[0]).toBe(0x00); // Original was modified
    });

    it("should preserve size type", () => {
      const original = FixedBuf.fromRandom<32>(32);
      const cloned = original.clone();
      expect(cloned._size).toBe(32);
    });
  });

  describe("toReverse", () => {
    it("should create reversed copy without modifying original", () => {
      const original = FixedBuf.fromHex(4, "01020304");
      const reversed = original.toReverse();

      expect(reversed.toHex()).toBe("04030201");
      expect(original.toHex()).toBe("01020304"); // Original unchanged
    });

    it("should preserve size", () => {
      const original = FixedBuf.fromRandom<32>(32);
      const reversed = original.toReverse();
      expect(reversed._size).toBe(32);
    });

    it("should handle single byte", () => {
      const original = FixedBuf.fromHex(1, "ab");
      const reversed = original.toReverse();
      expect(reversed.toHex()).toBe("ab");
    });

    it("should handle empty buffer", () => {
      const original = FixedBuf.alloc(0);
      const reversed = original.toReverse();
      expect(reversed.buf.length).toBe(0);
    });
  });
});

describe("Audit: Encoding round-trips", () => {
  describe("hex round-trip", () => {
    it("should round-trip through hex encoding", () => {
      const original = FixedBuf.fromRandom(32);
      const hex = original.toHex();
      const restored = FixedBuf.fromHex(32, hex);

      expect(restored.toHex()).toBe(original.toHex());
    });

    it("should handle all byte values", () => {
      // Create buffer with all possible byte values (for first 32)
      const buf = WebBuf.alloc(32);
      for (let i = 0; i < 32; i++) {
        buf[i] = i * 8; // 0, 8, 16, ... 248
      }
      const fixed = FixedBuf.fromBuf(32, buf);

      const hex = fixed.toHex();
      const restored = FixedBuf.fromHex(32, hex);

      for (let i = 0; i < 32; i++) {
        expect(restored.buf[i]).toBe(i * 8);
      }
    });
  });

  describe("base64 round-trip", () => {
    it("should round-trip through base64 encoding", () => {
      const original = FixedBuf.fromRandom(32);
      const base64 = original.toBase64();
      const restored = FixedBuf.fromBase64(32, base64);

      expect(restored.toHex()).toBe(original.toHex());
    });

    it("should handle various sizes", () => {
      const sizes = [1, 2, 3, 4, 5, 6, 15, 16, 17, 32, 33, 64];

      for (const size of sizes) {
        const original = FixedBuf.fromRandom(size);
        const base64 = original.toBase64();
        const restored = FixedBuf.fromBase64(size, base64);

        expect(restored.toHex()).toBe(original.toHex());
      }
    });
  });
});

describe("Audit: buf property access", () => {
  it("should provide access to underlying WebBuf", () => {
    const fixed = FixedBuf.fromHex(4, "deadbeef");
    const buf = fixed.buf;

    expect(buf).toBeInstanceOf(WebBuf);
    expect(buf.length).toBe(4);
    expect(buf.toHex()).toBe("deadbeef");
  });

  it("should allow reading individual bytes", () => {
    const fixed = FixedBuf.fromHex(4, "01020304");

    expect(fixed.buf[0]).toBe(0x01);
    expect(fixed.buf[1]).toBe(0x02);
    expect(fixed.buf[2]).toBe(0x03);
    expect(fixed.buf[3]).toBe(0x04);
  });

  it("should allow modifying underlying buffer", () => {
    const fixed = FixedBuf.fromHex(4, "deadbeef");
    fixed.buf[0] = 0x00;

    expect(fixed.toHex()).toBe("00adbeef");
  });
});
