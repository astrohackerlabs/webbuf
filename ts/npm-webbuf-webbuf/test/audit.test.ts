/**
 * Audit tests for @webbuf/webbuf
 *
 * These tests verify that WebBuf encoding/decoding matches standard implementations.
 * Reference implementations:
 * - Hex: Node.js Buffer (or manual byte-by-byte verification)
 * - Base64: Web standard atob/btoa
 * - UTF-8: Web standard TextEncoder/TextDecoder
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "../src/webbuf.js";

describe("Audit: Hex Encoding", () => {
  describe("comparison with standard implementation", () => {
    it("should match manual hex encoding for all byte values 0x00-0xff", () => {
      // Create buffer with all possible byte values
      const allBytes = new Uint8Array(256);
      for (let i = 0; i < 256; i++) {
        allBytes[i] = i;
      }

      const webBuf = WebBuf.fromUint8Array(allBytes);
      const hex = webBuf.toHex();

      // Verify each byte is correctly encoded
      for (let i = 0; i < 256; i++) {
        const expected = i.toString(16).padStart(2, "0");
        const actual = hex.slice(i * 2, i * 2 + 2);
        expect(actual).toBe(expected);
      }
    });

    it("should correctly decode hex back to original bytes", () => {
      // Build expected hex string manually
      let expectedHex = "";
      for (let i = 0; i < 256; i++) {
        expectedHex += i.toString(16).padStart(2, "0");
      }

      const decoded = WebBuf.fromHex(expectedHex);

      // Verify each byte
      for (let i = 0; i < 256; i++) {
        expect(decoded[i]).toBe(i);
      }
    });

    it("should handle uppercase hex input", () => {
      const uppercase = "DEADBEEF";
      const lowercase = "deadbeef";

      const fromUpper = WebBuf.fromHex(uppercase);
      const fromLower = WebBuf.fromHex(lowercase);

      expect(fromUpper.toHex()).toBe(lowercase);
      expect(fromLower.toHex()).toBe(lowercase);
      expect(fromUpper.equals(fromLower)).toBe(true);
    });

    it("should handle mixed case hex input", () => {
      const mixed = "DeAdBeEf";
      const decoded = WebBuf.fromHex(mixed);
      expect(decoded.toHex()).toBe("deadbeef");
    });
  });

  describe("known test vectors", () => {
    const hexVectors = [
      { bytes: [], hex: "" },
      { bytes: [0], hex: "00" },
      { bytes: [255], hex: "ff" },
      { bytes: [0, 0, 0, 0], hex: "00000000" },
      { bytes: [255, 255, 255, 255], hex: "ffffffff" },
      { bytes: [0xde, 0xad, 0xbe, 0xef], hex: "deadbeef" },
      { bytes: [0xca, 0xfe, 0xba, 0xbe], hex: "cafebabe" },
      { bytes: [1, 2, 3, 4, 5], hex: "0102030405" },
      {
        bytes: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        hex: "00112233445566778899aabbccddeeff",
      },
    ];

    for (const { bytes, hex } of hexVectors) {
      it(`should encode ${JSON.stringify(bytes)} to "${hex}"`, () => {
        const buf = WebBuf.fromArray(bytes);
        expect(buf.toHex()).toBe(hex);
      });

      it(`should decode "${hex}" to ${JSON.stringify(bytes)}`, () => {
        const buf = WebBuf.fromHex(hex);
        expect(Array.from(buf)).toEqual(bytes);
      });
    }
  });

  describe("edge cases", () => {
    it("should handle empty hex string", () => {
      const buf = WebBuf.fromHex("");
      expect(buf.length).toBe(0);
      expect(buf.toHex()).toBe("");
    });

    it("should reject odd-length hex string", () => {
      expect(() => WebBuf.fromHex("abc")).toThrow();
    });

    it("should handle large buffers (1MB)", () => {
      const size = 1024 * 1024; // 1MB
      const buf = WebBuf.alloc(size);
      for (let i = 0; i < size; i++) {
        buf[i] = i % 256;
      }

      const hex = buf.toHex();
      expect(hex.length).toBe(size * 2);

      const decoded = WebBuf.fromHex(hex);
      expect(decoded.length).toBe(size);
      expect(decoded.equals(buf)).toBe(true);
    });
  });

  describe("round-trip verification", () => {
    it("should round-trip random data of various sizes", () => {
      const sizes = [0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 100, 1000, 10000];

      for (const size of sizes) {
        const original = WebBuf.alloc(size);
        crypto.getRandomValues(original);

        const hex = original.toHex();
        const decoded = WebBuf.fromHex(hex);

        expect(decoded.equals(original)).toBe(true);
      }
    });
  });
});

describe("Audit: Base64 Encoding", () => {
  describe("comparison with Web standard atob/btoa", () => {
    it("should match btoa for ASCII strings", () => {
      const testStrings = [
        "",
        "a",
        "ab",
        "abc",
        "abcd",
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
      ];

      for (const str of testStrings) {
        const buf = WebBuf.fromUtf8(str);
        const webBufBase64 = buf.toBase64();
        const standardBase64 = btoa(str);

        expect(webBufBase64).toBe(standardBase64);
      }
    });

    it("should match atob for decoding", () => {
      const testBase64 = [
        "",
        "YQ==",
        "YWI=",
        "YWJj",
        "YWJjZA==",
        "SGVsbG8sIFdvcmxkIQ==",
      ];

      for (const b64 of testBase64) {
        if (b64 === "") {
          const webBufDecoded = WebBuf.fromBase64(b64);
          expect(webBufDecoded.length).toBe(0);
          continue;
        }

        const webBufDecoded = WebBuf.fromBase64(b64);
        const standardDecoded = atob(b64);

        expect(webBufDecoded.toUtf8()).toBe(standardDecoded);
      }
    });

    it("should handle binary data that btoa cannot handle", () => {
      // btoa only works with Latin-1, but WebBuf should handle any bytes
      const binaryData = WebBuf.alloc(256);
      for (let i = 0; i < 256; i++) {
        binaryData[i] = i;
      }

      const base64 = binaryData.toBase64();
      const decoded = WebBuf.fromBase64(base64);

      expect(decoded.equals(binaryData)).toBe(true);
    });
  });

  describe("RFC 4648 test vectors", () => {
    // From RFC 4648 Section 10
    const rfc4648Vectors = [
      { input: "", base64: "" },
      { input: "f", base64: "Zg==" },
      { input: "fo", base64: "Zm8=" },
      { input: "foo", base64: "Zm9v" },
      { input: "foob", base64: "Zm9vYg==" },
      { input: "fooba", base64: "Zm9vYmE=" },
      { input: "foobar", base64: "Zm9vYmFy" },
    ];

    for (const { input, base64 } of rfc4648Vectors) {
      it(`should encode "${input}" to "${base64}" (RFC 4648)`, () => {
        const buf = WebBuf.fromUtf8(input);
        expect(buf.toBase64()).toBe(base64);
      });

      it(`should decode "${base64}" to "${input}" (RFC 4648)`, () => {
        const buf = WebBuf.fromBase64(base64);
        expect(buf.toUtf8()).toBe(input);
      });
    }
  });

  describe("padding cases", () => {
    it("should handle 0 padding (input length divisible by 3)", () => {
      const buf = WebBuf.fromUtf8("abc"); // 3 bytes -> 4 base64 chars, no padding
      expect(buf.toBase64()).toBe("YWJj");
    });

    it("should handle 1 padding char (input length % 3 == 2)", () => {
      const buf = WebBuf.fromUtf8("ab"); // 2 bytes -> 3 base64 chars + 1 padding
      expect(buf.toBase64()).toBe("YWI=");
    });

    it("should handle 2 padding chars (input length % 3 == 1)", () => {
      const buf = WebBuf.fromUtf8("a"); // 1 byte -> 2 base64 chars + 2 padding
      expect(buf.toBase64()).toBe("YQ==");
    });
  });

  describe("edge cases", () => {
    it("should handle empty base64 string", () => {
      const buf = WebBuf.fromBase64("");
      expect(buf.length).toBe(0);
      expect(buf.toBase64()).toBe("");
    });

    it("should handle large buffers (1MB)", () => {
      const size = 1024 * 1024; // 1MB
      const buf = WebBuf.alloc(size);
      for (let i = 0; i < size; i++) {
        buf[i] = i % 256;
      }

      const base64 = buf.toBase64();
      const decoded = WebBuf.fromBase64(base64);

      expect(decoded.length).toBe(size);
      expect(decoded.equals(buf)).toBe(true);
    });

    it("should handle whitespace when stripWhitespace=true", () => {
      const base64WithWhitespace = "  SGVs\nbG8s\tIFdv\rcmxkIQ==  ";
      const decoded = WebBuf.fromBase64(base64WithWhitespace, true);
      expect(decoded.toUtf8()).toBe("Hello, World!");
    });
  });

  describe("round-trip verification", () => {
    it("should round-trip random data of various sizes", () => {
      const sizes = [0, 1, 2, 3, 4, 5, 6, 15, 16, 17, 100, 1000, 10000];

      for (const size of sizes) {
        const original = WebBuf.alloc(size);
        crypto.getRandomValues(original);

        const base64 = original.toBase64();
        const decoded = WebBuf.fromBase64(base64);

        expect(decoded.equals(original)).toBe(true);
      }
    });
  });
});

describe("Audit: UTF-8 Encoding", () => {
  describe("comparison with TextEncoder/TextDecoder", () => {
    it("should match TextEncoder for encoding", () => {
      const encoder = new TextEncoder();

      const testStrings = [
        "",
        "Hello",
        "Hello, World!",
        "αβγδ", // Greek
        "你好世界", // Chinese
        "🎉🚀💻", // Emojis
        "Mixed: Hello 你好 🎉",
        "\u0000\u0001\u0002", // Control characters
        "Line1\nLine2\rLine3\r\n", // Newlines
      ];

      for (const str of testStrings) {
        const webBufEncoded = WebBuf.fromUtf8(str);
        const standardEncoded = encoder.encode(str);

        expect(webBufEncoded.length).toBe(standardEncoded.length);
        for (let i = 0; i < webBufEncoded.length; i++) {
          expect(webBufEncoded[i]).toBe(standardEncoded[i]);
        }
      }
    });

    it("should match TextDecoder for decoding", () => {
      const decoder = new TextDecoder();

      // Test with known UTF-8 byte sequences
      const testCases = [
        { bytes: [], expected: "" },
        { bytes: [0x48, 0x65, 0x6c, 0x6c, 0x6f], expected: "Hello" }, // ASCII
        { bytes: [0xce, 0xb1, 0xce, 0xb2], expected: "αβ" }, // Greek (2-byte UTF-8)
        { bytes: [0xe4, 0xb8, 0xad, 0xe6, 0x96, 0x87], expected: "中文" }, // Chinese (3-byte UTF-8)
        { bytes: [0xf0, 0x9f, 0x8e, 0x89], expected: "🎉" }, // Emoji (4-byte UTF-8)
      ];

      for (const { bytes, expected } of testCases) {
        const buf = WebBuf.fromArray(bytes);
        const webBufDecoded = buf.toUtf8();
        const standardDecoded = decoder.decode(new Uint8Array(bytes));

        expect(webBufDecoded).toBe(standardDecoded);
        expect(webBufDecoded).toBe(expected);
      }
    });
  });

  describe("special characters", () => {
    it("should handle null bytes", () => {
      const str = "a\u0000b";
      const buf = WebBuf.fromUtf8(str);
      expect(buf.toUtf8()).toBe(str);
      expect(buf.length).toBe(3);
    });

    it("should handle all ASCII printable characters", () => {
      let ascii = "";
      for (let i = 32; i < 127; i++) {
        ascii += String.fromCharCode(i);
      }

      const buf = WebBuf.fromUtf8(ascii);
      expect(buf.toUtf8()).toBe(ascii);
      expect(buf.length).toBe(95); // 127 - 32
    });

    it("should handle multi-byte UTF-8 sequences", () => {
      const testCases = [
        { char: "é", bytes: 2 }, // Latin-1 supplement
        { char: "α", bytes: 2 }, // Greek
        { char: "中", bytes: 3 }, // CJK
        { char: "🎉", bytes: 4 }, // Emoji
      ];

      for (const { char, bytes } of testCases) {
        const buf = WebBuf.fromUtf8(char);
        expect(buf.length).toBe(bytes);
        expect(buf.toUtf8()).toBe(char);
      }
    });
  });

  describe("edge cases", () => {
    it("should handle empty string", () => {
      const buf = WebBuf.fromUtf8("");
      expect(buf.length).toBe(0);
      expect(buf.toUtf8()).toBe("");
    });

    it("should handle very long strings", () => {
      const longString = "x".repeat(100000);
      const buf = WebBuf.fromUtf8(longString);
      expect(buf.length).toBe(100000);
      expect(buf.toUtf8()).toBe(longString);
    });

    it("should handle strings with only emoji", () => {
      const emojis = "🎉🚀💻🔥✨";
      const buf = WebBuf.fromUtf8(emojis);
      expect(buf.toUtf8()).toBe(emojis);
    });
  });

  describe("round-trip verification", () => {
    it("should round-trip various Unicode strings", () => {
      const testStrings = [
        "Simple ASCII",
        "Ümläuts änd áccénts",
        "日本語テスト",
        "العربية",
        "עברית",
        "Ελληνικά",
        "한국어",
        "🇺🇸🇬🇧🇫🇷🇩🇪🇯🇵",
        "Mixed: ASCII, 中文, العربية, 🎉",
      ];

      for (const str of testStrings) {
        const buf = WebBuf.fromUtf8(str);
        const decoded = buf.toUtf8();
        expect(decoded).toBe(str);
      }
    });
  });
});

describe("Audit: Additional WebBuf Methods", () => {
  describe("concat", () => {
    it("should concatenate multiple buffers correctly", () => {
      const a = WebBuf.fromHex("0102");
      const b = WebBuf.fromHex("0304");
      const c = WebBuf.fromHex("05");

      const result = WebBuf.concat([a, b, c]);
      expect(result.toHex()).toBe("0102030405");
    });

    it("should handle empty array", () => {
      const result = WebBuf.concat([]);
      expect(result.length).toBe(0);
    });

    it("should handle single buffer", () => {
      const a = WebBuf.fromHex("deadbeef");
      const result = WebBuf.concat([a]);
      expect(result.toHex()).toBe("deadbeef");
    });

    it("should handle empty buffers in array", () => {
      const a = WebBuf.fromHex("");
      const b = WebBuf.fromHex("0102");
      const c = WebBuf.fromHex("");

      const result = WebBuf.concat([a, b, c]);
      expect(result.toHex()).toBe("0102");
    });
  });

  describe("alloc and fill", () => {
    it("should allocate buffer filled with zeros by default", () => {
      const buf = WebBuf.alloc(10);
      expect(buf.length).toBe(10);
      for (let i = 0; i < 10; i++) {
        expect(buf[i]).toBe(0);
      }
    });

    it("should allocate buffer filled with specified value", () => {
      const buf = WebBuf.alloc(10, 0xff);
      expect(buf.length).toBe(10);
      for (let i = 0; i < 10; i++) {
        expect(buf[i]).toBe(0xff);
      }
    });

    it("should fill buffer with specified value", () => {
      const buf = WebBuf.alloc(10);
      buf.fill(0xab);
      for (let i = 0; i < 10; i++) {
        expect(buf[i]).toBe(0xab);
      }
    });

    it("should fill buffer with range", () => {
      const buf = WebBuf.alloc(10, 0x00);
      buf.fill(0xff, 2, 8);
      expect(buf.toHex()).toBe("0000ffffffffffff0000");
    });
  });

  describe("equals and compare", () => {
    it("should correctly compare equal buffers", () => {
      const a = WebBuf.fromHex("deadbeef");
      const b = WebBuf.fromHex("deadbeef");
      expect(a.equals(b)).toBe(true);
      expect(a.compare(b)).toBe(0);
    });

    it("should correctly compare different buffers", () => {
      const a = WebBuf.fromHex("deadbeef");
      const b = WebBuf.fromHex("cafebabe");
      expect(a.equals(b)).toBe(false);
      expect(a.compare(b)).not.toBe(0);
    });

    it("should correctly compare buffers of different lengths", () => {
      const short = WebBuf.fromHex("dead");
      const long = WebBuf.fromHex("deadbeef");
      expect(short.equals(long)).toBe(false);
      expect(short.compare(long)).toBe(-1);
      expect(long.compare(short)).toBe(1);
    });

    it("should correctly compare empty buffers", () => {
      const a = WebBuf.alloc(0);
      const b = WebBuf.alloc(0);
      expect(a.equals(b)).toBe(true);
      expect(a.compare(b)).toBe(0);
    });
  });

  describe("clone and copy", () => {
    it("should create independent clone", () => {
      const original = WebBuf.fromHex("deadbeef");
      const cloned = original.clone();

      expect(cloned.equals(original)).toBe(true);

      // Modify original, clone should be unaffected
      original[0] = 0x00;
      expect(cloned[0]).toBe(0xde);
    });

    it("should copy data correctly", () => {
      const source = WebBuf.fromHex("0102030405");
      const target = WebBuf.alloc(10);

      const copied = source.copy(target, 2);

      expect(copied).toBe(5);
      expect(target.toHex()).toBe("00000102030405000000");
    });

    it("should copy partial data", () => {
      const source = WebBuf.fromHex("0102030405");
      const target = WebBuf.alloc(10);

      const copied = source.copy(target, 0, 1, 4);

      expect(copied).toBe(3);
      expect(target.toHex()).toBe("02030400000000000000");
    });
  });

  describe("reverse", () => {
    it("should reverse buffer in place", () => {
      const buf = WebBuf.fromHex("01020304");
      buf.reverse();
      expect(buf.toHex()).toBe("04030201");
    });

    it("should create reversed copy with toReverse", () => {
      const original = WebBuf.fromHex("01020304");
      const reversed = original.toReverse();

      expect(reversed.toHex()).toBe("04030201");
      expect(original.toHex()).toBe("01020304"); // Original unchanged
    });
  });
});
