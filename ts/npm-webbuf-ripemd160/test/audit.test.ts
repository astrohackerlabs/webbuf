/**
 * Audit tests for @webbuf/ripemd160
 *
 * These tests verify the RIPEMD-160 implementation against official test vectors
 * from the original RIPEMD-160 specification by Dobbertin, Bosselaers, and Preneel.
 * https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 */

import { describe, it, expect } from "vitest";
import { ripemd160Hash, doubleRipemd160Hash } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import ripemd160Js from "ripemd160-js/ripemd160.js";

// Helper to compute RIPEMD-160 using ripemd160-js library for comparison
async function referenceRipemd160(data: Uint8Array): Promise<Uint8Array> {
  return (await ripemd160Js(data)) as Uint8Array;
}

describe("Audit: Official RIPEMD-160 test vectors", () => {
  // Test vectors from the original RIPEMD-160 specification
  // https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

  it('should hash empty string "" correctly', () => {
    const input = WebBuf.alloc(0);
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("9c1185a5c5e9fc54612808977ee8f548b2258d31");
  });

  it('should hash "a" correctly', () => {
    const input = WebBuf.fromUtf8("a");
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
  });

  it('should hash "abc" correctly', () => {
    const input = WebBuf.fromUtf8("abc");
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  });

  it('should hash "message digest" correctly', () => {
    const input = WebBuf.fromUtf8("message digest");
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("5d0689ef49d2fae572b881b123a85ffa21595f36");
  });

  it('should hash "abcdefghijklmnopqrstuvwxyz" correctly', () => {
    const input = WebBuf.fromUtf8("abcdefghijklmnopqrstuvwxyz");
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
  });

  it('should hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" correctly', () => {
    const input = WebBuf.fromUtf8(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("12a053384a9c0c88e405a06c27dcf49ada62eb2b");
  });

  it('should hash "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" correctly', () => {
    const input = WebBuf.fromUtf8(
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    );
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("b0e20b6e3116640286ed3a87a5713079b21f5189");
  });

  it('should hash 8 repetitions of "1234567890" correctly', () => {
    const input = WebBuf.fromUtf8("1234567890".repeat(8));
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("9b752e45573d4b39f4dbd3323cab82bf63326bfb");
  });

  it('should hash 1 million repetitions of "a" correctly', () => {
    const input = WebBuf.alloc(1000000, 0x61); // 'a' = 0x61
    const result = ripemd160Hash(input);
    expect(result.toHex()).toBe("52783243c1697bdbe16d37f97f68f08325dc1528");
  });
});

describe("Audit: doubleRipemd160Hash correctness", () => {
  it("should produce RIPEMD160(RIPEMD160(input))", () => {
    const input = WebBuf.fromUtf8("test input");

    // Manual double hash
    const firstHash = ripemd160Hash(input);
    const manualDoubleHash = ripemd160Hash(firstHash.buf);

    // Using the convenience function
    const doubleHash = doubleRipemd160Hash(input);

    expect(doubleHash.toHex()).toBe(manualDoubleHash.toHex());
  });

  it("should produce different output than single hash", () => {
    const input = WebBuf.fromUtf8("test");
    const singleHash = ripemd160Hash(input);
    const doubleHash = doubleRipemd160Hash(input);

    expect(singleHash.toHex()).not.toBe(doubleHash.toHex());
  });

  it("should match expected double hash for empty input", () => {
    const input = WebBuf.alloc(0);
    const firstHash = ripemd160Hash(input);
    const expectedDoubleHash = ripemd160Hash(firstHash.buf);

    const result = doubleRipemd160Hash(input);
    expect(result.toHex()).toBe(expectedDoubleHash.toHex());
  });

  it('should match expected double hash for "abc"', () => {
    const input = WebBuf.fromUtf8("abc");
    const firstHash = ripemd160Hash(input);
    const expectedDoubleHash = ripemd160Hash(firstHash.buf);

    const result = doubleRipemd160Hash(input);
    expect(result.toHex()).toBe(expectedDoubleHash.toHex());
  });
});

describe("Audit: Comparison with ripemd160-js library", () => {
  it("should match reference implementation for empty input", async () => {
    const input = WebBuf.alloc(0);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should match reference implementation for single byte", async () => {
    const input = WebBuf.from([0x42]);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should match reference implementation for various sizes", async () => {
    const sizes = [1, 15, 55, 56, 63, 64, 65, 100, 500, 1000];

    for (const size of sizes) {
      const input = WebBuf.alloc(size, 0x42);
      const result = ripemd160Hash(input);
      const reference = await referenceRipemd160(input);
      expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
    }
  });

  it("should match reference implementation for random data", async () => {
    for (let i = 0; i < 10; i++) {
      const size = Math.floor(Math.random() * 1000) + 1;
      const input = WebBuf.alloc(size);
      crypto.getRandomValues(input);

      const result = ripemd160Hash(input);
      const reference = await referenceRipemd160(input);
      expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
    }
  });
});

describe("Audit: RIPEMD-160 properties", () => {
  describe("output size", () => {
    it("should always produce 20-byte output", () => {
      const testLengths = [0, 1, 20, 32, 64, 100, 1000, 10000];
      for (const len of testLengths) {
        const input = WebBuf.alloc(len, 0x42);
        const result = ripemd160Hash(input);
        expect(result.buf.length).toBe(20);
      }
    });

    it("should always produce 20-byte output for double hash", () => {
      const testLengths = [0, 1, 20, 32, 64, 100, 1000];
      for (const len of testLengths) {
        const input = WebBuf.alloc(len, 0x42);
        const result = doubleRipemd160Hash(input);
        expect(result.buf.length).toBe(20);
      }
    });
  });

  describe("determinism", () => {
    it("should produce same hash for same input", () => {
      const input = WebBuf.fromUtf8("deterministic test");
      const hash1 = ripemd160Hash(input);
      const hash2 = ripemd160Hash(input);
      expect(hash1.toHex()).toBe(hash2.toHex());
    });

    it("should produce same double hash for same input", () => {
      const input = WebBuf.fromUtf8("deterministic test");
      const hash1 = doubleRipemd160Hash(input);
      const hash2 = doubleRipemd160Hash(input);
      expect(hash1.toHex()).toBe(hash2.toHex());
    });
  });

  describe("collision resistance (basic)", () => {
    it("should produce different hashes for different inputs", () => {
      const input1 = WebBuf.fromUtf8("input 1");
      const input2 = WebBuf.fromUtf8("input 2");
      const hash1 = ripemd160Hash(input1);
      const hash2 = ripemd160Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });

    it("should produce different hashes for inputs differing by one bit", () => {
      const input1 = WebBuf.from([0x00]);
      const input2 = WebBuf.from([0x01]);
      const hash1 = ripemd160Hash(input1);
      const hash2 = ripemd160Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });

    it("should produce different hashes for inputs differing by length only", () => {
      const input1 = WebBuf.from([0x00]);
      const input2 = WebBuf.from([0x00, 0x00]);
      const hash1 = ripemd160Hash(input1);
      const hash2 = ripemd160Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });
  });
});

describe("Audit: Bitcoin-style usage (HASH160)", () => {
  // Bitcoin's HASH160 is RIPEMD160(SHA256(data))
  // This tests that our RIPEMD-160 works correctly with SHA-256 output

  it("should correctly hash 32-byte input (typical SHA-256 output size)", async () => {
    // Simulate SHA-256 output
    const sha256Output = WebBuf.alloc(32, 0xab);
    const result = ripemd160Hash(sha256Output);
    const reference = await referenceRipemd160(sha256Output);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should correctly hash compressed public key (33 bytes)", async () => {
    // Compressed public key format: 0x02 or 0x03 followed by 32 bytes
    const compressedPubKey = WebBuf.fromHex(
      "03d03a42c710b7cf9085bd3115338f72b86f2d77859b6afe6d33b13ea8957a9722",
    );
    const result = ripemd160Hash(compressedPubKey);
    const reference = await referenceRipemd160(compressedPubKey);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
    // Known hash from existing test
    expect(result.toHex()).toBe("5a95f9ebad92d7d0c145d835af4cecd73afd987e");
  });

  it("should correctly hash uncompressed public key (65 bytes)", async () => {
    // Uncompressed public key format: 0x04 followed by 64 bytes
    const uncompressedPubKey = WebBuf.alloc(65);
    uncompressedPubKey[0] = 0x04;
    for (let i = 1; i < 65; i++) {
      uncompressedPubKey[i] = i;
    }
    const result = ripemd160Hash(uncompressedPubKey);
    const reference = await referenceRipemd160(uncompressedPubKey);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });
});

describe("Audit: Block boundary tests", () => {
  // RIPEMD-160 processes data in 64-byte (512-bit) blocks

  it("should handle input exactly 55 bytes (padding fits in one block)", async () => {
    const input = WebBuf.alloc(55, 0x61);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should handle input exactly 56 bytes (padding spans two blocks)", async () => {
    const input = WebBuf.alloc(56, 0x61);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should handle input exactly 63 bytes", async () => {
    const input = WebBuf.alloc(63, 0x61);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should handle input exactly 64 bytes (one full block)", async () => {
    const input = WebBuf.alloc(64, 0x61);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should handle input exactly 65 bytes", async () => {
    const input = WebBuf.alloc(65, 0x61);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });

  it("should handle input exactly 128 bytes (two full blocks)", async () => {
    const input = WebBuf.alloc(128, 0x61);
    const result = ripemd160Hash(input);
    const reference = await referenceRipemd160(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(reference));
  });
});

describe("Audit: Edge cases", () => {
  it("should handle input with all zero bytes", () => {
    const zeros = WebBuf.alloc(64);
    const hash = ripemd160Hash(zeros);
    expect(hash.buf.length).toBe(20);
  });

  it("should handle input with all 0xFF bytes", () => {
    const ones = WebBuf.alloc(64, 0xff);
    const hash = ripemd160Hash(ones);
    expect(hash.buf.length).toBe(20);
  });

  it("should handle very large input (100KB)", () => {
    // Note: ripemd160-js has a 65KB size limit, so we don't compare against it
    // But we already validated with the official 1 million "a" test vector
    const large = WebBuf.alloc(100 * 1024, 0x42);
    const result = ripemd160Hash(large);
    expect(result.buf.length).toBe(20);
    // Verify determinism
    const result2 = ripemd160Hash(large);
    expect(result.toHex()).toBe(result2.toHex());
  });
});
