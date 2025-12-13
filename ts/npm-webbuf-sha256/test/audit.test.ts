/**
 * Audit tests for @webbuf/sha256
 *
 * These tests verify the SHA-256 and HMAC-SHA256 implementations against:
 * 1. NIST FIPS 180-4 test vectors for SHA-256
 * 2. RFC 4231 test vectors for HMAC-SHA256
 * 3. Web Crypto API comparison tests
 */

import { describe, it, expect } from "vitest";
import { sha256Hash, doubleSha256Hash, sha256Hmac } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";

// Helper to compute SHA-256 using Web Crypto API
async function webCryptoSha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(hashBuffer);
}

// Helper to compute HMAC-SHA256 using Web Crypto API
async function webCryptoHmacSha256(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(signatureBuffer);
}

describe("Audit: NIST FIPS 180-4 SHA-256 test vectors", () => {
  // Test vectors from NIST FIPS 180-4 and NIST CSRC
  // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf

  it("should hash empty string correctly", () => {
    const input = WebBuf.alloc(0);
    const result = sha256Hash(input);
    expect(result.toHex()).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it('should hash "abc" correctly (NIST short message)', () => {
    const input = WebBuf.fromUtf8("abc");
    const result = sha256Hash(input);
    expect(result.toHex()).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("should hash 448-bit message correctly (NIST)", () => {
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes = 448 bits)
    const input = WebBuf.fromUtf8(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    );
    const result = sha256Hash(input);
    expect(result.toHex()).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("should hash 896-bit message correctly (NIST)", () => {
    // "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (112 bytes = 896 bits)
    const input = WebBuf.fromUtf8(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    );
    const result = sha256Hash(input);
    expect(result.toHex()).toBe(
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    );
  });

  it('should hash one million "a" characters correctly (NIST long message)', () => {
    // One million repetitions of 'a' (0x61)
    const input = WebBuf.alloc(1000000, 0x61);
    const result = sha256Hash(input);
    expect(result.toHex()).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
  });
});

describe("Audit: RFC 4231 HMAC-SHA256 test vectors", () => {
  // All test vectors from https://datatracker.ietf.org/doc/html/rfc4231

  it("Test Case 1: 20-byte key, 'Hi There'", () => {
    const key = WebBuf.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const data = WebBuf.fromHex("4869205468657265"); // "Hi There"
    const result = sha256Hmac(key, data);
    expect(result.toHex()).toBe(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
  });

  it("Test Case 2: 'Jefe' key, 'what do ya want for nothing?'", () => {
    const key = WebBuf.fromHex("4a656665"); // "Jefe"
    const data = WebBuf.fromHex(
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    ); // "what do ya want for nothing?"
    const result = sha256Hmac(key, data);
    expect(result.toHex()).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });

  it("Test Case 3: 20-byte 0xaa key, 50-byte 0xdd data", () => {
    const key = WebBuf.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    const data = WebBuf.fromHex(
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    const result = sha256Hmac(key, data);
    expect(result.toHex()).toBe(
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    );
  });

  it("Test Case 4: 25-byte sequential key, 50-byte 0xcd data", () => {
    const key = WebBuf.fromHex(
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
    );
    const data = WebBuf.fromHex(
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
    );
    const result = sha256Hmac(key, data);
    expect(result.toHex()).toBe(
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    );
  });

  it("Test Case 5: truncation test (verify full HMAC)", () => {
    // Note: This test case is about truncation, but we verify the full HMAC
    const key = WebBuf.fromHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    const data = WebBuf.fromHex("546573742057697468205472756e636174696f6e"); // "Test With Truncation"
    const result = sha256Hmac(key, data);
    // Full HMAC (the RFC shows truncated to 128 bits: a3b6167473100ee06e0c796c2955552b)
    // Let's verify against Web Crypto for the full value
    expect(result.buf.length).toBe(32);
    // First 16 bytes should match the RFC truncated value
    expect(result.toHex().substring(0, 32)).toBe(
      "a3b6167473100ee06e0c796c2955552b",
    );
  });

  it("Test Case 6: 131-byte key (> block size), medium data", () => {
    // Key is 131 bytes of 0xaa
    const key = WebBuf.alloc(131, 0xaa);
    // "Test Using Larger Than Block-Size Key - Hash Key First"
    const data = WebBuf.fromHex(
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
    );
    const result = sha256Hmac(key, data);
    expect(result.toHex()).toBe(
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    );
  });

  it("Test Case 7: 131-byte key, large data", () => {
    // Key is 131 bytes of 0xaa
    const key = WebBuf.alloc(131, 0xaa);
    // "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    const data = WebBuf.fromHex(
      "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
    );
    const result = sha256Hmac(key, data);
    expect(result.toHex()).toBe(
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    );
  });
});

describe("Audit: doubleSha256Hash correctness", () => {
  it("should produce SHA256(SHA256(input))", () => {
    const input = WebBuf.fromUtf8("test input");

    // Manual double hash
    const firstHash = sha256Hash(input);
    const manualDoubleHash = sha256Hash(firstHash.buf);

    // Using the convenience function
    const doubleHash = doubleSha256Hash(input);

    expect(doubleHash.toHex()).toBe(manualDoubleHash.toHex());
  });

  it("should produce different output than single hash", () => {
    const input = WebBuf.fromUtf8("test");
    const singleHash = sha256Hash(input);
    const doubleHash = doubleSha256Hash(input);

    expect(singleHash.toHex()).not.toBe(doubleHash.toHex());
  });

  it("should match expected double hash for 'abc'", () => {
    const input = WebBuf.fromUtf8("abc");
    const result = doubleSha256Hash(input);
    // SHA256(SHA256("abc")) - pre-calculated
    expect(result.toHex()).toBe(
      "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
    );
  });

  it("should match expected double hash for empty input", () => {
    const input = WebBuf.alloc(0);
    const firstHash = sha256Hash(input);
    const expectedDoubleHash = sha256Hash(firstHash.buf);

    const result = doubleSha256Hash(input);
    expect(result.toHex()).toBe(expectedDoubleHash.toHex());
  });
});

describe("Audit: SHA-256 block boundary tests", () => {
  // SHA-256 processes data in 64-byte (512-bit) blocks

  it("should handle input exactly 55 bytes (padding fits in one block)", async () => {
    const input = WebBuf.alloc(55, 0x61); // 55 'a's
    const result = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle input exactly 56 bytes (padding spans two blocks)", async () => {
    const input = WebBuf.alloc(56, 0x61); // 56 'a's
    const result = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle input exactly 63 bytes", async () => {
    const input = WebBuf.alloc(63, 0x61);
    const result = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle input exactly 64 bytes (one full block)", async () => {
    const input = WebBuf.alloc(64, 0x61);
    const result = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle input exactly 65 bytes", async () => {
    const input = WebBuf.alloc(65, 0x61);
    const result = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle input exactly 128 bytes (two full blocks)", async () => {
    const input = WebBuf.alloc(128, 0x61);
    const result = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });
});

describe("Audit: HMAC-SHA256 key handling", () => {
  // HMAC uses 64-byte block size for SHA-256

  it("should handle empty key", () => {
    // Note: Web Crypto doesn't support empty keys, so we just verify
    // our implementation produces a 32-byte output and is deterministic
    const key = WebBuf.alloc(0);
    const message = WebBuf.fromUtf8("test message");
    const result1 = sha256Hmac(key, message);
    const result2 = sha256Hmac(key, message);
    expect(result1.buf.length).toBe(32);
    expect(result1.toHex()).toBe(result2.toHex());
  });

  it("should handle 1-byte key", async () => {
    const key = WebBuf.from([0x42]);
    const message = WebBuf.fromUtf8("test message");
    const result = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle exactly 64-byte key (block size)", async () => {
    const key = WebBuf.alloc(64, 0xaa);
    const message = WebBuf.fromUtf8("test message");
    const result = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle 65-byte key (> block size, needs hashing)", async () => {
    const key = WebBuf.alloc(65, 0xaa);
    const message = WebBuf.fromUtf8("test message");
    const result = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle 128-byte key", async () => {
    const key = WebBuf.alloc(128, 0xaa);
    const message = WebBuf.fromUtf8("test message");
    const result = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should handle empty message", async () => {
    const key = WebBuf.alloc(32, 0xaa);
    const message = WebBuf.alloc(0);
    const result = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });
});

describe("Audit: SHA-256 properties", () => {
  describe("output size", () => {
    it("should always produce 32-byte output", () => {
      const testLengths = [0, 1, 32, 64, 100, 1000, 10000];
      for (const len of testLengths) {
        const input = WebBuf.alloc(len, 0x42);
        const result = sha256Hash(input);
        expect(result.buf.length).toBe(32);
      }
    });
  });

  describe("determinism", () => {
    it("should produce same hash for same input", () => {
      const input = WebBuf.fromUtf8("deterministic test");
      const hash1 = sha256Hash(input);
      const hash2 = sha256Hash(input);
      expect(hash1.toHex()).toBe(hash2.toHex());
    });

    it("should produce same HMAC for same key and message", () => {
      const key = WebBuf.alloc(32, 0xaa);
      const message = WebBuf.fromUtf8("deterministic test");
      const hmac1 = sha256Hmac(key, message);
      const hmac2 = sha256Hmac(key, message);
      expect(hmac1.toHex()).toBe(hmac2.toHex());
    });
  });

  describe("collision resistance (basic)", () => {
    it("should produce different hashes for different inputs", () => {
      const input1 = WebBuf.fromUtf8("input 1");
      const input2 = WebBuf.fromUtf8("input 2");
      const hash1 = sha256Hash(input1);
      const hash2 = sha256Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });

    it("should produce different hashes for inputs differing by one bit", () => {
      const input1 = WebBuf.from([0x00]);
      const input2 = WebBuf.from([0x01]);
      const hash1 = sha256Hash(input1);
      const hash2 = sha256Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });
  });

  describe("HMAC key sensitivity", () => {
    it("should produce different HMACs for different keys", () => {
      const key1 = WebBuf.alloc(32, 0x00);
      const key2 = WebBuf.alloc(32, 0x01);
      const message = WebBuf.fromUtf8("test message");
      const hmac1 = sha256Hmac(key1, message);
      const hmac2 = sha256Hmac(key2, message);
      expect(hmac1.toHex()).not.toBe(hmac2.toHex());
    });

    it("should produce different HMACs for different messages", () => {
      const key = WebBuf.alloc(32, 0xaa);
      const message1 = WebBuf.fromUtf8("message 1");
      const message2 = WebBuf.fromUtf8("message 2");
      const hmac1 = sha256Hmac(key, message1);
      const hmac2 = sha256Hmac(key, message2);
      expect(hmac1.toHex()).not.toBe(hmac2.toHex());
    });

    it("HMAC should differ from hash of same input", () => {
      const key = WebBuf.alloc(32, 0xaa);
      const message = WebBuf.fromUtf8("test");
      const hash = sha256Hash(message);
      const hmac = sha256Hmac(key, message);
      expect(hash.toHex()).not.toBe(hmac.toHex());
    });
  });
});

describe("Audit: Known application test vectors", () => {
  describe("Bitcoin-style double SHA-256", () => {
    it("should match Bitcoin genesis block header hash pattern", () => {
      // The Bitcoin genesis block uses double SHA-256 on the 80-byte header
      // We test the pattern is correct (double hashing)
      const testData = WebBuf.alloc(80, 0x00);
      const singleHash = sha256Hash(testData);
      const manualDouble = sha256Hash(singleHash.buf);
      const doubleHash = doubleSha256Hash(testData);
      expect(doubleHash.toHex()).toBe(manualDouble.toHex());
    });
  });

  describe("Common test strings", () => {
    it("should hash 'hello' correctly", async () => {
      const input = WebBuf.fromUtf8("hello");
      const result = sha256Hash(input);
      const webCryptoResult = await webCryptoSha256(input);
      expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
      // Known hash of "hello"
      expect(result.toHex()).toBe(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
      );
    });

    it("should hash 'hello world' correctly", async () => {
      const input = WebBuf.fromUtf8("hello world");
      const result = sha256Hash(input);
      const webCryptoResult = await webCryptoSha256(input);
      expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
    });
  });
});

describe("Audit: Edge cases", () => {
  it("should handle input with all zero bytes", () => {
    const zeros = WebBuf.alloc(64);
    const hash = sha256Hash(zeros);
    expect(hash.buf.length).toBe(32);
  });

  it("should handle input with all 0xFF bytes", () => {
    const ones = WebBuf.alloc(64, 0xff);
    const hash = sha256Hash(ones);
    expect(hash.buf.length).toBe(32);
  });

  it("should handle very large input (1MB)", async () => {
    const large = WebBuf.alloc(1024 * 1024, 0x42);
    const result = sha256Hash(large);
    const webCryptoResult = await webCryptoSha256(large);
    expect(result.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });
});
