/**
 * Audit tests for @webbuf/blake3
 *
 * These tests verify the BLAKE3 implementation against official test vectors
 * from https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
 *
 * The test input is a repeating pattern of bytes 0-250 (251 bytes cycling).
 */

import { describe, it, expect } from "vitest";
import { blake3Hash, doubleBlake3Hash, blake3Mac } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

/**
 * Generate the test input pattern used by official BLAKE3 test vectors.
 * The pattern is a repeating sequence of bytes 0, 1, 2, ..., 250, 0, 1, 2, ...
 */
function generateTestInput(length: number): WebBuf {
  const buf = WebBuf.alloc(length);
  for (let i = 0; i < length; i++) {
    buf[i] = i % 251;
  }
  return buf;
}

/**
 * The key used in official BLAKE3 keyed_hash test vectors.
 * "whats the Elvish word for friend" (32 bytes)
 */
const OFFICIAL_TEST_KEY = WebBuf.fromUtf8("whats the Elvish word for friend");

describe("Audit: Official BLAKE3 test vectors - hash mode", () => {
  // Official test vectors from BLAKE3 repository
  const hashTestVectors: Array<{ inputLen: number; expectedHash: string }> = [
    {
      inputLen: 0,
      expectedHash:
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    },
    {
      inputLen: 1,
      expectedHash:
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    },
    {
      inputLen: 2,
      expectedHash:
        "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
    },
    {
      inputLen: 3,
      expectedHash:
        "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
    },
    {
      inputLen: 4,
      expectedHash:
        "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32",
    },
    {
      inputLen: 5,
      expectedHash:
        "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2",
    },
    {
      inputLen: 6,
      expectedHash:
        "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844",
    },
    {
      inputLen: 7,
      expectedHash:
        "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe",
    },
    {
      inputLen: 8,
      expectedHash:
        "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
    },
    {
      inputLen: 63,
      expectedHash:
        "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
    },
    {
      inputLen: 64,
      expectedHash:
        "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
    },
    {
      inputLen: 65,
      expectedHash:
        "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
    },
    {
      inputLen: 127,
      expectedHash:
        "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
    },
    {
      inputLen: 128,
      expectedHash:
        "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
    },
    {
      inputLen: 129,
      expectedHash:
        "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
    },
    {
      inputLen: 1023,
      expectedHash:
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    },
    {
      inputLen: 1024,
      expectedHash:
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    },
    {
      inputLen: 1025,
      expectedHash:
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    },
  ];

  for (const { inputLen, expectedHash } of hashTestVectors) {
    it(`should match official test vector for ${inputLen} byte input`, () => {
      const input = generateTestInput(inputLen);
      const result = blake3Hash(input);
      expect(result.toHex()).toBe(expectedHash);
    });
  }
});

describe("Audit: Official BLAKE3 test vectors - keyed_hash mode (MAC)", () => {
  // Official test vectors for keyed_hash mode
  const keyedHashTestVectors: Array<{
    inputLen: number;
    expectedHash: string;
  }> = [
    {
      inputLen: 0,
      expectedHash:
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
    },
    {
      inputLen: 1,
      expectedHash:
        "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
    },
    {
      inputLen: 2,
      expectedHash:
        "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
    },
    {
      inputLen: 3,
      expectedHash:
        "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
    },
    {
      inputLen: 4,
      expectedHash:
        "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070",
    },
    {
      inputLen: 5,
      expectedHash:
        "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c8461",
    },
    {
      inputLen: 6,
      expectedHash:
        "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6d",
    },
    {
      inputLen: 7,
      expectedHash:
        "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a",
    },
    {
      inputLen: 8,
      expectedHash:
        "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600",
    },
    {
      inputLen: 63,
      expectedHash:
        "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
    },
    {
      inputLen: 64,
      expectedHash:
        "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
    },
    {
      inputLen: 65,
      expectedHash:
        "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
    },
    {
      inputLen: 127,
      expectedHash:
        "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818",
    },
    {
      inputLen: 128,
      expectedHash:
        "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec",
    },
    {
      inputLen: 129,
      expectedHash:
        "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f",
    },
    {
      inputLen: 1023,
      expectedHash:
        "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
    },
    {
      inputLen: 1024,
      expectedHash:
        "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
    },
    {
      inputLen: 1025,
      expectedHash:
        "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
    },
  ];

  // The official test key is exactly 32 bytes
  const testKey = FixedBuf.fromBuf(32, OFFICIAL_TEST_KEY);

  for (const { inputLen, expectedHash } of keyedHashTestVectors) {
    it(`should match official keyed_hash test vector for ${inputLen} byte input`, () => {
      const input = generateTestInput(inputLen);
      const result = blake3Mac(testKey, input);
      expect(result.toHex()).toBe(expectedHash);
    });
  }
});

describe("Audit: doubleBlake3Hash correctness", () => {
  it("should produce BLAKE3(BLAKE3(input))", () => {
    const input = WebBuf.fromUtf8("test input");

    // Manual double hash
    const firstHash = blake3Hash(input);
    const manualDoubleHash = blake3Hash(firstHash.buf);

    // Using the convenience function
    const doubleHash = doubleBlake3Hash(input);

    expect(doubleHash.toHex()).toBe(manualDoubleHash.toHex());
  });

  it("should produce different output than single hash", () => {
    const input = WebBuf.fromUtf8("test");
    const singleHash = blake3Hash(input);
    const doubleHash = doubleBlake3Hash(input);

    expect(singleHash.toHex()).not.toBe(doubleHash.toHex());
  });

  it("should match expected double hash for empty input", () => {
    const input = WebBuf.alloc(0);
    const firstHash = blake3Hash(input);
    const expectedDoubleHash = blake3Hash(firstHash.buf);

    const result = doubleBlake3Hash(input);
    expect(result.toHex()).toBe(expectedDoubleHash.toHex());
  });
});

describe("Audit: BLAKE3 properties", () => {
  describe("output size", () => {
    it("should always produce 32-byte output for hash", () => {
      const testLengths = [0, 1, 32, 64, 100, 1000, 10000];
      for (const len of testLengths) {
        const input = generateTestInput(len);
        const result = blake3Hash(input);
        expect(result.buf.length).toBe(32);
      }
    });

    it("should always produce 32-byte output for MAC", () => {
      const key = FixedBuf.fromRandom(32);
      const testLengths = [0, 1, 32, 64, 100, 1000, 10000];
      for (const len of testLengths) {
        const input = generateTestInput(len);
        const result = blake3Mac(key, input);
        expect(result.buf.length).toBe(32);
      }
    });
  });

  describe("determinism", () => {
    it("should produce same hash for same input", () => {
      const input = WebBuf.fromUtf8("deterministic test");
      const hash1 = blake3Hash(input);
      const hash2 = blake3Hash(input);
      expect(hash1.toHex()).toBe(hash2.toHex());
    });

    it("should produce same MAC for same key and message", () => {
      const key = FixedBuf.fromRandom(32);
      const message = WebBuf.fromUtf8("deterministic test");
      const mac1 = blake3Mac(key, message);
      const mac2 = blake3Mac(key, message);
      expect(mac1.toHex()).toBe(mac2.toHex());
    });
  });

  describe("collision resistance (basic)", () => {
    it("should produce different hashes for different inputs", () => {
      const input1 = WebBuf.fromUtf8("input 1");
      const input2 = WebBuf.fromUtf8("input 2");
      const hash1 = blake3Hash(input1);
      const hash2 = blake3Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });

    it("should produce different hashes for inputs differing by one bit", () => {
      const input1 = WebBuf.from([0x00]);
      const input2 = WebBuf.from([0x01]);
      const hash1 = blake3Hash(input1);
      const hash2 = blake3Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });

    it("should produce different hashes for inputs differing by length only", () => {
      const input1 = WebBuf.from([0x00]);
      const input2 = WebBuf.from([0x00, 0x00]);
      const hash1 = blake3Hash(input1);
      const hash2 = blake3Hash(input2);
      expect(hash1.toHex()).not.toBe(hash2.toHex());
    });
  });

  describe("MAC key sensitivity", () => {
    it("should produce different MACs for different keys", () => {
      const key1 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000000",
      );
      const key2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const message = WebBuf.fromUtf8("test message");
      const mac1 = blake3Mac(key1, message);
      const mac2 = blake3Mac(key2, message);
      expect(mac1.toHex()).not.toBe(mac2.toHex());
    });

    it("should produce different MACs for different messages with same key", () => {
      const key = FixedBuf.fromRandom(32);
      const message1 = WebBuf.fromUtf8("message 1");
      const message2 = WebBuf.fromUtf8("message 2");
      const mac1 = blake3Mac(key, message1);
      const mac2 = blake3Mac(key, message2);
      expect(mac1.toHex()).not.toBe(mac2.toHex());
    });

    it("MAC should differ from hash of same input", () => {
      const key = FixedBuf.fromRandom(32);
      const message = WebBuf.fromUtf8("test");
      const hash = blake3Hash(message);
      const mac = blake3Mac(key, message);
      expect(hash.toHex()).not.toBe(mac.toHex());
    });
  });
});

describe("Audit: Edge cases", () => {
  it("should handle empty input", () => {
    const empty = WebBuf.alloc(0);
    const hash = blake3Hash(empty);
    expect(hash.buf.length).toBe(32);
    // Official empty hash from test vectors
    expect(hash.toHex()).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
  });

  it("should handle large input (100KB)", () => {
    const large = generateTestInput(100 * 1024);
    const hash = blake3Hash(large);
    expect(hash.buf.length).toBe(32);
  });

  it("should handle input with all zero bytes", () => {
    const zeros = WebBuf.alloc(64);
    const hash = blake3Hash(zeros);
    expect(hash.buf.length).toBe(32);
  });

  it("should handle input with all 0xFF bytes", () => {
    const ones = WebBuf.alloc(64, 0xff);
    const hash = blake3Hash(ones);
    expect(hash.buf.length).toBe(32);
  });
});
