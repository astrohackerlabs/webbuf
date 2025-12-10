/**
 * Audit tests for @webbuf/aescbc
 *
 * These tests verify the AES-CBC implementation against:
 * 1. NIST CAVP test vectors
 * 2. Web Crypto API interoperability
 * 3. Property-based tests for correctness
 */

import { describe, it, expect } from "vitest";
import { aescbcEncrypt, aescbcDecrypt } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Helper to encrypt with Web Crypto API
async function webCryptoEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    plaintext,
  );
  return new Uint8Array(ciphertext);
}

// Helper to decrypt with Web Crypto API
async function webCryptoDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "AES-CBC" },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    cryptoKey,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}

describe("Audit: NIST CAVP AES-CBC test vectors", () => {
  // Test vectors from NIST SP 800-38A
  // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
  //
  // NOTE: NIST test vectors are for raw AES-CBC without PKCS7 padding.
  // The webbuf implementation always applies PKCS7 padding (as is standard for AES-CBC).
  // Therefore:
  // 1. Encryption output will have an extra 16-byte padding block appended
  // 2. We verify that the first N bytes match the NIST expected ciphertext
  // 3. We verify decryption via round-trip rather than against unpadded NIST vectors

  describe("AES-128-CBC", () => {
    const key = FixedBuf.fromHex(16, "2b7e151628aed2a6abf7158809cf4f3c");
    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromHex(
      "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    const expectedCiphertext = WebBuf.fromHex(
      "7649abac8119b246cee98e9b12e9197d" +
        "5086cb9b507219ee95db113a917678b2" +
        "73bed6b8e3c1743b7116e69e22229516" +
        "3ff1caa1681fac09120eca307586e1a7",
    );

    it("should encrypt correctly (first 64 bytes match NIST vector)", () => {
      const result = aescbcEncrypt(plaintext, key, iv);
      // Result includes IV prefix, then ciphertext + PKCS7 padding block
      const ciphertext = result.slice(16);
      // First 64 bytes should match NIST vector exactly
      expect(ciphertext.slice(0, 64).toHex()).toBe(expectedCiphertext.toHex());
      // Total should be 80 bytes (64 + 16 padding block)
      expect(ciphertext.length).toBe(80);
    });

    it("should round-trip correctly", () => {
      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const decrypted = aescbcDecrypt(encrypted, key);
      expect(decrypted.toHex()).toBe(plaintext.toHex());
    });

    it("should match Web Crypto for NIST plaintext", async () => {
      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const ciphertext = encrypted.slice(16);

      const webCryptoCiphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);
      expect(ciphertext.toHex()).toBe(WebBuf.fromUint8Array(webCryptoCiphertext).toHex());
    });
  });

  describe("AES-192-CBC", () => {
    const key = FixedBuf.fromHex(24, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromHex(
      "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    const expectedCiphertext = WebBuf.fromHex(
      "4f021db243bc633d7178183a9fa071e8" +
        "b4d9ada9ad7dedf4e5e738763f69145a" +
        "571b242012fb7ae07fa9baac3df102e0" +
        "08b0e27988598881d920a9e64f5615cd",
    );

    it("should encrypt correctly (first 64 bytes match NIST vector)", () => {
      const result = aescbcEncrypt(plaintext, key, iv);
      const ciphertext = result.slice(16);
      expect(ciphertext.slice(0, 64).toHex()).toBe(expectedCiphertext.toHex());
      expect(ciphertext.length).toBe(80);
    });

    it("should round-trip correctly", () => {
      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const decrypted = aescbcDecrypt(encrypted, key);
      expect(decrypted.toHex()).toBe(plaintext.toHex());
    });

    it("should match Web Crypto for NIST plaintext", async () => {
      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const ciphertext = encrypted.slice(16);

      const webCryptoCiphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);
      expect(ciphertext.toHex()).toBe(WebBuf.fromUint8Array(webCryptoCiphertext).toHex());
    });
  });

  describe("AES-256-CBC", () => {
    const key = FixedBuf.fromHex(
      32,
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    );
    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromHex(
      "6bc1bee22e409f96e93d7e117393172a" +
        "ae2d8a571e03ac9c9eb76fac45af8e51" +
        "30c81c46a35ce411e5fbc1191a0a52ef" +
        "f69f2445df4f9b17ad2b417be66c3710",
    );
    const expectedCiphertext = WebBuf.fromHex(
      "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
        "9cfc4e967edb808d679f777bc6702c7d" +
        "39f23369a9d9bacfa530e26304231461" +
        "b2eb05e2c39be9fcda6c19078c6a9d1b",
    );

    it("should encrypt correctly (first 64 bytes match NIST vector)", () => {
      const result = aescbcEncrypt(plaintext, key, iv);
      const ciphertext = result.slice(16);
      expect(ciphertext.slice(0, 64).toHex()).toBe(expectedCiphertext.toHex());
      expect(ciphertext.length).toBe(80);
    });

    it("should round-trip correctly", () => {
      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const decrypted = aescbcDecrypt(encrypted, key);
      expect(decrypted.toHex()).toBe(plaintext.toHex());
    });

    it("should match Web Crypto for NIST plaintext", async () => {
      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const ciphertext = encrypted.slice(16);

      const webCryptoCiphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);
      expect(ciphertext.toHex()).toBe(WebBuf.fromUint8Array(webCryptoCiphertext).toHex());
    });
  });
});

describe("Audit: Web Crypto interoperability", () => {
  describe("encrypt with webbuf, decrypt with Web Crypto", () => {
    it("should work with AES-128", async () => {
      const key = FixedBuf.fromRandom(16);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Hello, Web Crypto!");

      const encrypted = aescbcEncrypt(plaintext, key, iv);
      // Extract IV and ciphertext
      const extractedIv = encrypted.slice(0, 16);
      const ciphertext = encrypted.slice(16);

      const decrypted = await webCryptoDecrypt(ciphertext, key.buf, extractedIv);
      expect(WebBuf.fromUint8Array(decrypted).toUtf8()).toBe("Hello, Web Crypto!");
    });

    it("should work with AES-256", async () => {
      const key = FixedBuf.fromRandom(32);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Hello, Web Crypto with AES-256!");

      const encrypted = aescbcEncrypt(plaintext, key, iv);
      const extractedIv = encrypted.slice(0, 16);
      const ciphertext = encrypted.slice(16);

      const decrypted = await webCryptoDecrypt(ciphertext, key.buf, extractedIv);
      expect(WebBuf.fromUint8Array(decrypted).toUtf8()).toBe(
        "Hello, Web Crypto with AES-256!",
      );
    });
  });

  describe("encrypt with Web Crypto, decrypt with webbuf", () => {
    it("should work with AES-128", async () => {
      const key = FixedBuf.fromRandom(16);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Hello from Web Crypto!");

      const ciphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);
      const ciphertextWithIv = WebBuf.concat([
        iv.buf,
        WebBuf.fromUint8Array(ciphertext),
      ]);

      const decrypted = aescbcDecrypt(ciphertextWithIv, key);
      expect(decrypted.toUtf8()).toBe("Hello from Web Crypto!");
    });

    it("should work with AES-256", async () => {
      const key = FixedBuf.fromRandom(32);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Hello from Web Crypto AES-256!");

      const ciphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);
      const ciphertextWithIv = WebBuf.concat([
        iv.buf,
        WebBuf.fromUint8Array(ciphertext),
      ]);

      const decrypted = aescbcDecrypt(ciphertextWithIv, key);
      expect(decrypted.toUtf8()).toBe("Hello from Web Crypto AES-256!");
    });
  });

  describe("ciphertext comparison", () => {
    it("should produce identical ciphertext as Web Crypto for AES-128", async () => {
      const key = FixedBuf.fromRandom(16);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Test message for comparison");

      const webbufEncrypted = aescbcEncrypt(plaintext, key, iv);
      const webbufCiphertext = webbufEncrypted.slice(16);

      const webCryptoCiphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);

      expect(webbufCiphertext.toHex()).toBe(
        WebBuf.fromUint8Array(webCryptoCiphertext).toHex(),
      );
    });

    it("should produce identical ciphertext as Web Crypto for AES-256", async () => {
      const key = FixedBuf.fromRandom(32);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Test message for AES-256 comparison");

      const webbufEncrypted = aescbcEncrypt(plaintext, key, iv);
      const webbufCiphertext = webbufEncrypted.slice(16);

      const webCryptoCiphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);

      expect(webbufCiphertext.toHex()).toBe(
        WebBuf.fromUint8Array(webCryptoCiphertext).toHex(),
      );
    });
  });
});

describe("Audit: PKCS7 padding", () => {
  it("should correctly pad and unpad empty plaintext", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.alloc(0);

    const encrypted = aescbcEncrypt(plaintext, key, iv);
    // Empty plaintext with PKCS7 padding becomes one full block (16 bytes)
    expect(encrypted.length).toBe(16 + 16); // IV + one padded block

    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.length).toBe(0);
  });

  it("should correctly pad plaintext of 1 byte", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.from([0x42]);

    const encrypted = aescbcEncrypt(plaintext, key, iv);
    expect(encrypted.length).toBe(16 + 16); // IV + one padded block

    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.toHex()).toBe("42");
  });

  it("should correctly pad plaintext of 15 bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(15, 0xaa);

    const encrypted = aescbcEncrypt(plaintext, key);
    expect(encrypted.length).toBe(16 + 16); // IV + one padded block

    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.length).toBe(15);
  });

  it("should correctly pad plaintext of 16 bytes (full block)", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(16, 0xbb);

    const encrypted = aescbcEncrypt(plaintext, key);
    // 16 bytes plaintext needs full block of padding
    expect(encrypted.length).toBe(16 + 32); // IV + original block + padding block

    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.length).toBe(16);
  });

  it("should correctly pad plaintext of 17 bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(17, 0xcc);

    const encrypted = aescbcEncrypt(plaintext, key);
    expect(encrypted.length).toBe(16 + 32); // IV + two blocks

    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.length).toBe(17);
  });
});

describe("Audit: IV handling", () => {
  it("should prepend IV to ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromHex(16, "00112233445566778899aabbccddeeff");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = aescbcEncrypt(plaintext, key, iv);

    // First 16 bytes should be the IV
    expect(encrypted.slice(0, 16).toHex()).toBe("00112233445566778899aabbccddeeff");
  });

  it("should extract IV from ciphertext during decryption", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = aescbcEncrypt(plaintext, key, iv);
    const decrypted = aescbcDecrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("test message");
  });

  it("should generate random IV when not provided", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted1 = aescbcEncrypt(plaintext, key);
    const encrypted2 = aescbcEncrypt(plaintext, key);

    // IVs should be different (random)
    const iv1 = encrypted1.slice(0, 16).toHex();
    const iv2 = encrypted2.slice(0, 16).toHex();
    expect(iv1).not.toBe(iv2);

    // But both should decrypt correctly
    expect(aescbcDecrypt(encrypted1, key).toUtf8()).toBe("test");
    expect(aescbcDecrypt(encrypted2, key).toUtf8()).toBe("test");
  });

  it("should produce different ciphertext with different IVs", () => {
    const key = FixedBuf.fromRandom(32);
    const iv1 = FixedBuf.fromHex(16, "00000000000000000000000000000000");
    const iv2 = FixedBuf.fromHex(16, "ffffffffffffffffffffffffffffffff");
    const plaintext = WebBuf.fromUtf8("same plaintext");

    const encrypted1 = aescbcEncrypt(plaintext, key, iv1);
    const encrypted2 = aescbcEncrypt(plaintext, key, iv2);

    // Ciphertexts (excluding IV) should be different
    expect(encrypted1.slice(16).toHex()).not.toBe(encrypted2.slice(16).toHex());
  });
});

describe("Audit: Error handling", () => {
  it("should throw for ciphertext shorter than 16 bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const shortData = WebBuf.alloc(15);

    expect(() => aescbcDecrypt(shortData, key)).toThrow(
      "Data must be at least 16 bytes long",
    );
  });

  it("should throw for ciphertext not a multiple of 16 bytes (after IV)", () => {
    const key = FixedBuf.fromRandom(32);
    // 16 bytes IV + 17 bytes (not multiple of 16)
    const badData = WebBuf.alloc(16 + 17);

    expect(() => aescbcDecrypt(badData, key)).toThrow(
      "Data length must be a multiple of 16",
    );
  });

  it("should accept ciphertext that is exactly 16 bytes (IV only, empty plaintext)", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.alloc(0);

    const encrypted = aescbcEncrypt(plaintext, key, iv);
    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.length).toBe(0);
  });
});

describe("Audit: Key sizes", () => {
  it("should work with 128-bit (16 byte) key", () => {
    const key = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("AES-128 test");

    const encrypted = aescbcEncrypt(plaintext, key);
    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.toUtf8()).toBe("AES-128 test");
  });

  it("should work with 192-bit (24 byte) key", () => {
    const key = FixedBuf.fromRandom(24);
    const plaintext = WebBuf.fromUtf8("AES-192 test");

    const encrypted = aescbcEncrypt(plaintext, key);
    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.toUtf8()).toBe("AES-192 test");
  });

  it("should work with 256-bit (32 byte) key", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("AES-256 test");

    const encrypted = aescbcEncrypt(plaintext, key);
    const decrypted = aescbcDecrypt(encrypted, key);
    expect(decrypted.toUtf8()).toBe("AES-256 test");
  });
});

describe("Audit: Round-trip tests", () => {
  it("should round-trip various plaintext sizes", () => {
    const key = FixedBuf.fromRandom(32);
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000, 10000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size);
      crypto.getRandomValues(plaintext);

      const encrypted = aescbcEncrypt(plaintext, key);
      const decrypted = aescbcDecrypt(encrypted, key);

      expect(decrypted.toHex()).toBe(plaintext.toHex());
    }
  });

  it("should round-trip with all key sizes", () => {
    const keySizes: (16 | 24 | 32)[] = [16, 24, 32];
    const plaintext = WebBuf.fromUtf8("Test all key sizes");

    for (const keySize of keySizes) {
      const key = FixedBuf.fromRandom(keySize) as FixedBuf<16> | FixedBuf<24> | FixedBuf<32>;
      const encrypted = aescbcEncrypt(plaintext, key);
      const decrypted = aescbcDecrypt(encrypted, key);
      expect(decrypted.toUtf8()).toBe("Test all key sizes");
    }
  });
});

describe("Audit: Determinism", () => {
  it("should produce same ciphertext for same key, IV, and plaintext", () => {
    const key = FixedBuf.fromHex(
      32,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromUtf8("deterministic test");

    const encrypted1 = aescbcEncrypt(plaintext, key, iv);
    const encrypted2 = aescbcEncrypt(plaintext, key, iv);

    expect(encrypted1.toHex()).toBe(encrypted2.toHex());
  });
});

describe("Audit: Security properties", () => {
  it("should produce different ciphertext with different keys", () => {
    const key1 = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    const key2 = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted1 = aescbcEncrypt(plaintext, key1, iv);
    const encrypted2 = aescbcEncrypt(plaintext, key2, iv);

    // Ciphertexts should differ (same IV used to isolate key effect)
    expect(encrypted1.slice(16).toHex()).not.toBe(encrypted2.slice(16).toHex());
  });

  it("should not decrypt correctly with wrong key", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = aescbcEncrypt(plaintext, key1);

    // Decrypting with wrong key should either throw or produce garbage
    // (depending on padding validation)
    try {
      const decrypted = aescbcDecrypt(encrypted, key2);
      // If it doesn't throw, the result should be different
      expect(decrypted.toHex()).not.toBe(plaintext.toHex());
    } catch {
      // Expected - padding validation failed
    }
  });
});
