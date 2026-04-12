/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Audit tests for @webbuf/aesgcm
 *
 * These tests verify the AES-GCM implementation against:
 * 1. NIST SP 800-38D test vectors
 * 2. Web Crypto API interoperability
 * 3. Authentication tag verification
 * 4. Property-based tests
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { aesgcmEncrypt, aesgcmDecrypt } from "../src/index.js";
import { webcrypto } from "node:crypto";

describe("Audit: NIST test vectors", () => {
  it("AES-128-GCM with zero key and zero plaintext", () => {
    const key = FixedBuf.fromHex(16, "00000000000000000000000000000000");
    const iv = FixedBuf.fromHex(12, "000000000000000000000000");
    const plaintext = WebBuf.fromHex("00000000000000000000000000000000");

    const ciphertext = aesgcmEncrypt(plaintext, key, iv);

    // First 12 bytes = nonce, next 16 = ciphertext, last 16 = tag
    expect(ciphertext.slice(12, 28).toHex()).toBe(
      "0388dace60b6a392f328c2b971b2fe78",
    );

    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toHex()).toBe("00000000000000000000000000000000");
  });

  it("AES-256-GCM with zero key and zero plaintext", () => {
    const key = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    const iv = FixedBuf.fromHex(12, "000000000000000000000000");
    const plaintext = WebBuf.fromHex("00000000000000000000000000000000");

    const ciphertext = aesgcmEncrypt(plaintext, key, iv);

    expect(ciphertext.slice(12, 28).toHex()).toBe(
      "cea7403d4d606b6e074ec5d3baf39d18",
    );

    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toHex()).toBe("00000000000000000000000000000000");
  });
});

describe("Audit: Web Crypto API interoperability", () => {
  it("should decrypt what Web Crypto encrypts (AES-256-GCM)", async () => {
    const keyBytes = new Uint8Array(32);
    webcrypto.getRandomValues(keyBytes);
    const iv = new Uint8Array(12);
    webcrypto.getRandomValues(iv);

    const cryptoKey = await webcrypto.subtle.importKey(
      "raw",
      keyBytes,
      "AES-GCM",
      false,
      ["encrypt"],
    );

    const plaintext = new TextEncoder().encode("Web Crypto interop test");
    const encrypted = await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      plaintext,
    );

    // Web Crypto returns ciphertext + tag concatenated
    // Our format: nonce + ciphertext + tag
    const webCryptoOutput = new Uint8Array(encrypted);
    const ourFormat = WebBuf.concat([
      WebBuf.fromUint8Array(iv),
      WebBuf.fromUint8Array(webCryptoOutput),
    ]);

    const key = FixedBuf.fromBuf(32, WebBuf.fromUint8Array(keyBytes));
    const decrypted = aesgcmDecrypt(ourFormat, key);
    expect(decrypted.toUtf8()).toBe("Web Crypto interop test");
  });

  it("Web Crypto should decrypt what we encrypt (AES-256-GCM)", async () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("webbuf to Web Crypto");

    const ciphertext = aesgcmEncrypt(plaintext, key);

    // Extract nonce (first 12 bytes) and encrypted data (rest)
    const nonce = ciphertext.slice(0, 12);
    const encryptedData = ciphertext.slice(12);

    const cryptoKey = await webcrypto.subtle.importKey(
      "raw",
      key.buf,
      "AES-GCM",
      false,
      ["decrypt"],
    );

    const decrypted = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      cryptoKey,
      encryptedData,
    );

    expect(new TextDecoder().decode(decrypted)).toBe("webbuf to Web Crypto");
  });
});

describe("Audit: Nonce handling", () => {
  it("should prepend 12-byte nonce to ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromHex(12, "000102030405060708090a0b");
    const plaintext = WebBuf.fromUtf8("test");

    const ciphertext = aesgcmEncrypt(plaintext, key, iv);

    expect(ciphertext.slice(0, 12).toHex()).toBe("000102030405060708090a0b");
  });

  it("should generate different random nonces", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test");

    const ct1 = aesgcmEncrypt(plaintext, key);
    const ct2 = aesgcmEncrypt(plaintext, key);

    expect(ct1.slice(0, 12).toHex()).not.toBe(ct2.slice(0, 12).toHex());

    // Both should decrypt correctly
    expect(aesgcmDecrypt(ct1, key).toUtf8()).toBe("test");
    expect(aesgcmDecrypt(ct2, key).toUtf8()).toBe("test");
  });

  it("different nonces produce different ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("same message");
    const iv1 = FixedBuf.fromRandom(12);
    const iv2 = FixedBuf.fromRandom(12);

    const ct1 = aesgcmEncrypt(plaintext, key, iv1);
    const ct2 = aesgcmEncrypt(plaintext, key, iv2);

    // Ciphertext portion (after nonce) should differ
    expect(ct1.slice(12).toHex()).not.toBe(ct2.slice(12).toHex());
  });
});

describe("Audit: Authentication tag verification", () => {
  it("should reject tampered ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");
    const ciphertext = aesgcmEncrypt(plaintext, key);

    // Tamper with ciphertext body (byte after nonce)
    const tampered = WebBuf.alloc(ciphertext.length);
    tampered.set(ciphertext);
    tampered[12]! ^= 0x01;

    expect(() => aesgcmDecrypt(tampered, key)).toThrow();
  });

  it("should reject tampered auth tag", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");
    const ciphertext = aesgcmEncrypt(plaintext, key);

    // Tamper with last byte (auth tag)
    const tampered = WebBuf.alloc(ciphertext.length);
    tampered.set(ciphertext);
    tampered[tampered.length - 1]! ^= 0x01;

    expect(() => aesgcmDecrypt(tampered, key)).toThrow();
  });

  it("should reject tampered nonce", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");
    const ciphertext = aesgcmEncrypt(plaintext, key);

    // Tamper with nonce (first byte)
    const tampered = WebBuf.alloc(ciphertext.length);
    tampered.set(ciphertext);
    tampered[0]! ^= 0x01;

    expect(() => aesgcmDecrypt(tampered, key)).toThrow();
  });

  it("should reject wrong key", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret");
    const ciphertext = aesgcmEncrypt(plaintext, key1);

    expect(() => aesgcmDecrypt(ciphertext, key2)).toThrow();
  });
});

describe("Audit: Round-trip tests", () => {
  it("should round-trip empty plaintext", () => {
    const key = FixedBuf.fromRandom(32);
    const ciphertext = aesgcmEncrypt(WebBuf.alloc(0), key);
    // 12 nonce + 0 ciphertext + 16 tag = 28 bytes
    expect(ciphertext.length).toBe(28);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.length).toBe(0);
  });

  it("should round-trip single byte", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.from([0x42]);
    const ciphertext = aesgcmEncrypt(plaintext, key);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toHex()).toBe("42");
  });

  it("should round-trip various sizes", () => {
    const key = FixedBuf.fromRandom(32);
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size, 0x42);
      const ciphertext = aesgcmEncrypt(plaintext, key);
      // 12 nonce + size ciphertext + 16 tag
      expect(ciphertext.length).toBe(12 + size + 16);
      const decrypted = aesgcmDecrypt(ciphertext, key);
      expect(decrypted.toHex()).toBe(plaintext.toHex());
    }
  });

  it("should round-trip UTF-8 strings", () => {
    const key = FixedBuf.fromRandom(32);
    const testStrings = [
      "Hello, World!",
      "Unicode: \u00e9\u00e8\u00ea \u4e2d\u6587 \u0410\u0411\u0412",
      "Special: <>&\"'\\/\n\t\r",
    ];

    for (const str of testStrings) {
      const plaintext = WebBuf.fromUtf8(str);
      const ciphertext = aesgcmEncrypt(plaintext, key);
      const decrypted = aesgcmDecrypt(ciphertext, key);
      expect(decrypted.toUtf8()).toBe(str);
    }
  });
});

describe("Audit: Key sizes", () => {
  it("should work with AES-128 (16-byte key)", () => {
    const key = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("AES-128 test");
    const ciphertext = aesgcmEncrypt(plaintext, key);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toUtf8()).toBe("AES-128 test");
  });

  it("should work with AES-256 (32-byte key)", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("AES-256 test");
    const ciphertext = aesgcmEncrypt(plaintext, key);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toUtf8()).toBe("AES-256 test");
  });
});

describe("Audit: Output format", () => {
  it("output should be nonce + ciphertext + tag", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(10, 0x41);
    const ciphertext = aesgcmEncrypt(plaintext, key);

    // 12 nonce + 10 ciphertext + 16 tag = 38 bytes
    expect(ciphertext.length).toBe(38);
  });

  it("should reject ciphertext shorter than 28 bytes", () => {
    const key = FixedBuf.fromRandom(32);
    expect(() => aesgcmDecrypt(WebBuf.alloc(27), key)).toThrow();
  });
});

describe("Audit: Determinism", () => {
  it("same inputs including nonce produce identical output", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(12);
    const plaintext = WebBuf.fromUtf8("deterministic test");

    const ct1 = aesgcmEncrypt(plaintext, key, iv);
    const ct2 = aesgcmEncrypt(plaintext, key, iv);
    expect(ct1.toHex()).toBe(ct2.toHex());
  });

  it("different keys produce different output", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(12);
    const plaintext = WebBuf.fromUtf8("same message");

    const ct1 = aesgcmEncrypt(plaintext, key1, iv);
    const ct2 = aesgcmEncrypt(plaintext, key2, iv);
    expect(ct1.toHex()).not.toBe(ct2.toHex());
  });
});

describe("Audit: Large plaintext", () => {
  it("should handle 50KB plaintext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(50 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }

    const ciphertext = aesgcmEncrypt(plaintext, key);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });
});
