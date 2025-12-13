/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Audit tests for @webbuf/acs2
 *
 * ACS2 = AES-CBC + SHA-256 HMAC (Encrypt-then-MAC)
 * Construction: HMAC_SHA256 (32 bytes) || IV (16 bytes) || ciphertext
 *
 * These tests verify:
 * 1. Correct construction (HMAC computed over IV || ciphertext)
 * 2. Web Crypto interoperability
 * 3. Tamper detection (any modification causes decryption failure)
 * 4. Cross-verification with audited primitives (@webbuf/aescbc, @webbuf/sha256)
 */

import { describe, it, expect } from "vitest";
import { acs2Encrypt, acs2Decrypt } from "../src/index.js";
import { aescbcEncrypt, aescbcDecrypt } from "@webbuf/aescbc";
import { sha256Hmac } from "@webbuf/sha256";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Helper to compute HMAC-SHA256 with Web Crypto
async function webCryptoHmac(
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
  const signature = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(signature);
}

// Helper to verify HMAC-SHA256 with Web Crypto
async function webCryptoHmacVerify(
  key: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "HMAC",
    cryptoKey,
    signature as Uint8Array<ArrayBuffer>,
    data as Uint8Array<ArrayBuffer>,
  );
}

// Helper to encrypt with Web Crypto AES-CBC
async function webCryptoEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "AES-CBC" },
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: iv as Uint8Array<ArrayBuffer> },
    cryptoKey,
    plaintext as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(ciphertext);
}

// Helper to decrypt with Web Crypto AES-CBC
async function webCryptoDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "AES-CBC" },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: iv as Uint8Array<ArrayBuffer> },
    cryptoKey,
    ciphertext as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(plaintext);
}

describe("Audit: Construction verification", () => {
  it("should produce output with correct structure: HMAC || IV || ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acs2Encrypt(plaintext, key, iv);

    // Minimum size: 32 (HMAC) + 16 (IV) + 16 (one block ciphertext)
    expect(encrypted.length).toBeGreaterThanOrEqual(64);

    // First 32 bytes should be HMAC
    const hmac = encrypted.slice(0, 32);
    expect(hmac.length).toBe(32);

    // Next 16 bytes should be IV
    const extractedIv = encrypted.slice(32, 48);
    expect(extractedIv.toHex()).toBe(iv.buf.toHex());
  });

  it("should compute HMAC over IV || ciphertext (not just ciphertext)", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acs2Encrypt(plaintext, key, iv);

    // Extract components
    const hmac = encrypted.slice(0, 32);
    const ivAndCiphertext = encrypted.slice(32);

    // Manually compute HMAC over IV || ciphertext
    const expectedHmac = sha256Hmac(key.buf, ivAndCiphertext);

    expect(hmac.toHex()).toBe(expectedHmac.buf.toHex());
  });

  it("should match manual construction using audited primitives", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test manual construction");

    // Manual construction using primitives
    const aesOutput = aescbcEncrypt(plaintext, key, iv); // IV || ciphertext
    const manualHmac = sha256Hmac(key.buf, aesOutput);
    const manualResult = WebBuf.concat([manualHmac.buf, aesOutput]);

    // ACS2 construction
    const acs2Result = acs2Encrypt(plaintext, key, iv);

    expect(acs2Result.toHex()).toBe(manualResult.toHex());
  });

  it("should decrypt to original plaintext using manual deconstruction", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test manual deconstruction");

    const encrypted = acs2Encrypt(plaintext, key);

    // Manual deconstruction
    const hmac = encrypted.slice(0, 32);
    const ivAndCiphertext = encrypted.slice(32);

    // Verify HMAC
    const expectedHmac = sha256Hmac(key.buf, ivAndCiphertext);
    expect(hmac.toHex()).toBe(expectedHmac.buf.toHex());

    // Decrypt using raw aescbc
    const decrypted = aescbcDecrypt(ivAndCiphertext, key);
    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });
});

describe("Audit: Web Crypto interoperability", () => {
  describe("encrypt with acs2, decrypt with Web Crypto", () => {
    it("should allow Web Crypto to verify HMAC and decrypt", async () => {
      const key = FixedBuf.fromRandom(32);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Hello from ACS2!");

      // Encrypt with acs2
      const encrypted = acs2Encrypt(plaintext, key, iv);

      // Extract components
      const hmac = encrypted.slice(0, 32);
      const ivAndCiphertext = encrypted.slice(32);
      const extractedIv = ivAndCiphertext.slice(0, 16);
      const ciphertext = ivAndCiphertext.slice(16);

      // Verify HMAC with Web Crypto
      const hmacValid = await webCryptoHmacVerify(key.buf, ivAndCiphertext, hmac);
      expect(hmacValid).toBe(true);

      // Decrypt with Web Crypto
      const decrypted = await webCryptoDecrypt(ciphertext, key.buf, extractedIv);
      expect(WebBuf.fromUint8Array(decrypted).toUtf8()).toBe("Hello from ACS2!");
    });
  });

  describe("encrypt with Web Crypto, decrypt with acs2", () => {
    it("should allow acs2 to verify HMAC and decrypt", async () => {
      const key = FixedBuf.fromRandom(32);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Hello from Web Crypto!");

      // Encrypt with Web Crypto
      const ciphertext = await webCryptoEncrypt(plaintext, key.buf, iv.buf);

      // Construct IV || ciphertext
      const ivAndCiphertext = WebBuf.concat([iv.buf, WebBuf.fromUint8Array(ciphertext)]);

      // Compute HMAC with Web Crypto
      const hmac = await webCryptoHmac(key.buf, ivAndCiphertext);

      // Assemble as HMAC || IV || ciphertext
      const assembled = WebBuf.concat([WebBuf.fromUint8Array(hmac), ivAndCiphertext]);

      // Decrypt with acs2
      const decrypted = acs2Decrypt(assembled, key);
      expect(decrypted.toUtf8()).toBe("Hello from Web Crypto!");
    });
  });

  describe("HMAC comparison", () => {
    it("should produce identical HMAC as Web Crypto", async () => {
      const key = FixedBuf.fromRandom(32);
      const iv = FixedBuf.fromRandom(16);
      const plaintext = WebBuf.fromUtf8("Test HMAC comparison");

      const encrypted = acs2Encrypt(plaintext, key, iv);

      // Extract webbuf HMAC
      const webbufHmac = encrypted.slice(0, 32);

      // Extract data that HMAC was computed over
      const ivAndCiphertext = encrypted.slice(32);

      // Compute HMAC with Web Crypto
      const webCryptoHmacResult = await webCryptoHmac(key.buf, ivAndCiphertext);

      expect(webbufHmac.toHex()).toBe(WebBuf.fromUint8Array(webCryptoHmacResult).toHex());
    });
  });
});

describe("Audit: HMAC tampering detection", () => {
  it("should reject when first byte of HMAC is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with first byte of HMAC
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[0]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });

  it("should reject when last byte of HMAC is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with last byte of HMAC (byte 31)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[31]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });

  it("should reject when middle byte of HMAC is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with middle byte of HMAC (byte 16)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[16]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });

  it("should reject when HMAC is replaced with all zeros", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Replace HMAC with zeros
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    for (let i = 0; i < 32; i++) {
      tampered[i] = 0;
    }

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });
});

describe("Audit: IV tampering detection", () => {
  it("should reject when first byte of IV is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with first byte of IV (byte 32)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[32]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });

  it("should reject when last byte of IV is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with last byte of IV (byte 47)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[47]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });
});

describe("Audit: Ciphertext tampering detection", () => {
  it("should reject when first byte of ciphertext is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with first byte of ciphertext (byte 48)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[48]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });

  it("should reject when last byte of ciphertext is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with last byte of ciphertext
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[encrypted.length - 1]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });

  it("should reject when middle byte of ciphertext is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message with more content for multiple blocks");

    const encrypted = acs2Encrypt(plaintext, key);

    // Tamper with middle byte of ciphertext
    const middleIndex = 48 + Math.floor((encrypted.length - 48) / 2);
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[middleIndex]! ^= 0x01;

    expect(() => acs2Decrypt(tampered, key)).toThrow("Message authentication failed");
  });
});

describe("Audit: Length validation", () => {
  it("should reject data shorter than minimum length (64 bytes)", () => {
    const key = FixedBuf.fromRandom(32);

    // 63 bytes - too short
    const shortData = WebBuf.alloc(63);
    expect(() => acs2Decrypt(shortData, key)).toThrow("at least 256+128+128 bits");
  });

  it("should accept data of exactly minimum length (64 bytes)", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(0); // Empty plaintext

    const encrypted = acs2Encrypt(plaintext, key);
    // 32 (HMAC) + 16 (IV) + 16 (one padded block) = 64 bytes
    expect(encrypted.length).toBe(64);

    const decrypted = acs2Decrypt(encrypted, key);
    expect(decrypted.length).toBe(0);
  });

  it("should reject truncated ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Truncate by one byte
    const truncated = encrypted.slice(0, encrypted.length - 1);

    expect(() => acs2Decrypt(truncated, key)).toThrow();
  });

  it("should reject ciphertext with appended bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acs2Encrypt(plaintext, key);

    // Append extra bytes
    const extended = WebBuf.concat([encrypted, WebBuf.from([0x00])]);

    // Should fail HMAC verification since the HMAC was computed over original data
    expect(() => acs2Decrypt(extended, key)).toThrow();
  });
});

describe("Audit: Key sensitivity", () => {
  it("should fail decryption with wrong key", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acs2Encrypt(plaintext, key1);

    expect(() => acs2Decrypt(encrypted, key2)).toThrow("Message authentication failed");
  });

  it("should fail with key differing by one bit", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2Bytes = WebBuf.alloc(32);
    key2Bytes.set(key1.buf);
    key2Bytes[0]! ^= 0x01;
    const key2 = FixedBuf.fromBuf(32, key2Bytes);

    const plaintext = WebBuf.fromUtf8("secret message");
    const encrypted = acs2Encrypt(plaintext, key1);

    expect(() => acs2Decrypt(encrypted, key2)).toThrow("Message authentication failed");
  });

  it("should produce different ciphertext with different keys", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("same plaintext");

    const encrypted1 = acs2Encrypt(plaintext, key1, iv);
    const encrypted2 = acs2Encrypt(plaintext, key2, iv);

    expect(encrypted1.toHex()).not.toBe(encrypted2.toHex());
  });
});

describe("Audit: Round-trip tests", () => {
  it("should round-trip empty plaintext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(0);

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.length).toBe(0);
  });

  it("should round-trip single byte", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.from([0x42]);

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe("42");
  });

  it("should round-trip various sizes", () => {
    const key = FixedBuf.fromRandom(32);
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000, 10000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size);
      // Use deterministic pattern instead of crypto.getRandomValues
      for (let i = 0; i < size; i++) {
        plaintext[i] = i % 256;
      }

      const encrypted = acs2Encrypt(plaintext, key);
      const decrypted = acs2Decrypt(encrypted, key);

      expect(decrypted.toHex()).toBe(plaintext.toHex());
    }
  });

  it("should round-trip UTF-8 strings", () => {
    const key = FixedBuf.fromRandom(32);
    const testStrings = [
      "Hello, World!",
      "Unicode: éèê 中文 АБВ",
      "Emoji: 😀👍🎉",
      "Special: <>&\"'\\/\n\t\r",
    ];

    for (const str of testStrings) {
      const plaintext = WebBuf.fromUtf8(str);
      const encrypted = acs2Encrypt(plaintext, key);
      const decrypted = acs2Decrypt(encrypted, key);
      expect(decrypted.toUtf8()).toBe(str);
    }
  });
});

describe("Audit: IV handling", () => {
  it("should use provided IV", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromHex(16, "00112233445566778899aabbccddeeff");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acs2Encrypt(plaintext, key, iv);

    // IV should be at position 32-48 (after HMAC)
    expect(encrypted.slice(32, 48).toHex()).toBe("00112233445566778899aabbccddeeff");
  });

  it("should generate random IV when not provided", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted1 = acs2Encrypt(plaintext, key);
    const encrypted2 = acs2Encrypt(plaintext, key);

    // IVs should be different
    const iv1 = encrypted1.slice(32, 48).toHex();
    const iv2 = encrypted2.slice(32, 48).toHex();
    expect(iv1).not.toBe(iv2);

    // Both should still decrypt correctly
    expect(acs2Decrypt(encrypted1, key).toUtf8()).toBe("test");
    expect(acs2Decrypt(encrypted2, key).toUtf8()).toBe("test");
  });

  it("should produce different ciphertext with different IVs", () => {
    const key = FixedBuf.fromRandom(32);
    const iv1 = FixedBuf.fromHex(16, "00000000000000000000000000000000");
    const iv2 = FixedBuf.fromHex(16, "ffffffffffffffffffffffffffffffff");
    const plaintext = WebBuf.fromUtf8("same message");

    const encrypted1 = acs2Encrypt(plaintext, key, iv1);
    const encrypted2 = acs2Encrypt(plaintext, key, iv2);

    // Entire output should differ (different IV means different ciphertext means different HMAC)
    expect(encrypted1.toHex()).not.toBe(encrypted2.toHex());
  });
});

describe("Audit: Determinism", () => {
  it("should produce same output for same inputs", () => {
    const key = FixedBuf.fromHex(
      32,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromUtf8("deterministic test");

    const encrypted1 = acs2Encrypt(plaintext, key, iv);
    const encrypted2 = acs2Encrypt(plaintext, key, iv);

    expect(encrypted1.toHex()).toBe(encrypted2.toHex());
  });
});

describe("Audit: Output size verification", () => {
  it("should have correct output size for various plaintext sizes", () => {
    const key = FixedBuf.fromRandom(32);

    // Output = 32 (HMAC) + 16 (IV) + ceil((plaintext + 1) / 16) * 16
    const testCases = [
      { plaintextSize: 0, expectedSize: 32 + 16 + 16 },
      { plaintextSize: 1, expectedSize: 32 + 16 + 16 },
      { plaintextSize: 15, expectedSize: 32 + 16 + 16 },
      { plaintextSize: 16, expectedSize: 32 + 16 + 32 },
      { plaintextSize: 17, expectedSize: 32 + 16 + 32 },
      { plaintextSize: 32, expectedSize: 32 + 16 + 48 },
    ];

    for (const { plaintextSize, expectedSize } of testCases) {
      const plaintext = WebBuf.alloc(plaintextSize, 0x42);
      const encrypted = acs2Encrypt(plaintext, key);
      expect(encrypted.length).toBe(expectedSize);
    }
  });
});

describe("Audit: Security properties", () => {
  it("should not reveal plaintext in ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("AAAAAAAAAAAAAAAA"); // Repeated pattern

    const encrypted = acs2Encrypt(plaintext, key);

    // Plaintext pattern should not appear in ciphertext
    const plaintextHex = plaintext.toHex();
    const ciphertextHex = encrypted.slice(48).toHex(); // Skip HMAC and IV
    expect(ciphertextHex).not.toContain(plaintextHex);
  });

  it("should produce completely different output for similar plaintexts", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);

    const plaintext1 = WebBuf.fromUtf8("message1");
    const plaintext2 = WebBuf.fromUtf8("message2");

    const encrypted1 = acs2Encrypt(plaintext1, key, iv);
    const encrypted2 = acs2Encrypt(plaintext2, key, iv);

    // Count differing bytes (should be many due to CBC mode propagation)
    let differentBytes = 0;
    for (let i = 0; i < encrypted1.length; i++) {
      if (encrypted1[i] !== encrypted2[i]) {
        differentBytes++;
      }
    }

    // At least half the bytes should differ (HMAC + ciphertext all change)
    expect(differentBytes).toBeGreaterThan(encrypted1.length / 2);
  });

  it("should use Encrypt-then-MAC construction (HMAC computed after encryption)", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acs2Encrypt(plaintext, key, iv);

    // Extract HMAC and the data it should cover
    const hmac = encrypted.slice(0, 32);
    const ivAndCiphertext = encrypted.slice(32);

    // In Encrypt-then-MAC, HMAC is computed over ciphertext (including IV)
    const expectedHmac = sha256Hmac(key.buf, ivAndCiphertext);
    expect(hmac.toHex()).toBe(expectedHmac.buf.toHex());

    // The HMAC should NOT match if we compute it over plaintext
    const wrongHmac = sha256Hmac(key.buf, plaintext);
    expect(hmac.toHex()).not.toBe(wrongHmac.buf.toHex());
  });
});

describe("Audit: Edge cases", () => {
  it("should handle plaintext with all zeros", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(64);

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle plaintext with all 0xFF bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(64, 0xff);

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle large plaintext (100KB)", () => {
    const key = FixedBuf.fromRandom(32);
    // Use deterministic pattern
    const plaintext = WebBuf.alloc(100 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle key with all zeros", () => {
    const key = FixedBuf.fromBuf(32, WebBuf.alloc(32));
    const plaintext = WebBuf.fromUtf8("test with zero key");

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("test with zero key");
  });

  it("should handle key with all 0xFF bytes", () => {
    const key = FixedBuf.fromBuf(32, WebBuf.alloc(32, 0xff));
    const plaintext = WebBuf.fromUtf8("test with 0xFF key");

    const encrypted = acs2Encrypt(plaintext, key);
    const decrypted = acs2Decrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("test with 0xFF key");
  });
});
