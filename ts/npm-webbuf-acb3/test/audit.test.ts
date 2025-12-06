/**
 * Audit tests for @webbuf/acb3
 *
 * ACB3 = AES-CBC + BLAKE3 MAC (Encrypt-then-MAC)
 * Construction: BLAKE3_MAC (32 bytes) || IV (16 bytes) || ciphertext
 *
 * These tests verify:
 * 1. Correct construction (MAC computed over IV || ciphertext)
 * 2. Tamper detection (any modification causes decryption failure)
 * 3. Cross-verification with audited primitives (@webbuf/aescbc, @webbuf/blake3)
 * 4. Security properties
 */

import { describe, it, expect } from "vitest";
import { acb3Encrypt, acb3Decrypt } from "../src/index.js";
import { aescbcEncrypt, aescbcDecrypt } from "@webbuf/aescbc";
import { blake3Mac } from "@webbuf/blake3";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("Audit: Construction verification", () => {
  it("should produce output with correct structure: MAC || IV || ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acb3Encrypt(plaintext, key, iv);

    // Minimum size: 32 (MAC) + 16 (IV) + 16 (one block ciphertext)
    expect(encrypted.length).toBeGreaterThanOrEqual(64);

    // First 32 bytes should be MAC
    const mac = encrypted.slice(0, 32);
    expect(mac.length).toBe(32);

    // Next 16 bytes should be IV
    const extractedIv = encrypted.slice(32, 48);
    expect(extractedIv.toHex()).toBe(iv.buf.toHex());
  });

  it("should compute MAC over IV || ciphertext (not just ciphertext)", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acb3Encrypt(plaintext, key, iv);

    // Extract components
    const mac = encrypted.slice(0, 32);
    const ivAndCiphertext = encrypted.slice(32);

    // Manually compute MAC over IV || ciphertext
    const expectedMac = blake3Mac(key, ivAndCiphertext);

    expect(mac.toHex()).toBe(expectedMac.buf.toHex());
  });

  it("should match manual construction using audited primitives", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test manual construction");

    // Manual construction using primitives
    const aesOutput = aescbcEncrypt(plaintext, key, iv); // IV || ciphertext
    const manualMac = blake3Mac(key, aesOutput);
    const manualResult = WebBuf.concat([manualMac.buf, aesOutput]);

    // ACB3 construction
    const acb3Result = acb3Encrypt(plaintext, key, iv);

    expect(acb3Result.toHex()).toBe(manualResult.toHex());
  });

  it("should decrypt to original plaintext using manual deconstruction", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test manual deconstruction");

    const encrypted = acb3Encrypt(plaintext, key);

    // Manual deconstruction
    const mac = encrypted.slice(0, 32);
    const ivAndCiphertext = encrypted.slice(32);

    // Verify MAC
    const expectedMac = blake3Mac(key, ivAndCiphertext);
    expect(mac.toHex()).toBe(expectedMac.buf.toHex());

    // Decrypt using raw aescbc
    const decrypted = aescbcDecrypt(ivAndCiphertext, key);
    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });
});

describe("Audit: MAC tampering detection", () => {
  it("should reject when first byte of MAC is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with first byte of MAC
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[0] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });

  it("should reject when last byte of MAC is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with last byte of MAC (byte 31)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[31] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });

  it("should reject when middle byte of MAC is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with middle byte of MAC (byte 16)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[16] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });

  it("should reject when MAC is replaced with all zeros", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Replace MAC with zeros
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    for (let i = 0; i < 32; i++) {
      tampered[i] = 0;
    }

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });
});

describe("Audit: IV tampering detection", () => {
  it("should reject when first byte of IV is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with first byte of IV (byte 32)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[32] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });

  it("should reject when last byte of IV is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with last byte of IV (byte 47)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[47] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });
});

describe("Audit: Ciphertext tampering detection", () => {
  it("should reject when first byte of ciphertext is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with first byte of ciphertext (byte 48)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[48] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });

  it("should reject when last byte of ciphertext is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with last byte of ciphertext
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[encrypted.length - 1] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });

  it("should reject when middle byte of ciphertext is modified", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message with more content for multiple blocks");

    const encrypted = acb3Encrypt(plaintext, key);

    // Tamper with middle byte of ciphertext
    const middleIndex = 48 + Math.floor((encrypted.length - 48) / 2);
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[middleIndex] ^= 0x01;

    expect(() => acb3Decrypt(tampered, key)).toThrow(
      "Message authentication failed",
    );
  });
});

describe("Audit: Length validation", () => {
  it("should reject data shorter than minimum length (64 bytes)", () => {
    const key = FixedBuf.fromRandom(32);

    // 63 bytes - too short
    const shortData = WebBuf.alloc(63);
    expect(() => acb3Decrypt(shortData, key)).toThrow(
      "at least 256+128+128 bits",
    );
  });

  it("should accept data of exactly minimum length (64 bytes)", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(0); // Empty plaintext

    const encrypted = acb3Encrypt(plaintext, key);
    // 32 (MAC) + 16 (IV) + 16 (one padded block) = 64 bytes
    expect(encrypted.length).toBe(64);

    const decrypted = acb3Decrypt(encrypted, key);
    expect(decrypted.length).toBe(0);
  });

  it("should reject truncated ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Truncate by one byte
    const truncated = encrypted.slice(0, encrypted.length - 1);

    expect(() => acb3Decrypt(truncated, key)).toThrow();
  });

  it("should reject ciphertext with appended bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test message");

    const encrypted = acb3Encrypt(plaintext, key);

    // Append extra bytes
    const extended = WebBuf.concat([encrypted, WebBuf.from([0x00])]);

    // Should fail MAC verification since the MAC was computed over original data
    expect(() => acb3Decrypt(extended, key)).toThrow();
  });
});

describe("Audit: Key sensitivity", () => {
  it("should fail decryption with wrong key", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3Encrypt(plaintext, key1);

    expect(() => acb3Decrypt(encrypted, key2)).toThrow(
      "Message authentication failed",
    );
  });

  it("should fail with key differing by one bit", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2Bytes = WebBuf.alloc(32);
    key2Bytes.set(key1.buf);
    key2Bytes[0] ^= 0x01;
    const key2 = FixedBuf.fromBuf(32, key2Bytes);

    const plaintext = WebBuf.fromUtf8("secret message");
    const encrypted = acb3Encrypt(plaintext, key1);

    expect(() => acb3Decrypt(encrypted, key2)).toThrow(
      "Message authentication failed",
    );
  });

  it("should produce different ciphertext with different keys", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("same plaintext");

    const encrypted1 = acb3Encrypt(plaintext, key1, iv);
    const encrypted2 = acb3Encrypt(plaintext, key2, iv);

    expect(encrypted1.toHex()).not.toBe(encrypted2.toHex());
  });
});

describe("Audit: Round-trip tests", () => {
  it("should round-trip empty plaintext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(0);

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.length).toBe(0);
  });

  it("should round-trip single byte", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.from([0x42]);

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe("42");
  });

  it("should round-trip various sizes", () => {
    const key = FixedBuf.fromRandom(32);
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000, 10000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size);
      crypto.getRandomValues(plaintext);

      const encrypted = acb3Encrypt(plaintext, key);
      const decrypted = acb3Decrypt(encrypted, key);

      expect(decrypted.toHex()).toBe(plaintext.toHex());
    }
  });

  it("should round-trip UTF-8 strings", () => {
    const key = FixedBuf.fromRandom(32);
    const testStrings = [
      "Hello, World!",
      "Unicode: \u00e9\u00e8\u00ea \u4e2d\u6587 \u0410\u0411\u0412",
      "Emoji: \ud83d\ude00\ud83d\udc4d\ud83c\udf89",
      "Special: <>&\"'\\/\n\t\r",
    ];

    for (const str of testStrings) {
      const plaintext = WebBuf.fromUtf8(str);
      const encrypted = acb3Encrypt(plaintext, key);
      const decrypted = acb3Decrypt(encrypted, key);
      expect(decrypted.toUtf8()).toBe(str);
    }
  });
});

describe("Audit: IV handling", () => {
  it("should use provided IV", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromHex(16, "00112233445566778899aabbccddeeff");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acb3Encrypt(plaintext, key, iv);

    // IV should be at position 32-48 (after MAC)
    expect(encrypted.slice(32, 48).toHex()).toBe("00112233445566778899aabbccddeeff");
  });

  it("should generate random IV when not provided", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted1 = acb3Encrypt(plaintext, key);
    const encrypted2 = acb3Encrypt(plaintext, key);

    // IVs should be different
    const iv1 = encrypted1.slice(32, 48).toHex();
    const iv2 = encrypted2.slice(32, 48).toHex();
    expect(iv1).not.toBe(iv2);

    // Both should still decrypt correctly
    expect(acb3Decrypt(encrypted1, key).toUtf8()).toBe("test");
    expect(acb3Decrypt(encrypted2, key).toUtf8()).toBe("test");
  });

  it("should produce different ciphertext with different IVs", () => {
    const key = FixedBuf.fromRandom(32);
    const iv1 = FixedBuf.fromHex(16, "00000000000000000000000000000000");
    const iv2 = FixedBuf.fromHex(16, "ffffffffffffffffffffffffffffffff");
    const plaintext = WebBuf.fromUtf8("same message");

    const encrypted1 = acb3Encrypt(plaintext, key, iv1);
    const encrypted2 = acb3Encrypt(plaintext, key, iv2);

    // Entire output should differ (different IV means different ciphertext means different MAC)
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

    const encrypted1 = acb3Encrypt(plaintext, key, iv);
    const encrypted2 = acb3Encrypt(plaintext, key, iv);

    expect(encrypted1.toHex()).toBe(encrypted2.toHex());
  });
});

describe("Audit: Output size verification", () => {
  it("should have correct output size for various plaintext sizes", () => {
    const key = FixedBuf.fromRandom(32);

    // Output = 32 (MAC) + 16 (IV) + ceil((plaintext + 1) / 16) * 16
    // The +1 accounts for PKCS7 padding (at least 1 byte)
    const testCases = [
      { plaintextSize: 0, expectedSize: 32 + 16 + 16 }, // 0 bytes -> 16 bytes padded
      { plaintextSize: 1, expectedSize: 32 + 16 + 16 }, // 1 byte -> 16 bytes padded
      { plaintextSize: 15, expectedSize: 32 + 16 + 16 }, // 15 bytes -> 16 bytes padded
      { plaintextSize: 16, expectedSize: 32 + 16 + 32 }, // 16 bytes -> 32 bytes padded
      { plaintextSize: 17, expectedSize: 32 + 16 + 32 }, // 17 bytes -> 32 bytes padded
      { plaintextSize: 32, expectedSize: 32 + 16 + 48 }, // 32 bytes -> 48 bytes padded
    ];

    for (const { plaintextSize, expectedSize } of testCases) {
      const plaintext = WebBuf.alloc(plaintextSize, 0x42);
      const encrypted = acb3Encrypt(plaintext, key);
      expect(encrypted.length).toBe(expectedSize);
    }
  });
});

describe("Audit: Security properties", () => {
  it("should not reveal plaintext in ciphertext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("AAAAAAAAAAAAAAAA"); // Repeated pattern

    const encrypted = acb3Encrypt(plaintext, key);

    // Plaintext pattern should not appear in ciphertext
    const plaintextHex = plaintext.toHex();
    const ciphertextHex = encrypted.slice(48).toHex(); // Skip MAC and IV
    expect(ciphertextHex).not.toContain(plaintextHex);
  });

  it("should produce completely different output for similar plaintexts", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);

    const plaintext1 = WebBuf.fromUtf8("message1");
    const plaintext2 = WebBuf.fromUtf8("message2");

    const encrypted1 = acb3Encrypt(plaintext1, key, iv);
    const encrypted2 = acb3Encrypt(plaintext2, key, iv);

    // Count differing bytes (should be many due to CBC mode propagation)
    let differentBytes = 0;
    for (let i = 0; i < encrypted1.length; i++) {
      if (encrypted1[i] !== encrypted2[i]) {
        differentBytes++;
      }
    }

    // At least half the bytes should differ (MAC + ciphertext all change)
    expect(differentBytes).toBeGreaterThan(encrypted1.length / 2);
  });

  it("should use Encrypt-then-MAC construction (MAC computed after encryption)", () => {
    // This is verified by the construction tests above, but let's be explicit
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acb3Encrypt(plaintext, key, iv);

    // Extract MAC and the data it should cover
    const mac = encrypted.slice(0, 32);
    const ivAndCiphertext = encrypted.slice(32);

    // In Encrypt-then-MAC, MAC is computed over ciphertext (including IV)
    const expectedMac = blake3Mac(key, ivAndCiphertext);
    expect(mac.toHex()).toBe(expectedMac.buf.toHex());

    // The MAC should NOT match if we compute it over plaintext
    const wrongMac = blake3Mac(key, plaintext);
    expect(mac.toHex()).not.toBe(wrongMac.buf.toHex());
  });
});

describe("Audit: Edge cases", () => {
  it("should handle plaintext with all zeros", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(64);

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle plaintext with all 0xFF bytes", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.alloc(64, 0xff);

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle large plaintext (100KB)", () => {
    const key = FixedBuf.fromRandom(32);
    // Use deterministic pattern instead of random (crypto.getRandomValues has 65KB limit)
    const plaintext = WebBuf.alloc(100 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle key with all zeros", () => {
    const key = FixedBuf.fromBuf(32, WebBuf.alloc(32));
    const plaintext = WebBuf.fromUtf8("test with zero key");

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("test with zero key");
  });

  it("should handle key with all 0xFF bytes", () => {
    const key = FixedBuf.fromBuf(32, WebBuf.alloc(32, 0xff));
    const plaintext = WebBuf.fromUtf8("test with 0xFF key");

    const encrypted = acb3Encrypt(plaintext, key);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("test with 0xFF key");
  });
});
