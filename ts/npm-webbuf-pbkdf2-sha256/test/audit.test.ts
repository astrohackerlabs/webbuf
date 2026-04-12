/**
 * Audit tests for @webbuf/pbkdf2-sha256
 *
 * These tests verify the PBKDF2-HMAC-SHA256 implementation against:
 * 1. Known test vectors from cryptographic standards
 * 2. Property-based tests for correctness
 * 3. Edge cases
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { pbkdf2Sha256 } from "../src/index.js";

describe("Audit: Known test vectors", () => {
  // Test vectors from RFC 7914 and various PBKDF2-HMAC-SHA256 references
  // https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

  it("password='password', salt='salt', iterations=1, keylen=32", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      1,
      32,
    );
    expect(result.toHex()).toBe(
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    );
  });

  it("password='password', salt='salt', iterations=2, keylen=32", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      2,
      32,
    );
    expect(result.toHex()).toBe(
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
    );
  });

  it("password='password', salt='salt', iterations=4096, keylen=32", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      4096,
      32,
    );
    expect(result.toHex()).toBe(
      "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
    );
  });

  it("long password and salt, iterations=4096, keylen=40", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("passwordPASSWORDpassword"),
      WebBuf.fromUtf8("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
      4096,
      40,
    );
    expect(result.toHex()).toBe(
      "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
    );
  });

  it("password with null byte, salt with null byte", () => {
    const password = WebBuf.from([
      0x70, 0x61, 0x73, 0x73, 0x00, 0x77, 0x6f, 0x72, 0x64,
    ]); // "pass\0word"
    const salt = WebBuf.from([0x73, 0x61, 0x00, 0x6c, 0x74]); // "sa\0lt"
    const result = pbkdf2Sha256(password, salt, 4096, 16);
    expect(result.toHex()).toBe("89b69d0516f829893c696226650a8687");
  });
});

describe("Audit: Determinism", () => {
  it("should produce identical output for identical inputs", () => {
    const password = WebBuf.fromUtf8("test-password");
    const salt = WebBuf.fromUtf8("test-salt");
    const result1 = pbkdf2Sha256(password, salt, 1000, 32);
    const result2 = pbkdf2Sha256(password, salt, 1000, 32);
    expect(result1.toHex()).toBe(result2.toHex());
  });
});

describe("Audit: Sensitivity to inputs", () => {
  it("different passwords produce different keys", () => {
    const salt = WebBuf.fromUtf8("salt");
    const result1 = pbkdf2Sha256(WebBuf.fromUtf8("password1"), salt, 1, 32);
    const result2 = pbkdf2Sha256(WebBuf.fromUtf8("password2"), salt, 1, 32);
    expect(result1.toHex()).not.toBe(result2.toHex());
  });

  it("different salts produce different keys", () => {
    const password = WebBuf.fromUtf8("password");
    const result1 = pbkdf2Sha256(password, WebBuf.fromUtf8("salt1"), 1, 32);
    const result2 = pbkdf2Sha256(password, WebBuf.fromUtf8("salt2"), 1, 32);
    expect(result1.toHex()).not.toBe(result2.toHex());
  });

  it("different iteration counts produce different keys", () => {
    const password = WebBuf.fromUtf8("password");
    const salt = WebBuf.fromUtf8("salt");
    const result1 = pbkdf2Sha256(password, salt, 1, 32);
    const result2 = pbkdf2Sha256(password, salt, 2, 32);
    expect(result1.toHex()).not.toBe(result2.toHex());
  });

  it("different key lengths produce different length outputs", () => {
    const password = WebBuf.fromUtf8("password");
    const salt = WebBuf.fromUtf8("salt");
    const result16 = pbkdf2Sha256(password, salt, 1, 16);
    const result32 = pbkdf2Sha256(password, salt, 1, 32);
    expect(result16.buf.length).toBe(16);
    expect(result32.buf.length).toBe(32);
    // The 16-byte result should be a prefix of the 32-byte result
    // (PBKDF2 property: shorter keys are prefixes of longer keys within the same block)
    expect(result32.toHex().startsWith(result16.toHex())).toBe(true);
  });
});

describe("Audit: Output length", () => {
  it("should return correct length for various key sizes", () => {
    const password = WebBuf.fromUtf8("password");
    const salt = WebBuf.fromUtf8("salt");

    for (const keyLen of [1, 16, 20, 32, 48, 64, 128]) {
      const result = pbkdf2Sha256(password, salt, 1, keyLen);
      expect(result.buf.length).toBe(keyLen);
    }
  });
});

describe("Audit: Edge cases", () => {
  it("should handle empty password", () => {
    const result = pbkdf2Sha256(WebBuf.alloc(0), WebBuf.fromUtf8("salt"), 1, 32);
    expect(result.buf.length).toBe(32);
  });

  it("should handle empty salt", () => {
    const result = pbkdf2Sha256(WebBuf.fromUtf8("password"), WebBuf.alloc(0), 1, 32);
    expect(result.buf.length).toBe(32);
  });

  it("should handle single iteration", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      1,
      32,
    );
    expect(result.buf.length).toBe(32);
  });

  it("should handle key length of 1", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      1,
      1,
    );
    expect(result.buf.length).toBe(1);
  });

  it("should handle max key length (128)", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      1,
      128,
    );
    expect(result.buf.length).toBe(128);
  });

  it("should reject zero iterations", () => {
    expect(() =>
      pbkdf2Sha256(WebBuf.fromUtf8("password"), WebBuf.fromUtf8("salt"), 0, 32),
    ).toThrow();
  });

  it("should reject zero key length", () => {
    expect(() =>
      pbkdf2Sha256(WebBuf.fromUtf8("password"), WebBuf.fromUtf8("salt"), 1, 0),
    ).toThrow();
  });

  it("should reject key length > 128", () => {
    expect(() =>
      pbkdf2Sha256(WebBuf.fromUtf8("password"), WebBuf.fromUtf8("salt"), 1, 129),
    ).toThrow();
  });

  it("should handle long password", () => {
    const longPassword = WebBuf.alloc(1000, 0x41); // 1000 'A's
    const result = pbkdf2Sha256(longPassword, WebBuf.fromUtf8("salt"), 1, 32);
    expect(result.buf.length).toBe(32);
  });

  it("should handle long salt", () => {
    const longSalt = WebBuf.alloc(1000, 0x42); // 1000 'B's
    const result = pbkdf2Sha256(WebBuf.fromUtf8("password"), longSalt, 1, 32);
    expect(result.buf.length).toBe(32);
  });
});

describe("Audit: Higher iteration counts", () => {
  it("should work with 10000 iterations", () => {
    const result = pbkdf2Sha256(
      WebBuf.fromUtf8("password"),
      WebBuf.fromUtf8("salt"),
      10000,
      32,
    );
    expect(result.buf.length).toBe(32);
    // Should not be all zeros
    expect(result.toHex()).not.toBe("0".repeat(64));
  });
});
