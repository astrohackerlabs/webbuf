/* eslint-disable @typescript-eslint/no-non-null-assertion */
import { describe, it, expect } from "vitest";
import { acs2Encrypt, acs2Decrypt } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { sha256Hash } from "@webbuf/sha256";

describe("Index", () => {
  it("should exist", () => {
    expect(acs2Encrypt).toBeDefined();
    expect(acs2Decrypt).toBeDefined();
  });
});

describe("Encryption Tests", () => {
  it("should pass sanity check", () => {
    const plaintext = WebBuf.from("hello world");
    const key = sha256Hash(WebBuf.from("123456789012345678"));
    const iv = FixedBuf.fromBuf(
      16,
      sha256Hash(WebBuf.from("1234")).buf.slice(0, 16),
    );
    const encrypted = acs2Encrypt(plaintext, key, iv);
    const decrypted = acs2Decrypt(encrypted, key);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it("should pass 1000 random tests", () => {
    for (let i = 0; i < 1000; i++) {
      const plaintext = WebBuf.from(
        (i + 10 ** 12).toString(36).substring(2, 15),
      );
      const key = sha256Hash(WebBuf.from("12345678901234567"));
      const iv = FixedBuf.fromBuf(
        16,
        sha256Hash(WebBuf.from("1234")).buf.slice(0, 16),
      );
      const encrypted = acs2Encrypt(plaintext, key, iv);
      const decrypted = acs2Decrypt(encrypted, key);
      expect(decrypted.toString()).toBe(plaintext.toString());
    }
  });

  it("should pass a test with 1000+ byte message", () => {
    const plaintext = WebBuf.from("12".repeat(1000));
    const key = sha256Hash(WebBuf.from("1234567890123456"));
    const iv = FixedBuf.fromBuf(
      16,
      sha256Hash(WebBuf.from("1234")).buf.slice(0, 16),
    );
    const encrypted = acs2Encrypt(plaintext, key, iv);
    const decrypted = acs2Decrypt(encrypted, key);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it("should fail to decrypt with wrong key", () => {
    const plaintext = WebBuf.from("hello world");
    const key1 = sha256Hash(WebBuf.from("key1"));
    const key2 = sha256Hash(WebBuf.from("key2"));
    const encrypted = acs2Encrypt(plaintext, key1);
    expect(() => acs2Decrypt(encrypted, key2)).toThrow(
      "Message authentication failed",
    );
  });

  it("should fail to decrypt tampered ciphertext", () => {
    const plaintext = WebBuf.from("hello world");
    const key = sha256Hash(WebBuf.from("testkey"));
    const encrypted = acs2Encrypt(plaintext, key);
    // Tamper with the ciphertext (after the HMAC)
    encrypted[40] = encrypted[40]! ^ 0xff;
    expect(() => acs2Decrypt(encrypted, key)).toThrow(
      "Message authentication failed",
    );
  });
});
