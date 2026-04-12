import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { aesgcmEncrypt, aesgcmDecrypt } from "../src/index.js";

describe("aesgcm", () => {
  it("should encrypt and decrypt with AES-128", () => {
    const key = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("hello world");
    const ciphertext = aesgcmEncrypt(plaintext, key);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toUtf8()).toBe("hello world");
  });

  it("should encrypt and decrypt with AES-256", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("hello world");
    const ciphertext = aesgcmEncrypt(plaintext, key);
    const decrypted = aesgcmDecrypt(ciphertext, key);
    expect(decrypted.toUtf8()).toBe("hello world");
  });

  it("should reject invalid ciphertext with wrong key", () => {
    const key1 = FixedBuf.fromRandom(32);
    const key2 = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret");
    const ciphertext = aesgcmEncrypt(plaintext, key1);
    expect(() => aesgcmDecrypt(ciphertext, key2)).toThrow();
  });

  it("should generate random nonce when not provided", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("test");
    const ct1 = aesgcmEncrypt(plaintext, key);
    const ct2 = aesgcmEncrypt(plaintext, key);
    // Nonces (first 12 bytes) should differ
    expect(ct1.slice(0, 12).toHex()).not.toBe(ct2.slice(0, 12).toHex());
  });
});
