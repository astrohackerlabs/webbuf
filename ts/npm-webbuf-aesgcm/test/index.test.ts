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

describe("aesgcm AAD support", () => {
  it("default empty AAD matches explicit empty AAD byte-for-byte", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromHex(12, "0102030405060708090a0b0c");
    const plaintext = WebBuf.fromUtf8("default-vs-explicit");

    const ctNoArg = aesgcmEncrypt(plaintext, key, iv);
    const ctEmptyAad = aesgcmEncrypt(plaintext, key, iv, WebBuf.alloc(0));

    expect(ctNoArg.toHex()).toBe(ctEmptyAad.toHex());
  });

  it("non-empty AAD round-trip recovers the plaintext", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("context-aware");
    const aad = WebBuf.fromUtf8("protocol-v1:alice@a:bob@b");

    const ct = aesgcmEncrypt(plaintext, key, undefined, aad);
    const pt = aesgcmDecrypt(ct, key, aad);

    expect(pt.toUtf8()).toBe("context-aware");
  });

  it("decrypt with mismatched AAD throws", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret");
    const aadA = WebBuf.fromUtf8("context-A");
    const aadB = WebBuf.fromUtf8("context-B");

    const ct = aesgcmEncrypt(plaintext, key, undefined, aadA);
    expect(() => aesgcmDecrypt(ct, key, aadB)).toThrow();
  });

  it("decrypt without AAD when AAD was used at encrypt time throws", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret");
    const aad = WebBuf.fromUtf8("ctx");

    const ct = aesgcmEncrypt(plaintext, key, undefined, aad);
    expect(() => aesgcmDecrypt(ct, key)).toThrow();
  });

  it("decrypt with AAD when no AAD was used at encrypt time throws", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("secret");

    const ct = aesgcmEncrypt(plaintext, key);
    const aad = WebBuf.fromUtf8("ctx");
    expect(() => aesgcmDecrypt(ct, key, aad)).toThrow();
  });

  it("AAD changes only the tag, not the encrypted body", () => {
    const key = FixedBuf.fromRandom(32);
    const iv = FixedBuf.fromHex(12, "0102030405060708090a0b0c");
    const plaintext = WebBuf.fromUtf8("plaintext-bytes");

    const ct1 = aesgcmEncrypt(plaintext, key, iv);
    const ct2 = aesgcmEncrypt(plaintext, key, iv, WebBuf.fromUtf8("ctx"));

    // Same length: AAD is not transmitted, so the wire size doesn't grow.
    expect(ct1.length).toBe(ct2.length);
    // The IV (first 12) and the AES-CTR body are identical because
    // AES-CTR with the same key/IV produces the same keystream
    // regardless of AAD.
    const bodyEnd = ct1.length - 16; // last 16 bytes are the tag
    expect(ct1.slice(0, bodyEnd).toHex()).toBe(ct2.slice(0, bodyEnd).toHex());
    // The 16-byte tag differs because AAD changes the GHASH input.
    expect(ct1.slice(bodyEnd).toHex()).not.toBe(ct2.slice(bodyEnd).toHex());
  });

  it("large AAD (4 KiB) round-trip", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("hi");
    const aad = WebBuf.alloc(4096);
    for (let i = 0; i < aad.length; i++) {
      aad[i] = i & 0xff;
    }

    const ct = aesgcmEncrypt(plaintext, key, undefined, aad);
    const pt = aesgcmDecrypt(ct, key, aad);
    expect(pt.toUtf8()).toBe("hi");

    // Tampering with one byte of AAD on the recipient side must fail.
    const tampered = WebBuf.alloc(4096);
    tampered.set(aad);
    tampered[2000] = (tampered[2000]! ^ 0x01) & 0xff;
    expect(() => aesgcmDecrypt(ct, key, tampered)).toThrow();
  });

  it("KeyPears-style AAD construction round-trips", () => {
    const key = FixedBuf.fromRandom(32);
    const plaintext = WebBuf.fromUtf8("text message body");

    // Mirror the AAD shape suggested in @webbuf/aesgcm-p256dh-mlkem README.
    const PROTOCOL_VERSION = 1;
    const MESSAGE_TYPE_TEXT = 1;
    const aad = WebBuf.concat([
      WebBuf.fromArray([PROTOCOL_VERSION]),
      WebBuf.fromArray([MESSAGE_TYPE_TEXT]),
      WebBuf.fromUtf8("alice@example.com"),
      WebBuf.fromArray([0]),
      WebBuf.fromUtf8("bob@example.org"),
    ]);

    const ct = aesgcmEncrypt(plaintext, key, undefined, aad);
    const pt = aesgcmDecrypt(ct, key, aad);
    expect(pt.toUtf8()).toBe("text message body");

    // Wrong recipient address in AAD on decrypt → fails.
    const wrongAad = WebBuf.concat([
      WebBuf.fromArray([PROTOCOL_VERSION]),
      WebBuf.fromArray([MESSAGE_TYPE_TEXT]),
      WebBuf.fromUtf8("alice@example.com"),
      WebBuf.fromArray([0]),
      WebBuf.fromUtf8("eve@attacker.com"),
    ]);
    expect(() => aesgcmDecrypt(ct, key, wrongAad)).toThrow();
  });
});
