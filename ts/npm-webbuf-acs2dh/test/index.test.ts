import { describe, it, expect } from "vitest";
import { acs2dhEncrypt, acs2dhDecrypt } from "../src/index.js";
import { publicKeyCreate } from "@webbuf/secp256k1";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

describe("Index", () => {
  it("should exist", () => {
    expect(acs2dhEncrypt).toBeDefined();
    expect(acs2dhDecrypt).toBeDefined();
  });
});

describe("Encryption Tests", () => {
  it("should encrypt and decrypt", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const alicePubKey = publicKeyCreate(alicePrivKey);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = publicKeyCreate(bobPrivKey);
    const plaintext = WebBuf.fromString("hello world");
    const encrypted = acs2dhEncrypt(alicePrivKey, bobPubKey, plaintext);
    const decrypted = acs2dhDecrypt(bobPrivKey, alicePubKey, encrypted);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it("should encrypt and decrypt with custom IV", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const alicePubKey = publicKeyCreate(alicePrivKey);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = publicKeyCreate(bobPrivKey);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromString("hello world with IV");
    const encrypted = acs2dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    const decrypted = acs2dhDecrypt(bobPrivKey, alicePubKey, encrypted);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it("should fail to decrypt with wrong keys", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = publicKeyCreate(bobPrivKey);
    const evePrivKey = FixedBuf.fromRandom(32);
    const evePubKey = publicKeyCreate(evePrivKey);
    const plaintext = WebBuf.fromString("secret message");
    const encrypted = acs2dhEncrypt(alicePrivKey, bobPubKey, plaintext);
    // Eve tries to decrypt with her own keys
    expect(() => acs2dhDecrypt(evePrivKey, evePubKey, encrypted)).toThrow(
      "Message authentication failed",
    );
  });

  it("should pass 100 random tests", () => {
    for (let i = 0; i < 100; i++) {
      const alicePrivKey = FixedBuf.fromRandom(32);
      const alicePubKey = publicKeyCreate(alicePrivKey);
      const bobPrivKey = FixedBuf.fromRandom(32);
      const bobPubKey = publicKeyCreate(bobPrivKey);
      const plaintext = WebBuf.fromString(`message ${i}`);
      const encrypted = acs2dhEncrypt(alicePrivKey, bobPubKey, plaintext);
      const decrypted = acs2dhDecrypt(bobPrivKey, alicePubKey, encrypted);
      expect(decrypted.toString()).toBe(plaintext.toString());
    }
  });
});
