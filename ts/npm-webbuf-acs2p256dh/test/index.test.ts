import { describe, it, expect } from "vitest";
import { acs2p256dhEncrypt, acs2p256dhDecrypt } from "../src/index.js";
import { p256PublicKeyCreate } from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

describe("Index", () => {
  it("should exist", () => {
    expect(acs2p256dhEncrypt).toBeDefined();
    expect(acs2p256dhDecrypt).toBeDefined();
  });
});

describe("Encryption Tests", () => {
  it("should encrypt and decrypt", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const alicePubKey = p256PublicKeyCreate(alicePrivKey);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = p256PublicKeyCreate(bobPrivKey);
    const plaintext = WebBuf.fromString("hello world");
    const encrypted = acs2p256dhEncrypt(alicePrivKey, bobPubKey, plaintext);
    const decrypted = acs2p256dhDecrypt(bobPrivKey, alicePubKey, encrypted);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it("should encrypt and decrypt with custom IV", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const alicePubKey = p256PublicKeyCreate(alicePrivKey);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = p256PublicKeyCreate(bobPrivKey);
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromString("hello world with IV");
    const encrypted = acs2p256dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    const decrypted = acs2p256dhDecrypt(bobPrivKey, alicePubKey, encrypted);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });

  it("should fail to decrypt with wrong keys", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = p256PublicKeyCreate(bobPrivKey);
    const evePrivKey = FixedBuf.fromRandom(32);
    const evePubKey = p256PublicKeyCreate(evePrivKey);
    const plaintext = WebBuf.fromString("secret message");
    const encrypted = acs2p256dhEncrypt(alicePrivKey, bobPubKey, plaintext);
    expect(() => acs2p256dhDecrypt(evePrivKey, evePubKey, encrypted)).toThrow(
      "Message authentication failed",
    );
  });

  it("should pass 100 random tests", () => {
    for (let i = 0; i < 100; i++) {
      const alicePrivKey = FixedBuf.fromRandom(32);
      const alicePubKey = p256PublicKeyCreate(alicePrivKey);
      const bobPrivKey = FixedBuf.fromRandom(32);
      const bobPubKey = p256PublicKeyCreate(bobPrivKey);
      const plaintext = WebBuf.fromString(`message ${String(i)}`);
      const encrypted = acs2p256dhEncrypt(alicePrivKey, bobPubKey, plaintext);
      const decrypted = acs2p256dhDecrypt(bobPrivKey, alicePubKey, encrypted);
      expect(decrypted.toString()).toBe(plaintext.toString());
    }
  });
});
