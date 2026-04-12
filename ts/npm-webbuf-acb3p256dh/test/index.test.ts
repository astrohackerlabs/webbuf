import { describe, it, expect } from "vitest";
import { acb3p256dhEncrypt, acb3p256dhDecrypt } from "../src/index.js";
import { p256PublicKeyCreate } from "@webbuf/p256";
import { FixedBuf } from "@webbuf/fixedbuf";
import { WebBuf } from "@webbuf/webbuf";

describe("Index", () => {
  it("should exist", () => {
    expect(acb3p256dhEncrypt).toBeDefined();
    expect(acb3p256dhDecrypt).toBeDefined();
  });
});

describe("Encryption Tests", () => {
  it("should encrypt and decrypt", () => {
    const alicePrivKey = FixedBuf.fromRandom(32);
    const alicePubKey = p256PublicKeyCreate(alicePrivKey);
    const bobPrivKey = FixedBuf.fromRandom(32);
    const bobPubKey = p256PublicKeyCreate(bobPrivKey);
    const plaintext = WebBuf.fromString("hello world");
    const encrypted = acb3p256dhEncrypt(alicePrivKey, bobPubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(bobPrivKey, alicePubKey, encrypted);
    expect(decrypted.toString()).toBe(plaintext.toString());
  });
});
