import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  p256Sign,
  p256Verify,
  p256SharedSecret,
  p256SharedSecretRaw,
  p256PublicKeyAdd,
  p256PublicKeyCreate,
  p256PublicKeyVerify,
  p256PrivateKeyAdd,
} from "../src/index.js";
import { blake3Hash } from "@webbuf/blake3";

describe("p256", () => {
  it("should correctly sign and verify a message", () => {
    const privateKey = FixedBuf.fromRandom(32);
    const publicKey = p256PublicKeyCreate(privateKey);
    const message = WebBuf.fromString("test message");
    const digest = blake3Hash(message);
    const signature = p256Sign(digest, privateKey, FixedBuf.fromRandom(32));
    expect(p256Verify(signature, digest, publicKey)).toBe(true);
  });

  it("should correctly not verify an invalid signature", () => {
    const privateKey = FixedBuf.fromRandom(32);
    const publicKey = p256PublicKeyCreate(privateKey);
    const message = WebBuf.fromString("test message");
    const digest = blake3Hash(message);
    const invalidSignature = FixedBuf.fromRandom(64);
    expect(p256Verify(invalidSignature, digest, publicKey)).toBe(false);
  });

  it("should correctly compute shared secret", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const pubKey1 = p256PublicKeyCreate(privKey1);
    const pubKey2 = p256PublicKeyCreate(privKey2);
    const shared1 = p256SharedSecret(privKey1, pubKey2);
    const shared2 = p256SharedSecret(privKey2, pubKey1);
    expect(shared1.toHex()).toBe(shared2.toHex());
  });

  it("p256SharedSecretRaw returns the X-coordinate of the compressed point", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const pubKey2 = p256PublicKeyCreate(privKey2);
    const compressed = p256SharedSecret(privKey1, pubKey2);
    const raw = p256SharedSecretRaw(privKey1, pubKey2);
    expect(raw.buf.length).toBe(32);
    expect(compressed.buf.length).toBe(33);
    // Compressed = [0x02 or 0x03, X0..X31]; raw = X0..X31.
    expect(raw.toHex()).toBe(compressed.toHex().slice(2));
    expect(["02", "03"]).toContain(compressed.toHex().slice(0, 2));
  });

  it("p256SharedSecretRaw is symmetric across the two parties", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const pubKey1 = p256PublicKeyCreate(privKey1);
    const pubKey2 = p256PublicKeyCreate(privKey2);
    const raw1 = p256SharedSecretRaw(privKey1, pubKey2);
    const raw2 = p256SharedSecretRaw(privKey2, pubKey1);
    expect(raw1.toHex()).toBe(raw2.toHex());
  });

  it("should correctly add public keys", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const pubKey1 = p256PublicKeyCreate(privKey1);
    const pubKey2 = p256PublicKeyCreate(privKey2);
    const sum = p256PublicKeyAdd(pubKey1, pubKey2);
    expect(p256PublicKeyVerify(sum)).toBe(true);
  });

  it("should correctly add private keys", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const sum = p256PrivateKeyAdd(privKey1, privKey2);
    expect(p256PublicKeyVerify(p256PublicKeyCreate(sum))).toBe(true);
  });
});
