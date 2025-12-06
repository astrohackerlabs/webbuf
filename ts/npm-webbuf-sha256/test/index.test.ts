import { describe, it, expect } from "vitest";
import { sha256Hash, doubleSha256Hash, sha256Hmac } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("SHA256", () => {
  it("should correctly compute sha256 hash of empty string", () => {
    const input = WebBuf.fromUtf8("");
    const result = sha256Hash(input);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    // NIST test vector for empty string
    const expectedHashHex =
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    expect(result.toHex()).toBe(expectedHashHex);
  });

  it("should correctly compute sha256 hash of 'abc'", () => {
    const input = WebBuf.fromUtf8("abc");
    const result = sha256Hash(input);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    // NIST test vector for "abc"
    const expectedHashHex =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    expect(result.toHex()).toBe(expectedHashHex);
  });

  it("should correctly compute double sha256 hash", () => {
    const input = WebBuf.fromUtf8("abc");
    const result = doubleSha256Hash(input);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    // SHA256(SHA256("abc"))
    const expectedDoubleHashHex =
      "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
    expect(result.toHex()).toBe(expectedDoubleHashHex);
  });

  it("should correctly compute HMAC-SHA256 (RFC 4231 Test Case 1)", () => {
    // Key = 0x0b repeated 20 times
    const key = WebBuf.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const message = WebBuf.fromUtf8("Hi There");
    const result = sha256Hmac(key, message);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    const expectedMacHex =
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    expect(result.toHex()).toBe(expectedMacHex);
  });

  it("should correctly compute HMAC-SHA256 (RFC 4231 Test Case 2)", () => {
    // Key = "Jefe"
    const key = WebBuf.fromUtf8("Jefe");
    const message = WebBuf.fromUtf8("what do ya want for nothing?");
    const result = sha256Hmac(key, message);

    expect(result).toBeInstanceOf(FixedBuf);
    expect(result.buf.length).toBe(32);
    const expectedMacHex =
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    expect(result.toHex()).toBe(expectedMacHex);
  });
});
