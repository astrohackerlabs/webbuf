import { describe, it, expect } from "vitest";
import { sha256Hash, doubleSha256Hash, sha256Hmac } from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Helper to compute SHA-256 using Web Crypto API
async function webCryptoSha256(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(hashBuffer);
}

// Helper to compute HMAC-SHA256 using Web Crypto API
async function webCryptoHmacSha256(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    data as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(signatureBuffer);
}

// Helper to generate random bytes
function randomBytes(length: number): WebBuf {
  const buf = WebBuf.alloc(length);
  crypto.getRandomValues(buf);
  return buf;
}

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

describe("SHA256 vs Web Crypto API", () => {
  it("should match Web Crypto for empty input", async () => {
    const input = WebBuf.fromUtf8("");
    const webbufResult = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for single byte", async () => {
    const input = WebBuf.fromHex("42");
    const webbufResult = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for small input (< 64 bytes)", async () => {
    const input = randomBytes(32);
    const webbufResult = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for exactly 64 bytes (one block)", async () => {
    const input = randomBytes(64);
    const webbufResult = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for medium input (500 bytes)", async () => {
    const input = randomBytes(500);
    const webbufResult = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for large input (10KB)", async () => {
    const input = randomBytes(10 * 1024);
    const webbufResult = sha256Hash(input);
    const webCryptoResult = await webCryptoSha256(input);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for multiple random sizes", async () => {
    const sizes = [1, 15, 63, 64, 65, 127, 128, 129, 256, 1000, 4096];

    for (const size of sizes) {
      const input = randomBytes(size);
      const webbufResult = sha256Hash(input);
      const webCryptoResult = await webCryptoSha256(input);

      expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
    }
  });
});

describe("HMAC-SHA256 vs Web Crypto API", () => {
  it("should match Web Crypto for small key and message", async () => {
    const key = randomBytes(32);
    const message = randomBytes(64);
    const webbufResult = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for empty message", async () => {
    const key = randomBytes(32);
    const message = WebBuf.fromUtf8("");
    const webbufResult = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for short key (< 64 bytes)", async () => {
    const key = randomBytes(16);
    const message = randomBytes(100);
    const webbufResult = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for long key (> 64 bytes)", async () => {
    const key = randomBytes(128);
    const message = randomBytes(100);
    const webbufResult = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for large message (10KB)", async () => {
    const key = randomBytes(32);
    const message = randomBytes(10 * 1024);
    const webbufResult = sha256Hmac(key, message);
    const webCryptoResult = await webCryptoHmacSha256(key, message);

    expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
  });

  it("should match Web Crypto for multiple random key/message sizes", async () => {
    const testCases = [
      { keySize: 1, messageSize: 1 },
      { keySize: 16, messageSize: 32 },
      { keySize: 32, messageSize: 64 },
      { keySize: 64, messageSize: 128 },
      { keySize: 128, messageSize: 256 },
      { keySize: 32, messageSize: 1000 },
      { keySize: 64, messageSize: 4096 },
    ];

    for (const { keySize, messageSize } of testCases) {
      const key = randomBytes(keySize);
      const message = randomBytes(messageSize);
      const webbufResult = sha256Hmac(key, message);
      const webCryptoResult = await webCryptoHmacSha256(key, message);

      expect(webbufResult.buf).toEqual(WebBuf.fromUint8Array(webCryptoResult));
    }
  });
});
