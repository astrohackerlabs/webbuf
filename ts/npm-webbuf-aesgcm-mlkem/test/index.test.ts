import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { mlKem768KeyPair, mlKem768KeyPairDeterministic } from "@webbuf/mlkem";
import {
  AESGCM_MLKEM,
  aesgcmMlkemEncrypt,
  aesgcmMlkemDecrypt,
} from "../src/index.js";

describe("aesgcm-mlkem round-trip", () => {
  it("encrypts + decrypts a random plaintext", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("hello, post-quantum world");

    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const recovered = aesgcmMlkemDecrypt(decapsulationKey, ciphertext);

    expect(recovered.toHex()).toBe(plaintext.toHex());
  });

  it("encrypts + decrypts an empty plaintext", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.alloc(0);

    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const recovered = aesgcmMlkemDecrypt(decapsulationKey, ciphertext);

    expect(recovered.length).toBe(0);
  });

  it("encrypts + decrypts a 64 KiB plaintext", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.alloc(64 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i & 0xff;
    }

    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const recovered = aesgcmMlkemDecrypt(decapsulationKey, ciphertext);

    expect(recovered.length).toBe(plaintext.length);
    expect(recovered.toHex()).toBe(plaintext.toHex());
  });

  it("default encryption is non-deterministic", () => {
    const { encapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("repeat me");

    const ct1 = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const ct2 = aesgcmMlkemEncrypt(encapsulationKey, plaintext);

    expect(ct1.toHex()).not.toBe(ct2.toHex());
  });

  it("ciphertext length equals fixedOverhead + plaintext length", () => {
    const { encapsulationKey } = mlKem768KeyPair();
    for (const len of [0, 1, 16, 100, 1024, 65535]) {
      const plaintext = WebBuf.alloc(len);
      const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
      expect(ciphertext.length).toBe(AESGCM_MLKEM.fixedOverhead + len);
    }
  });

  it("ciphertext begins with the version byte 0x01", () => {
    const { encapsulationKey } = mlKem768KeyPair();
    const ciphertext = aesgcmMlkemEncrypt(
      encapsulationKey,
      WebBuf.fromUtf8("x"),
    );
    expect(ciphertext[0]).toBe(AESGCM_MLKEM.versionByte);
    expect(ciphertext[0]).toBe(0x01);
  });
});

describe("aesgcm-mlkem rejection paths", () => {
  it("wrong recipient (different keypair) fails to decrypt", () => {
    const a = mlKem768KeyPair();
    const b = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("for A only");

    const ciphertext = aesgcmMlkemEncrypt(a.encapsulationKey, plaintext);

    expect(() => aesgcmMlkemDecrypt(b.decapsulationKey, ciphertext)).toThrow();
  });

  it("tampered KEM ciphertext rejected (AES-GCM tag mismatch)", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("tamper me");

    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const tampered = WebBuf.fromUint8Array(ciphertext);
    // Flip a byte inside the KEM ciphertext region (bytes 1..1089)
    tampered[500] = (tampered[500]! ^ 0xff) & 0xff;

    expect(() => aesgcmMlkemDecrypt(decapsulationKey, tampered)).toThrow();
  });

  it("tampered AES ciphertext rejected (AES-GCM tag mismatch)", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("tamper the body");

    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const tampered = WebBuf.fromUint8Array(ciphertext);
    // Flip a byte in the AES ciphertext region (after IV, before tag)
    const aesBodyStart =
      1 + AESGCM_MLKEM.kemCiphertextSize + AESGCM_MLKEM.ivSize;
    tampered[aesBodyStart] = (tampered[aesBodyStart]! ^ 0xff) & 0xff;

    expect(() => aesgcmMlkemDecrypt(decapsulationKey, tampered)).toThrow();
  });

  it("tampered IV rejected (AES-GCM tag mismatch)", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("tamper IV");

    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const tampered = WebBuf.fromUint8Array(ciphertext);
    const ivStart = 1 + AESGCM_MLKEM.kemCiphertextSize;
    tampered[ivStart] = (tampered[ivStart]! ^ 0xff) & 0xff;

    expect(() => aesgcmMlkemDecrypt(decapsulationKey, tampered)).toThrow();
  });

  it("wrong version byte rejected with a clear error", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const ciphertext = aesgcmMlkemEncrypt(
      encapsulationKey,
      WebBuf.fromUtf8("x"),
    );
    const wrongVersion = WebBuf.fromUint8Array(ciphertext);
    wrongVersion[0] = 0x02;

    expect(() => aesgcmMlkemDecrypt(decapsulationKey, wrongVersion)).toThrow(
      /version byte/,
    );
  });

  it("truncated ciphertext rejected with a length error", () => {
    const { decapsulationKey } = mlKem768KeyPair();
    const truncated = WebBuf.alloc(100);

    expect(() => aesgcmMlkemDecrypt(decapsulationKey, truncated)).toThrow(
      /too short/,
    );
  });

  it("deterministic keypair from issue 0004 KAT seeds is well-formed", () => {
    // Sanity check that the KAT seeds in the issue still produce a usable
    // keypair. The full byte-precise KAT is asserted in test/audit.test.ts.
    const d = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    const z = FixedBuf.fromHex(
      32,
      "1111111111111111111111111111111111111111111111111111111111111111",
    );
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPairDeterministic(
      d,
      z,
    );
    const plaintext = WebBuf.fromUtf8("kat sanity");
    const ciphertext = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    const recovered = aesgcmMlkemDecrypt(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(plaintext.toHex());
  });
});

describe("aesgcm-mlkem AAD support", () => {
  it("non-empty AAD round-trip recovers the plaintext", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("context-bound");
    const aad = WebBuf.fromUtf8("alice@a:bob@b:v1");

    const ct = aesgcmMlkemEncrypt(encapsulationKey, plaintext, aad);
    const pt = aesgcmMlkemDecrypt(decapsulationKey, ct, aad);

    expect(pt.toUtf8()).toBe("context-bound");
  });

  it("AAD mismatch on decrypt throws", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("for one context only");
    const aadA = WebBuf.fromUtf8("context-A");
    const aadB = WebBuf.fromUtf8("context-B");

    const ct = aesgcmMlkemEncrypt(encapsulationKey, plaintext, aadA);
    expect(() => aesgcmMlkemDecrypt(decapsulationKey, ct, aadB)).toThrow();
  });

  it("decrypting AAD-encrypted ciphertext without AAD throws", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("needs context");
    const aad = WebBuf.fromUtf8("ctx");

    const ct = aesgcmMlkemEncrypt(encapsulationKey, plaintext, aad);
    expect(() => aesgcmMlkemDecrypt(decapsulationKey, ct)).toThrow();
  });

  it("decrypting empty-AAD ciphertext with AAD throws", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("no context at encrypt");
    const aad = WebBuf.fromUtf8("ctx");

    const ct = aesgcmMlkemEncrypt(encapsulationKey, plaintext);
    expect(() => aesgcmMlkemDecrypt(decapsulationKey, ct, aad)).toThrow();
  });
});
