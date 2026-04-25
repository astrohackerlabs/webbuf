/**
 * Audit tests for @webbuf/aesgcm-mlkem
 *
 * Reproduces the byte-precise KAT captured in
 * `issues/0004-hybrid-pq-encryption/README.md` Experiment 1 to assert
 * that this implementation matches the spec byte-for-byte.
 *
 * Inputs (deterministic):
 *   d = 0x00 * 32
 *   z = 0x11 * 32
 *   m = 0x22 * 32
 *   plaintext = "hello, post-quantum"
 *   AES-GCM IV = 0x33 * 12
 *
 * Expected:
 *   ML-KEM sharedSecret = 14da7607...07aeedef
 *   Derived AES key      = 7222f04b...a88bbed1
 *   Ciphertext length    = 1136 bytes
 *   SHA-256(ciphertext)  = 680beaa6...8ef240
 */
import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { mlKem768KeyPairDeterministic } from "@webbuf/mlkem";
import { sha256Hash } from "@webbuf/sha256";
import { _aesgcmMlkemEncryptDeterministic } from "../src/index.js";

const KAT_D = FixedBuf.fromHex(
  32,
  "0000000000000000000000000000000000000000000000000000000000000000",
);
const KAT_Z = FixedBuf.fromHex(
  32,
  "1111111111111111111111111111111111111111111111111111111111111111",
);
const KAT_M = FixedBuf.fromHex(
  32,
  "2222222222222222222222222222222222222222222222222222222222222222",
);
const KAT_IV = FixedBuf.fromHex(12, "333333333333333333333333");
const KAT_PLAINTEXT = WebBuf.fromUtf8("hello, post-quantum");

const KAT_CIPHERTEXT_SHA256 =
  "680beaa6d06d2324db4bf1545814f85fcc5f60ca7790ed5702779f497f8ef240";
const KAT_CIPHERTEXT_LENGTH = 1136;

describe("Audit: issue 0004 Experiment 1 KAT", () => {
  it("matches the captured byte-precise ciphertext from the issue", () => {
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);
    const ciphertext = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );

    expect(ciphertext.length).toBe(KAT_CIPHERTEXT_LENGTH);
    expect(sha256Hash(ciphertext).toHex()).toBe(KAT_CIPHERTEXT_SHA256);
  });

  it("ciphertext begins with the captured version byte and KEM ciphertext prefix", () => {
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);
    const ciphertext = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );

    // Version byte
    expect(ciphertext[0]).toBe(0x01);
    // KEM ciphertext prefix from the captured KAT
    expect(ciphertext.toHex().slice(2, 18)).toBe("2afd05db59114a15");
    // IV is at offset 1089 (1 version + 1088 KEM ct)
    expect(ciphertext.toHex().slice(1089 * 2, 1089 * 2 + 24)).toBe(
      "333333333333333333333333",
    );
  });

  it("explicit empty AAD produces the same bytes as the no-AAD default", () => {
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);
    const ctNoAad = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );
    const ctEmptyAad = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
      WebBuf.alloc(0),
    );
    expect(ctEmptyAad.toHex()).toBe(ctNoAad.toHex());
  });
});

describe("Audit: issue 0006 Experiment 2 AAD KAT", () => {
  // Same deterministic inputs as the issue 0004 KAT, plus a fixed AAD.
  // The ciphertext bytes differ because AAD changes the AES-GCM tag,
  // even though all other inputs (including IV) are identical.
  const KAT_AAD = WebBuf.fromUtf8("webbuf:test-aad-v1");
  const AAD_KAT_CIPHERTEXT_SHA256 =
    "f05197b57c6d26122e558cb365bf10a81d13fca1b71e6d35e46399165bafc2ab";

  it("matches the captured byte-precise ciphertext with non-empty AAD", () => {
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);
    const ciphertext = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
      KAT_AAD,
    );

    // AAD is not transmitted; ciphertext length unchanged from empty-AAD KAT
    expect(ciphertext.length).toBe(KAT_CIPHERTEXT_LENGTH);
    expect(sha256Hash(ciphertext).toHex()).toBe(AAD_KAT_CIPHERTEXT_SHA256);
  });

  it("AAD changes only the tag, not the IV or AES-CTR body", () => {
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);
    const ctNoAad = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );
    const ctWithAad = _aesgcmMlkemEncryptDeterministic(
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
      KAT_AAD,
    );

    // Same length
    expect(ctWithAad.length).toBe(ctNoAad.length);
    // Same body up through end of AES-CTR ciphertext (everything before
    // the trailing 16-byte tag) — AES-CTR keystream is unaffected by
    // AAD.
    const tagStart = ctNoAad.length - 16;
    expect(ctWithAad.slice(0, tagStart).toHex()).toBe(
      ctNoAad.slice(0, tagStart).toHex(),
    );
    // Tag differs because AAD changes the GHASH input.
    expect(ctWithAad.slice(tagStart).toHex()).not.toBe(
      ctNoAad.slice(tagStart).toHex(),
    );
  });
});
