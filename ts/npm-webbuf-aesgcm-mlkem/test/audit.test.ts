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
});
