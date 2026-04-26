/**
 * Audit tests for @webbuf/aesgcm-x25519dh-mlkem
 *
 * Reproduces the byte-precise KATs captured in
 * `issues/0007-curve25519-hybrid-pq/README.md` Experiment 4 to assert
 * that this implementation matches the spec byte-for-byte.
 *
 * Inputs (deterministic):
 *   sender X25519 priv     = 0x44 * 32
 *   recipient X25519 priv  = 0x55 * 32 (recipient pub derived)
 *   ML-KEM d (seed 1)      = 0x66 * 32
 *   ML-KEM z (seed 2)      = 0x77 * 32
 *   ML-KEM m (encap rand)  = 0x88 * 32
 *   AES-GCM IV             = 0x99 * 12
 *   plaintext              = "hybrid"
 *
 * Recipient X25519 pub (from captured run):
 *   38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67
 *
 * Empty-AAD KAT:
 *   ciphertext length      = 1123 bytes
 *   SHA-256(ciphertext)    = 81ebae8d75e5724131baeb8fa3c03a92767ee0adaab9adbd37212114d9c986e1
 *
 * Non-empty-AAD KAT (aad = "webbuf:test-aad-v1"):
 *   ciphertext length      = 1123 bytes
 *   SHA-256(ciphertext)    = 20ec384a9a43dbd097a5b35205210c115009838fb3064046accefb2dcea0b9c9
 */
import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { mlKem768KeyPairDeterministic } from "@webbuf/mlkem";
import { x25519PublicKeyCreate } from "@webbuf/x25519";
import { sha256Hash } from "@webbuf/sha256";
import { _aesgcmX25519dhMlkemEncryptDeterministic } from "../src/index.js";

const KAT_SENDER_PRIV = FixedBuf.fromHex(
  32,
  "4444444444444444444444444444444444444444444444444444444444444444",
);
const KAT_RECIPIENT_PRIV = FixedBuf.fromHex(
  32,
  "5555555555555555555555555555555555555555555555555555555555555555",
);
const KAT_D = FixedBuf.fromHex(
  32,
  "6666666666666666666666666666666666666666666666666666666666666666",
);
const KAT_Z = FixedBuf.fromHex(
  32,
  "7777777777777777777777777777777777777777777777777777777777777777",
);
const KAT_M = FixedBuf.fromHex(
  32,
  "8888888888888888888888888888888888888888888888888888888888888888",
);
const KAT_IV = FixedBuf.fromHex(12, "999999999999999999999999");
const KAT_PLAINTEXT = WebBuf.fromUtf8("hybrid");

const KAT_RECIPIENT_PUB_HEX =
  "38ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67";
const KAT_CIPHERTEXT_LENGTH = 1123;
const KAT_EMPTY_AAD_CIPHERTEXT_SHA256 =
  "81ebae8d75e5724131baeb8fa3c03a92767ee0adaab9adbd37212114d9c986e1";
const KAT_AAD_CIPHERTEXT_SHA256 =
  "20ec384a9a43dbd097a5b35205210c115009838fb3064046accefb2dcea0b9c9";

describe("Audit: issue 0007 Experiment 4 hybrid X25519 KAT", () => {
  it("derives the captured recipient X25519 public key", () => {
    const recipientPub = x25519PublicKeyCreate(KAT_RECIPIENT_PRIV);
    expect(recipientPub.toHex()).toBe(KAT_RECIPIENT_PUB_HEX);
  });

  it("matches the captured byte-precise empty-AAD ciphertext", () => {
    const recipientPub = x25519PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ciphertext = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );

    expect(ciphertext.length).toBe(KAT_CIPHERTEXT_LENGTH);
    expect(sha256Hash(ciphertext).toHex()).toBe(
      KAT_EMPTY_AAD_CIPHERTEXT_SHA256,
    );
  });

  it("ciphertext begins with version byte 0x03 and the captured KEM prefix", () => {
    const recipientPub = x25519PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ciphertext = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );

    // Version byte 0x03.
    expect(ciphertext[0]).toBe(0x03);
    // KEM ciphertext prefix from the captured KAT (same ML-KEM seeds as
    // the P-256 hybrid KAT, so the KEM prefix matches).
    expect(ciphertext.toHex().slice(2, 18)).toBe("dbfdf2752836f809");
    // IV is at offset 1089 (1 version + 1088 KEM ct).
    expect(ciphertext.toHex().slice(1089 * 2, 1089 * 2 + 24)).toBe(
      "999999999999999999999999",
    );
  });

  it("explicit empty AAD produces the same bytes as the no-AAD default", () => {
    const recipientPub = x25519PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ctNoAad = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );
    const ctEmptyAad = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
      WebBuf.alloc(0),
    );
    expect(ctEmptyAad.toHex()).toBe(ctNoAad.toHex());
  });
});

describe("Audit: issue 0007 Experiment 4 hybrid X25519 AAD KAT", () => {
  // Same deterministic inputs as the empty-AAD KAT, plus a fixed AAD.
  // The ciphertext bytes differ because AAD changes the AES-GCM tag,
  // even though all other inputs (including IV) are identical.
  const KAT_AAD = WebBuf.fromUtf8("webbuf:test-aad-v1");

  it("matches the captured byte-precise ciphertext with non-empty AAD", () => {
    const recipientPub = x25519PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ciphertext = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
      KAT_AAD,
    );

    // AAD is not transmitted; ciphertext length unchanged from empty-AAD KAT.
    expect(ciphertext.length).toBe(KAT_CIPHERTEXT_LENGTH);
    expect(sha256Hash(ciphertext).toHex()).toBe(KAT_AAD_CIPHERTEXT_SHA256);
  });

  it("AAD changes only the tag, not the IV or AES-CTR body", () => {
    const recipientPub = x25519PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ctNoAad = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );
    const ctWithAad = _aesgcmX25519dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
      KAT_AAD,
    );

    expect(ctWithAad.length).toBe(ctNoAad.length);
    const tagStart = ctNoAad.length - 16;
    expect(ctWithAad.slice(0, tagStart).toHex()).toBe(
      ctNoAad.slice(0, tagStart).toHex(),
    );
    expect(ctWithAad.slice(tagStart).toHex()).not.toBe(
      ctNoAad.slice(tagStart).toHex(),
    );
  });
});
