/**
 * Audit tests for @webbuf/aesgcm-p256dh-mlkem
 *
 * Reproduces the byte-precise KAT captured in
 * `issues/0004-hybrid-pq-encryption/README.md` Experiment 1 to assert
 * that this implementation matches the spec byte-for-byte.
 *
 * Inputs (deterministic):
 *   sender P-256 priv      = 0x44 * 32
 *   recipient P-256 priv   = 0x55 * 32 (recipient pub derived)
 *   ML-KEM d (seed 1)      = 0x66 * 32
 *   ML-KEM z (seed 2)      = 0x77 * 32
 *   ML-KEM m (encap rand)  = 0x88 * 32
 *   AES-GCM IV             = 0x99 * 12
 *   plaintext              = "hybrid"
 *
 * Expected:
 *   ECDH raw X-coord       = f0517205...017dc7ed
 *   ML-KEM sharedSecret    = 9ad302f2...83675870
 *   Derived AES key        = 5d77954f...b7fcaacc
 *   Ciphertext length      = 1123 bytes
 *   SHA-256(ciphertext)    = c689ccce3ad0194c00377441af4f89c4d8aa48f530b451216e7b26f566a02b6d
 */
import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { mlKem768KeyPairDeterministic } from "@webbuf/mlkem";
import { p256PublicKeyCreate } from "@webbuf/p256";
import { sha256Hash } from "@webbuf/sha256";
import { _aesgcmP256dhMlkemEncryptDeterministic } from "../src/index.js";

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
  "0257e977f6db7e33c3fe7acf2842ed987009caf56d458682fca447b7d3d762ab34";
const KAT_CIPHERTEXT_SHA256 =
  "c689ccce3ad0194c00377441af4f89c4d8aa48f530b451216e7b26f566a02b6d";
const KAT_CIPHERTEXT_LENGTH = 1123;

describe("Audit: issue 0004 Experiment 1 hybrid KAT", () => {
  it("derives the captured recipient P-256 public key", () => {
    const recipientPub = p256PublicKeyCreate(KAT_RECIPIENT_PRIV);
    expect(recipientPub.toHex()).toBe(KAT_RECIPIENT_PUB_HEX);
  });

  it("matches the captured byte-precise ciphertext from the issue", () => {
    const recipientPub = p256PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ciphertext = _aesgcmP256dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );

    expect(ciphertext.length).toBe(KAT_CIPHERTEXT_LENGTH);
    expect(sha256Hash(ciphertext).toHex()).toBe(KAT_CIPHERTEXT_SHA256);
  });

  it("ciphertext begins with the captured version byte and KEM ciphertext prefix", () => {
    const recipientPub = p256PublicKeyCreate(KAT_RECIPIENT_PRIV);
    const { encapsulationKey } = mlKem768KeyPairDeterministic(KAT_D, KAT_Z);

    const ciphertext = _aesgcmP256dhMlkemEncryptDeterministic(
      KAT_SENDER_PRIV,
      recipientPub,
      encapsulationKey,
      KAT_PLAINTEXT,
      KAT_M,
      KAT_IV,
    );

    // Version byte
    expect(ciphertext[0]).toBe(0x02);
    // KEM ciphertext prefix from the captured KAT
    expect(ciphertext.toHex().slice(2, 18)).toBe("dbfdf2752836f809");
    // IV is at offset 1089 (1 version + 1088 KEM ct)
    expect(ciphertext.toHex().slice(1089 * 2, 1089 * 2 + 24)).toBe(
      "999999999999999999999999",
    );
  });
});
