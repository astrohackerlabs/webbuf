/**
 * Audit tests for @webbuf/sig-ed25519-mldsa
 *
 * Reproduces the byte-precise deterministic KAT captured in
 * `issues/0007-curve25519-hybrid-pq/README.md` Experiment 5 to assert
 * that this implementation matches the spec byte-for-byte.
 *
 * Inputs (deterministic):
 *   Ed25519 seed         = 0xaa * 32
 *   ML-DSA-65 seed       = 0xbb * 32
 *   Message              = "composite signature"
 *
 * Captured outputs:
 *   Ed25519 pub          = e734ea6c...b5636b58
 *   ML-DSA-65 vk SHA-256 = 985ef876...c9889eae
 *   Signature length     = 3374 bytes
 *   SHA-256(signature)   = 401a517c...47158c53
 */
import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { ed25519PublicKeyCreate } from "@webbuf/ed25519";
import { mlDsa65KeyPairDeterministic } from "@webbuf/mldsa";
import { sha256Hash } from "@webbuf/sha256";
import {
  SIG_ED25519_MLDSA,
  _sigEd25519MldsaSignDeterministic,
  sigEd25519MldsaVerify,
} from "../src/index.js";

const KAT_ED25519_SEED = FixedBuf.fromHex(32, "aa".repeat(32));
const KAT_MLDSA_SEED = FixedBuf.fromHex(32, "bb".repeat(32));
const KAT_MESSAGE = WebBuf.fromUtf8("composite signature");

const KAT_ED25519_PUB_HEX =
  "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58";
const KAT_MLDSA_VK_SHA256 =
  "985ef8763b1eb7f9b05d535735924b7d9fbf20ada3304c0bfdd78db8c9889eae";
const KAT_ED25519_SIG_HEX =
  "ec5a9be5a744a00ac6c2528eb00c005fae21fb476842b65f9eaf63984350948da2b14e65cd955c4ab944305fe0228d922aeba06722e2eb435ece3fc1da0d9f02";
const KAT_MLDSA_SIG_PREFIX_HEX = "7223bf2f5a2253ece0ed48c5c4f2bc11";
const KAT_SIGNATURE_LENGTH = 3374;
const KAT_SIGNATURE_SHA256 =
  "401a517ca7568a7a3655a03b9fd42ad88431586cbc71a86f70fa51eb47158c53";

describe("Audit: issue 0007 Experiment 5 sig-ed25519-mldsa KAT", () => {
  it("derives the captured Ed25519 public key", () => {
    const edPub = ed25519PublicKeyCreate(KAT_ED25519_SEED);
    expect(edPub.toHex()).toBe(KAT_ED25519_PUB_HEX);
  });

  it("derives the captured ML-DSA-65 verifying key (by SHA-256)", () => {
    const { verifyingKey } = mlDsa65KeyPairDeterministic(KAT_MLDSA_SEED);
    expect(sha256Hash(WebBuf.fromUint8Array(verifyingKey.buf)).toHex()).toBe(
      KAT_MLDSA_VK_SHA256,
    );
  });

  it("matches the captured byte-precise composite signature", () => {
    const { signingKey } = mlDsa65KeyPairDeterministic(KAT_MLDSA_SEED);
    const sig = _sigEd25519MldsaSignDeterministic(
      KAT_ED25519_SEED,
      signingKey,
      KAT_MESSAGE,
    );

    expect(sig.buf.length).toBe(KAT_SIGNATURE_LENGTH);
    expect(sha256Hash(WebBuf.fromUint8Array(sig.buf)).toHex()).toBe(
      KAT_SIGNATURE_SHA256,
    );
  });

  it("wire-format prefix matches the captured KAT", () => {
    const { signingKey } = mlDsa65KeyPairDeterministic(KAT_MLDSA_SEED);
    const sig = _sigEd25519MldsaSignDeterministic(
      KAT_ED25519_SEED,
      signingKey,
      KAT_MESSAGE,
    );

    // Version byte 0x01.
    expect(sig.buf[0]).toBe(SIG_ED25519_MLDSA.versionByte);
    expect(sig.buf[0]).toBe(0x01);

    // Ed25519 signature occupies bytes 1..65.
    expect(WebBuf.fromUint8Array(sig.buf.slice(1, 65)).toHex()).toBe(
      KAT_ED25519_SIG_HEX,
    );

    // ML-DSA signature begins at byte 65; check the first 16 bytes.
    expect(WebBuf.fromUint8Array(sig.buf.slice(65, 81)).toHex()).toBe(
      KAT_MLDSA_SIG_PREFIX_HEX,
    );
  });

  it("the captured composite signature verifies correctly", () => {
    const edPub = ed25519PublicKeyCreate(KAT_ED25519_SEED);
    const { signingKey, verifyingKey } =
      mlDsa65KeyPairDeterministic(KAT_MLDSA_SEED);
    const sig = _sigEd25519MldsaSignDeterministic(
      KAT_ED25519_SEED,
      signingKey,
      KAT_MESSAGE,
    );

    expect(
      sigEd25519MldsaVerify(edPub, verifyingKey, KAT_MESSAGE, sig),
    ).toBe(true);
  });
});
