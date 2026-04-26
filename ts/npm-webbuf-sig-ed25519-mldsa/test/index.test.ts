import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { ed25519PublicKeyCreate } from "@webbuf/ed25519";
import { mlDsa65KeyPair } from "@webbuf/mldsa";
import {
  SIG_ED25519_MLDSA,
  sigEd25519MldsaSign,
  sigEd25519MldsaVerify,
} from "../src/index.js";

function freshSetup() {
  const edPriv = FixedBuf.fromRandom<32>(32);
  const edPub = ed25519PublicKeyCreate(edPriv);
  const mldsa = mlDsa65KeyPair();
  return {
    edPriv,
    edPub,
    mldsaSigningKey: mldsa.signingKey,
    mldsaVerifyingKey: mldsa.verifyingKey,
  };
}

describe("sig-ed25519-mldsa round-trip", () => {
  it("signs and verifies a random message with random keys", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("composite signature");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);
    expect(sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, message, sig))
      .toBe(true);
  });

  it("signs and verifies an empty message", () => {
    const s = freshSetup();
    const empty = WebBuf.alloc(0);
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, empty);
    expect(sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, empty, sig))
      .toBe(true);
  });

  it("signs and verifies a 64 KiB message", () => {
    const s = freshSetup();
    const big = WebBuf.alloc(64 * 1024);
    for (let i = 0; i < big.length; i++) {
      big[i] = i & 0xff;
    }
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, big);
    expect(sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, big, sig))
      .toBe(true);
  });

  it("signature is exactly 3374 bytes", () => {
    const s = freshSetup();
    const sig = sigEd25519MldsaSign(
      s.edPriv,
      s.mldsaSigningKey,
      WebBuf.fromUtf8("x"),
    );
    expect(sig.buf.length).toBe(SIG_ED25519_MLDSA.fixedSize);
    expect(sig.buf.length).toBe(3374);
  });

  it("signature begins with version byte 0x01", () => {
    const s = freshSetup();
    const sig = sigEd25519MldsaSign(
      s.edPriv,
      s.mldsaSigningKey,
      WebBuf.fromUtf8("x"),
    );
    expect(sig.buf[0]).toBe(SIG_ED25519_MLDSA.versionByte);
    expect(sig.buf[0]).toBe(0x01);
  });

  it("constants object reports the expected sizes", () => {
    expect(SIG_ED25519_MLDSA.ed25519SignatureSize).toBe(64);
    expect(SIG_ED25519_MLDSA.mldsaSignatureSize).toBe(3309);
    expect(SIG_ED25519_MLDSA.fixedSize).toBe(3374);
    expect(SIG_ED25519_MLDSA.ed25519PublicKeySize).toBe(32);
    expect(SIG_ED25519_MLDSA.mldsaVerifyingKeySize).toBe(1952);
    expect(SIG_ED25519_MLDSA.mldsaSigningKeySize).toBe(4032);
  });

  it("default sign is non-deterministic (ML-DSA half hedged)", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("repeat me");
    const sig1 = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);
    const sig2 = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);
    // Composite signatures differ because ML-DSA is hedged by default.
    expect(sig1.toHex()).not.toBe(sig2.toHex());
    // The Ed25519 halves (bytes 1..65) are byte-identical because
    // PureEdDSA is RFC-deterministic.
    const ed1 = sig1.buf.slice(1, 65);
    const ed2 = sig2.buf.slice(1, 65);
    expect(WebBuf.fromUint8Array(ed1).toHex()).toBe(
      WebBuf.fromUint8Array(ed2).toHex(),
    );
  });
});

describe("sig-ed25519-mldsa hybrid defense-in-depth", () => {
  it("Ed25519 is load-bearing: wrong Ed25519 pub fails verification", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("needs both keys");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);

    const wrongEdPriv = FixedBuf.fromRandom<32>(32);
    const wrongEdPub = ed25519PublicKeyCreate(wrongEdPriv);

    // Right ML-DSA verify key, wrong Ed25519 pub → verification must
    // fail. Without the Ed25519 half's check, this would succeed and
    // the "hybrid" claim would be false.
    expect(
      sigEd25519MldsaVerify(wrongEdPub, s.mldsaVerifyingKey, message, sig),
    ).toBe(false);
  });

  it("ML-DSA is load-bearing: wrong ML-DSA verify key fails verification", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("needs both keys");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);

    const otherMldsa = mlDsa65KeyPair();

    // Right Ed25519 pub, wrong ML-DSA verifying key → verification
    // must fail. Without the ML-DSA half's check, this would succeed
    // and the "hybrid" claim would be false.
    expect(
      sigEd25519MldsaVerify(s.edPub, otherMldsa.verifyingKey, message, sig),
    ).toBe(false);
  });

  it("tampering just the Ed25519 half (signature[1..65]) fails", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("tamper Ed25519 half");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);

    const tamperedBuf = WebBuf.fromUint8Array(sig.buf);
    // Flip a byte in the Ed25519 R portion (byte 1).
    tamperedBuf[1] = ((tamperedBuf[1] ?? 0) ^ 0x01) & 0xff;
    const tampered = FixedBuf.fromBuf(3374, tamperedBuf);

    expect(
      sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, message, tampered),
    ).toBe(false);
  });

  it("tampering just the ML-DSA half (signature[65..3374]) fails", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("tamper ML-DSA half");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);

    const tamperedBuf = WebBuf.fromUint8Array(sig.buf);
    // Flip a byte deep inside the ML-DSA half.
    tamperedBuf[200] = ((tamperedBuf[200] ?? 0) ^ 0x01) & 0xff;
    const tampered = FixedBuf.fromBuf(3374, tamperedBuf);

    expect(
      sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, message, tampered),
    ).toBe(false);
  });

  it("tampering the version byte fails", () => {
    const s = freshSetup();
    const message = WebBuf.fromUtf8("tamper version");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);

    for (const wrongVersion of [0x00, 0x02, 0xff]) {
      const tamperedBuf = WebBuf.fromUint8Array(sig.buf);
      tamperedBuf[0] = wrongVersion;
      const tampered = FixedBuf.fromBuf(3374, tamperedBuf);
      expect(
        sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, message, tampered),
      ).toBe(false);
    }
  });
});

describe("sig-ed25519-mldsa rejection paths", () => {
  it("tampered message rejected", () => {
    const s = freshSetup();
    const original = WebBuf.fromUtf8("original message");
    const sig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, original);

    const tampered = WebBuf.fromUint8Array(original);
    tampered[0] = ((tampered[0] ?? 0) ^ 0xff) & 0xff;

    expect(
      sigEd25519MldsaVerify(s.edPub, s.mldsaVerifyingKey, tampered, sig),
    ).toBe(false);
  });

  it("strict Ed25519 inheritance: small-order pub key universal-forgery rejected", () => {
    // The issue-0007-Codex universal-forgery test: identity-element
    // Ed25519 public key (01 || 00*31) + identity-R / zero-S Ed25519
    // signature half + arbitrary ML-DSA half. The composite verifier
    // must reject this regardless of the ML-DSA side, because the
    // Ed25519 strict-verify path closes the small-order forgery hole.
    const s = freshSetup();
    const message = WebBuf.fromUtf8("forged");

    const weakEdPub = FixedBuf.fromHex(
      32,
      "0100000000000000000000000000000000000000000000000000000000000000",
    );
    // Build a "signature" with an Ed25519 forgery prefix and any ML-DSA
    // signature (we use a real one signed by the random ML-DSA key just
    // to keep the bytes parseable; the Ed25519 half should be rejected
    // before the ML-DSA half matters).
    const realSig = sigEd25519MldsaSign(s.edPriv, s.mldsaSigningKey, message);

    const forgeryBuf = WebBuf.fromUint8Array(realSig.buf);
    forgeryBuf[0] = 0x01; // version
    // R = identity (01 || 00*31), S = zeros.
    forgeryBuf[1] = 0x01;
    for (let i = 2; i < 1 + 64; i++) {
      forgeryBuf[i] = 0;
    }
    const forgery = FixedBuf.fromBuf(3374, forgeryBuf);

    expect(
      sigEd25519MldsaVerify(weakEdPub, s.mldsaVerifyingKey, message, forgery),
    ).toBe(false);
  });
});
