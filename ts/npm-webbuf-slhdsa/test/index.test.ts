import { describe, it, expect } from "vitest";
import {
  SLH_DSA_SHA2_128F,
  SLH_DSA_SHAKE_192S,
  SLH_DSA_SHA2_256F,
  slhDsaSha2_128fKeyPair,
  slhDsaSha2_128fKeyPairDeterministic,
  slhDsaSha2_128fSign,
  slhDsaSha2_128fSignDeterministic,
  slhDsaSha2_128fSignInternal,
  slhDsaSha2_128fVerify,
  slhDsaSha2_128fVerifyInternal,
  slhDsaShake_192sKeyPair,
  slhDsaShake_192sSign,
  slhDsaShake_192sSignInternal,
  slhDsaShake_192sVerify,
  slhDsaShake_192sVerifyInternal,
  slhDsaSha2_256fKeyPair,
  slhDsaSha2_256fSign,
  slhDsaSha2_256fSignDeterministic,
  slhDsaSha2_256fVerify,
  slhDsaSha2_256fSignInternal,
  slhDsaSha2_256fVerifyInternal,
} from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("SLH-DSA round-trip", () => {
  it("SHA2-128f keygen + sign + verify", () => {
    const message = WebBuf.fromUtf8("hash-based test 128f");

    const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPair();
    expect(verifyingKey.buf.length).toBe(SLH_DSA_SHA2_128F.verifyingKeySize);
    expect(signingKey.buf.length).toBe(SLH_DSA_SHA2_128F.signingKeySize);

    const sig = slhDsaSha2_128fSign(signingKey, message);
    expect(sig.buf.length).toBe(SLH_DSA_SHA2_128F.signatureSize);

    expect(slhDsaSha2_128fVerify(verifyingKey, message, sig)).toBe(true);
    expect(
      slhDsaSha2_128fVerify(verifyingKey, WebBuf.fromUtf8("nope"), sig),
    ).toBe(false);
  });

  it("SHAKE-192s keygen + sign + verify with hedged rnd", () => {
    const message = WebBuf.fromUtf8("shake 192s hedged");

    const { verifyingKey, signingKey } = slhDsaShake_192sKeyPair();

    const sig = slhDsaShake_192sSign(signingKey, message);
    expect(sig.buf.length).toBe(SLH_DSA_SHAKE_192S.signatureSize);

    expect(slhDsaShake_192sVerify(verifyingKey, message, sig)).toBe(true);
  });

  it("SHA2-256f keygen + sign + verify", () => {
    const message = WebBuf.fromUtf8("256-bit security");

    const { verifyingKey, signingKey } = slhDsaSha2_256fKeyPair();

    const sig = slhDsaSha2_256fSign(signingKey, message);
    expect(sig.buf.length).toBe(SLH_DSA_SHA2_256F.signatureSize);

    expect(slhDsaSha2_256fVerify(verifyingKey, message, sig)).toBe(true);
  });

  it("deterministic aliases reproduce seeded compatibility", () => {
    const skSeed = FixedBuf.fromHex(16, "00000000000000000000000000000000");
    const skPrf = FixedBuf.fromHex(16, "01010101010101010101010101010101");
    const pkSeed = FixedBuf.fromHex(16, "02020202020202020202020202020202");
    const message = WebBuf.fromUtf8("deterministic");

    const { signingKey } = slhDsaSha2_128fKeyPair(skSeed, skPrf, pkSeed);
    const { signingKey: signingKey2 } = slhDsaSha2_128fKeyPairDeterministic(
      skSeed,
      skPrf,
      pkSeed,
    );
    expect(signingKey.toHex()).toBe(signingKey2.toHex());

    const sig1 = slhDsaSha2_128fSignDeterministic(signingKey, message);
    const sig2 = slhDsaSha2_128fSignDeterministic(signingKey, message);
    expect(sig1.toHex()).toBe(sig2.toHex());
  });

  it("default signing is hedged", () => {
    const message = WebBuf.fromUtf8("hedged by default");
    const { signingKey } = slhDsaSha2_128fKeyPair();

    const sig1 = slhDsaSha2_128fSign(signingKey, message);
    const sig2 = slhDsaSha2_128fSign(signingKey, message);
    expect(sig1.toHex()).not.toBe(sig2.toHex());
  });

  it("message-level signatures are context separated", () => {
    const message = WebBuf.fromUtf8("context-aware");
    const context = WebBuf.fromUtf8("webbuf");
    const wrongContext = WebBuf.fromUtf8("other");
    const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPair();

    const sig = slhDsaSha2_128fSign(signingKey, message, context);
    expect(slhDsaSha2_128fVerify(verifyingKey, message, sig, context)).toBe(
      true,
    );
    expect(
      slhDsaSha2_128fVerify(verifyingKey, message, sig, wrongContext),
    ).toBe(false);
    expect(slhDsaSha2_128fVerifyInternal(verifyingKey, message, sig)).toBe(
      false,
    );
  });

  it("contexts longer than 255 bytes are rejected", () => {
    const message = WebBuf.fromUtf8("too much context");
    const context = WebBuf.alloc(256);
    const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPair();

    expect(() => slhDsaSha2_128fSign(signingKey, message, context)).toThrow();
    expect(
      slhDsaSha2_128fVerify(
        verifyingKey,
        message,
        FixedBuf.alloc(SLH_DSA_SHA2_128F.signatureSize),
        context,
      ),
    ).toBe(false);
  });

  it("internal sign/verify remains available for ACVP-style use", () => {
    const skSeed = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const skPrf = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const pkSeed = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const rnd = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const message = WebBuf.fromUtf8("internal path");

    const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPairDeterministic(
      skSeed,
      skPrf,
      pkSeed,
    );
    const sig = slhDsaSha2_128fSignInternal(signingKey, message, rnd);
    expect(slhDsaSha2_128fVerifyInternal(verifyingKey, message, sig)).toBe(
      true,
    );
    expect(slhDsaSha2_128fVerify(verifyingKey, message, sig)).toBe(false);
  });

  it("deterministic high-level aliases are available for larger parameter sets", () => {
    const message = WebBuf.fromUtf8("larger deterministic");
    const context = WebBuf.fromUtf8("ctx");
    const { verifyingKey, signingKey } = slhDsaSha2_256fKeyPair();

    const sig1 = slhDsaSha2_256fSignDeterministic(signingKey, message, context);
    const sig2 = slhDsaSha2_256fSignDeterministic(signingKey, message, context);
    expect(sig1.toHex()).toBe(sig2.toHex());
    expect(slhDsaSha2_256fVerify(verifyingKey, message, sig1, context)).toBe(
      true,
    );
  });
});
