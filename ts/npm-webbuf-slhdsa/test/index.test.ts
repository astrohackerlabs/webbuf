import { describe, it, expect } from "vitest";
import {
  SLH_DSA_SHA2_128F,
  SLH_DSA_SHAKE_192S,
  SLH_DSA_SHA2_256F,
  slhDsaSha2_128fKeyPair,
  slhDsaSha2_128fSignInternal,
  slhDsaSha2_128fVerifyInternal,
  slhDsaShake_192sKeyPair,
  slhDsaShake_192sSignInternal,
  slhDsaShake_192sVerifyInternal,
  slhDsaSha2_256fKeyPair,
  slhDsaSha2_256fSignInternal,
  slhDsaSha2_256fVerifyInternal,
} from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("SLH-DSA round-trip", () => {
  it("SHA2-128f keygen + sign + verify", () => {
    const skSeed = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const skPrf = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const pkSeed = FixedBuf.fromRandom(SLH_DSA_SHA2_128F.seedSize);
    const message = WebBuf.fromUtf8("hash-based test 128f");

    const { verifyingKey, signingKey } = slhDsaSha2_128fKeyPair(
      skSeed,
      skPrf,
      pkSeed,
    );
    expect(verifyingKey.buf.length).toBe(SLH_DSA_SHA2_128F.verifyingKeySize);
    expect(signingKey.buf.length).toBe(SLH_DSA_SHA2_128F.signingKeySize);

    const sig = slhDsaSha2_128fSignInternal(signingKey, message);
    expect(sig.buf.length).toBe(SLH_DSA_SHA2_128F.signatureSize);

    expect(slhDsaSha2_128fVerifyInternal(verifyingKey, message, sig)).toBe(
      true,
    );
    expect(
      slhDsaSha2_128fVerifyInternal(verifyingKey, WebBuf.fromUtf8("nope"), sig),
    ).toBe(false);
  });

  it("SHAKE-192s keygen + sign + verify with hedged rnd", () => {
    const skSeed = FixedBuf.fromRandom(SLH_DSA_SHAKE_192S.seedSize);
    const skPrf = FixedBuf.fromRandom(SLH_DSA_SHAKE_192S.seedSize);
    const pkSeed = FixedBuf.fromRandom(SLH_DSA_SHAKE_192S.seedSize);
    const rnd = FixedBuf.fromRandom(SLH_DSA_SHAKE_192S.seedSize);
    const message = WebBuf.fromUtf8("shake 192s hedged");

    const { verifyingKey, signingKey } = slhDsaShake_192sKeyPair(
      skSeed,
      skPrf,
      pkSeed,
    );

    const sig = slhDsaShake_192sSignInternal(signingKey, message, rnd);
    expect(sig.buf.length).toBe(SLH_DSA_SHAKE_192S.signatureSize);

    expect(slhDsaShake_192sVerifyInternal(verifyingKey, message, sig)).toBe(
      true,
    );
  });

  it("SHA2-256f keygen + sign + verify", () => {
    const skSeed = FixedBuf.fromRandom(SLH_DSA_SHA2_256F.seedSize);
    const skPrf = FixedBuf.fromRandom(SLH_DSA_SHA2_256F.seedSize);
    const pkSeed = FixedBuf.fromRandom(SLH_DSA_SHA2_256F.seedSize);
    const message = WebBuf.fromUtf8("256-bit security");

    const { verifyingKey, signingKey } = slhDsaSha2_256fKeyPair(
      skSeed,
      skPrf,
      pkSeed,
    );

    const sig = slhDsaSha2_256fSignInternal(signingKey, message);
    expect(sig.buf.length).toBe(SLH_DSA_SHA2_256F.signatureSize);

    expect(slhDsaSha2_256fVerifyInternal(verifyingKey, message, sig)).toBe(
      true,
    );
  });

  it("deterministic signing without addrnd produces same sig twice", () => {
    const skSeed = FixedBuf.fromHex(
      16,
      "00000000000000000000000000000000",
    );
    const skPrf = FixedBuf.fromHex(16, "01010101010101010101010101010101");
    const pkSeed = FixedBuf.fromHex(
      16,
      "02020202020202020202020202020202",
    );
    const message = WebBuf.fromUtf8("deterministic");

    const { signingKey } = slhDsaSha2_128fKeyPair(skSeed, skPrf, pkSeed);
    const sig1 = slhDsaSha2_128fSignInternal(signingKey, message);
    const sig2 = slhDsaSha2_128fSignInternal(signingKey, message);
    expect(sig1.toHex()).toBe(sig2.toHex());
  });
});
