import { describe, it, expect } from "vitest";
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  mlDsa44KeyPair,
  mlDsa44SignInternal,
  mlDsa44VerifyInternal,
  mlDsa65KeyPair,
  mlDsa65SignInternal,
  mlDsa65VerifyInternal,
  mlDsa87KeyPair,
  mlDsa87SignInternal,
  mlDsa87VerifyInternal,
} from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("ML-DSA round-trip", () => {
  it("ML-DSA-44 keygen + sign + verify", () => {
    const seed = FixedBuf.fromRandom(32);
    const rnd = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("test message");

    const { verifyingKey, signingKey } = mlDsa44KeyPair(seed);
    expect(verifyingKey.buf.length).toBe(ML_DSA_44.verifyingKeySize);
    expect(signingKey.buf.length).toBe(ML_DSA_44.signingKeySize);

    const sig = mlDsa44SignInternal(signingKey, message, rnd);
    expect(sig.buf.length).toBe(ML_DSA_44.signatureSize);

    expect(mlDsa44VerifyInternal(verifyingKey, message, sig)).toBe(true);
    expect(
      mlDsa44VerifyInternal(verifyingKey, WebBuf.fromUtf8("other"), sig),
    ).toBe(false);
  });

  it("ML-DSA-65 keygen + sign + verify", () => {
    const seed = FixedBuf.fromRandom(32);
    const rnd = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("test message 65");

    const { verifyingKey, signingKey } = mlDsa65KeyPair(seed);
    expect(verifyingKey.buf.length).toBe(ML_DSA_65.verifyingKeySize);
    expect(signingKey.buf.length).toBe(ML_DSA_65.signingKeySize);

    const sig = mlDsa65SignInternal(signingKey, message, rnd);
    expect(sig.buf.length).toBe(ML_DSA_65.signatureSize);

    expect(mlDsa65VerifyInternal(verifyingKey, message, sig)).toBe(true);
  });

  it("ML-DSA-87 keygen + sign + verify", () => {
    const seed = FixedBuf.fromRandom(32);
    const rnd = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("test message 87");

    const { verifyingKey, signingKey } = mlDsa87KeyPair(seed);
    expect(verifyingKey.buf.length).toBe(ML_DSA_87.verifyingKeySize);
    expect(signingKey.buf.length).toBe(ML_DSA_87.signingKeySize);

    const sig = mlDsa87SignInternal(signingKey, message, rnd);
    expect(sig.buf.length).toBe(ML_DSA_87.signatureSize);

    expect(mlDsa87VerifyInternal(verifyingKey, message, sig)).toBe(true);
  });

  it("same seed produces identical keypair (deterministic)", () => {
    const seed = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );

    const kp1 = mlDsa65KeyPair(seed);
    const kp2 = mlDsa65KeyPair(seed);
    expect(kp1.verifyingKey.toHex()).toBe(kp2.verifyingKey.toHex());
    expect(kp1.signingKey.toHex()).toBe(kp2.signingKey.toHex());
  });

  it("same rnd produces identical signature (deterministic internal sign)", () => {
    const seed = FixedBuf.fromHex(
      32,
      "0202020202020202020202020202020202020202020202020202020202020202",
    );
    const rnd = FixedBuf.fromHex(
      32,
      "0303030303030303030303030303030303030303030303030303030303030303",
    );
    const message = WebBuf.fromUtf8("deterministic");

    const { signingKey } = mlDsa65KeyPair(seed);
    const sig1 = mlDsa65SignInternal(signingKey, message, rnd);
    const sig2 = mlDsa65SignInternal(signingKey, message, rnd);
    expect(sig1.toHex()).toBe(sig2.toHex());
  });

  it("tampered signature rejected", () => {
    const seed = FixedBuf.fromRandom(32);
    const rnd = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("verify me");

    const { verifyingKey, signingKey } = mlDsa65KeyPair(seed);
    const sig = mlDsa65SignInternal(signingKey, message, rnd);

    const tamperedBytes = WebBuf.alloc(ML_DSA_65.signatureSize);
    tamperedBytes.set(sig.buf);
    tamperedBytes[0] = (tamperedBytes[0]! ^ 0xff) & 0xff;
    const tampered = FixedBuf.fromBuf(ML_DSA_65.signatureSize, tamperedBytes);

    expect(mlDsa65VerifyInternal(verifyingKey, message, tampered)).toBe(false);
  });
});
