import { describe, it, expect } from "vitest";
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  mlDsa44KeyPair,
  mlDsa44KeyPairDeterministic,
  mlDsa44Sign,
  mlDsa44SignDeterministic,
  mlDsa44SignInternal,
  mlDsa44Verify,
  mlDsa44VerifyInternal,
  mlDsa65KeyPair,
  mlDsa65KeyPairDeterministic,
  mlDsa65Sign,
  mlDsa65SignDeterministic,
  mlDsa65SignInternal,
  mlDsa65Verify,
  mlDsa65VerifyInternal,
  mlDsa87KeyPair,
  mlDsa87KeyPairDeterministic,
  mlDsa87Sign,
  mlDsa87SignDeterministic,
  mlDsa87SignInternal,
  mlDsa87Verify,
  mlDsa87VerifyInternal,
} from "../src/index.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("ML-DSA round-trip", () => {
  it("ML-DSA-44 keygen + sign + verify", () => {
    const message = WebBuf.fromUtf8("test message");

    const { verifyingKey, signingKey } = mlDsa44KeyPair();
    expect(verifyingKey.buf.length).toBe(ML_DSA_44.verifyingKeySize);
    expect(signingKey.buf.length).toBe(ML_DSA_44.signingKeySize);

    const sig = mlDsa44Sign(signingKey, message);
    expect(sig.buf.length).toBe(ML_DSA_44.signatureSize);

    expect(mlDsa44Verify(verifyingKey, message, sig)).toBe(true);
    expect(mlDsa44Verify(verifyingKey, WebBuf.fromUtf8("other"), sig)).toBe(
      false,
    );
  });

  it("ML-DSA-65 keygen + sign + verify", () => {
    const message = WebBuf.fromUtf8("test message 65");

    const { verifyingKey, signingKey } = mlDsa65KeyPair();
    expect(verifyingKey.buf.length).toBe(ML_DSA_65.verifyingKeySize);
    expect(signingKey.buf.length).toBe(ML_DSA_65.signingKeySize);

    const sig = mlDsa65Sign(signingKey, message);
    expect(sig.buf.length).toBe(ML_DSA_65.signatureSize);

    expect(mlDsa65Verify(verifyingKey, message, sig)).toBe(true);
  });

  it("ML-DSA-87 keygen + sign + verify", () => {
    const message = WebBuf.fromUtf8("test message 87");

    const { verifyingKey, signingKey } = mlDsa87KeyPair();
    expect(verifyingKey.buf.length).toBe(ML_DSA_87.verifyingKeySize);
    expect(signingKey.buf.length).toBe(ML_DSA_87.signingKeySize);

    const sig = mlDsa87Sign(signingKey, message);
    expect(sig.buf.length).toBe(ML_DSA_87.signatureSize);

    expect(mlDsa87Verify(verifyingKey, message, sig)).toBe(true);
  });

  it("deterministic keypair aliases reproduce the compatibility overloads", () => {
    const seed = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );

    const kp1 = mlDsa65KeyPair(seed);
    const kp2 = mlDsa65KeyPairDeterministic(seed);
    expect(kp1.verifyingKey.toHex()).toBe(kp2.verifyingKey.toHex());
    expect(kp1.signingKey.toHex()).toBe(kp2.signingKey.toHex());
  });

  it("default sign is hedged: same key + message produces different signatures", () => {
    const seed = FixedBuf.fromHex(
      32,
      "0202020202020202020202020202020202020202020202020202020202020202",
    );
    const message = WebBuf.fromUtf8("hedged");
    const context = WebBuf.fromUtf8("domain");

    const { verifyingKey, signingKey } = mlDsa65KeyPair(seed);
    const sig1 = mlDsa65Sign(signingKey, message, context);
    const sig2 = mlDsa65Sign(signingKey, message, context);
    expect(sig1.toHex()).not.toBe(sig2.toHex());
    expect(mlDsa65Verify(verifyingKey, message, sig1, context)).toBe(true);
    expect(mlDsa65Verify(verifyingKey, message, sig2, context)).toBe(true);
    expect(mlDsa65VerifyInternal(verifyingKey, message, sig1)).toBe(false);
  });

  it("SignDeterministic is reproducible: same key + message produces identical signatures", () => {
    const seed = FixedBuf.fromHex(
      32,
      "0202020202020202020202020202020202020202020202020202020202020202",
    );
    const message = WebBuf.fromUtf8("deterministic");
    const context = WebBuf.fromUtf8("domain");

    const { verifyingKey, signingKey } = mlDsa65KeyPair(seed);
    const sig1 = mlDsa65SignDeterministic(signingKey, message, context);
    const sig2 = mlDsa65SignDeterministic(signingKey, message, context);
    expect(sig1.toHex()).toBe(sig2.toHex());
    expect(mlDsa65Verify(verifyingKey, message, sig1, context)).toBe(true);
  });

  it("message-level signatures are context separated", () => {
    const message = WebBuf.fromUtf8("context-aware message");
    const context = WebBuf.fromUtf8("webbuf");
    const wrongContext = WebBuf.fromUtf8("other");

    const { verifyingKey, signingKey } = mlDsa65KeyPair();
    const sig = mlDsa65Sign(signingKey, message, context);

    expect(mlDsa65Verify(verifyingKey, message, sig, context)).toBe(true);
    expect(mlDsa65Verify(verifyingKey, message, sig, wrongContext)).toBe(false);
    expect(mlDsa65VerifyInternal(verifyingKey, message, sig)).toBe(false);
  });

  it("contexts longer than 255 bytes are rejected", () => {
    const message = WebBuf.fromUtf8("too much context");
    const longContext = WebBuf.alloc(256);

    const { verifyingKey, signingKey } = mlDsa44KeyPair();
    expect(() => mlDsa44Sign(signingKey, message, longContext)).toThrow();
    expect(
      mlDsa44Verify(
        verifyingKey,
        message,
        FixedBuf.alloc(ML_DSA_44.signatureSize),
        longContext,
      ),
    ).toBe(false);
  });

  it("no-argument keypairs use fresh randomness", () => {
    const kp1 = mlDsa87KeyPair();
    const kp2 = mlDsa87KeyPair();
    expect(kp1.verifyingKey.toHex()).not.toBe(kp2.verifyingKey.toHex());
  });

  it("deterministic aliases are available for all parameter sets", () => {
    const seed = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("all levels");
    const context = WebBuf.fromUtf8("ctx");

    const kp44 = mlDsa44KeyPairDeterministic(seed);
    const sig44 = mlDsa44SignDeterministic(kp44.signingKey, message, context);
    expect(mlDsa44Verify(kp44.verifyingKey, message, sig44, context)).toBe(
      true,
    );

    const kp87 = mlDsa87KeyPairDeterministic(seed);
    const sig87 = mlDsa87SignDeterministic(kp87.signingKey, message, context);
    expect(mlDsa87Verify(kp87.verifyingKey, message, sig87, context)).toBe(
      true,
    );
  });

  it("internal sign/verify remains available for ACVP-style use", () => {
    const seed = FixedBuf.fromRandom(32);
    const rnd = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("internal path");

    const { verifyingKey, signingKey } = mlDsa65KeyPairDeterministic(seed);
    const sig = mlDsa65SignInternal(signingKey, message, rnd);
    expect(mlDsa65VerifyInternal(verifyingKey, message, sig)).toBe(true);
    expect(mlDsa65Verify(verifyingKey, message, sig)).toBe(false);
  });

  it("tampered signature rejected", () => {
    const seed = FixedBuf.fromRandom(32);
    const message = WebBuf.fromUtf8("verify me");

    const { verifyingKey, signingKey } = mlDsa65KeyPair(seed);
    const sig = mlDsa65Sign(signingKey, message);

    const tamperedBytes = WebBuf.alloc(ML_DSA_65.signatureSize);
    tamperedBytes.set(sig.buf);
    tamperedBytes[0] = (tamperedBytes[0]! ^ 0xff) & 0xff;
    const tampered = FixedBuf.fromBuf(ML_DSA_65.signatureSize, tamperedBytes);

    expect(mlDsa65Verify(verifyingKey, message, tampered)).toBe(false);
  });
});
