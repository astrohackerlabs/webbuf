import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  ed25519PublicKeyCreate,
  ed25519Sign,
  ed25519Verify,
} from "../src/index.js";

describe("@webbuf/ed25519 round-trip", () => {
  it("signs and verifies a random message with a random keypair", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const message = WebBuf.fromUtf8("hello, ed25519");

    const sig = ed25519Sign(priv, message);
    expect(ed25519Verify(pub, message, sig)).toBe(true);
  });

  it("produces 32-byte public keys and 64-byte signatures", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    expect(pub.buf.length).toBe(32);

    const sig = ed25519Sign(priv, WebBuf.fromUtf8("x"));
    expect(sig.buf.length).toBe(64);
  });

  it("public-key derivation is deterministic", () => {
    const priv = FixedBuf.fromHex(
      32,
      "11111111111111111111111111111111111111111111111111111111111111ff",
    );
    const pub1 = ed25519PublicKeyCreate(priv);
    const pub2 = ed25519PublicKeyCreate(priv);
    expect(pub1.toHex()).toBe(pub2.toHex());
  });

  it("signing is deterministic (PureEdDSA)", () => {
    const priv = FixedBuf.fromHex(
      32,
      "2222222222222222222222222222222222222222222222222222222222222222",
    );
    const message = WebBuf.fromUtf8("deterministic");
    const sig1 = ed25519Sign(priv, message);
    const sig2 = ed25519Sign(priv, message);
    expect(sig1.toHex()).toBe(sig2.toHex());
  });

  it("signs and verifies an empty message", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const empty = WebBuf.alloc(0);

    const sig = ed25519Sign(priv, empty);
    expect(ed25519Verify(pub, empty, sig)).toBe(true);
  });

  it("signs and verifies a 64 KiB message", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const big = WebBuf.alloc(64 * 1024);
    for (let i = 0; i < big.length; i++) {
      big[i] = i & 0xff;
    }

    const sig = ed25519Sign(priv, big);
    expect(ed25519Verify(pub, big, sig)).toBe(true);
  });
});

describe("@webbuf/ed25519 verification rejection paths", () => {
  it("returns false on tampered message", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const message = WebBuf.fromUtf8("original message");
    const sig = ed25519Sign(priv, message);

    const tampered = WebBuf.fromUint8Array(message);
    tampered[0] = ((tampered[0] ?? 0) ^ 0xff) & 0xff;
    expect(ed25519Verify(pub, tampered, sig)).toBe(false);
  });

  it("returns false on tampered signature R", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const message = WebBuf.fromUtf8("flip a bit");
    const sig = ed25519Sign(priv, message);

    const tamperedBuf = WebBuf.fromUint8Array(sig.buf);
    tamperedBuf[0] = ((tamperedBuf[0] ?? 0) ^ 0x01) & 0xff;
    const tampered = FixedBuf.fromBuf(64, tamperedBuf);
    expect(ed25519Verify(pub, message, tampered)).toBe(false);
  });

  it("returns false on tampered signature S", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const message = WebBuf.fromUtf8("flip another bit");
    const sig = ed25519Sign(priv, message);

    const tamperedBuf = WebBuf.fromUint8Array(sig.buf);
    tamperedBuf[40] = ((tamperedBuf[40] ?? 0) ^ 0x01) & 0xff;
    const tampered = FixedBuf.fromBuf(64, tamperedBuf);
    expect(ed25519Verify(pub, message, tampered)).toBe(false);
  });

  it("returns false on wrong public key", () => {
    const privA = FixedBuf.fromRandom<32>(32);
    const privB = FixedBuf.fromRandom<32>(32);
    const pubB = ed25519PublicKeyCreate(privB);
    const message = WebBuf.fromUtf8("for A only");
    const sig = ed25519Sign(privA, message);

    expect(ed25519Verify(pubB, message, sig)).toBe(false);
  });

  it("returns false on a public key that isn't a valid Ed25519 point", () => {
    // 32 0xff bytes — not on the curve.
    const badPub = FixedBuf.fromHex(
      32,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    const sig = FixedBuf.alloc(64);
    expect(ed25519Verify(badPub, WebBuf.fromUtf8("anything"), sig)).toBe(false);
  });

  it("returns false on a small-order public key (universal-forgery rejection)", () => {
    // Identity element on Curve25519: 01 || 00*31. Decompresses to a
    // valid-but-small-order point. The non-strict `verify` would accept
    // an identity-R / zero-S signature against ANY message — a universal
    // forgery. WebBuf calls `verify_strict` under the hood, which closes
    // this hole.
    const weakPub = FixedBuf.fromHex(
      32,
      "0100000000000000000000000000000000000000000000000000000000000000",
    );
    // R = identity (01 || 00*31), S = 0*32.
    const forgerySig = FixedBuf.fromHex(
      64,
      "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );

    for (const message of ["", "hello", "forged"]) {
      expect(
        ed25519Verify(weakPub, WebBuf.fromUtf8(message), forgerySig),
      ).toBe(false);
    }
  });

  it("returns false on an all-zero signature", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = ed25519PublicKeyCreate(priv);
    const zeroSig = FixedBuf.alloc(64);
    expect(ed25519Verify(pub, WebBuf.fromUtf8("hello"), zeroSig)).toBe(false);
  });
});
