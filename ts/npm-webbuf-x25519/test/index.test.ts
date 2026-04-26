import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { x25519PublicKeyCreate, x25519SharedSecretRaw } from "../src/index.js";

describe("@webbuf/x25519 round-trip", () => {
  it("derives matching shared secrets between two random keypairs", () => {
    const privA = FixedBuf.fromRandom<32>(32);
    const privB = FixedBuf.fromRandom<32>(32);
    const pubA = x25519PublicKeyCreate(privA);
    const pubB = x25519PublicKeyCreate(privB);

    const ssA = x25519SharedSecretRaw(privA, pubB);
    const ssB = x25519SharedSecretRaw(privB, pubA);

    expect(ssA.toHex()).toBe(ssB.toHex());
  });

  it("produces 32-byte public keys and shared secrets", () => {
    const priv = FixedBuf.fromRandom<32>(32);
    const pub = x25519PublicKeyCreate(priv);
    expect(pub.buf.length).toBe(32);

    const peerPriv = FixedBuf.fromRandom<32>(32);
    const peerPub = x25519PublicKeyCreate(peerPriv);
    const ss = x25519SharedSecretRaw(priv, peerPub);
    expect(ss.buf.length).toBe(32);
  });

  it("public-key derivation is deterministic for a fixed private key", () => {
    const priv = FixedBuf.fromHex(
      32,
      "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    );
    const pub1 = x25519PublicKeyCreate(priv);
    const pub2 = x25519PublicKeyCreate(priv);
    expect(pub1.toHex()).toBe(pub2.toHex());
  });
});

describe("@webbuf/x25519 small-order rejection", () => {
  // The seven canonical small-order Curve25519 u-coordinates from
  // Cremers & Jackson, "Prime, Order Please!" (2019) and Adam Langley's
  // curves-list notes. Each must cause `x25519SharedSecretRaw` to throw
  // with the contributory-check error.
  const SMALL_ORDER_POINTS = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  ];

  const LOCAL_PRIV = FixedBuf.fromHex(
    32,
    "0101010101010101010101010101010101010101010101010101010101010101",
  );

  for (const u of SMALL_ORDER_POINTS) {
    it(`rejects small-order public key u=${u.slice(0, 16)}…`, () => {
      const peerPub = FixedBuf.fromHex(32, u);
      expect(() => x25519SharedSecretRaw(LOCAL_PRIV, peerPub)).toThrow(
        /non-contributory/,
      );
    });
  }
});

describe("@webbuf/x25519 input validation", () => {
  it("throws on non-32-byte private key (via FixedBuf size mismatch)", () => {
    // FixedBuf.fromBuf enforces the size at the type/runtime layer, so the
    // private-key length error originates from FixedBuf, not from the WASM
    // side. The WASM-side length checks are exercised by the Rust tests.
    expect(() => FixedBuf.fromBuf(32, WebBuf.alloc(31))).toThrow();
  });
});
