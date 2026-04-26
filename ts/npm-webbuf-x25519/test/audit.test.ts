/**
 * Audit tests for @webbuf/x25519
 *
 * Reproduces the canonical RFC 7748 test vectors:
 *
 *   §5.2 — single-iteration scalar/u-coordinate vector.
 *   §6.1 — Alice / Bob worked example with the published shared secret.
 *
 * These vectors are stable in the RFC and provide byte-precise
 * regression coverage for the X25519 ECDH primitive.
 */
import { describe, it, expect } from "vitest";
import { FixedBuf } from "@webbuf/fixedbuf";
import { x25519PublicKeyCreate, x25519SharedSecretRaw } from "../src/index.js";

describe("Audit: RFC 7748 §6.1 Alice/Bob worked example", () => {
  const ALICE_PRIV = FixedBuf.fromHex(
    32,
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  );
  const ALICE_PUB_EXPECTED =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

  const BOB_PRIV = FixedBuf.fromHex(
    32,
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  );
  const BOB_PUB_EXPECTED =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

  const SHARED_EXPECTED =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  it("derives Alice's published public key", () => {
    expect(x25519PublicKeyCreate(ALICE_PRIV).toHex()).toBe(ALICE_PUB_EXPECTED);
  });

  it("derives Bob's published public key", () => {
    expect(x25519PublicKeyCreate(BOB_PRIV).toHex()).toBe(BOB_PUB_EXPECTED);
  });

  it("derives the published shared secret in both directions", () => {
    const bobPub = FixedBuf.fromHex(32, BOB_PUB_EXPECTED);
    const alicePub = FixedBuf.fromHex(32, ALICE_PUB_EXPECTED);

    expect(x25519SharedSecretRaw(ALICE_PRIV, bobPub).toHex()).toBe(
      SHARED_EXPECTED,
    );
    expect(x25519SharedSecretRaw(BOB_PRIV, alicePub).toHex()).toBe(
      SHARED_EXPECTED,
    );
  });
});

describe("Audit: RFC 7748 §5.2 single-iteration vector", () => {
  // Input scalar (= private key, accepted as-is and clamped internally).
  const SCALAR = FixedBuf.fromHex(
    32,
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  );
  // Input u-coordinate (= peer public key bytes).
  const U_IN = FixedBuf.fromHex(
    32,
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  );
  // Output u-coordinate (= shared secret bytes).
  const U_OUT_EXPECTED =
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

  it("produces the published output u-coordinate", () => {
    expect(x25519SharedSecretRaw(SCALAR, U_IN).toHex()).toBe(U_OUT_EXPECTED);
  });
});
