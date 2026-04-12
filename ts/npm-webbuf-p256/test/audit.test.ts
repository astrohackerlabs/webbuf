/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Audit tests for @webbuf/p256
 *
 * These tests verify the P-256 (NIST) ECDSA implementation against:
 * 1. Known test vectors from cryptographic standards
 * 2. Cross-implementation verification with @noble/curves/p256
 * 3. Property-based tests for correctness
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  p256Sign,
  p256Verify,
  p256SharedSecret,
  p256PublicKeyAdd,
  p256PublicKeyCreate,
  p256PublicKeyVerify,
  p256PrivateKeyAdd,
  p256PrivateKeyVerify,
} from "../src/index.js";
import { blake3Hash } from "@webbuf/blake3";
import { p256 as noble } from "@noble/curves/p256";

describe("Audit: Known test vectors", () => {
  describe("p256PublicKeyCreate with known private keys", () => {
    it("should generate correct public key for private key 1", () => {
      // Private key = 1 should give the generator point G for P-256
      const privKey = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const pubKey = p256PublicKeyCreate(privKey);

      // P-256 Generator point G (compressed)
      // G.x = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
      // G.y ends in F5 (odd) so prefix is 03
      expect(pubKey.buf.length).toBe(33);
      expect(pubKey.buf[0]).toBe(0x03); // Odd y coordinate
      expect(pubKey.toHex().substring(2)).toBe(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      );
    });

    it("should generate correct public key for private key 2", () => {
      const privKey = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );
      const pubKey = p256PublicKeyCreate(privKey);

      expect(pubKey.buf.length).toBe(33);
      // Verify against noble
      const noblePubKey = noble.getPublicKey(privKey.buf, true);
      expect(pubKey.toHex()).toBe(WebBuf.fromUint8Array(noblePubKey).toHex());
    });

    it("should generate correct public key for private key 3", () => {
      const privKey = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000003",
      );
      const pubKey = p256PublicKeyCreate(privKey);

      // Verify against noble
      const noblePubKey = noble.getPublicKey(privKey.buf, true);
      expect(pubKey.toHex()).toBe(WebBuf.fromUint8Array(noblePubKey).toHex());
    });

    it("should match noble for a specific test private key", () => {
      const privKey = FixedBuf.fromHex(
        32,
        "d30519bcae8d180dbfcc94fe0b8383dc310185b0be97b4365083ebceccd75759",
      );
      const pubKey = p256PublicKeyCreate(privKey);

      const noblePubKey = noble.getPublicKey(privKey.buf, true);
      expect(pubKey.toHex()).toBe(WebBuf.fromUint8Array(noblePubKey).toHex());
    });
  });
});

describe("Audit: Cross-implementation verification with @noble/curves/p256", () => {
  describe("p256PublicKeyCreate", () => {
    it("should match noble for random private keys", () => {
      for (let i = 0; i < 10; i++) {
        const privKey = FixedBuf.fromRandom(32);

        if (!p256PrivateKeyVerify(privKey)) continue;

        const webbufPubKey = p256PublicKeyCreate(privKey);
        const noblePubKey = noble.getPublicKey(privKey.buf, true);

        expect(webbufPubKey.toHex()).toBe(
          WebBuf.fromUint8Array(noblePubKey).toHex(),
        );
      }
    });

    it("should match noble for specific edge case private keys", () => {
      const testKeys = [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", // n-1
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1111111111111111111111111111111111111111111111111111111111111111",
      ];

      for (const keyHex of testKeys) {
        const privKey = FixedBuf.fromHex(32, keyHex);
        const webbufPubKey = p256PublicKeyCreate(privKey);
        const noblePubKey = noble.getPublicKey(privKey.buf, true);

        expect(webbufPubKey.toHex()).toBe(
          WebBuf.fromUint8Array(noblePubKey).toHex(),
        );
      }
    });
  });

  describe("ECDH shared secret", () => {
    it("should produce matching shared secrets for ECDH", () => {
      for (let i = 0; i < 5; i++) {
        let privKey1 = FixedBuf.fromRandom(32);
        let privKey2 = FixedBuf.fromRandom(32);

        while (!p256PrivateKeyVerify(privKey1)) {
          privKey1 = FixedBuf.fromRandom(32);
        }
        while (!p256PrivateKeyVerify(privKey2)) {
          privKey2 = FixedBuf.fromRandom(32);
        }

        const pubKey1 = p256PublicKeyCreate(privKey1);
        const pubKey2 = p256PublicKeyCreate(privKey2);

        const shared1 = p256SharedSecret(privKey1, pubKey2);
        const shared2 = p256SharedSecret(privKey2, pubKey1);

        expect(shared1.toHex()).toBe(shared2.toHex());

        // Compare with noble
        const nobleShared = noble.getSharedSecret(
          privKey1.buf,
          pubKey2.buf,
          true,
        );
        expect(shared1.toHex()).toBe(
          WebBuf.fromUint8Array(nobleShared).toHex(),
        );
      }
    });
  });

  describe("signature verification", () => {
    it("should verify signatures correctly", () => {
      for (let i = 0; i < 5; i++) {
        let privKey = FixedBuf.fromRandom(32);
        while (!p256PrivateKeyVerify(privKey)) {
          privKey = FixedBuf.fromRandom(32);
        }

        const pubKey = p256PublicKeyCreate(privKey);
        const message = WebBuf.fromUtf8(`test message ${String(i)}`);
        const digest = blake3Hash(message);

        let k = FixedBuf.fromRandom(32);
        while (!p256PrivateKeyVerify(k)) {
          k = FixedBuf.fromRandom(32);
        }
        const signature = p256Sign(digest, privKey, k);

        expect(p256Verify(signature, digest, pubKey)).toBe(true);
      }
    });
  });
});

describe("Audit: Signature correctness", () => {
  it("should sign and verify correctly", () => {
    const privKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const pubKey = p256PublicKeyCreate(privKey);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const k = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000002",
    );
    const signature = p256Sign(digest, privKey, k);

    expect(signature.buf.length).toBe(64);
    expect(p256Verify(signature, digest, pubKey)).toBe(true);
  });

  it("should reject signature with wrong digest", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = p256PublicKeyCreate(privKey);
    const message1 = WebBuf.fromUtf8("message 1");
    const message2 = WebBuf.fromUtf8("message 2");
    const digest1 = blake3Hash(message1);
    const digest2 = blake3Hash(message2);

    const k = FixedBuf.fromRandom(32);
    const signature = p256Sign(digest1, privKey, k);

    expect(p256Verify(signature, digest1, pubKey)).toBe(true);
    expect(p256Verify(signature, digest2, pubKey)).toBe(false);
  });

  it("should reject signature with wrong public key", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const pubKey1 = p256PublicKeyCreate(privKey1);
    const pubKey2 = p256PublicKeyCreate(privKey2);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const k = FixedBuf.fromRandom(32);
    const signature = p256Sign(digest, privKey1, k);

    expect(p256Verify(signature, digest, pubKey1)).toBe(true);
    expect(p256Verify(signature, digest, pubKey2)).toBe(false);
  });

  it("should reject tampered signature", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = p256PublicKeyCreate(privKey);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const k = FixedBuf.fromRandom(32);
    const signature = p256Sign(digest, privKey, k);

    expect(p256Verify(signature, digest, pubKey)).toBe(true);

    const tamperedBytes = WebBuf.alloc(64);
    tamperedBytes.set(signature.buf);
    tamperedBytes[0]! ^= 0x01;
    const tamperedSig = FixedBuf.fromBuf(64, tamperedBytes);

    expect(p256Verify(tamperedSig, digest, pubKey)).toBe(false);
  });

  it("should reject random signature", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = p256PublicKeyCreate(privKey);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const randomSig = FixedBuf.fromRandom(64);
    expect(p256Verify(randomSig, digest, pubKey)).toBe(false);
  });
});

describe("Audit: Private key validation", () => {
  it("should accept valid private keys", () => {
    const validKeys = [
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", // n-1
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    for (const keyHex of validKeys) {
      const privKey = FixedBuf.fromHex(32, keyHex);
      expect(p256PrivateKeyVerify(privKey)).toBe(true);
    }
  });

  it("should reject zero private key", () => {
    const zeroKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    expect(p256PrivateKeyVerify(zeroKey)).toBe(false);
  });

  it("should reject private key >= n (curve order)", () => {
    // P-256 n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    const nKey = FixedBuf.fromHex(
      32,
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    expect(p256PrivateKeyVerify(nKey)).toBe(false);

    // n+1
    const nPlusOneKey = FixedBuf.fromHex(
      32,
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
    );
    expect(p256PrivateKeyVerify(nPlusOneKey)).toBe(false);
  });
});

describe("Audit: Public key validation", () => {
  it("should accept valid public keys", () => {
    for (let i = 0; i < 5; i++) {
      const privKey = FixedBuf.fromRandom(32);
      const pubKey = p256PublicKeyCreate(privKey);
      expect(p256PublicKeyVerify(pubKey)).toBe(true);
    }
  });

  it("should reject invalid public key prefix", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = p256PublicKeyCreate(privKey);
    const invalidPubKey = pubKey.clone();
    invalidPubKey.buf[0] = 0x04; // Invalid for compressed key

    expect(p256PublicKeyVerify(invalidPubKey)).toBe(false);
  });

  it("should reject invalid point (not on curve)", () => {
    // Construct a 33-byte key with valid prefix but x-coordinate not on the P-256 curve
    const invalidPubKey = FixedBuf.fromHex(
      33,
      "02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    expect(p256PublicKeyVerify(invalidPubKey)).toBe(false);
  });
});

describe("Audit: Key addition (HD wallet support)", () => {
  describe("p256PrivateKeyAdd", () => {
    it("should add private keys correctly", () => {
      const privKey1 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const privKey2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );

      const sum = p256PrivateKeyAdd(privKey1, privKey2);

      // 1 + 2 = 3
      expect(sum.toHex()).toBe(
        "0000000000000000000000000000000000000000000000000000000000000003",
      );
    });

    it("should wrap around curve order", () => {
      const privKey1 = FixedBuf.fromHex(
        32,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", // n-1
      );
      const privKey2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );

      const sum = p256PrivateKeyAdd(privKey1, privKey2);

      // (n-1) + 2 = n + 1 ≡ 1 (mod n)
      expect(sum.toHex()).toBe(
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
    });

    it("should produce valid private key from addition", () => {
      for (let i = 0; i < 5; i++) {
        const privKey1 = FixedBuf.fromRandom(32);
        const privKey2 = FixedBuf.fromRandom(32);

        if (!p256PrivateKeyVerify(privKey1) || !p256PrivateKeyVerify(privKey2))
          continue;

        const sum = p256PrivateKeyAdd(privKey1, privKey2);
        const pubKey = p256PublicKeyCreate(sum);
        expect(p256PublicKeyVerify(pubKey)).toBe(true);
      }
    });
  });

  describe("p256PublicKeyAdd", () => {
    it("should satisfy additive homomorphism: G*(a+b) = G*a + G*b", () => {
      const privKey1 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const privKey2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );

      const pubKey1 = p256PublicKeyCreate(privKey1);
      const pubKey2 = p256PublicKeyCreate(privKey2);

      const pubKeySum = p256PublicKeyAdd(pubKey1, pubKey2);

      const privKeySum = p256PrivateKeyAdd(privKey1, privKey2);
      const expectedPubKey = p256PublicKeyCreate(privKeySum);

      expect(pubKeySum.toHex()).toBe(expectedPubKey.toHex());
    });

    it("should satisfy additive homomorphism for random keys", () => {
      for (let i = 0; i < 5; i++) {
        let privKey1 = FixedBuf.fromRandom(32);
        let privKey2 = FixedBuf.fromRandom(32);

        while (!p256PrivateKeyVerify(privKey1)) {
          privKey1 = FixedBuf.fromRandom(32);
        }
        while (!p256PrivateKeyVerify(privKey2)) {
          privKey2 = FixedBuf.fromRandom(32);
        }

        const pubKey1 = p256PublicKeyCreate(privKey1);
        const pubKey2 = p256PublicKeyCreate(privKey2);

        const pubKeySum = p256PublicKeyAdd(pubKey1, pubKey2);
        const privKeySum = p256PrivateKeyAdd(privKey1, privKey2);
        const expectedPubKey = p256PublicKeyCreate(privKeySum);

        expect(pubKeySum.toHex()).toBe(expectedPubKey.toHex());
      }
    });
  });
});

describe("Audit: ECDH (Diffie-Hellman)", () => {
  it("should produce equal shared secrets for both parties", () => {
    for (let i = 0; i < 10; i++) {
      const alicePriv = FixedBuf.fromRandom(32);
      const bobPriv = FixedBuf.fromRandom(32);

      const alicePub = p256PublicKeyCreate(alicePriv);
      const bobPub = p256PublicKeyCreate(bobPriv);

      const aliceShared = p256SharedSecret(alicePriv, bobPub);
      const bobShared = p256SharedSecret(bobPriv, alicePub);

      expect(aliceShared.toHex()).toBe(bobShared.toHex());
    }
  });

  it("should produce different shared secrets for different key pairs", () => {
    const alice1Priv = FixedBuf.fromRandom(32);
    const alice2Priv = FixedBuf.fromRandom(32);
    const bobPriv = FixedBuf.fromRandom(32);

    p256PublicKeyCreate(alice1Priv);
    p256PublicKeyCreate(alice2Priv);
    const bobPub = p256PublicKeyCreate(bobPriv);

    const shared1 = p256SharedSecret(alice1Priv, bobPub);
    const shared2 = p256SharedSecret(alice2Priv, bobPub);

    expect(shared1.toHex()).not.toBe(shared2.toHex());
  });

  it("should produce 33-byte compressed point as shared secret", () => {
    const alicePriv = FixedBuf.fromRandom(32);
    const bobPriv = FixedBuf.fromRandom(32);

    const bobPub = p256PublicKeyCreate(bobPriv);
    const shared = p256SharedSecret(alicePriv, bobPub);

    expect(shared.buf.length).toBe(33);
    expect([0x02, 0x03]).toContain(shared.buf[0]);
  });
});

describe("Audit: Output sizes", () => {
  it("p256PublicKeyCreate should produce 33-byte compressed public key", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = p256PublicKeyCreate(privKey);
    expect(pubKey.buf.length).toBe(33);
  });

  it("p256Sign should produce 64-byte signature", () => {
    const privKey = FixedBuf.fromRandom(32);
    const digest = FixedBuf.fromRandom(32);
    const k = FixedBuf.fromRandom(32);
    const signature = p256Sign(digest, privKey, k);
    expect(signature.buf.length).toBe(64);
  });

  it("p256SharedSecret should produce 33-byte compressed point", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = p256PublicKeyCreate(FixedBuf.fromRandom(32));
    const shared = p256SharedSecret(privKey, pubKey);
    expect(shared.buf.length).toBe(33);
  });

  it("p256PrivateKeyAdd should produce 32-byte private key", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const sum = p256PrivateKeyAdd(privKey1, privKey2);
    expect(sum.buf.length).toBe(32);
  });

  it("p256PublicKeyAdd should produce 33-byte compressed public key", () => {
    const pubKey1 = p256PublicKeyCreate(FixedBuf.fromRandom(32));
    const pubKey2 = p256PublicKeyCreate(FixedBuf.fromRandom(32));
    const sum = p256PublicKeyAdd(pubKey1, pubKey2);
    expect(sum.buf.length).toBe(33);
  });
});

describe("Audit: Determinism", () => {
  it("p256PublicKeyCreate should be deterministic", () => {
    const privKey = FixedBuf.fromHex(
      32,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const pubKey1 = p256PublicKeyCreate(privKey);
    const pubKey2 = p256PublicKeyCreate(privKey);
    expect(pubKey1.toHex()).toBe(pubKey2.toHex());
  });

  it("p256Sign should be deterministic for same k", () => {
    const privKey = FixedBuf.fromHex(
      32,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const digest = FixedBuf.fromHex(
      32,
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    const k = FixedBuf.fromHex(
      32,
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    );

    const sig1 = p256Sign(digest, privKey, k);
    const sig2 = p256Sign(digest, privKey, k);
    expect(sig1.toHex()).toBe(sig2.toHex());
  });

  it("p256SharedSecret should be deterministic", () => {
    const privKey = FixedBuf.fromHex(
      32,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const otherPriv = FixedBuf.fromHex(
      32,
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    const otherPub = p256PublicKeyCreate(otherPriv);

    const shared1 = p256SharedSecret(privKey, otherPub);
    const shared2 = p256SharedSecret(privKey, otherPub);
    expect(shared1.toHex()).toBe(shared2.toHex());
  });
});
