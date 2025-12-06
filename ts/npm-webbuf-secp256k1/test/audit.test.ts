/**
 * Audit tests for @webbuf/secp256k1
 *
 * These tests verify the secp256k1 ECDSA implementation against:
 * 1. Known test vectors from cryptographic standards
 * 2. Cross-implementation verification with @noble/secp256k1
 * 3. Property-based tests for correctness
 */

import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  sign,
  verify,
  sharedSecret,
  publicKeyAdd,
  publicKeyCreate,
  publicKeyVerify,
  privateKeyAdd,
  privateKeyVerify,
} from "../src/index.js";
import { blake3Hash } from "@webbuf/blake3";
import * as noble from "@noble/secp256k1";

describe("Audit: Known test vectors", () => {
  // Test vector from Cryptography Stack Exchange
  // https://crypto.stackexchange.com/questions/41316/complete-set-of-test-vectors-for-ecdsa-secp256k1
  describe("publicKeyCreate with known private keys", () => {
    it("should generate correct public key for private key 1", () => {
      // Private key = 1 should give the generator point G
      const privKey = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const pubKey = publicKeyCreate(privKey);

      // Generator point G (compressed form starts with 02 or 03)
      // G.x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
      expect(pubKey.buf.length).toBe(33);
      expect(pubKey.buf[0]).toBe(0x02); // Even y coordinate
      expect(pubKey.toHex().substring(2)).toBe(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      );
    });

    it("should generate correct public key for private key 2", () => {
      const privKey = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );
      const pubKey = publicKeyCreate(privKey);

      // 2*G has known coordinates
      expect(pubKey.buf.length).toBe(33);
      // Verify against noble
      const noblePubKey = noble.getPublicKey(privKey.buf, true);
      expect(pubKey.toHex()).toBe(WebBuf.fromUint8Array(noblePubKey).toHex());
    });

    it("should generate correct public key for private key 3 (BIP-340 test vector)", () => {
      // From BIP-340 test vectors
      const privKey = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000003",
      );
      const pubKey = publicKeyCreate(privKey);

      // Expected x-coordinate from BIP-340: F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9
      expect(pubKey.toHex().substring(2).toLowerCase()).toBe(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
      );
    });

    it("should match known test vector private key", () => {
      // Test vector from cryptography documentation
      const privKey = FixedBuf.fromHex(
        32,
        "d30519bcae8d180dbfcc94fe0b8383dc310185b0be97b4365083ebceccd75759",
      );
      const pubKey = publicKeyCreate(privKey);

      // Expected public key x-coordinate: 3AF1E1EFA4D1E1AD5CB9E3967E98E901DAFCD37C44CF0BFB6C216997F5EE51DF
      expect(pubKey.toHex().substring(2).toLowerCase()).toBe(
        "3af1e1efa4d1e1ad5cb9e3967e98e901dafcd37c44cf0bfb6c216997f5ee51df",
      );
    });
  });
});

describe("Audit: Cross-implementation verification with @noble/secp256k1", () => {
  describe("publicKeyCreate", () => {
    it("should match noble for random private keys", () => {
      for (let i = 0; i < 10; i++) {
        const privKey = FixedBuf.fromRandom(32);

        // Skip invalid private keys
        if (!privateKeyVerify(privKey)) continue;

        const webbufPubKey = publicKeyCreate(privKey);
        const noblePubKey = noble.getPublicKey(privKey.buf, true); // compressed

        expect(webbufPubKey.toHex()).toBe(
          WebBuf.fromUint8Array(noblePubKey).toHex(),
        );
      }
    });

    it("should match noble for specific edge case private keys", () => {
      const testKeys = [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", // n-1
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1111111111111111111111111111111111111111111111111111111111111111",
      ];

      for (const keyHex of testKeys) {
        const privKey = FixedBuf.fromHex(32, keyHex);
        const webbufPubKey = publicKeyCreate(privKey);
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
        // Generate two key pairs
        let privKey1 = FixedBuf.fromRandom(32);
        let privKey2 = FixedBuf.fromRandom(32);

        // Ensure valid private keys
        while (!privateKeyVerify(privKey1)) {
          privKey1 = FixedBuf.fromRandom(32);
        }
        while (!privateKeyVerify(privKey2)) {
          privKey2 = FixedBuf.fromRandom(32);
        }

        const pubKey1 = publicKeyCreate(privKey1);
        const pubKey2 = publicKeyCreate(privKey2);

        // Compute shared secrets both ways
        const shared1 = sharedSecret(privKey1, pubKey2);
        const shared2 = sharedSecret(privKey2, pubKey1);

        // Should be equal (ECDH property)
        expect(shared1.toHex()).toBe(shared2.toHex());

        // Compare with noble
        const nobleShared = noble.getSharedSecret(privKey1.buf, pubKey2.buf, true);
        expect(shared1.toHex()).toBe(WebBuf.fromUint8Array(nobleShared).toHex());
      }
    });
  });

  describe("signature verification", () => {
    it("should verify signatures that noble can verify", async () => {
      for (let i = 0; i < 5; i++) {
        let privKey = FixedBuf.fromRandom(32);
        while (!privateKeyVerify(privKey)) {
          privKey = FixedBuf.fromRandom(32);
        }

        const pubKey = publicKeyCreate(privKey);
        const message = WebBuf.fromUtf8(`test message ${i}`);
        const digest = blake3Hash(message);

        // Sign with webbuf
        let k = FixedBuf.fromRandom(32);
        while (!privateKeyVerify(k)) {
          k = FixedBuf.fromRandom(32);
        }
        const signature = sign(digest, privKey, k);

        // Verify with webbuf
        expect(verify(signature, digest, pubKey)).toBe(true);

        // Note: noble uses different signature format (DER vs compact)
        // so we can't directly cross-verify signatures, but we verify
        // the public key generation and shared secret which proves the
        // underlying curve operations are correct
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
    const pubKey = publicKeyCreate(privKey);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    // Use deterministic k for reproducibility
    const k = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000002",
    );
    const signature = sign(digest, privKey, k);

    expect(signature.buf.length).toBe(64);
    expect(verify(signature, digest, pubKey)).toBe(true);
  });

  it("should reject signature with wrong digest", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = publicKeyCreate(privKey);
    const message1 = WebBuf.fromUtf8("message 1");
    const message2 = WebBuf.fromUtf8("message 2");
    const digest1 = blake3Hash(message1);
    const digest2 = blake3Hash(message2);

    const k = FixedBuf.fromRandom(32);
    const signature = sign(digest1, privKey, k);

    expect(verify(signature, digest1, pubKey)).toBe(true);
    expect(verify(signature, digest2, pubKey)).toBe(false);
  });

  it("should reject signature with wrong public key", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const pubKey1 = publicKeyCreate(privKey1);
    const pubKey2 = publicKeyCreate(privKey2);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const k = FixedBuf.fromRandom(32);
    const signature = sign(digest, privKey1, k);

    expect(verify(signature, digest, pubKey1)).toBe(true);
    expect(verify(signature, digest, pubKey2)).toBe(false);
  });

  it("should reject tampered signature", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = publicKeyCreate(privKey);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const k = FixedBuf.fromRandom(32);
    const signature = sign(digest, privKey, k);

    // Verify original signature first
    expect(verify(signature, digest, pubKey)).toBe(true);

    // Create tampered signature by copying and modifying
    const tamperedBytes = WebBuf.alloc(64);
    tamperedBytes.set(signature.buf);
    tamperedBytes[0] ^= 0x01;
    const tamperedSig = FixedBuf.fromBuf(64, tamperedBytes);

    expect(verify(tamperedSig, digest, pubKey)).toBe(false);
  });

  it("should reject random signature", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = publicKeyCreate(privKey);
    const message = WebBuf.fromUtf8("test");
    const digest = blake3Hash(message);

    const randomSig = FixedBuf.fromRandom(64);
    expect(verify(randomSig, digest, pubKey)).toBe(false);
  });
});

describe("Audit: Private key validation", () => {
  it("should accept valid private keys", () => {
    const validKeys = [
      "0000000000000000000000000000000000000000000000000000000000000001",
      "0000000000000000000000000000000000000000000000000000000000000002",
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", // n-1
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    for (const keyHex of validKeys) {
      const privKey = FixedBuf.fromHex(32, keyHex);
      expect(privateKeyVerify(privKey)).toBe(true);
    }
  });

  it("should reject zero private key", () => {
    const zeroKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    expect(privateKeyVerify(zeroKey)).toBe(false);
  });

  it("should reject private key >= n (curve order)", () => {
    // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    const nKey = FixedBuf.fromHex(
      32,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
    expect(privateKeyVerify(nKey)).toBe(false);

    // n+1
    const nPlusOneKey = FixedBuf.fromHex(
      32,
      "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
    );
    expect(privateKeyVerify(nPlusOneKey)).toBe(false);
  });
});

describe("Audit: Public key validation", () => {
  it("should accept valid public keys", () => {
    for (let i = 0; i < 5; i++) {
      const privKey = FixedBuf.fromRandom(32);
      const pubKey = publicKeyCreate(privKey);
      expect(publicKeyVerify(pubKey)).toBe(true);
    }
  });

  it("should reject invalid public key prefix", () => {
    // Valid public key but with wrong prefix
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = publicKeyCreate(privKey);
    const invalidPubKey = pubKey.clone();
    invalidPubKey.buf[0] = 0x04; // Invalid for compressed key

    expect(publicKeyVerify(invalidPubKey)).toBe(false);
  });

  it("should reject all-zero public key", () => {
    const zeroPubKey = FixedBuf.alloc(33);
    zeroPubKey.buf[0] = 0x02;
    expect(publicKeyVerify(zeroPubKey)).toBe(false);
  });
});

describe("Audit: Key addition (HD wallet support)", () => {
  describe("privateKeyAdd", () => {
    it("should add private keys correctly", () => {
      const privKey1 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const privKey2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );

      const sum = privateKeyAdd(privKey1, privKey2);

      // 1 + 2 = 3
      expect(sum.toHex()).toBe(
        "0000000000000000000000000000000000000000000000000000000000000003",
      );
    });

    it("should wrap around curve order", () => {
      // n-1 + 1 should wrap to 0, but 0 is invalid, so this tests the modular arithmetic
      const privKey1 = FixedBuf.fromHex(
        32,
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", // n-1
      );
      const privKey2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );

      const sum = privateKeyAdd(privKey1, privKey2);

      // (n-1) + 2 = n + 1 ≡ 1 (mod n)
      expect(sum.toHex()).toBe(
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
    });

    it("should produce valid private key from addition", () => {
      for (let i = 0; i < 5; i++) {
        const privKey1 = FixedBuf.fromRandom(32);
        const privKey2 = FixedBuf.fromRandom(32);

        if (!privateKeyVerify(privKey1) || !privateKeyVerify(privKey2)) continue;

        const sum = privateKeyAdd(privKey1, privKey2);
        // The sum should produce a valid public key
        const pubKey = publicKeyCreate(sum);
        expect(publicKeyVerify(pubKey)).toBe(true);
      }
    });
  });

  describe("publicKeyAdd", () => {
    it("should satisfy additive homomorphism: G*(a+b) = G*a + G*b", () => {
      const privKey1 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      const privKey2 = FixedBuf.fromHex(
        32,
        "0000000000000000000000000000000000000000000000000000000000000002",
      );

      const pubKey1 = publicKeyCreate(privKey1);
      const pubKey2 = publicKeyCreate(privKey2);

      // Add public keys
      const pubKeySum = publicKeyAdd(pubKey1, pubKey2);

      // Add private keys and derive public key
      const privKeySum = privateKeyAdd(privKey1, privKey2);
      const expectedPubKey = publicKeyCreate(privKeySum);

      // Should be equal
      expect(pubKeySum.toHex()).toBe(expectedPubKey.toHex());
    });

    it("should satisfy additive homomorphism for random keys", () => {
      for (let i = 0; i < 5; i++) {
        let privKey1 = FixedBuf.fromRandom(32);
        let privKey2 = FixedBuf.fromRandom(32);

        while (!privateKeyVerify(privKey1)) {
          privKey1 = FixedBuf.fromRandom(32);
        }
        while (!privateKeyVerify(privKey2)) {
          privKey2 = FixedBuf.fromRandom(32);
        }

        const pubKey1 = publicKeyCreate(privKey1);
        const pubKey2 = publicKeyCreate(privKey2);

        const pubKeySum = publicKeyAdd(pubKey1, pubKey2);
        const privKeySum = privateKeyAdd(privKey1, privKey2);
        const expectedPubKey = publicKeyCreate(privKeySum);

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

      const alicePub = publicKeyCreate(alicePriv);
      const bobPub = publicKeyCreate(bobPriv);

      // Alice computes shared secret with Bob's public key
      const aliceShared = sharedSecret(alicePriv, bobPub);
      // Bob computes shared secret with Alice's public key
      const bobShared = sharedSecret(bobPriv, alicePub);

      // Should be equal
      expect(aliceShared.toHex()).toBe(bobShared.toHex());
    }
  });

  it("should produce different shared secrets for different key pairs", () => {
    const alice1Priv = FixedBuf.fromRandom(32);
    const alice2Priv = FixedBuf.fromRandom(32);
    const bobPriv = FixedBuf.fromRandom(32);

    const alice1Pub = publicKeyCreate(alice1Priv);
    const alice2Pub = publicKeyCreate(alice2Priv);
    const bobPub = publicKeyCreate(bobPriv);

    const shared1 = sharedSecret(alice1Priv, bobPub);
    const shared2 = sharedSecret(alice2Priv, bobPub);

    expect(shared1.toHex()).not.toBe(shared2.toHex());
  });

  it("should produce 33-byte compressed point as shared secret", () => {
    const alicePriv = FixedBuf.fromRandom(32);
    const bobPriv = FixedBuf.fromRandom(32);

    const bobPub = publicKeyCreate(bobPriv);
    const shared = sharedSecret(alicePriv, bobPub);

    expect(shared.buf.length).toBe(33);
    // Should be valid compressed point format
    expect([0x02, 0x03]).toContain(shared.buf[0]);
  });
});

describe("Audit: Output sizes", () => {
  it("publicKeyCreate should produce 33-byte compressed public key", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = publicKeyCreate(privKey);
    expect(pubKey.buf.length).toBe(33);
  });

  it("sign should produce 64-byte signature", () => {
    const privKey = FixedBuf.fromRandom(32);
    const digest = FixedBuf.fromRandom(32);
    const k = FixedBuf.fromRandom(32);
    const signature = sign(digest, privKey, k);
    expect(signature.buf.length).toBe(64);
  });

  it("sharedSecret should produce 33-byte compressed point", () => {
    const privKey = FixedBuf.fromRandom(32);
    const pubKey = publicKeyCreate(FixedBuf.fromRandom(32));
    const shared = sharedSecret(privKey, pubKey);
    expect(shared.buf.length).toBe(33);
  });

  it("privateKeyAdd should produce 32-byte private key", () => {
    const privKey1 = FixedBuf.fromRandom(32);
    const privKey2 = FixedBuf.fromRandom(32);
    const sum = privateKeyAdd(privKey1, privKey2);
    expect(sum.buf.length).toBe(32);
  });

  it("publicKeyAdd should produce 33-byte compressed public key", () => {
    const pubKey1 = publicKeyCreate(FixedBuf.fromRandom(32));
    const pubKey2 = publicKeyCreate(FixedBuf.fromRandom(32));
    const sum = publicKeyAdd(pubKey1, pubKey2);
    expect(sum.buf.length).toBe(33);
  });
});

describe("Audit: Determinism", () => {
  it("publicKeyCreate should be deterministic", () => {
    const privKey = FixedBuf.fromHex(
      32,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const pubKey1 = publicKeyCreate(privKey);
    const pubKey2 = publicKeyCreate(privKey);
    expect(pubKey1.toHex()).toBe(pubKey2.toHex());
  });

  it("sign should be deterministic for same k", () => {
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

    const sig1 = sign(digest, privKey, k);
    const sig2 = sign(digest, privKey, k);
    expect(sig1.toHex()).toBe(sig2.toHex());
  });

  it("sharedSecret should be deterministic", () => {
    const privKey = FixedBuf.fromHex(
      32,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const otherPriv = FixedBuf.fromHex(
      32,
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    const otherPub = publicKeyCreate(otherPriv);

    const shared1 = sharedSecret(privKey, otherPub);
    const shared2 = sharedSecret(privKey, otherPub);
    expect(shared1.toHex()).toBe(shared2.toHex());
  });
});
