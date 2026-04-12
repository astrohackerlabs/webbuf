/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Audit tests for @webbuf/aesgcm-p256dh
 *
 * AES-GCM + P-256 ECDH + SHA-256 key derivation
 * Fully NIST-approved authenticated encryption with key exchange.
 */

import { describe, it, expect } from "vitest";
import { aesgcmP256dhEncrypt, aesgcmP256dhDecrypt } from "../src/index.js";
import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";
import { p256PublicKeyCreate, p256SharedSecret } from "@webbuf/p256";
import { sha256Hash } from "@webbuf/sha256";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

function createKeyPair() {
  const privKey = FixedBuf.fromRandom(32);
  const pubKey = p256PublicKeyCreate(privKey);
  return { privKey, pubKey };
}

describe("Audit: Key derivation verification", () => {
  it("should derive key as SHA256(p256SharedSecret(alicePriv, bobPub))", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(12);
    const plaintext = WebBuf.fromUtf8("test key derivation");

    const ecdhSecret = p256SharedSecret(alice.privKey, bob.pubKey);
    const derivedKey = sha256Hash(ecdhSecret.buf);

    const dhEncrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const manualEncrypted = aesgcmEncrypt(plaintext, derivedKey, iv);

    expect(dhEncrypted.toHex()).toBe(manualEncrypted.toHex());
  });

  it("should produce same derived key from both directions", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const aliceEcdh = p256SharedSecret(alice.privKey, bob.pubKey);
    const aliceDerivedKey = sha256Hash(aliceEcdh.buf);

    const bobEcdh = p256SharedSecret(bob.privKey, alice.pubKey);
    const bobDerivedKey = sha256Hash(bobEcdh.buf);

    expect(aliceDerivedKey.toHex()).toBe(bobDerivedKey.toHex());
  });
});

describe("Audit: Bidirectional encryption", () => {
  it("should allow Alice to encrypt and Bob to decrypt", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Hello Bob, from Alice!");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Hello Bob, from Alice!");
  });

  it("should allow Bob to encrypt and Alice to decrypt", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Hello Alice, from Bob!");

    const encrypted = aesgcmP256dhEncrypt(bob.privKey, alice.pubKey, plaintext);
    const decrypted = aesgcmP256dhDecrypt(alice.privKey, bob.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Hello Alice, from Bob!");
  });

  it("should allow same-direction encryption and decryption", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Same direction test");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = aesgcmP256dhDecrypt(alice.privKey, bob.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Same direction test");
  });
});

describe("Audit: Third party cannot decrypt", () => {
  it("should not allow Eve to decrypt Alice->Bob message", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const eve = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(() => aesgcmP256dhDecrypt(eve.privKey, alice.pubKey, encrypted)).toThrow();
    expect(() => aesgcmP256dhDecrypt(eve.privKey, bob.pubKey, encrypted)).toThrow();
  });

  it("should not allow decryption with wrong private key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const wrongKey = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(() => aesgcmP256dhDecrypt(wrongKey.privKey, alice.pubKey, encrypted)).toThrow();
  });

  it("should not allow decryption with wrong public key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const wrongKey = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(() => aesgcmP256dhDecrypt(bob.privKey, wrongKey.pubKey, encrypted)).toThrow();
  });
});

describe("Audit: Cross-verification with primitives", () => {
  it("should match manual construction with aesgcm + p256 + sha256", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(12);
    const plaintext = WebBuf.fromUtf8("cross-verification test");

    const ecdhSecret = p256SharedSecret(alice.privKey, bob.pubKey);
    const key = sha256Hash(ecdhSecret.buf);
    const manualEncrypted = aesgcmEncrypt(plaintext, key, iv);

    const dhEncrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    expect(dhEncrypted.toHex()).toBe(manualEncrypted.toHex());
  });

  it("should allow decryption with manually derived key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("manual decryption test");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const ecdhSecret = p256SharedSecret(bob.privKey, alice.pubKey);
    const key = sha256Hash(ecdhSecret.buf);
    const decrypted = aesgcmDecrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("manual decryption test");
  });
});

describe("Audit: Round-trip tests", () => {
  it("should round-trip empty plaintext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, WebBuf.alloc(0));
    const decrypted = aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.length).toBe(0);
  });

  it("should round-trip various sizes", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size, 0x42);
      const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
      const decrypted = aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, encrypted);
      expect(decrypted.toHex()).toBe(plaintext.toHex());
    }
  });

  it("should round-trip UTF-8 strings", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const testStrings = [
      "Hello, World!",
      "Unicode: \u00e9\u00e8\u00ea \u4e2d\u6587 \u0410\u0411\u0412",
      "Special: <>&\"'\\/\n\t\r",
    ];

    for (const str of testStrings) {
      const plaintext = WebBuf.fromUtf8(str);
      const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
      const decrypted = aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, encrypted);
      expect(decrypted.toUtf8()).toBe(str);
    }
  });
});

describe("Audit: Tamper detection", () => {
  it("should reject tampered ciphertext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[12]! ^= 0x01;

    expect(() => aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });

  it("should reject tampered auth tag", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[tampered.length - 1]! ^= 0x01;

    expect(() => aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });

  it("should reject tampered nonce", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[0]! ^= 0x01;

    expect(() => aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });
});

describe("Audit: Known test vectors", () => {
  it("should work with known private keys", () => {
    const alicePrivKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const bobPrivKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000002",
    );

    const alicePubKey = p256PublicKeyCreate(alicePrivKey);
    const bobPubKey = p256PublicKeyCreate(bobPrivKey);

    const iv = FixedBuf.fromHex(12, "000102030405060708090a0b");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = aesgcmP256dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    const decrypted = aesgcmP256dhDecrypt(bobPrivKey, alicePubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("test");

    // Verify determinism
    const encrypted2 = aesgcmP256dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    expect(encrypted.toHex()).toBe(encrypted2.toHex());
  });
});

describe("Audit: Security properties", () => {
  it("should produce different ciphertext for different recipients", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const charlie = createKeyPair();
    const iv = FixedBuf.fromRandom(12);
    const plaintext = WebBuf.fromUtf8("same message");

    const encryptedForBob = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const encryptedForCharlie = aesgcmP256dhEncrypt(alice.privKey, charlie.pubKey, plaintext, iv);

    expect(encryptedForBob.toHex()).not.toBe(encryptedForCharlie.toHex());
  });

  it("should be symmetric - both parties can encrypt to each other", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const msg1 = WebBuf.fromUtf8("Alice to Bob");
    const enc1 = aesgcmP256dhEncrypt(alice.privKey, bob.pubKey, msg1);
    const dec1 = aesgcmP256dhDecrypt(bob.privKey, alice.pubKey, enc1);
    expect(dec1.toUtf8()).toBe("Alice to Bob");

    const msg2 = WebBuf.fromUtf8("Bob to Alice");
    const enc2 = aesgcmP256dhEncrypt(bob.privKey, alice.pubKey, msg2);
    const dec2 = aesgcmP256dhDecrypt(alice.privKey, bob.pubKey, enc2);
    expect(dec2.toUtf8()).toBe("Bob to Alice");
  });
});
