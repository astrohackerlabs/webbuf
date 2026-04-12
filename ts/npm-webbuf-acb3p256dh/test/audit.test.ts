/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Audit tests for @webbuf/acb3p256dh
 *
 * ACB3P256DH = ACB3 encryption with P-256 ECDH key exchange
 * Key derivation: BLAKE3(p256SharedSecret(alicePriv, bobPub))
 *
 * These tests verify:
 * 1. Bidirectional encryption (Alice->Bob and Bob->Alice use same derived key)
 * 2. Key derivation correctness
 * 3. Third-party cannot decrypt
 * 4. Cross-verification with audited primitives
 */

import { describe, it, expect } from "vitest";
import { acb3p256dhEncrypt, acb3p256dhDecrypt } from "../src/index.js";
import { acb3Encrypt, acb3Decrypt } from "@webbuf/acb3";
import { p256PublicKeyCreate, p256SharedSecret } from "@webbuf/p256";
import { blake3Hash } from "@webbuf/blake3";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Helper to create a key pair
function createKeyPair() {
  const privKey = FixedBuf.fromRandom(32);
  const pubKey = p256PublicKeyCreate(privKey);
  return { privKey, pubKey };
}

describe("Audit: Key derivation verification", () => {
  it("should derive key as BLAKE3(p256SharedSecret(alicePriv, bobPub))", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test key derivation");

    // Manual key derivation
    const ecdhSecret = p256SharedSecret(alice.privKey, bob.pubKey);
    const derivedKey = blake3Hash(ecdhSecret.buf);

    // Encrypt with acb3p256dh
    const acb3p256dhEncrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    // Encrypt with manual key using acb3
    const manualEncrypted = acb3Encrypt(plaintext, derivedKey, iv);

    // Should produce identical ciphertext
    expect(acb3p256dhEncrypted.toHex()).toBe(manualEncrypted.toHex());
  });

  it("should produce same derived key from both directions", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const aliceEcdh = p256SharedSecret(alice.privKey, bob.pubKey);
    const aliceDerivedKey = blake3Hash(aliceEcdh.buf);

    const bobEcdh = p256SharedSecret(bob.privKey, alice.pubKey);
    const bobDerivedKey = blake3Hash(bobEcdh.buf);

    expect(aliceDerivedKey.toHex()).toBe(bobDerivedKey.toHex());
  });

  it("should derive different keys for different key pairs", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const charlie = createKeyPair();

    const aliceBobEcdh = p256SharedSecret(alice.privKey, bob.pubKey);
    const aliceBobKey = blake3Hash(aliceBobEcdh.buf);

    const aliceCharlieEcdh = p256SharedSecret(alice.privKey, charlie.pubKey);
    const aliceCharlieKey = blake3Hash(aliceCharlieEcdh.buf);

    const bobCharlieEcdh = p256SharedSecret(bob.privKey, charlie.pubKey);
    const bobCharlieKey = blake3Hash(bobCharlieEcdh.buf);

    expect(aliceBobKey.toHex()).not.toBe(aliceCharlieKey.toHex());
    expect(aliceBobKey.toHex()).not.toBe(bobCharlieKey.toHex());
    expect(aliceCharlieKey.toHex()).not.toBe(bobCharlieKey.toHex());
  });
});

describe("Audit: Bidirectional encryption", () => {
  it("should allow Alice to encrypt and Bob to decrypt", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Hello Bob, from Alice!");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Hello Bob, from Alice!");
  });

  it("should allow Bob to encrypt and Alice to decrypt", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Hello Alice, from Bob!");

    const encrypted = acb3p256dhEncrypt(bob.privKey, alice.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(alice.privKey, bob.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Hello Alice, from Bob!");
  });

  it("should allow same-direction encryption and decryption", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Same direction test");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(alice.privKey, bob.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Same direction test");
  });
});

describe("Audit: Third party cannot decrypt", () => {
  it("should not allow Eve (third party) to decrypt Alice->Bob message", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const eve = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message between Alice and Bob");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(() => acb3p256dhDecrypt(eve.privKey, alice.pubKey, encrypted)).toThrow();
    expect(() => acb3p256dhDecrypt(eve.privKey, bob.pubKey, encrypted)).toThrow();
  });

  it("should not allow decryption with wrong private key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const wrongKey = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(() => acb3p256dhDecrypt(wrongKey.privKey, alice.pubKey, encrypted)).toThrow();
  });

  it("should not allow decryption with wrong public key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const wrongKey = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(() => acb3p256dhDecrypt(bob.privKey, wrongKey.pubKey, encrypted)).toThrow();
  });
});

describe("Audit: Cross-verification with primitives", () => {
  it("should match manual construction with acb3 + p256 + blake3", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("cross-verification test");

    const ecdhSecret = p256SharedSecret(alice.privKey, bob.pubKey);
    const key = blake3Hash(ecdhSecret.buf);
    const manualEncrypted = acb3Encrypt(plaintext, key, iv);

    const acb3p256dhEncrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    expect(acb3p256dhEncrypted.toHex()).toBe(manualEncrypted.toHex());
  });

  it("should allow decryption with manually derived key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("manual decryption test");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const ecdhSecret = p256SharedSecret(bob.privKey, alice.pubKey);
    const key = blake3Hash(ecdhSecret.buf);
    const decrypted = acb3Decrypt(encrypted, key);

    expect(decrypted.toUtf8()).toBe("manual decryption test");
  });
});

describe("Audit: Round-trip tests", () => {
  it("should round-trip empty plaintext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.alloc(0);

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.length).toBe(0);
  });

  it("should round-trip single byte", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.from([0x42]);

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toHex()).toBe("42");
  });

  it("should round-trip various sizes", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size, 0x42);

      const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
      const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

      expect(decrypted.toHex()).toBe(plaintext.toHex());
    }
  });

  it("should round-trip UTF-8 strings", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const testStrings = [
      "Hello, World!",
      "Unicode: éèê 中文 АБВ",
      "Emoji: 😀👍🎉",
      "Special: <>&\"'\\/\n\t\r",
    ];

    for (const str of testStrings) {
      const plaintext = WebBuf.fromUtf8(str);
      const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
      const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted);
      expect(decrypted.toUtf8()).toBe(str);
    }
  });
});

describe("Audit: IV handling", () => {
  it("should use provided IV", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromHex(16, "00112233445566778899aabbccddeeff");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    expect(encrypted.slice(32, 48).toHex()).toBe("00112233445566778899aabbccddeeff");
  });

  it("should generate random IV when not provided", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted1 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const encrypted2 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const iv1 = encrypted1.slice(32, 48).toHex();
    const iv2 = encrypted2.slice(32, 48).toHex();
    expect(iv1).not.toBe(iv2);

    expect(acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted1).toUtf8()).toBe("test");
    expect(acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted2).toUtf8()).toBe("test");
  });
});

describe("Audit: Determinism", () => {
  it("should produce same output for same inputs including IV", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("deterministic test");

    const encrypted1 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const encrypted2 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    expect(encrypted1.toHex()).toBe(encrypted2.toHex());
  });

  it("should produce different output without IV (random IV)", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("non-deterministic test");

    const encrypted1 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const encrypted2 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(encrypted1.toHex()).not.toBe(encrypted2.toHex());
  });
});

describe("Audit: Tamper detection", () => {
  it("should reject tampered MAC", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[0]! ^= 0x01;

    expect(() => acb3p256dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });

  it("should reject tampered IV", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[32]! ^= 0x01;

    expect(() => acb3p256dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });

  it("should reject tampered ciphertext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[48]! ^= 0x01;

    expect(() => acb3p256dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
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

    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acb3p256dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    const decrypted = acb3p256dhDecrypt(bobPrivKey, alicePubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("test");

    // Verify determinism
    const encrypted2 = acb3p256dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    expect(encrypted.toHex()).toBe(encrypted2.toHex());
  });
});

describe("Audit: Edge cases", () => {
  it("should handle large plaintext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.alloc(50 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }

    const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle multiple sequential messages", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const messages = ["First message", "Second message", "Third message"];
    const encryptedMessages: WebBuf[] = [];

    for (const msg of messages) {
      const encrypted = acb3p256dhEncrypt(alice.privKey, bob.pubKey, WebBuf.fromUtf8(msg));
      encryptedMessages.push(encrypted);
    }

    for (let i = 0; i < messages.length; i++) {
      const decrypted = acb3p256dhDecrypt(bob.privKey, alice.pubKey, encryptedMessages[i]!);
      expect(decrypted.toUtf8()).toBe(messages[i]);
    }
  });

  it("should work with minimum valid private key (1)", () => {
    const alicePrivKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const bob = createKeyPair();
    const alicePubKey = p256PublicKeyCreate(alicePrivKey);
    const plaintext = WebBuf.fromUtf8("test min key");

    const encrypted = acb3p256dhEncrypt(alicePrivKey, bob.pubKey, plaintext);
    const decrypted = acb3p256dhDecrypt(bob.privKey, alicePubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("test min key");
  });
});

describe("Audit: Security properties", () => {
  it("should produce different ciphertext for same message to different recipients", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const charlie = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("same message");

    const encryptedForBob = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const encryptedForCharlie = acb3p256dhEncrypt(alice.privKey, charlie.pubKey, plaintext, iv);

    expect(encryptedForBob.toHex()).not.toBe(encryptedForCharlie.toHex());
  });

  it("should not leak information about sender in ciphertext", () => {
    const alice = createKeyPair();
    const alice2 = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("same message");

    const fromAlice = acb3p256dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const fromAlice2 = acb3p256dhEncrypt(alice2.privKey, bob.pubKey, plaintext, iv);

    expect(fromAlice.toHex()).not.toBe(fromAlice2.toHex());
  });

  it("should be symmetric - both parties can encrypt to each other", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const msg1 = WebBuf.fromUtf8("Alice to Bob");
    const enc1 = acb3p256dhEncrypt(alice.privKey, bob.pubKey, msg1);
    const dec1 = acb3p256dhDecrypt(bob.privKey, alice.pubKey, enc1);
    expect(dec1.toUtf8()).toBe("Alice to Bob");

    const msg2 = WebBuf.fromUtf8("Bob to Alice");
    const enc2 = acb3p256dhEncrypt(bob.privKey, alice.pubKey, msg2);
    const dec2 = acb3p256dhDecrypt(alice.privKey, bob.pubKey, enc2);
    expect(dec2.toUtf8()).toBe("Bob to Alice");
  });
});
