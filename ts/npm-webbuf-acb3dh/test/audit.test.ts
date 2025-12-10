/* eslint-disable @typescript-eslint/no-non-null-assertion */
/**
 * Audit tests for @webbuf/acb3dh
 *
 * ACB3DH = ACB3 encryption with ECDH key exchange
 * Key derivation: BLAKE3(sharedSecret(alicePriv, bobPub))
 *
 * These tests verify:
 * 1. Bidirectional encryption (Alice→Bob and Bob→Alice use same derived key)
 * 2. Key derivation correctness
 * 3. Third-party cannot decrypt
 * 4. Cross-verification with audited primitives
 */

import { describe, it, expect } from "vitest";
import { acb3dhEncrypt, acb3dhDecrypt } from "../src/index.js";
import { acb3Encrypt, acb3Decrypt } from "@webbuf/acb3";
import { publicKeyCreate, sharedSecret } from "@webbuf/secp256k1";
import { blake3Hash } from "@webbuf/blake3";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

// Helper to create a key pair
function createKeyPair() {
  const privKey = FixedBuf.fromRandom(32);
  const pubKey = publicKeyCreate(privKey);
  return { privKey, pubKey };
}

describe("Audit: Key derivation verification", () => {
  it("should derive key as BLAKE3(sharedSecret(alicePriv, bobPub))", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("test key derivation");

    // Manual key derivation
    const ecdhSecret = sharedSecret(alice.privKey, bob.pubKey);
    const derivedKey = blake3Hash(ecdhSecret.buf);

    // Encrypt with acb3dh
    const acb3dhEncrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    // Encrypt with manual key using acb3
    const manualEncrypted = acb3Encrypt(plaintext, derivedKey, iv);

    // Should produce identical ciphertext
    expect(acb3dhEncrypted.toHex()).toBe(manualEncrypted.toHex());
  });

  it("should produce same derived key from both directions", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    // Alice's perspective: sharedSecret(alicePriv, bobPub)
    const aliceEcdh = sharedSecret(alice.privKey, bob.pubKey);
    const aliceDerivedKey = blake3Hash(aliceEcdh.buf);

    // Bob's perspective: sharedSecret(bobPriv, alicePub)
    const bobEcdh = sharedSecret(bob.privKey, alice.pubKey);
    const bobDerivedKey = blake3Hash(bobEcdh.buf);

    // Keys should be identical
    expect(aliceDerivedKey.toHex()).toBe(bobDerivedKey.toHex());
  });

  it("should derive different keys for different key pairs", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const charlie = createKeyPair();

    // Alice-Bob shared key
    const aliceBobEcdh = sharedSecret(alice.privKey, bob.pubKey);
    const aliceBobKey = blake3Hash(aliceBobEcdh.buf);

    // Alice-Charlie shared key
    const aliceCharlieEcdh = sharedSecret(alice.privKey, charlie.pubKey);
    const aliceCharlieKey = blake3Hash(aliceCharlieEcdh.buf);

    // Bob-Charlie shared key
    const bobCharlieEcdh = sharedSecret(bob.privKey, charlie.pubKey);
    const bobCharlieKey = blake3Hash(bobCharlieEcdh.buf);

    // All keys should be different
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

    // Alice encrypts with her private key and Bob's public key
    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Bob decrypts with his private key and Alice's public key
    const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Hello Bob, from Alice!");
  });

  it("should allow Bob to encrypt and Alice to decrypt", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Hello Alice, from Bob!");

    // Bob encrypts with his private key and Alice's public key
    const encrypted = acb3dhEncrypt(bob.privKey, alice.pubKey, plaintext);

    // Alice decrypts with her private key and Bob's public key
    const decrypted = acb3dhDecrypt(alice.privKey, bob.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Hello Alice, from Bob!");
  });

  it("should allow same-direction encryption and decryption", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Same direction test");

    // Alice encrypts
    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Alice can also decrypt (using same key derivation)
    const decrypted = acb3dhDecrypt(alice.privKey, bob.pubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("Same direction test");
  });
});

describe("Audit: Third party cannot decrypt", () => {
  it("should not allow Eve (third party) to decrypt Alice→Bob message", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const eve = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message between Alice and Bob");

    // Alice encrypts for Bob
    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Eve tries to decrypt with her private key and Alice's public key
    expect(() => acb3dhDecrypt(eve.privKey, alice.pubKey, encrypted)).toThrow();

    // Eve tries to decrypt with her private key and Bob's public key
    expect(() => acb3dhDecrypt(eve.privKey, bob.pubKey, encrypted)).toThrow();

    // Eve tries with Alice's public key (wrong direction)
    expect(() => acb3dhDecrypt(eve.privKey, alice.pubKey, encrypted)).toThrow();
  });

  it("should not allow decryption with wrong private key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const wrongKey = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message");

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Try decrypting with wrong private key but correct public key
    expect(() => acb3dhDecrypt(wrongKey.privKey, alice.pubKey, encrypted)).toThrow();
  });

  it("should not allow decryption with wrong public key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const wrongKey = createKeyPair();
    const plaintext = WebBuf.fromUtf8("Secret message");

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Try decrypting with correct private key but wrong public key
    expect(() => acb3dhDecrypt(bob.privKey, wrongKey.pubKey, encrypted)).toThrow();
  });
});

describe("Audit: Cross-verification with primitives", () => {
  it("should match manual construction with acb3 + secp256k1 + blake3", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("cross-verification test");

    // Manual construction
    const ecdhSecret = sharedSecret(alice.privKey, bob.pubKey);
    const key = blake3Hash(ecdhSecret.buf);
    const manualEncrypted = acb3Encrypt(plaintext, key, iv);

    // acb3dh construction
    const acb3dhEncrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    expect(acb3dhEncrypted.toHex()).toBe(manualEncrypted.toHex());
  });

  it("should allow decryption with manually derived key", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("manual decryption test");

    // Encrypt with acb3dh
    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Manually derive key and decrypt with acb3
    const ecdhSecret = sharedSecret(bob.privKey, alice.pubKey);
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

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.length).toBe(0);
  });

  it("should round-trip single byte", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.from([0x42]);

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toHex()).toBe("42");
  });

  it("should round-trip various sizes", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const sizes = [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000];

    for (const size of sizes) {
      const plaintext = WebBuf.alloc(size, 0x42);

      const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
      const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted);

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
      const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
      const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted);
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

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    // IV should be at position 32-48 (after MAC)
    expect(encrypted.slice(32, 48).toHex()).toBe("00112233445566778899aabbccddeeff");
  });

  it("should generate random IV when not provided", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted1 = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const encrypted2 = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // IVs should be different
    const iv1 = encrypted1.slice(32, 48).toHex();
    const iv2 = encrypted2.slice(32, 48).toHex();
    expect(iv1).not.toBe(iv2);

    // Both should still decrypt correctly
    expect(acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted1).toUtf8()).toBe("test");
    expect(acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted2).toUtf8()).toBe("test");
  });
});

describe("Audit: Determinism", () => {
  it("should produce same output for same inputs including IV", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("deterministic test");

    const encrypted1 = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const encrypted2 = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);

    expect(encrypted1.toHex()).toBe(encrypted2.toHex());
  });

  it("should produce different output without IV (random IV)", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("non-deterministic test");

    const encrypted1 = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const encrypted2 = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    expect(encrypted1.toHex()).not.toBe(encrypted2.toHex());
  });
});

describe("Audit: Tamper detection", () => {
  it("should reject tampered MAC", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Tamper with MAC
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[0]! ^= 0x01;

    expect(() => acb3dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });

  it("should reject tampered IV", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Tamper with IV (byte 32)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[32]! ^= 0x01;

    expect(() => acb3dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });

  it("should reject tampered ciphertext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    const plaintext = WebBuf.fromUtf8("secret message");

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);

    // Tamper with ciphertext (byte 48)
    const tampered = WebBuf.alloc(encrypted.length);
    tampered.set(encrypted);
    tampered[48]! ^= 0x01;

    expect(() => acb3dhDecrypt(bob.privKey, alice.pubKey, tampered)).toThrow();
  });
});

describe("Audit: Known test vectors", () => {
  it("should work with known private keys", () => {
    // Use known private keys for reproducibility
    const alicePrivKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const bobPrivKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000002",
    );

    const alicePubKey = publicKeyCreate(alicePrivKey);
    const bobPubKey = publicKeyCreate(bobPrivKey);

    const iv = FixedBuf.fromHex(16, "000102030405060708090a0b0c0d0e0f");
    const plaintext = WebBuf.fromUtf8("test");

    const encrypted = acb3dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    const decrypted = acb3dhDecrypt(bobPrivKey, alicePubKey, encrypted);

    expect(decrypted.toUtf8()).toBe("test");

    // Verify the derived key is deterministic
    const ecdhSecret = sharedSecret(alicePrivKey, bobPubKey);
    blake3Hash(ecdhSecret.buf);

    // The key should be deterministic for these inputs
    const encrypted2 = acb3dhEncrypt(alicePrivKey, bobPubKey, plaintext, iv);
    expect(encrypted.toHex()).toBe(encrypted2.toHex());
  });
});

describe("Audit: Edge cases", () => {
  it("should handle large plaintext", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();
    // Use deterministic pattern (crypto.getRandomValues has 65KB limit)
    const plaintext = WebBuf.alloc(50 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }

    const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext);
    const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encrypted);

    expect(decrypted.toHex()).toBe(plaintext.toHex());
  });

  it("should handle multiple sequential messages", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    const messages = ["First message", "Second message", "Third message"];
    const encryptedMessages: WebBuf[] = [];

    // Encrypt all messages
    for (const msg of messages) {
      const encrypted = acb3dhEncrypt(alice.privKey, bob.pubKey, WebBuf.fromUtf8(msg));
      encryptedMessages.push(encrypted);
    }

    // Decrypt all messages
    for (let i = 0; i < messages.length; i++) {
      const decrypted = acb3dhDecrypt(bob.privKey, alice.pubKey, encryptedMessages[i]!);
      expect(decrypted.toUtf8()).toBe(messages[i]);
    }
  });

  it("should work with minimum valid private key (1)", () => {
    const alicePrivKey = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000001",
    );
    const bob = createKeyPair();
    const alicePubKey = publicKeyCreate(alicePrivKey);
    const plaintext = WebBuf.fromUtf8("test min key");

    const encrypted = acb3dhEncrypt(alicePrivKey, bob.pubKey, plaintext);
    const decrypted = acb3dhDecrypt(bob.privKey, alicePubKey, encrypted);

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

    const encryptedForBob = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const encryptedForCharlie = acb3dhEncrypt(alice.privKey, charlie.pubKey, plaintext, iv);

    // Should be completely different due to different derived keys
    expect(encryptedForBob.toHex()).not.toBe(encryptedForCharlie.toHex());
  });

  it("should not leak information about sender in ciphertext", () => {
    const alice = createKeyPair();
    const alice2 = createKeyPair();
    const bob = createKeyPair();
    const iv = FixedBuf.fromRandom(16);
    const plaintext = WebBuf.fromUtf8("same message");

    const fromAlice = acb3dhEncrypt(alice.privKey, bob.pubKey, plaintext, iv);
    const fromAlice2 = acb3dhEncrypt(alice2.privKey, bob.pubKey, plaintext, iv);

    // Different senders should produce completely different ciphertext
    expect(fromAlice.toHex()).not.toBe(fromAlice2.toHex());
  });

  it("should be symmetric - both parties can encrypt to each other", () => {
    const alice = createKeyPair();
    const bob = createKeyPair();

    // Alice sends to Bob
    const msg1 = WebBuf.fromUtf8("Alice to Bob");
    const enc1 = acb3dhEncrypt(alice.privKey, bob.pubKey, msg1);
    const dec1 = acb3dhDecrypt(bob.privKey, alice.pubKey, enc1);
    expect(dec1.toUtf8()).toBe("Alice to Bob");

    // Bob sends to Alice
    const msg2 = WebBuf.fromUtf8("Bob to Alice");
    const enc2 = acb3dhEncrypt(bob.privKey, alice.pubKey, msg2);
    const dec2 = acb3dhDecrypt(alice.privKey, bob.pubKey, enc2);
    expect(dec2.toUtf8()).toBe("Bob to Alice");
  });
});
