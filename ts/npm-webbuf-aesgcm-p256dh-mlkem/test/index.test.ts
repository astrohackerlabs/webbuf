import { describe, it, expect } from "vitest";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { mlKem768KeyPair } from "@webbuf/mlkem";
import { p256PublicKeyCreate } from "@webbuf/p256";
import {
  AESGCM_P256DH_MLKEM,
  aesgcmP256dhMlkemEncrypt,
  aesgcmP256dhMlkemDecrypt,
} from "../src/index.js";

function freshSetup() {
  const senderPriv = FixedBuf.fromRandom<32>(32);
  const senderPub = p256PublicKeyCreate(senderPriv);
  const recipientPriv = FixedBuf.fromRandom<32>(32);
  const recipientPub = p256PublicKeyCreate(recipientPriv);
  const kp = mlKem768KeyPair();
  return {
    senderPriv,
    senderPub,
    recipientPriv,
    recipientPub,
    encapKey: kp.encapsulationKey,
    decapKey: kp.decapsulationKey,
  };
}

describe("aesgcm-p256dh-mlkem round-trip", () => {
  it("encrypts + decrypts a random plaintext", () => {
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("hello, hybrid world");

    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );
    const recovered = aesgcmP256dhMlkemDecrypt(
      s.recipientPriv,
      s.senderPub,
      s.decapKey,
      ciphertext,
    );

    expect(recovered.toHex()).toBe(plaintext.toHex());
  });

  it("encrypts + decrypts an empty plaintext", () => {
    const s = freshSetup();
    const plaintext = WebBuf.alloc(0);

    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );
    const recovered = aesgcmP256dhMlkemDecrypt(
      s.recipientPriv,
      s.senderPub,
      s.decapKey,
      ciphertext,
    );

    expect(recovered.length).toBe(0);
  });

  it("encrypts + decrypts a 64 KiB plaintext", () => {
    const s = freshSetup();
    const plaintext = WebBuf.alloc(64 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i & 0xff;
    }

    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );
    const recovered = aesgcmP256dhMlkemDecrypt(
      s.recipientPriv,
      s.senderPub,
      s.decapKey,
      ciphertext,
    );

    expect(recovered.toHex()).toBe(plaintext.toHex());
  });

  it("default encryption is non-deterministic", () => {
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("repeat me");

    const ct1 = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );
    const ct2 = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );

    expect(ct1.toHex()).not.toBe(ct2.toHex());
  });

  it("ciphertext length equals fixedOverhead + plaintext length", () => {
    const s = freshSetup();
    for (const len of [0, 1, 16, 100, 1024, 65535]) {
      const plaintext = WebBuf.alloc(len);
      const ciphertext = aesgcmP256dhMlkemEncrypt(
        s.senderPriv,
        s.recipientPub,
        s.encapKey,
        plaintext,
      );
      expect(ciphertext.length).toBe(AESGCM_P256DH_MLKEM.fixedOverhead + len);
    }
  });

  it("ciphertext begins with the version byte 0x02", () => {
    const s = freshSetup();
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      WebBuf.fromUtf8("x"),
    );
    expect(ciphertext[0]).toBe(AESGCM_P256DH_MLKEM.versionByte);
    expect(ciphertext[0]).toBe(0x02);
  });
});

describe("aesgcm-p256dh-mlkem rejection paths", () => {
  it("wrong recipient ML-KEM key fails", () => {
    const s = freshSetup();
    const otherKp = mlKem768KeyPair();
    const plaintext = WebBuf.fromUtf8("for A only");

    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        otherKp.decapsulationKey,
        ciphertext,
      ),
    ).toThrow();
  });

  it("wrong recipient P-256 priv fails", () => {
    const s = freshSetup();
    const wrongRecipientPriv = FixedBuf.fromRandom<32>(32);
    const plaintext = WebBuf.fromUtf8("for A only");

    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        wrongRecipientPriv,
        s.senderPub,
        s.decapKey,
        ciphertext,
      ),
    ).toThrow();
  });

  it("wrong sender P-256 pub at decrypt time fails", () => {
    const s = freshSetup();
    const otherSenderPriv = FixedBuf.fromRandom<32>(32);
    const otherSenderPub = p256PublicKeyCreate(otherSenderPriv);
    const plaintext = WebBuf.fromUtf8("authenticated as A");

    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        otherSenderPub,
        s.decapKey,
        ciphertext,
      ),
    ).toThrow();
  });

  it("tampered KEM ciphertext rejected", () => {
    const s = freshSetup();
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      WebBuf.fromUtf8("tamper me"),
    );
    const tampered = WebBuf.fromUint8Array(ciphertext);
    tampered[500] = (tampered[500]! ^ 0xff) & 0xff;

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        tampered,
      ),
    ).toThrow();
  });

  it("tampered AES ciphertext rejected", () => {
    const s = freshSetup();
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      WebBuf.fromUtf8("tamper body"),
    );
    const tampered = WebBuf.fromUint8Array(ciphertext);
    const aesBodyStart =
      1 + AESGCM_P256DH_MLKEM.kemCiphertextSize + AESGCM_P256DH_MLKEM.ivSize;
    tampered[aesBodyStart] = (tampered[aesBodyStart]! ^ 0xff) & 0xff;

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        tampered,
      ),
    ).toThrow();
  });

  it("tampered IV rejected", () => {
    const s = freshSetup();
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      WebBuf.fromUtf8("tamper IV"),
    );
    const tampered = WebBuf.fromUint8Array(ciphertext);
    const ivStart = 1 + AESGCM_P256DH_MLKEM.kemCiphertextSize;
    tampered[ivStart] = (tampered[ivStart]! ^ 0xff) & 0xff;

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        tampered,
      ),
    ).toThrow();
  });

  it("wrong version byte (0x01 from sibling package) rejected", () => {
    const s = freshSetup();
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      WebBuf.fromUtf8("x"),
    );
    const wrongVersion = WebBuf.fromUint8Array(ciphertext);
    wrongVersion[0] = 0x01;

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        wrongVersion,
      ),
    ).toThrow(/version byte/);
  });

  it("truncated ciphertext rejected", () => {
    const s = freshSetup();
    const truncated = WebBuf.alloc(100);

    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        truncated,
      ),
    ).toThrow(/too short/);
  });
});

describe("aesgcm-p256dh-mlkem hybrid defense-in-depth", () => {
  it("both shared secrets are load-bearing: ECDH alone is not enough", () => {
    // Encrypt with the correct setup.
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("needs both secrets");
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );

    // Wrong ML-KEM key (right P-256 keys → ECDH still derives correctly)
    // → must fail. If the implementation accidentally only used the ECDH
    // contribution as IKM, this would succeed and the "hybrid" claim
    // would be false.
    const otherKp = mlKem768KeyPair();
    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        otherKp.decapsulationKey,
        ciphertext,
      ),
    ).toThrow();
  });

  it("both shared secrets are load-bearing: ML-KEM alone is not enough", () => {
    // Encrypt with the correct setup.
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("needs both secrets");
    const ciphertext = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
    );

    // Right ML-KEM keys but wrong P-256 setup (different sender) → must
    // fail. If the implementation accidentally only used the ML-KEM
    // contribution as IKM, this would succeed and the "hybrid" claim
    // would be false.
    const wrongSenderPriv = FixedBuf.fromRandom<32>(32);
    const wrongSenderPub = p256PublicKeyCreate(wrongSenderPriv);
    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        wrongSenderPub,
        s.decapKey,
        ciphertext,
      ),
    ).toThrow();
  });
});

describe("aesgcm-p256dh-mlkem AAD support", () => {
  it("non-empty AAD round-trip recovers the plaintext", () => {
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("hybrid + context");
    const aad = WebBuf.fromUtf8("alice@a:bob@b:v1");

    const ct = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
      aad,
    );
    const pt = aesgcmP256dhMlkemDecrypt(
      s.recipientPriv,
      s.senderPub,
      s.decapKey,
      ct,
      aad,
    );

    expect(pt.toUtf8()).toBe("hybrid + context");
  });

  it("AAD mismatch on decrypt throws", () => {
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("for one context only");
    const aadA = WebBuf.fromUtf8("context-A");
    const aadB = WebBuf.fromUtf8("context-B");

    const ct = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
      aadA,
    );
    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        ct,
        aadB,
      ),
    ).toThrow();
  });

  it("KeyPears-style AAD construction round-trips", () => {
    const s = freshSetup();
    const plaintext = WebBuf.fromUtf8("text body");
    const PROTOCOL_VERSION = 1;
    const MESSAGE_TYPE_TEXT = 1;
    const aad = WebBuf.concat([
      WebBuf.fromArray([PROTOCOL_VERSION]),
      WebBuf.fromArray([MESSAGE_TYPE_TEXT]),
      WebBuf.fromUtf8("alice@example.com"),
      WebBuf.fromArray([0]),
      WebBuf.fromUtf8("bob@example.org"),
    ]);

    const ct = aesgcmP256dhMlkemEncrypt(
      s.senderPriv,
      s.recipientPub,
      s.encapKey,
      plaintext,
      aad,
    );
    const pt = aesgcmP256dhMlkemDecrypt(
      s.recipientPriv,
      s.senderPub,
      s.decapKey,
      ct,
      aad,
    );
    expect(pt.toUtf8()).toBe("text body");

    // Tamper with the recipient address inside AAD → fails.
    const wrongAad = WebBuf.concat([
      WebBuf.fromArray([PROTOCOL_VERSION]),
      WebBuf.fromArray([MESSAGE_TYPE_TEXT]),
      WebBuf.fromUtf8("alice@example.com"),
      WebBuf.fromArray([0]),
      WebBuf.fromUtf8("eve@attacker.com"),
    ]);
    expect(() =>
      aesgcmP256dhMlkemDecrypt(
        s.recipientPriv,
        s.senderPub,
        s.decapKey,
        ct,
        wrongAad,
      ),
    ).toThrow();
  });
});
