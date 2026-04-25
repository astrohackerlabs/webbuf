import { describe, it, expect } from "vitest";
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  mlKem512KeyPair,
  mlKem512Encapsulate,
  mlKem512Decapsulate,
  mlKem768KeyPair,
  mlKem768Encapsulate,
  mlKem768Decapsulate,
  mlKem1024KeyPair,
  mlKem1024Encapsulate,
  mlKem1024Decapsulate,
} from "../src/index.js";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("ML-KEM round-trip", () => {
  it("ML-KEM-512 keygen + encapsulate + decapsulate produces matching shared secret", () => {
    const d = FixedBuf.fromRandom(32);
    const z = FixedBuf.fromRandom(32);
    const m = FixedBuf.fromRandom(32);

    const { encapsulationKey, decapsulationKey } = mlKem512KeyPair(d, z);
    expect(encapsulationKey.buf.length).toBe(ML_KEM_512.encapsulationKeySize);
    expect(decapsulationKey.buf.length).toBe(ML_KEM_512.decapsulationKeySize);

    const { ciphertext, sharedSecret } = mlKem512Encapsulate(
      encapsulationKey,
      m,
    );
    expect(ciphertext.buf.length).toBe(ML_KEM_512.ciphertextSize);
    expect(sharedSecret.buf.length).toBe(ML_KEM_512.sharedSecretSize);

    const recovered = mlKem512Decapsulate(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(sharedSecret.toHex());
  });

  it("ML-KEM-768 keygen + encapsulate + decapsulate produces matching shared secret", () => {
    const d = FixedBuf.fromRandom(32);
    const z = FixedBuf.fromRandom(32);
    const m = FixedBuf.fromRandom(32);

    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair(d, z);
    expect(encapsulationKey.buf.length).toBe(ML_KEM_768.encapsulationKeySize);
    expect(decapsulationKey.buf.length).toBe(ML_KEM_768.decapsulationKeySize);

    const { ciphertext, sharedSecret } = mlKem768Encapsulate(
      encapsulationKey,
      m,
    );
    expect(ciphertext.buf.length).toBe(ML_KEM_768.ciphertextSize);
    expect(sharedSecret.buf.length).toBe(ML_KEM_768.sharedSecretSize);

    const recovered = mlKem768Decapsulate(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(sharedSecret.toHex());
  });

  it("ML-KEM-1024 keygen + encapsulate + decapsulate produces matching shared secret", () => {
    const d = FixedBuf.fromRandom(32);
    const z = FixedBuf.fromRandom(32);
    const m = FixedBuf.fromRandom(32);

    const { encapsulationKey, decapsulationKey } = mlKem1024KeyPair(d, z);
    expect(encapsulationKey.buf.length).toBe(ML_KEM_1024.encapsulationKeySize);
    expect(decapsulationKey.buf.length).toBe(ML_KEM_1024.decapsulationKeySize);

    const { ciphertext, sharedSecret } = mlKem1024Encapsulate(
      encapsulationKey,
      m,
    );
    expect(ciphertext.buf.length).toBe(ML_KEM_1024.ciphertextSize);
    expect(sharedSecret.buf.length).toBe(ML_KEM_1024.sharedSecretSize);

    const recovered = mlKem1024Decapsulate(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(sharedSecret.toHex());
  });

  it("same seeds produce identical keypairs (deterministic)", () => {
    const d = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    const z = FixedBuf.fromHex(
      32,
      "0101010101010101010101010101010101010101010101010101010101010101",
    );

    const kp1 = mlKem768KeyPair(d, z);
    const kp2 = mlKem768KeyPair(d, z);
    expect(kp1.encapsulationKey.toHex()).toBe(kp2.encapsulationKey.toHex());
    expect(kp1.decapsulationKey.toHex()).toBe(kp2.decapsulationKey.toHex());
  });

  it("different seeds produce different keypairs", () => {
    const d1 = FixedBuf.fromRandom(32);
    const d2 = FixedBuf.fromRandom(32);
    const z = FixedBuf.fromRandom(32);

    const kp1 = mlKem768KeyPair(d1, z);
    const kp2 = mlKem768KeyPair(d2, z);
    expect(kp1.encapsulationKey.toHex()).not.toBe(kp2.encapsulationKey.toHex());
  });
});
