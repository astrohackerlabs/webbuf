import { describe, it, expect } from "vitest";
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  mlKem512KeyPair,
  mlKem512KeyPairDeterministic,
  mlKem512Encapsulate,
  mlKem512EncapsulateDeterministic,
  mlKem512Decapsulate,
  mlKem768KeyPair,
  mlKem768KeyPairDeterministic,
  mlKem768Encapsulate,
  mlKem768EncapsulateDeterministic,
  mlKem768Decapsulate,
  mlKem1024KeyPair,
  mlKem1024KeyPairDeterministic,
  mlKem1024Encapsulate,
  mlKem1024EncapsulateDeterministic,
  mlKem1024Decapsulate,
} from "../src/index.js";
import { FixedBuf } from "@webbuf/fixedbuf";

describe("ML-KEM round-trip", () => {
  it("ML-KEM-512 keygen + encapsulate + decapsulate produces matching shared secret", () => {
    const { encapsulationKey, decapsulationKey } = mlKem512KeyPair();
    expect(encapsulationKey.buf.length).toBe(ML_KEM_512.encapsulationKeySize);
    expect(decapsulationKey.buf.length).toBe(ML_KEM_512.decapsulationKeySize);

    const { ciphertext, sharedSecret } = mlKem512Encapsulate(encapsulationKey);
    expect(ciphertext.buf.length).toBe(ML_KEM_512.ciphertextSize);
    expect(sharedSecret.buf.length).toBe(ML_KEM_512.sharedSecretSize);

    const recovered = mlKem512Decapsulate(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(sharedSecret.toHex());
  });

  it("ML-KEM-768 keygen + encapsulate + decapsulate produces matching shared secret", () => {
    const { encapsulationKey, decapsulationKey } = mlKem768KeyPair();
    expect(encapsulationKey.buf.length).toBe(ML_KEM_768.encapsulationKeySize);
    expect(decapsulationKey.buf.length).toBe(ML_KEM_768.decapsulationKeySize);

    const { ciphertext, sharedSecret } = mlKem768Encapsulate(encapsulationKey);
    expect(ciphertext.buf.length).toBe(ML_KEM_768.ciphertextSize);
    expect(sharedSecret.buf.length).toBe(ML_KEM_768.sharedSecretSize);

    const recovered = mlKem768Decapsulate(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(sharedSecret.toHex());
  });

  it("ML-KEM-1024 keygen + encapsulate + decapsulate produces matching shared secret", () => {
    const { encapsulationKey, decapsulationKey } = mlKem1024KeyPair();
    expect(encapsulationKey.buf.length).toBe(ML_KEM_1024.encapsulationKeySize);
    expect(decapsulationKey.buf.length).toBe(ML_KEM_1024.decapsulationKeySize);

    const { ciphertext, sharedSecret } = mlKem1024Encapsulate(encapsulationKey);
    expect(ciphertext.buf.length).toBe(ML_KEM_1024.ciphertextSize);
    expect(sharedSecret.buf.length).toBe(ML_KEM_1024.sharedSecretSize);

    const recovered = mlKem1024Decapsulate(decapsulationKey, ciphertext);
    expect(recovered.toHex()).toBe(sharedSecret.toHex());
  });

  it("deterministic keypair aliases reproduce the compatibility overloads", () => {
    const d = FixedBuf.fromHex(
      32,
      "0000000000000000000000000000000000000000000000000000000000000000",
    );
    const z = FixedBuf.fromHex(
      32,
      "0101010101010101010101010101010101010101010101010101010101010101",
    );

    const kp1 = mlKem768KeyPair(d, z);
    const kp2 = mlKem768KeyPairDeterministic(d, z);
    expect(kp1.encapsulationKey.toHex()).toBe(kp2.encapsulationKey.toHex());
    expect(kp1.decapsulationKey.toHex()).toBe(kp2.decapsulationKey.toHex());
  });

  it("deterministic encapsulation aliases reproduce the compatibility overloads", () => {
    const d = FixedBuf.fromHex(
      32,
      "0202020202020202020202020202020202020202020202020202020202020202",
    );
    const z = FixedBuf.fromHex(
      32,
      "0303030303030303030303030303030303030303030303030303030303030303",
    );
    const m = FixedBuf.fromHex(
      32,
      "0404040404040404040404040404040404040404040404040404040404040404",
    );

    const { encapsulationKey } = mlKem512KeyPairDeterministic(d, z);
    const encap1 = mlKem512Encapsulate(encapsulationKey, m);
    const encap2 = mlKem512EncapsulateDeterministic(encapsulationKey, m);
    expect(encap1.ciphertext.toHex()).toBe(encap2.ciphertext.toHex());
    expect(encap1.sharedSecret.toHex()).toBe(encap2.sharedSecret.toHex());
  });

  it("no-argument keypairs use fresh randomness", () => {
    const kp1 = mlKem768KeyPair();
    const kp2 = mlKem768KeyPair();
    expect(kp1.encapsulationKey.toHex()).not.toBe(kp2.encapsulationKey.toHex());
  });

  it("default encapsulation uses fresh randomness", () => {
    const { encapsulationKey } = mlKem768KeyPair();

    const encap1 = mlKem768Encapsulate(encapsulationKey);
    const encap2 = mlKem768Encapsulate(encapsulationKey);
    expect(encap1.ciphertext.toHex()).not.toBe(encap2.ciphertext.toHex());
  });

  it("partial deterministic keypair entropy throws at runtime", () => {
    const partialKeyPair = mlKem512KeyPair as unknown as (
      d: FixedBuf<32>,
    ) => unknown;

    expect(() => partialKeyPair(FixedBuf.fromRandom(32))).toThrow(
      "mlKem512KeyPair requires both d and z, or neither",
    );
  });

  it("deterministic aliases are available for all parameter sets", () => {
    const d = FixedBuf.fromRandom(32);
    const z = FixedBuf.fromRandom(32);
    const m = FixedBuf.fromRandom(32);

    const kp512 = mlKem512KeyPairDeterministic(d, z);
    const enc512 = mlKem512EncapsulateDeterministic(kp512.encapsulationKey, m);
    expect(
      mlKem512Decapsulate(kp512.decapsulationKey, enc512.ciphertext).toHex(),
    ).toBe(enc512.sharedSecret.toHex());

    const kp768 = mlKem768KeyPairDeterministic(d, z);
    const enc768 = mlKem768EncapsulateDeterministic(kp768.encapsulationKey, m);
    expect(
      mlKem768Decapsulate(kp768.decapsulationKey, enc768.ciphertext).toHex(),
    ).toBe(enc768.sharedSecret.toHex());

    const kp1024 = mlKem1024KeyPairDeterministic(d, z);
    const enc1024 = mlKem1024EncapsulateDeterministic(
      kp1024.encapsulationKey,
      m,
    );
    expect(
      mlKem1024Decapsulate(kp1024.decapsulationKey, enc1024.ciphertext).toHex(),
    ).toBe(enc1024.sharedSecret.toHex());
  });
});
