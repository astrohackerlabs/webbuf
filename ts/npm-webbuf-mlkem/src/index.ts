import {
  ml_kem_512_keypair,
  ml_kem_512_encapsulate,
  ml_kem_512_decapsulate,
  ml_kem_768_keypair,
  ml_kem_768_encapsulate,
  ml_kem_768_decapsulate,
  ml_kem_1024_keypair,
  ml_kem_1024_encapsulate,
  ml_kem_1024_decapsulate,
} from "./rs-webbuf_mlkem-inline-base64/webbuf_mlkem.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export const ML_KEM_512 = {
  encapsulationKeySize: 800,
  decapsulationKeySize: 1632,
  ciphertextSize: 768,
  sharedSecretSize: 32,
} as const;

export const ML_KEM_768 = {
  encapsulationKeySize: 1184,
  decapsulationKeySize: 2400,
  ciphertextSize: 1088,
  sharedSecretSize: 32,
} as const;

export const ML_KEM_1024 = {
  encapsulationKeySize: 1568,
  decapsulationKeySize: 3168,
  ciphertextSize: 1568,
  sharedSecretSize: 32,
} as const;

export interface MlKemKeyPair<EkSize extends number, DkSize extends number> {
  encapsulationKey: FixedBuf<EkSize>;
  decapsulationKey: FixedBuf<DkSize>;
}

export interface MlKemEncapResult<
  CtSize extends number,
  SsSize extends number,
> {
  ciphertext: FixedBuf<CtSize>;
  sharedSecret: FixedBuf<SsSize>;
}

function splitKeypair<EkSize extends number, DkSize extends number>(
  out: Uint8Array,
  ekSize: EkSize,
  dkSize: DkSize,
): MlKemKeyPair<EkSize, DkSize> {
  const ek = WebBuf.fromUint8Array(out.subarray(0, ekSize));
  const dk = WebBuf.fromUint8Array(out.subarray(ekSize, ekSize + dkSize));
  return {
    encapsulationKey: FixedBuf.fromBuf(ekSize, ek),
    decapsulationKey: FixedBuf.fromBuf(dkSize, dk),
  };
}

function splitEncap<CtSize extends number, SsSize extends number>(
  out: Uint8Array,
  ctSize: CtSize,
  ssSize: SsSize,
): MlKemEncapResult<CtSize, SsSize> {
  const ct = WebBuf.fromUint8Array(out.subarray(0, ctSize));
  const ss = WebBuf.fromUint8Array(out.subarray(ctSize, ctSize + ssSize));
  return {
    ciphertext: FixedBuf.fromBuf(ctSize, ct),
    sharedSecret: FixedBuf.fromBuf(ssSize, ss),
  };
}

// ML-KEM-512

export function mlKem512KeyPair(
  d: FixedBuf<32>,
  z: FixedBuf<32>,
): MlKemKeyPair<800, 1632> {
  const out = ml_kem_512_keypair(d.buf, z.buf);
  return splitKeypair(out, 800, 1632);
}

export function mlKem512Encapsulate(
  encapsulationKey: FixedBuf<800>,
  m: FixedBuf<32>,
): MlKemEncapResult<768, 32> {
  const out = ml_kem_512_encapsulate(encapsulationKey.buf, m.buf);
  return splitEncap(out, 768, 32);
}

export function mlKem512Decapsulate(
  decapsulationKey: FixedBuf<1632>,
  ciphertext: FixedBuf<768>,
): FixedBuf<32> {
  const out = ml_kem_512_decapsulate(decapsulationKey.buf, ciphertext.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(out));
}

// ML-KEM-768

export function mlKem768KeyPair(
  d: FixedBuf<32>,
  z: FixedBuf<32>,
): MlKemKeyPair<1184, 2400> {
  const out = ml_kem_768_keypair(d.buf, z.buf);
  return splitKeypair(out, 1184, 2400);
}

export function mlKem768Encapsulate(
  encapsulationKey: FixedBuf<1184>,
  m: FixedBuf<32>,
): MlKemEncapResult<1088, 32> {
  const out = ml_kem_768_encapsulate(encapsulationKey.buf, m.buf);
  return splitEncap(out, 1088, 32);
}

export function mlKem768Decapsulate(
  decapsulationKey: FixedBuf<2400>,
  ciphertext: FixedBuf<1088>,
): FixedBuf<32> {
  const out = ml_kem_768_decapsulate(decapsulationKey.buf, ciphertext.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(out));
}

// ML-KEM-1024

export function mlKem1024KeyPair(
  d: FixedBuf<32>,
  z: FixedBuf<32>,
): MlKemKeyPair<1568, 3168> {
  const out = ml_kem_1024_keypair(d.buf, z.buf);
  return splitKeypair(out, 1568, 3168);
}

export function mlKem1024Encapsulate(
  encapsulationKey: FixedBuf<1568>,
  m: FixedBuf<32>,
): MlKemEncapResult<1568, 32> {
  const out = ml_kem_1024_encapsulate(encapsulationKey.buf, m.buf);
  return splitEncap(out, 1568, 32);
}

export function mlKem1024Decapsulate(
  decapsulationKey: FixedBuf<3168>,
  ciphertext: FixedBuf<1568>,
): FixedBuf<32> {
  const out = ml_kem_1024_decapsulate(decapsulationKey.buf, ciphertext.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(out));
}
