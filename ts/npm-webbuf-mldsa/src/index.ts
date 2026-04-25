import {
  ml_dsa_44_keypair,
  ml_dsa_44_sign_internal,
  ml_dsa_44_verify_internal,
  ml_dsa_65_keypair,
  ml_dsa_65_sign_internal,
  ml_dsa_65_verify_internal,
  ml_dsa_87_keypair,
  ml_dsa_87_sign_internal,
  ml_dsa_87_verify_internal,
} from "./rs-webbuf_mldsa-inline-base64/webbuf_mldsa.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export const ML_DSA_44 = {
  verifyingKeySize: 1312,
  signingKeySize: 2560,
  signatureSize: 2420,
} as const;

export const ML_DSA_65 = {
  verifyingKeySize: 1952,
  signingKeySize: 4032,
  signatureSize: 3309,
} as const;

export const ML_DSA_87 = {
  verifyingKeySize: 2592,
  signingKeySize: 4896,
  signatureSize: 4627,
} as const;

export interface MlDsaKeyPair<VkSize extends number, SkSize extends number> {
  verifyingKey: FixedBuf<VkSize>;
  signingKey: FixedBuf<SkSize>;
}

function splitKeypair<VkSize extends number, SkSize extends number>(
  out: Uint8Array,
  vkSize: VkSize,
  skSize: SkSize,
): MlDsaKeyPair<VkSize, SkSize> {
  const vk = WebBuf.fromUint8Array(out.subarray(0, vkSize));
  const sk = WebBuf.fromUint8Array(out.subarray(vkSize, vkSize + skSize));
  return {
    verifyingKey: FixedBuf.fromBuf(vkSize, vk),
    signingKey: FixedBuf.fromBuf(skSize, sk),
  };
}

// ML-DSA-44

export function mlDsa44KeyPair(seed: FixedBuf<32>): MlDsaKeyPair<1312, 2560> {
  const out = ml_dsa_44_keypair(seed.buf);
  return splitKeypair(out, 1312, 2560);
}

export function mlDsa44SignInternal(
  signingKey: FixedBuf<2560>,
  message: WebBuf,
  rnd: FixedBuf<32>,
): FixedBuf<2420> {
  const out = ml_dsa_44_sign_internal(signingKey.buf, message, rnd.buf);
  return FixedBuf.fromBuf(2420, WebBuf.fromUint8Array(out));
}

export function mlDsa44VerifyInternal(
  verifyingKey: FixedBuf<1312>,
  message: WebBuf,
  signature: FixedBuf<2420>,
): boolean {
  return ml_dsa_44_verify_internal(verifyingKey.buf, message, signature.buf);
}

// ML-DSA-65

export function mlDsa65KeyPair(seed: FixedBuf<32>): MlDsaKeyPair<1952, 4032> {
  const out = ml_dsa_65_keypair(seed.buf);
  return splitKeypair(out, 1952, 4032);
}

export function mlDsa65SignInternal(
  signingKey: FixedBuf<4032>,
  message: WebBuf,
  rnd: FixedBuf<32>,
): FixedBuf<3309> {
  const out = ml_dsa_65_sign_internal(signingKey.buf, message, rnd.buf);
  return FixedBuf.fromBuf(3309, WebBuf.fromUint8Array(out));
}

export function mlDsa65VerifyInternal(
  verifyingKey: FixedBuf<1952>,
  message: WebBuf,
  signature: FixedBuf<3309>,
): boolean {
  return ml_dsa_65_verify_internal(verifyingKey.buf, message, signature.buf);
}

// ML-DSA-87

export function mlDsa87KeyPair(seed: FixedBuf<32>): MlDsaKeyPair<2592, 4896> {
  const out = ml_dsa_87_keypair(seed.buf);
  return splitKeypair(out, 2592, 4896);
}

export function mlDsa87SignInternal(
  signingKey: FixedBuf<4896>,
  message: WebBuf,
  rnd: FixedBuf<32>,
): FixedBuf<4627> {
  const out = ml_dsa_87_sign_internal(signingKey.buf, message, rnd.buf);
  return FixedBuf.fromBuf(4627, WebBuf.fromUint8Array(out));
}

export function mlDsa87VerifyInternal(
  verifyingKey: FixedBuf<2592>,
  message: WebBuf,
  signature: FixedBuf<4627>,
): boolean {
  return ml_dsa_87_verify_internal(verifyingKey.buf, message, signature.buf);
}
