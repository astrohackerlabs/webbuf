import {
  slh_dsa_sha2_128s_keypair,
  slh_dsa_sha2_128s_sign_internal,
  slh_dsa_sha2_128s_verify_internal,
  slh_dsa_sha2_128f_keypair,
  slh_dsa_sha2_128f_sign_internal,
  slh_dsa_sha2_128f_verify_internal,
  slh_dsa_sha2_192s_keypair,
  slh_dsa_sha2_192s_sign_internal,
  slh_dsa_sha2_192s_verify_internal,
  slh_dsa_sha2_192f_keypair,
  slh_dsa_sha2_192f_sign_internal,
  slh_dsa_sha2_192f_verify_internal,
  slh_dsa_sha2_256s_keypair,
  slh_dsa_sha2_256s_sign_internal,
  slh_dsa_sha2_256s_verify_internal,
  slh_dsa_sha2_256f_keypair,
  slh_dsa_sha2_256f_sign_internal,
  slh_dsa_sha2_256f_verify_internal,
  slh_dsa_shake_128s_keypair,
  slh_dsa_shake_128s_sign_internal,
  slh_dsa_shake_128s_verify_internal,
  slh_dsa_shake_128f_keypair,
  slh_dsa_shake_128f_sign_internal,
  slh_dsa_shake_128f_verify_internal,
  slh_dsa_shake_192s_keypair,
  slh_dsa_shake_192s_sign_internal,
  slh_dsa_shake_192s_verify_internal,
  slh_dsa_shake_192f_keypair,
  slh_dsa_shake_192f_sign_internal,
  slh_dsa_shake_192f_verify_internal,
  slh_dsa_shake_256s_keypair,
  slh_dsa_shake_256s_sign_internal,
  slh_dsa_shake_256s_verify_internal,
  slh_dsa_shake_256f_keypair,
  slh_dsa_shake_256f_sign_internal,
  slh_dsa_shake_256f_verify_internal,
} from "./rs-webbuf_slhdsa-inline-base64/webbuf_slhdsa.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export const SLH_DSA_SHA2_128S = {
  seedSize: 16,
  verifyingKeySize: 32,
  signingKeySize: 64,
  signatureSize: 7856,
} as const;
export const SLH_DSA_SHA2_128F = {
  seedSize: 16,
  verifyingKeySize: 32,
  signingKeySize: 64,
  signatureSize: 17088,
} as const;
export const SLH_DSA_SHA2_192S = {
  seedSize: 24,
  verifyingKeySize: 48,
  signingKeySize: 96,
  signatureSize: 16224,
} as const;
export const SLH_DSA_SHA2_192F = {
  seedSize: 24,
  verifyingKeySize: 48,
  signingKeySize: 96,
  signatureSize: 35664,
} as const;
export const SLH_DSA_SHA2_256S = {
  seedSize: 32,
  verifyingKeySize: 64,
  signingKeySize: 128,
  signatureSize: 29792,
} as const;
export const SLH_DSA_SHA2_256F = {
  seedSize: 32,
  verifyingKeySize: 64,
  signingKeySize: 128,
  signatureSize: 49856,
} as const;
export const SLH_DSA_SHAKE_128S = SLH_DSA_SHA2_128S;
export const SLH_DSA_SHAKE_128F = SLH_DSA_SHA2_128F;
export const SLH_DSA_SHAKE_192S = SLH_DSA_SHA2_192S;
export const SLH_DSA_SHAKE_192F = SLH_DSA_SHA2_192F;
export const SLH_DSA_SHAKE_256S = SLH_DSA_SHA2_256S;
export const SLH_DSA_SHAKE_256F = SLH_DSA_SHA2_256F;

export interface SlhDsaKeyPair<VkSize extends number, SkSize extends number> {
  verifyingKey: FixedBuf<VkSize>;
  signingKey: FixedBuf<SkSize>;
}

const EMPTY_OPT_RAND = WebBuf.alloc(0);

function splitKeypair<VkSize extends number, SkSize extends number>(
  out: Uint8Array,
  vkSize: VkSize,
  skSize: SkSize,
): SlhDsaKeyPair<VkSize, SkSize> {
  const vk = WebBuf.fromUint8Array(out.subarray(0, vkSize));
  const sk = WebBuf.fromUint8Array(out.subarray(vkSize, vkSize + skSize));
  return {
    verifyingKey: FixedBuf.fromBuf(vkSize, vk),
    signingKey: FixedBuf.fromBuf(skSize, sk),
  };
}

// =====================================================================
// SHA2 family
// =====================================================================

// SHA2-128s

export function slhDsaSha2_128sKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_sha2_128s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaSha2_128sSignInternal(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  addrnd?: FixedBuf<16>,
): FixedBuf<7856> {
  const out = slh_dsa_sha2_128s_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(7856, WebBuf.fromUint8Array(out));
}

export function slhDsaSha2_128sVerifyInternal(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<7856>,
): boolean {
  return slh_dsa_sha2_128s_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHA2-128f

export function slhDsaSha2_128fKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_sha2_128f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaSha2_128fSignInternal(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  addrnd?: FixedBuf<16>,
): FixedBuf<17088> {
  const out = slh_dsa_sha2_128f_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(17088, WebBuf.fromUint8Array(out));
}

export function slhDsaSha2_128fVerifyInternal(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<17088>,
): boolean {
  return slh_dsa_sha2_128f_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHA2-192s

export function slhDsaSha2_192sKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_sha2_192s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaSha2_192sSignInternal(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  addrnd?: FixedBuf<24>,
): FixedBuf<16224> {
  const out = slh_dsa_sha2_192s_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(16224, WebBuf.fromUint8Array(out));
}

export function slhDsaSha2_192sVerifyInternal(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<16224>,
): boolean {
  return slh_dsa_sha2_192s_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHA2-192f

export function slhDsaSha2_192fKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_sha2_192f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaSha2_192fSignInternal(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  addrnd?: FixedBuf<24>,
): FixedBuf<35664> {
  const out = slh_dsa_sha2_192f_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(35664, WebBuf.fromUint8Array(out));
}

export function slhDsaSha2_192fVerifyInternal(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<35664>,
): boolean {
  return slh_dsa_sha2_192f_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHA2-256s

export function slhDsaSha2_256sKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_sha2_256s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaSha2_256sSignInternal(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  addrnd?: FixedBuf<32>,
): FixedBuf<29792> {
  const out = slh_dsa_sha2_256s_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(29792, WebBuf.fromUint8Array(out));
}

export function slhDsaSha2_256sVerifyInternal(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<29792>,
): boolean {
  return slh_dsa_sha2_256s_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHA2-256f

export function slhDsaSha2_256fKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_sha2_256f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaSha2_256fSignInternal(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  addrnd?: FixedBuf<32>,
): FixedBuf<49856> {
  const out = slh_dsa_sha2_256f_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(49856, WebBuf.fromUint8Array(out));
}

export function slhDsaSha2_256fVerifyInternal(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<49856>,
): boolean {
  return slh_dsa_sha2_256f_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// =====================================================================
// SHAKE family
// =====================================================================

// SHAKE-128s

export function slhDsaShake_128sKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_shake_128s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaShake_128sSignInternal(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  addrnd?: FixedBuf<16>,
): FixedBuf<7856> {
  const out = slh_dsa_shake_128s_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(7856, WebBuf.fromUint8Array(out));
}

export function slhDsaShake_128sVerifyInternal(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<7856>,
): boolean {
  return slh_dsa_shake_128s_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHAKE-128f

export function slhDsaShake_128fKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_shake_128f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaShake_128fSignInternal(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  addrnd?: FixedBuf<16>,
): FixedBuf<17088> {
  const out = slh_dsa_shake_128f_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(17088, WebBuf.fromUint8Array(out));
}

export function slhDsaShake_128fVerifyInternal(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<17088>,
): boolean {
  return slh_dsa_shake_128f_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHAKE-192s

export function slhDsaShake_192sKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_shake_192s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaShake_192sSignInternal(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  addrnd?: FixedBuf<24>,
): FixedBuf<16224> {
  const out = slh_dsa_shake_192s_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(16224, WebBuf.fromUint8Array(out));
}

export function slhDsaShake_192sVerifyInternal(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<16224>,
): boolean {
  return slh_dsa_shake_192s_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHAKE-192f

export function slhDsaShake_192fKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_shake_192f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaShake_192fSignInternal(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  addrnd?: FixedBuf<24>,
): FixedBuf<35664> {
  const out = slh_dsa_shake_192f_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(35664, WebBuf.fromUint8Array(out));
}

export function slhDsaShake_192fVerifyInternal(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<35664>,
): boolean {
  return slh_dsa_shake_192f_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHAKE-256s

export function slhDsaShake_256sKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_shake_256s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaShake_256sSignInternal(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  addrnd?: FixedBuf<32>,
): FixedBuf<29792> {
  const out = slh_dsa_shake_256s_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(29792, WebBuf.fromUint8Array(out));
}

export function slhDsaShake_256sVerifyInternal(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<29792>,
): boolean {
  return slh_dsa_shake_256s_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}

// SHAKE-256f

export function slhDsaShake_256fKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_shake_256f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaShake_256fSignInternal(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  addrnd?: FixedBuf<32>,
): FixedBuf<49856> {
  const out = slh_dsa_shake_256f_sign_internal(
    signingKey.buf,
    message,
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(49856, WebBuf.fromUint8Array(out));
}

export function slhDsaShake_256fVerifyInternal(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<49856>,
): boolean {
  return slh_dsa_shake_256f_verify_internal(
    verifyingKey.buf,
    message,
    signature.buf,
  );
}
