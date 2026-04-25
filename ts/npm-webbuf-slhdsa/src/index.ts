import {
  slh_dsa_sha2_128s_keypair,
  slh_dsa_sha2_128s_sign,
  slh_dsa_sha2_128s_sign_internal,
  slh_dsa_sha2_128s_verify,
  slh_dsa_sha2_128s_verify_internal,
  slh_dsa_sha2_128f_keypair,
  slh_dsa_sha2_128f_sign,
  slh_dsa_sha2_128f_sign_internal,
  slh_dsa_sha2_128f_verify,
  slh_dsa_sha2_128f_verify_internal,
  slh_dsa_sha2_192s_keypair,
  slh_dsa_sha2_192s_sign,
  slh_dsa_sha2_192s_sign_internal,
  slh_dsa_sha2_192s_verify,
  slh_dsa_sha2_192s_verify_internal,
  slh_dsa_sha2_192f_keypair,
  slh_dsa_sha2_192f_sign,
  slh_dsa_sha2_192f_sign_internal,
  slh_dsa_sha2_192f_verify,
  slh_dsa_sha2_192f_verify_internal,
  slh_dsa_sha2_256s_keypair,
  slh_dsa_sha2_256s_sign,
  slh_dsa_sha2_256s_sign_internal,
  slh_dsa_sha2_256s_verify,
  slh_dsa_sha2_256s_verify_internal,
  slh_dsa_sha2_256f_keypair,
  slh_dsa_sha2_256f_sign,
  slh_dsa_sha2_256f_sign_internal,
  slh_dsa_sha2_256f_verify,
  slh_dsa_sha2_256f_verify_internal,
  slh_dsa_shake_128s_keypair,
  slh_dsa_shake_128s_sign,
  slh_dsa_shake_128s_sign_internal,
  slh_dsa_shake_128s_verify,
  slh_dsa_shake_128s_verify_internal,
  slh_dsa_shake_128f_keypair,
  slh_dsa_shake_128f_sign,
  slh_dsa_shake_128f_sign_internal,
  slh_dsa_shake_128f_verify,
  slh_dsa_shake_128f_verify_internal,
  slh_dsa_shake_192s_keypair,
  slh_dsa_shake_192s_sign,
  slh_dsa_shake_192s_sign_internal,
  slh_dsa_shake_192s_verify,
  slh_dsa_shake_192s_verify_internal,
  slh_dsa_shake_192f_keypair,
  slh_dsa_shake_192f_sign,
  slh_dsa_shake_192f_sign_internal,
  slh_dsa_shake_192f_verify,
  slh_dsa_shake_192f_verify_internal,
  slh_dsa_shake_256s_keypair,
  slh_dsa_shake_256s_sign,
  slh_dsa_shake_256s_sign_internal,
  slh_dsa_shake_256s_verify,
  slh_dsa_shake_256s_verify_internal,
  slh_dsa_shake_256f_keypair,
  slh_dsa_shake_256f_sign,
  slh_dsa_shake_256f_sign_internal,
  slh_dsa_shake_256f_verify,
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

type SlhSignFn = (
  signingKey: Uint8Array,
  message: Uint8Array,
  context: Uint8Array,
  addrnd: Uint8Array,
) => Uint8Array;

type SlhVerifyFn = (
  verifyingKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  context: Uint8Array,
) => boolean;

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

function randomSeed<N extends number>(size: N): FixedBuf<N> {
  return FixedBuf.fromRandom(size);
}

function defaultContext(context?: WebBuf): WebBuf {
  return context ?? WebBuf.alloc(0);
}

function requireAllSeeds<N extends number>(
  name: string,
  seedSize: N,
  skSeed?: FixedBuf<N>,
  skPrf?: FixedBuf<N>,
  pkSeed?: FixedBuf<N>,
): [FixedBuf<N>, FixedBuf<N>, FixedBuf<N>] {
  if (skSeed === undefined && skPrf === undefined && pkSeed === undefined) {
    return [randomSeed(seedSize), randomSeed(seedSize), randomSeed(seedSize)];
  }
  if (skSeed === undefined || skPrf === undefined || pkSeed === undefined) {
    throw new Error(`${name} requires all three seeds, or none`);
  }
  return [skSeed, skPrf, pkSeed];
}

function slhSignHedged<
  SkSize extends number,
  SigSize extends number,
  N extends number,
>(
  sign: SlhSignFn,
  signatureSize: SigSize,
  seedSize: N,
  signingKey: FixedBuf<SkSize>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<SigSize> {
  return slhSignDeterministic(
    sign,
    signatureSize,
    signingKey,
    message,
    context,
    randomSeed(seedSize),
  );
}

function slhSignDeterministic<
  SkSize extends number,
  SigSize extends number,
  N extends number,
>(
  sign: SlhSignFn,
  signatureSize: SigSize,
  signingKey: FixedBuf<SkSize>,
  message: WebBuf,
  context?: WebBuf,
  addrnd?: FixedBuf<N>,
): FixedBuf<SigSize> {
  const out = sign(
    signingKey.buf,
    message,
    defaultContext(context),
    addrnd ? addrnd.buf : EMPTY_OPT_RAND,
  );
  return FixedBuf.fromBuf(signatureSize, WebBuf.fromUint8Array(out));
}

function slhVerify<VkSize extends number, SigSize extends number>(
  verify: SlhVerifyFn,
  verifyingKey: FixedBuf<VkSize>,
  message: WebBuf,
  signature: FixedBuf<SigSize>,
  context?: WebBuf,
): boolean {
  return verify(
    verifyingKey.buf,
    message,
    signature.buf,
    defaultContext(context),
  );
}

// =====================================================================
// SHA2 family
// =====================================================================

// SHA2-128s

export function slhDsaSha2_128sKeyPair(): SlhDsaKeyPair<32, 64>;
export function slhDsaSha2_128sKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64>;
export function slhDsaSha2_128sKeyPair(
  skSeed?: FixedBuf<16>,
  skPrf?: FixedBuf<16>,
  pkSeed?: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const seeds = requireAllSeeds(
    "slhDsaSha2_128sKeyPair",
    16,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaSha2_128sKeyPairDeterministic(...seeds);
}

export function slhDsaSha2_128sKeyPairDeterministic(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_sha2_128s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaSha2_128sSign(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<7856> {
  return slhSignHedged(
    slh_dsa_sha2_128s_sign,
    7856,
    16,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_128sSignDeterministic(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<7856> {
  return slhSignDeterministic(
    slh_dsa_sha2_128s_sign,
    7856,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_128sVerify(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<7856>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_sha2_128s_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaSha2_128fKeyPair(): SlhDsaKeyPair<32, 64>;
export function slhDsaSha2_128fKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64>;
export function slhDsaSha2_128fKeyPair(
  skSeed?: FixedBuf<16>,
  skPrf?: FixedBuf<16>,
  pkSeed?: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const seeds = requireAllSeeds(
    "slhDsaSha2_128fKeyPair",
    16,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaSha2_128fKeyPairDeterministic(...seeds);
}

export function slhDsaSha2_128fKeyPairDeterministic(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_sha2_128f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaSha2_128fSign(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<17088> {
  return slhSignHedged(
    slh_dsa_sha2_128f_sign,
    17088,
    16,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_128fSignDeterministic(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<17088> {
  return slhSignDeterministic(
    slh_dsa_sha2_128f_sign,
    17088,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_128fVerify(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<17088>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_sha2_128f_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaSha2_192sKeyPair(): SlhDsaKeyPair<48, 96>;
export function slhDsaSha2_192sKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96>;
export function slhDsaSha2_192sKeyPair(
  skSeed?: FixedBuf<24>,
  skPrf?: FixedBuf<24>,
  pkSeed?: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const seeds = requireAllSeeds(
    "slhDsaSha2_192sKeyPair",
    24,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaSha2_192sKeyPairDeterministic(...seeds);
}

export function slhDsaSha2_192sKeyPairDeterministic(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_sha2_192s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaSha2_192sSign(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<16224> {
  return slhSignHedged(
    slh_dsa_sha2_192s_sign,
    16224,
    24,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_192sSignDeterministic(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<16224> {
  return slhSignDeterministic(
    slh_dsa_sha2_192s_sign,
    16224,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_192sVerify(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<16224>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_sha2_192s_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaSha2_192fKeyPair(): SlhDsaKeyPair<48, 96>;
export function slhDsaSha2_192fKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96>;
export function slhDsaSha2_192fKeyPair(
  skSeed?: FixedBuf<24>,
  skPrf?: FixedBuf<24>,
  pkSeed?: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const seeds = requireAllSeeds(
    "slhDsaSha2_192fKeyPair",
    24,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaSha2_192fKeyPairDeterministic(...seeds);
}

export function slhDsaSha2_192fKeyPairDeterministic(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_sha2_192f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaSha2_192fSign(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<35664> {
  return slhSignHedged(
    slh_dsa_sha2_192f_sign,
    35664,
    24,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_192fSignDeterministic(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<35664> {
  return slhSignDeterministic(
    slh_dsa_sha2_192f_sign,
    35664,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_192fVerify(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<35664>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_sha2_192f_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaSha2_256sKeyPair(): SlhDsaKeyPair<64, 128>;
export function slhDsaSha2_256sKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128>;
export function slhDsaSha2_256sKeyPair(
  skSeed?: FixedBuf<32>,
  skPrf?: FixedBuf<32>,
  pkSeed?: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const seeds = requireAllSeeds(
    "slhDsaSha2_256sKeyPair",
    32,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaSha2_256sKeyPairDeterministic(...seeds);
}

export function slhDsaSha2_256sKeyPairDeterministic(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_sha2_256s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaSha2_256sSign(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<29792> {
  return slhSignHedged(
    slh_dsa_sha2_256s_sign,
    29792,
    32,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_256sSignDeterministic(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<29792> {
  return slhSignDeterministic(
    slh_dsa_sha2_256s_sign,
    29792,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_256sVerify(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<29792>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_sha2_256s_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaSha2_256fKeyPair(): SlhDsaKeyPair<64, 128>;
export function slhDsaSha2_256fKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128>;
export function slhDsaSha2_256fKeyPair(
  skSeed?: FixedBuf<32>,
  skPrf?: FixedBuf<32>,
  pkSeed?: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const seeds = requireAllSeeds(
    "slhDsaSha2_256fKeyPair",
    32,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaSha2_256fKeyPairDeterministic(...seeds);
}

export function slhDsaSha2_256fKeyPairDeterministic(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_sha2_256f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaSha2_256fSign(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<49856> {
  return slhSignHedged(
    slh_dsa_sha2_256f_sign,
    49856,
    32,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_256fSignDeterministic(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<49856> {
  return slhSignDeterministic(
    slh_dsa_sha2_256f_sign,
    49856,
    signingKey,
    message,
    context,
  );
}

export function slhDsaSha2_256fVerify(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<49856>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_sha2_256f_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaShake_128sKeyPair(): SlhDsaKeyPair<32, 64>;
export function slhDsaShake_128sKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64>;
export function slhDsaShake_128sKeyPair(
  skSeed?: FixedBuf<16>,
  skPrf?: FixedBuf<16>,
  pkSeed?: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const seeds = requireAllSeeds(
    "slhDsaShake_128sKeyPair",
    16,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaShake_128sKeyPairDeterministic(...seeds);
}

export function slhDsaShake_128sKeyPairDeterministic(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_shake_128s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaShake_128sSign(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<7856> {
  return slhSignHedged(
    slh_dsa_shake_128s_sign,
    7856,
    16,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_128sSignDeterministic(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<7856> {
  return slhSignDeterministic(
    slh_dsa_shake_128s_sign,
    7856,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_128sVerify(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<7856>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_shake_128s_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaShake_128fKeyPair(): SlhDsaKeyPair<32, 64>;
export function slhDsaShake_128fKeyPair(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64>;
export function slhDsaShake_128fKeyPair(
  skSeed?: FixedBuf<16>,
  skPrf?: FixedBuf<16>,
  pkSeed?: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const seeds = requireAllSeeds(
    "slhDsaShake_128fKeyPair",
    16,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaShake_128fKeyPairDeterministic(...seeds);
}

export function slhDsaShake_128fKeyPairDeterministic(
  skSeed: FixedBuf<16>,
  skPrf: FixedBuf<16>,
  pkSeed: FixedBuf<16>,
): SlhDsaKeyPair<32, 64> {
  const out = slh_dsa_shake_128f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 32, 64);
}

export function slhDsaShake_128fSign(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<17088> {
  return slhSignHedged(
    slh_dsa_shake_128f_sign,
    17088,
    16,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_128fSignDeterministic(
  signingKey: FixedBuf<64>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<17088> {
  return slhSignDeterministic(
    slh_dsa_shake_128f_sign,
    17088,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_128fVerify(
  verifyingKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<17088>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_shake_128f_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaShake_192sKeyPair(): SlhDsaKeyPair<48, 96>;
export function slhDsaShake_192sKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96>;
export function slhDsaShake_192sKeyPair(
  skSeed?: FixedBuf<24>,
  skPrf?: FixedBuf<24>,
  pkSeed?: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const seeds = requireAllSeeds(
    "slhDsaShake_192sKeyPair",
    24,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaShake_192sKeyPairDeterministic(...seeds);
}

export function slhDsaShake_192sKeyPairDeterministic(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_shake_192s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaShake_192sSign(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<16224> {
  return slhSignHedged(
    slh_dsa_shake_192s_sign,
    16224,
    24,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_192sSignDeterministic(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<16224> {
  return slhSignDeterministic(
    slh_dsa_shake_192s_sign,
    16224,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_192sVerify(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<16224>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_shake_192s_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaShake_192fKeyPair(): SlhDsaKeyPair<48, 96>;
export function slhDsaShake_192fKeyPair(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96>;
export function slhDsaShake_192fKeyPair(
  skSeed?: FixedBuf<24>,
  skPrf?: FixedBuf<24>,
  pkSeed?: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const seeds = requireAllSeeds(
    "slhDsaShake_192fKeyPair",
    24,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaShake_192fKeyPairDeterministic(...seeds);
}

export function slhDsaShake_192fKeyPairDeterministic(
  skSeed: FixedBuf<24>,
  skPrf: FixedBuf<24>,
  pkSeed: FixedBuf<24>,
): SlhDsaKeyPair<48, 96> {
  const out = slh_dsa_shake_192f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 48, 96);
}

export function slhDsaShake_192fSign(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<35664> {
  return slhSignHedged(
    slh_dsa_shake_192f_sign,
    35664,
    24,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_192fSignDeterministic(
  signingKey: FixedBuf<96>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<35664> {
  return slhSignDeterministic(
    slh_dsa_shake_192f_sign,
    35664,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_192fVerify(
  verifyingKey: FixedBuf<48>,
  message: WebBuf,
  signature: FixedBuf<35664>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_shake_192f_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaShake_256sKeyPair(): SlhDsaKeyPair<64, 128>;
export function slhDsaShake_256sKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128>;
export function slhDsaShake_256sKeyPair(
  skSeed?: FixedBuf<32>,
  skPrf?: FixedBuf<32>,
  pkSeed?: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const seeds = requireAllSeeds(
    "slhDsaShake_256sKeyPair",
    32,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaShake_256sKeyPairDeterministic(...seeds);
}

export function slhDsaShake_256sKeyPairDeterministic(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_shake_256s_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaShake_256sSign(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<29792> {
  return slhSignHedged(
    slh_dsa_shake_256s_sign,
    29792,
    32,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_256sSignDeterministic(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<29792> {
  return slhSignDeterministic(
    slh_dsa_shake_256s_sign,
    29792,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_256sVerify(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<29792>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_shake_256s_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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

export function slhDsaShake_256fKeyPair(): SlhDsaKeyPair<64, 128>;
export function slhDsaShake_256fKeyPair(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128>;
export function slhDsaShake_256fKeyPair(
  skSeed?: FixedBuf<32>,
  skPrf?: FixedBuf<32>,
  pkSeed?: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const seeds = requireAllSeeds(
    "slhDsaShake_256fKeyPair",
    32,
    skSeed,
    skPrf,
    pkSeed,
  );
  return slhDsaShake_256fKeyPairDeterministic(...seeds);
}

export function slhDsaShake_256fKeyPairDeterministic(
  skSeed: FixedBuf<32>,
  skPrf: FixedBuf<32>,
  pkSeed: FixedBuf<32>,
): SlhDsaKeyPair<64, 128> {
  const out = slh_dsa_shake_256f_keypair(skSeed.buf, skPrf.buf, pkSeed.buf);
  return splitKeypair(out, 64, 128);
}

export function slhDsaShake_256fSign(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<49856> {
  return slhSignHedged(
    slh_dsa_shake_256f_sign,
    49856,
    32,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_256fSignDeterministic(
  signingKey: FixedBuf<128>,
  message: WebBuf,
  context?: WebBuf,
): FixedBuf<49856> {
  return slhSignDeterministic(
    slh_dsa_shake_256f_sign,
    49856,
    signingKey,
    message,
    context,
  );
}

export function slhDsaShake_256fVerify(
  verifyingKey: FixedBuf<64>,
  message: WebBuf,
  signature: FixedBuf<49856>,
  context?: WebBuf,
): boolean {
  return slhVerify(
    slh_dsa_shake_256f_verify,
    verifyingKey,
    message,
    signature,
    context,
  );
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
