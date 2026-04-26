/**
 * One-shot script to capture the KAT vector for issue 0007 Experiment 5.
 *
 * Outputs the deterministic KAT for @webbuf/sig-ed25519-mldsa using
 * `_sigEd25519MldsaSignDeterministic` (which uses
 * `mlDsa65SignDeterministic` plus the inherently-deterministic
 * Ed25519). Production code should always use the hedged
 * `sigEd25519MldsaSign`; deterministic mode is for fixtures only.
 *
 * Inputs:
 *   - Ed25519 seed: 0xaa * 32
 *   - ML-DSA-65 keypair seed: 0xbb * 32
 *   - Message: "composite signature"
 *
 * Run from ts/npm-webbuf:
 *   tsx scripts/capture-issue-0007-sig-ed25519-mldsa-kats.ts
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { ed25519PublicKeyCreate } from "@webbuf/ed25519";
import { mlDsa65KeyPairDeterministic } from "@webbuf/mldsa";
import { sha256Hash } from "@webbuf/sha256";
import { _sigEd25519MldsaSignDeterministic } from "@webbuf/sig-ed25519-mldsa";

const ED25519_SEED = FixedBuf.fromHex(32, "aa".repeat(32));
const MLDSA_SEED = FixedBuf.fromHex(32, "bb".repeat(32));
const MESSAGE = WebBuf.fromUtf8("composite signature");

const edPub = ed25519PublicKeyCreate(ED25519_SEED);
const { signingKey, verifyingKey } = mlDsa65KeyPairDeterministic(MLDSA_SEED);

const signature = _sigEd25519MldsaSignDeterministic(
  ED25519_SEED,
  signingKey,
  MESSAGE,
);

console.log("=".repeat(70));
console.log("@webbuf/sig-ed25519-mldsa v1 KAT (deterministic)");
console.log("=".repeat(70));
console.log("Ed25519 seed         :", ED25519_SEED.toHex());
console.log("Ed25519 pub          :", edPub.toHex());
console.log("ML-DSA-65 seed       :", MLDSA_SEED.toHex());
console.log(
  "ML-DSA-65 verify key (first 32B) :",
  verifyingKey.buf.slice(0, 32).toHex(),
);
console.log(
  "ML-DSA-65 verify key (last 32B)  :",
  verifyingKey.buf.slice(verifyingKey.buf.length - 32).toHex(),
);
console.log("Message (utf8)       : 'composite signature'");
console.log("Signature length     :", signature.buf.length, "bytes");
console.log("Signature[0]         : 0x" + signature.buf[0]!.toString(16).padStart(2, "0"));
console.log(
  "Ed25519 sig (bytes 1..65)  :",
  signature.buf.slice(1, 65).toHex(),
);
console.log(
  "ML-DSA sig prefix 16B (bytes 65..81) :",
  signature.buf.slice(65, 81).toHex(),
);
console.log(
  "SHA-256(verifyingKey):",
  sha256Hash(WebBuf.fromUint8Array(verifyingKey.buf)).toHex(),
);
console.log(
  "SHA-256(signature)   :",
  sha256Hash(WebBuf.fromUint8Array(signature.buf)).toHex(),
);
