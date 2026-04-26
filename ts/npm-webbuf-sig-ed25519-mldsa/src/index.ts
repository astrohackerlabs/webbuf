/**
 * @webbuf/sig-ed25519-mldsa
 *
 * Composite Ed25519 + ML-DSA-65 signatures: two independent signatures
 * over the raw message bytes, both required to verify. An attacker must
 * forge BOTH the classical Ed25519 signature AND the post-quantum
 * ML-DSA-65 signature to forge the composite — secure against today's
 * classical adversaries and a future quantum-capable adversary.
 *
 * Matches the OpenPGP `draft-ietf-openpgp-pqc` "MUST" pairing and the
 * LAMPS X.509 `id-Ed25519-MLDSA65` OID at the primitive level. WebBuf
 * does not provide Web PKI / X.509 / OpenPGP framing — the package
 * signs and verifies raw bytes; consumers do their own packaging.
 *
 * Wire format: `0x01 || ed25519_sig (64) || mldsa_sig (3309)` = 3374
 * bytes. See `issues/0007-curve25519-hybrid-pq/README.md` Experiment 5
 * for the byte-precise spec and KAT.
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { ed25519Sign, ed25519Verify } from "@webbuf/ed25519";
import {
  ML_DSA_65,
  mlDsa65Sign,
  mlDsa65SignDeterministic,
  mlDsa65Verify,
} from "@webbuf/mldsa";

const VERSION = 0x01;
const ED25519_PUBLIC_KEY_SIZE = 32;
const ED25519_PRIVATE_KEY_SIZE = 32;
const ED25519_SIGNATURE_SIZE = 64;
const MLDSA_VERIFYING_KEY_SIZE = ML_DSA_65.verifyingKeySize; // 1952
const MLDSA_SIGNING_KEY_SIZE = ML_DSA_65.signingKeySize; // 4032
const MLDSA_SIGNATURE_SIZE = ML_DSA_65.signatureSize; // 3309
const FIXED_SIZE = 1 + ED25519_SIGNATURE_SIZE + MLDSA_SIGNATURE_SIZE; // 3374

/**
 * Composite Ed25519 + ML-DSA-65 signature over a message.
 *
 * Signs the raw message bytes with both PureEdDSA (RFC 8032 §5.1.6) and
 * FIPS 204 ML-DSA-65 Sign. Both signers consume the message verbatim —
 * no prehash, no digest indirection. Returns the wire-format
 * concatenation: `version || ed25519_sig (64) || mldsa_sig (3309)` =
 * 3374 bytes.
 *
 * Determinism: PureEdDSA is RFC-deterministic; ML-DSA-65 is hedged by
 * default (issue 0003). The composite signature is therefore
 * non-deterministic by default — the Ed25519 half is stable for a
 * given (seed, message), but the ML-DSA half varies per call.
 */
export function sigEd25519MldsaSign(
  ed25519Priv: FixedBuf<32>,
  mldsaSigningKey: FixedBuf<4032>,
  message: WebBuf,
): FixedBuf<3374> {
  const edSig = ed25519Sign(ed25519Priv, message);
  const mldsaSig = mlDsa65Sign(mldsaSigningKey, message);
  return FixedBuf.fromBuf(
    3374,
    WebBuf.concat([WebBuf.fromArray([VERSION]), edSig.buf, mldsaSig.buf]),
  );
}

/**
 * Test/internal-only: sign with deterministic ML-DSA-65 (FIPS 204
 * `Sign`, no per-call randomness). Used by KAT regression tests.
 *
 * Application code should never call this directly — the leading
 * underscore signals deterministic randomness, which is unsafe in
 * production per issue 0003. Use `sigEd25519MldsaSign` instead, which
 * uses ML-DSA-65's hedged-signing default.
 */
export function _sigEd25519MldsaSignDeterministic(
  ed25519Priv: FixedBuf<32>,
  mldsaSigningKey: FixedBuf<4032>,
  message: WebBuf,
): FixedBuf<3374> {
  const edSig = ed25519Sign(ed25519Priv, message);
  const mldsaSig = mlDsa65SignDeterministic(mldsaSigningKey, message);
  return FixedBuf.fromBuf(
    3374,
    WebBuf.concat([WebBuf.fromArray([VERSION]), edSig.buf, mldsaSig.buf]),
  );
}

/**
 * Composite Ed25519 + ML-DSA-65 signature verification.
 *
 * Both halves must verify against their respective public keys for the
 * composite to verify. Returns `true` iff both pass; returns `false`
 * for any rejection (wrong key on either side, tampered message,
 * tampered signature, version-byte mismatch, malformed Ed25519 point,
 * non-canonical Ed25519 S, etc.). Throws **only** on input-length
 * errors at the top level.
 *
 * Strict Ed25519 verification (`verify_strict` under the hood) is
 * enforced via `@webbuf/ed25519` — small-order Ed25519 public keys
 * and non-canonical S are rejected, closing the universal-forgery
 * hole that fooled the experiment-3 wrapper before the Codex fix.
 *
 * Both halves are verified regardless of either half's individual
 * result, so this does not short-circuit. Neither primitive's
 * underlying verifier is constant-time, however — the abstraction
 * does not add timing safety we don't already have at the primitive
 * layer.
 */
export function sigEd25519MldsaVerify(
  ed25519Pub: FixedBuf<32>,
  mldsaVerifyingKey: FixedBuf<1952>,
  message: WebBuf,
  signature: FixedBuf<3374>,
): boolean {
  const sigBytes = signature.buf;
  // FixedBuf<3374> already enforces the length; defensive double-check
  // (and gives wasm-bindgen-thrown errors stable wording if a mis-sized
  // FixedBuf ever slipped through).
  if (sigBytes.length !== FIXED_SIZE) {
    return false;
  }
  if (sigBytes[0] !== VERSION) {
    return false;
  }
  const edSig = FixedBuf.fromBuf(
    ED25519_SIGNATURE_SIZE,
    WebBuf.fromUint8Array(sigBytes.subarray(1, 1 + ED25519_SIGNATURE_SIZE)),
  );
  const mldsaSig = FixedBuf.fromBuf(
    MLDSA_SIGNATURE_SIZE,
    WebBuf.fromUint8Array(sigBytes.subarray(1 + ED25519_SIGNATURE_SIZE)),
  );

  const edOk = ed25519Verify(ed25519Pub, message, edSig);
  const mldsaOk = mlDsa65Verify(mldsaVerifyingKey, message, mldsaSig);
  return edOk && mldsaOk;
}

export const SIG_ED25519_MLDSA = {
  versionByte: VERSION,
  ed25519SignatureSize: ED25519_SIGNATURE_SIZE,
  mldsaSignatureSize: MLDSA_SIGNATURE_SIZE,
  fixedSize: FIXED_SIZE,
  ed25519PublicKeySize: ED25519_PUBLIC_KEY_SIZE,
  ed25519PrivateKeySize: ED25519_PRIVATE_KEY_SIZE,
  mldsaVerifyingKeySize: MLDSA_VERIFYING_KEY_SIZE,
  mldsaSigningKeySize: MLDSA_SIGNING_KEY_SIZE,
} as const;
