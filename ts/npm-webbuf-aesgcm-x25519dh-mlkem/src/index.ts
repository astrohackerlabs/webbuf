/**
 * @webbuf/aesgcm-x25519dh-mlkem
 *
 * Hybrid classical+post-quantum authenticated encryption: AES-256-GCM
 * keyed by an HKDF-SHA-256 derivation over both an X25519 ECDH shared
 * secret and an ML-KEM-768 shared secret. An attacker must break both
 * X25519 and ML-KEM to recover the AES key, so the package is secure
 * against classical adversaries today and quantum adversaries in the
 * harvest-now-decrypt-later threat model.
 *
 * Curve25519-flavored sibling of `@webbuf/aesgcm-p256dh-mlkem`. Uses the
 * X25519 primitive (RFC 7748) for the classical half — the standards
 * direction the wider ecosystem (Chrome X25519MLKEM768, Signal PQXDH,
 * IETF TLS hybrid draft) is converging on. The P-256 sibling stays
 * available for consumers needing NIST-curves-everywhere.
 *
 * Wire format: `0x03 || kemCiphertext (1088) || iv (12) ||
 * aesCiphertext+tag` — see `issues/0007-curve25519-hybrid-pq/README.md`
 * Experiment 4 for the byte-precise spec and KAT.
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  ML_KEM_768,
  mlKem768Encapsulate,
  mlKem768EncapsulateDeterministic,
  mlKem768Decapsulate,
} from "@webbuf/mlkem";
import { x25519SharedSecretRaw } from "@webbuf/x25519";
import { sha256Hmac } from "@webbuf/sha256";
import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";

const VERSION = 0x03;
const KEM_CT_SIZE = ML_KEM_768.ciphertextSize; // 1088
const IV_SIZE = 12;
const TAG_SIZE = 16;
const FIXED_OVERHEAD = 1 + KEM_CT_SIZE + IV_SIZE + TAG_SIZE; // 1117

const ZERO_SALT = FixedBuf.alloc(32);
const INFO = WebBuf.fromUtf8("webbuf:aesgcm-x25519dh-mlkem v1");
const EMPTY_AAD = WebBuf.alloc(0);

/**
 * HKDF-SHA-256 (RFC 5869) for output length L = 32 bytes.
 *
 * Implements Extract + Expand in two HMAC-SHA-256 calls:
 *   PRK = HMAC-SHA-256(salt, IKM)
 *   OKM = HMAC-SHA-256(PRK, info || 0x01)
 */
function hkdfSha256L32(
  salt: FixedBuf<32>,
  ikm: WebBuf,
  info: WebBuf,
): FixedBuf<32> {
  const prk = sha256Hmac(salt.buf, ikm);
  const t1Input = WebBuf.concat([info, WebBuf.fromArray([0x01])]);
  return sha256Hmac(prk.buf, t1Input);
}

/**
 * Encrypt a message with hybrid X25519 ECDH + ML-KEM-768 key exchange.
 *
 * Both parties use persistent (static-static) X25519 keypairs. The
 * sender provides their own private X25519 key and the recipient's
 * public X25519 key plus ML-KEM-768 encapsulation key. The AES key is
 * derived from the concatenation of the raw 32-byte X25519 ECDH shared
 * secret and the 32-byte ML-KEM shared secret via HKDF-SHA-256.
 *
 * **Small-order rejection.** `x25519SharedSecretRaw` throws if the
 * recipient's public key is small-order (the resulting shared secret is
 * non-contributory). This protects the hybrid construction from being
 * collapsed to PQ-only by a malicious peer presenting a small-order
 * public key.
 *
 * `aad` is optional Additional Authenticated Data — bytes that are
 * authenticated by the AES-GCM tag but not encrypted and not
 * transmitted in the output. The recipient must supply the same `aad`
 * bytes the sender used; any mismatch causes
 * `aesgcmX25519dhMlkemDecrypt` to throw.
 *
 * Output layout:
 *   [0..1)         version byte (0x03)
 *   [1..1089)      ML-KEM-768 ciphertext (1088 bytes)
 *   [1089..1101)   AES-GCM IV (12 bytes)
 *   [1101..1101+N) AES-GCM ciphertext (N bytes; same length as plaintext)
 *   [1101+N..1117+N) AES-GCM authentication tag (16 bytes)
 */
export function aesgcmX25519dhMlkemEncrypt(
  senderPrivKey: FixedBuf<32>,
  recipientPubKey: FixedBuf<32>,
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  const ecdhRaw = x25519SharedSecretRaw(senderPrivKey, recipientPubKey);
  const { ciphertext: kemCt, sharedSecret: kemSS } =
    mlKem768Encapsulate(recipientEncapKey);
  const ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf]);
  const aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO);
  const aesPart = aesgcmEncrypt(plaintext, aesKey, undefined, aad);
  return WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart]);
}

/**
 * Test/internal-only: encrypt with caller-supplied ML-KEM `m` and
 * AES-GCM `iv`. Used by the KAT regression tests in
 * `test/audit.test.ts` to assert byte-precise output against the
 * fixtures captured in issue 0007 Experiment 4. Application code should
 * use `aesgcmX25519dhMlkemEncrypt`.
 */
export function _aesgcmX25519dhMlkemEncryptDeterministic(
  senderPrivKey: FixedBuf<32>,
  recipientPubKey: FixedBuf<32>,
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
  m: FixedBuf<32>,
  iv: FixedBuf<12>,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  const ecdhRaw = x25519SharedSecretRaw(senderPrivKey, recipientPubKey);
  const { ciphertext: kemCt, sharedSecret: kemSS } =
    mlKem768EncapsulateDeterministic(recipientEncapKey, m);
  const ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf]);
  const aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO);
  const aesPart = aesgcmEncrypt(plaintext, aesKey, iv, aad);
  return WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart]);
}

/**
 * Decrypt an `@webbuf/aesgcm-x25519dh-mlkem` ciphertext.
 *
 * Validates the version byte and minimum length, computes the same
 * hybrid key by combining X25519 ECDH and decapsulated KEM shared
 * secrets, and decrypts. Throws on version-byte mismatch, truncation,
 * or AES-GCM authentication failure (which catches tampered KEM
 * ciphertext, tampered AES ciphertext, tampered IV, AAD mismatch, or
 * any wrong input key — including a wrong X25519 sender pub, wrong
 * X25519 recipient priv, or wrong ML-KEM decapsulation key).
 *
 * Also throws if the X25519 shared secret with the supplied sender pub
 * key is non-contributory (small-order public key). This propagates the
 * `@webbuf/x25519` strict-rejection guarantee through the hybrid layer.
 */
export function aesgcmX25519dhMlkemDecrypt(
  recipientPrivKey: FixedBuf<32>,
  senderPubKey: FixedBuf<32>,
  decapKey: FixedBuf<2400>,
  ciphertext: WebBuf,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  if (ciphertext.length < FIXED_OVERHEAD) {
    throw new Error(
      `aesgcm-x25519dh-mlkem ciphertext too short: ${String(ciphertext.length)} < ${String(FIXED_OVERHEAD)}`,
    );
  }
  const versionByte = ciphertext[0] ?? 0;
  if (versionByte !== VERSION) {
    throw new Error(
      `aesgcm-x25519dh-mlkem unexpected version byte: 0x${versionByte.toString(16).padStart(2, "0")} (expected 0x03)`,
    );
  }
  const kemCt = FixedBuf.fromBuf(
    KEM_CT_SIZE,
    WebBuf.fromUint8Array(ciphertext.subarray(1, 1 + KEM_CT_SIZE)),
  );
  const aesPart = WebBuf.fromUint8Array(ciphertext.subarray(1 + KEM_CT_SIZE));
  const ecdhRaw = x25519SharedSecretRaw(recipientPrivKey, senderPubKey);
  const kemSS = mlKem768Decapsulate(decapKey, kemCt);
  const ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf]);
  const aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO);
  return aesgcmDecrypt(aesPart, aesKey, aad);
}

export const AESGCM_X25519DH_MLKEM = {
  versionByte: VERSION,
  kemCiphertextSize: KEM_CT_SIZE,
  ivSize: IV_SIZE,
  tagSize: TAG_SIZE,
  fixedOverhead: FIXED_OVERHEAD,
  hkdfInfo: "webbuf:aesgcm-x25519dh-mlkem v1",
} as const;
