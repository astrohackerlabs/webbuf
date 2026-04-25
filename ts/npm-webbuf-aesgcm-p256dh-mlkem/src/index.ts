/**
 * @webbuf/aesgcm-p256dh-mlkem
 *
 * Hybrid classical+post-quantum authenticated encryption: AES-256-GCM
 * keyed by an HKDF-SHA-256 derivation over both a P-256 ECDH shared
 * secret and an ML-KEM-768 shared secret. An attacker must break both
 * P-256 and ML-KEM to recover the AES key, so the package is secure
 * against classical adversaries today and quantum adversaries in the
 * harvest-now-decrypt-later threat model.
 *
 * The wire format is `0x02 || kemCiphertext (1088) || iv (12) ||
 * aesCiphertext+tag` — see `issues/0004-hybrid-pq-encryption/README.md`
 * for the byte-precise spec and KAT.
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  ML_KEM_768,
  mlKem768Encapsulate,
  mlKem768EncapsulateDeterministic,
  mlKem768Decapsulate,
} from "@webbuf/mlkem";
import { p256SharedSecretRaw } from "@webbuf/p256";
import { sha256Hmac } from "@webbuf/sha256";
import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";

const VERSION = 0x02;
const KEM_CT_SIZE = ML_KEM_768.ciphertextSize; // 1088
const IV_SIZE = 12;
const TAG_SIZE = 16;
const FIXED_OVERHEAD = 1 + KEM_CT_SIZE + IV_SIZE + TAG_SIZE; // 1117

const ZERO_SALT = FixedBuf.alloc(32);
const INFO = WebBuf.fromUtf8("webbuf:aesgcm-p256dh-mlkem v1");

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
 * Encrypt a message with hybrid P-256 ECDH + ML-KEM-768 key exchange.
 *
 * Both parties use persistent (static-static) P-256 keypairs. The
 * sender provides their own private P-256 key and the recipient's
 * public P-256 key plus ML-KEM-768 encapsulation key. The AES key is
 * derived from the concatenation of the raw 32-byte ECDH X-coordinate
 * and the 32-byte ML-KEM shared secret via HKDF-SHA-256.
 *
 * Output layout:
 *   [0..1)         version byte (0x02)
 *   [1..1089)      ML-KEM-768 ciphertext (1088 bytes)
 *   [1089..1101)   AES-GCM IV (12 bytes)
 *   [1101..1101+N) AES-GCM ciphertext (N bytes; same length as plaintext)
 *   [1101+N..1117+N) AES-GCM authentication tag (16 bytes)
 */
export function aesgcmP256dhMlkemEncrypt(
  senderPrivKey: FixedBuf<32>,
  recipientPubKey: FixedBuf<33>,
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
): WebBuf {
  const ecdhRaw = p256SharedSecretRaw(senderPrivKey, recipientPubKey);
  const { ciphertext: kemCt, sharedSecret: kemSS } =
    mlKem768Encapsulate(recipientEncapKey);
  const ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf]);
  const aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO);
  const aesPart = aesgcmEncrypt(plaintext, aesKey);
  return WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart]);
}

/**
 * Test/internal-only: encrypt with caller-supplied ML-KEM `m` and
 * AES-GCM `iv`. Used by the KAT regression test in
 * `test/audit.test.ts` to assert byte-precise output against the
 * fixture from issue 0004 Experiment 1. Application code should use
 * `aesgcmP256dhMlkemEncrypt`.
 */
export function _aesgcmP256dhMlkemEncryptDeterministic(
  senderPrivKey: FixedBuf<32>,
  recipientPubKey: FixedBuf<33>,
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
  m: FixedBuf<32>,
  iv: FixedBuf<12>,
): WebBuf {
  const ecdhRaw = p256SharedSecretRaw(senderPrivKey, recipientPubKey);
  const { ciphertext: kemCt, sharedSecret: kemSS } =
    mlKem768EncapsulateDeterministic(recipientEncapKey, m);
  const ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf]);
  const aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO);
  const aesPart = aesgcmEncrypt(plaintext, aesKey, iv);
  return WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart]);
}

/**
 * Decrypt an `@webbuf/aesgcm-p256dh-mlkem` ciphertext.
 *
 * Validates the version byte and minimum length, computes the same
 * hybrid key by combining ECDH and decapsulated KEM shared secrets,
 * and decrypts. Throws on version-byte mismatch, truncation, or
 * AES-GCM authentication failure (which catches tampered KEM
 * ciphertext, tampered AES ciphertext, tampered IV, or any wrong
 * input key — including a wrong P-256 sender pub, wrong P-256
 * recipient priv, or wrong ML-KEM decapsulation key).
 */
export function aesgcmP256dhMlkemDecrypt(
  recipientPrivKey: FixedBuf<32>,
  senderPubKey: FixedBuf<33>,
  decapKey: FixedBuf<2400>,
  ciphertext: WebBuf,
): WebBuf {
  if (ciphertext.length < FIXED_OVERHEAD) {
    throw new Error(
      `aesgcm-p256dh-mlkem ciphertext too short: ${String(ciphertext.length)} < ${String(FIXED_OVERHEAD)}`,
    );
  }
  const versionByte = ciphertext[0];
  if (versionByte !== VERSION) {
    throw new Error(
      `aesgcm-p256dh-mlkem unexpected version byte: 0x${versionByte!.toString(16).padStart(2, "0")} (expected 0x02)`,
    );
  }
  const kemCt = FixedBuf.fromBuf(
    KEM_CT_SIZE,
    WebBuf.fromUint8Array(ciphertext.subarray(1, 1 + KEM_CT_SIZE)),
  );
  const aesPart = WebBuf.fromUint8Array(ciphertext.subarray(1 + KEM_CT_SIZE));
  const ecdhRaw = p256SharedSecretRaw(recipientPrivKey, senderPubKey);
  const kemSS = mlKem768Decapsulate(decapKey, kemCt);
  const ikm = WebBuf.concat([ecdhRaw.buf, kemSS.buf]);
  const aesKey = hkdfSha256L32(ZERO_SALT, ikm, INFO);
  return aesgcmDecrypt(aesPart, aesKey);
}

export const AESGCM_P256DH_MLKEM = {
  versionByte: VERSION,
  kemCiphertextSize: KEM_CT_SIZE,
  ivSize: IV_SIZE,
  tagSize: TAG_SIZE,
  fixedOverhead: FIXED_OVERHEAD,
  hkdfInfo: "webbuf:aesgcm-p256dh-mlkem v1",
} as const;
