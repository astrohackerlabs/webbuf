/**
 * @webbuf/aesgcm-mlkem
 *
 * AES-256-GCM encryption with ML-KEM-768 key encapsulation. Pure
 * post-quantum authenticated encryption: the recipient holds an ML-KEM-768
 * keypair and the sender encapsulates a fresh shared secret per message,
 * derives an AES-256 key via HKDF-SHA-256, and encrypts with AES-GCM.
 *
 * The wire format is `0x01 || kemCiphertext (1088) || iv (12) ||
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
import { sha256Hmac } from "@webbuf/sha256";
import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";

const VERSION = 0x01;
const KEM_CT_SIZE = ML_KEM_768.ciphertextSize; // 1088
const IV_SIZE = 12;
const TAG_SIZE = 16;
const FIXED_OVERHEAD = 1 + KEM_CT_SIZE + IV_SIZE + TAG_SIZE; // 1117

const ZERO_SALT = FixedBuf.alloc(32);
const INFO = WebBuf.fromUtf8("webbuf:aesgcm-mlkem v1");
const EMPTY_AAD = WebBuf.alloc(0);

/**
 * HKDF-SHA-256 (RFC 5869) for output length L = 32 bytes.
 *
 * Implements Extract + Expand in two HMAC-SHA-256 calls. For L = 32 the
 * Expand step needs only one HMAC iteration:
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
 * Encrypt a message under an ML-KEM-768 encapsulation key.
 *
 * Generates fresh ML-KEM encapsulation randomness and a fresh AES-GCM
 * IV per call via `FixedBuf.fromRandom`. Two calls with identical
 * `recipientEncapKey` and `plaintext` produce different ciphertexts.
 *
 * `aad` is optional Additional Authenticated Data — bytes that are
 * authenticated by the AES-GCM tag but not encrypted and not
 * transmitted in the output. The recipient must supply the same `aad`
 * bytes the sender used; any mismatch causes `aesgcmMlkemDecrypt` to
 * throw. Empty AAD is the default and matches the original issue 0004
 * behavior.
 *
 * Output layout:
 *   [0..1)         version byte (0x01)
 *   [1..1089)      ML-KEM-768 ciphertext (1088 bytes)
 *   [1089..1101)   AES-GCM IV (12 bytes)
 *   [1101..1101+N) AES-GCM ciphertext (N bytes; same length as plaintext)
 *   [1101+N..1117+N) AES-GCM authentication tag (16 bytes)
 */
export function aesgcmMlkemEncrypt(
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  const { ciphertext: kemCt, sharedSecret } =
    mlKem768Encapsulate(recipientEncapKey);
  const aesKey = hkdfSha256L32(ZERO_SALT, sharedSecret.buf, INFO);
  const aesPart = aesgcmEncrypt(plaintext, aesKey, undefined, aad);
  return WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart]);
}

/**
 * Test/internal-only: encrypt with caller-supplied ML-KEM `m` and AES-GCM
 * `iv`. Used by the KAT regression tests in `test/audit.test.ts` to
 * assert byte-precise output against the captured fixtures from issue
 * 0004 (empty AAD) and issue 0006 Experiment 2 (non-empty AAD).
 * Application code should use `aesgcmMlkemEncrypt`.
 */
export function _aesgcmMlkemEncryptDeterministic(
  recipientEncapKey: FixedBuf<1184>,
  plaintext: WebBuf,
  m: FixedBuf<32>,
  iv: FixedBuf<12>,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  const { ciphertext: kemCt, sharedSecret } = mlKem768EncapsulateDeterministic(
    recipientEncapKey,
    m,
  );
  const aesKey = hkdfSha256L32(ZERO_SALT, sharedSecret.buf, INFO);
  const aesPart = aesgcmEncrypt(plaintext, aesKey, iv, aad);
  return WebBuf.concat([WebBuf.fromArray([VERSION]), kemCt.buf, aesPart]);
}

/**
 * Decrypt an `@webbuf/aesgcm-mlkem` ciphertext using an ML-KEM-768
 * decapsulation key.
 *
 * Validates the version byte and minimum length, decapsulates the
 * shared secret, derives the AES key, and decrypts. Throws if the
 * version byte is wrong, the ciphertext is truncated, or AES-GCM
 * authentication fails (which catches tampered KEM ciphertext,
 * tampered AES ciphertext, tampered IV, AAD mismatch, or wrong
 * recipient key).
 */
export function aesgcmMlkemDecrypt(
  decapKey: FixedBuf<2400>,
  ciphertext: WebBuf,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  if (ciphertext.length < FIXED_OVERHEAD) {
    throw new Error(
      `aesgcm-mlkem ciphertext too short: ${String(ciphertext.length)} < ${String(FIXED_OVERHEAD)}`,
    );
  }
  const versionByte = ciphertext[0];
  if (versionByte !== VERSION) {
    throw new Error(
      `aesgcm-mlkem unexpected version byte: 0x${versionByte!.toString(16).padStart(2, "0")} (expected 0x01)`,
    );
  }
  const kemCt = FixedBuf.fromBuf(
    KEM_CT_SIZE,
    WebBuf.fromUint8Array(ciphertext.subarray(1, 1 + KEM_CT_SIZE)),
  );
  const aesPart = WebBuf.fromUint8Array(ciphertext.subarray(1 + KEM_CT_SIZE));
  const sharedSecret = mlKem768Decapsulate(decapKey, kemCt);
  const aesKey = hkdfSha256L32(ZERO_SALT, sharedSecret.buf, INFO);
  return aesgcmDecrypt(aesPart, aesKey, aad);
}

export const AESGCM_MLKEM = {
  versionByte: VERSION,
  kemCiphertextSize: KEM_CT_SIZE,
  ivSize: IV_SIZE,
  tagSize: TAG_SIZE,
  fixedOverhead: FIXED_OVERHEAD,
  hkdfInfo: "webbuf:aesgcm-mlkem v1",
} as const;
