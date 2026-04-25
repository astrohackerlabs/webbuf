import {
  aesgcm_encrypt,
  aesgcm_decrypt,
} from "./rs-webbuf_aesgcm-inline-base64/webbuf_aesgcm.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

const EMPTY_AAD = WebBuf.alloc(0);

/**
 * AES-GCM authenticated encryption.
 *
 * `aad` is optional Additional Authenticated Data — bytes that are
 * authenticated by the AES-GCM tag but not encrypted and not transmitted
 * in the output. The recipient must supply the same `aad` bytes the
 * sender used; any mismatch causes `aesgcmDecrypt` to throw. Empty AAD
 * is the default and produces output identical to AES-GCM with no AAD.
 *
 * Returns `iv (12 bytes) || ciphertext || tag (16 bytes)`.
 */
export function aesgcmEncrypt(
  plaintext: WebBuf,
  aesKey: FixedBuf<16> | FixedBuf<32>,
  iv: FixedBuf<12> = FixedBuf.fromRandom(12),
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  const encrypted = aesgcm_encrypt(plaintext, aesKey.buf, iv.buf, aad);
  return WebBuf.concat([iv.buf, WebBuf.fromUint8Array(encrypted)]);
}

/**
 * AES-GCM authenticated decryption.
 *
 * Expects input layout `iv (12) || ciphertext || tag (16)` (the format
 * produced by `aesgcmEncrypt`). The `aad` parameter must match the AAD
 * supplied at encryption time, or AES-GCM authentication fails and this
 * function throws. Empty AAD is the default.
 */
export function aesgcmDecrypt(
  ciphertext: WebBuf,
  aesKey: FixedBuf<16> | FixedBuf<32>,
  aad: WebBuf = EMPTY_AAD,
): WebBuf {
  if (ciphertext.length < 28) {
    throw new Error("Data must be at least 28 bytes (12 nonce + 16 tag)");
  }
  const iv = FixedBuf.fromBuf(12, ciphertext.slice(0, 12));
  const encryptedData = ciphertext.slice(12);
  return WebBuf.fromUint8Array(
    aesgcm_decrypt(encryptedData, aesKey.buf, iv.buf, aad),
  );
}
