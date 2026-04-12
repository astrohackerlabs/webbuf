import {
  aesgcm_encrypt,
  aesgcm_decrypt,
} from "./rs-webbuf_aesgcm-inline-base64/webbuf_aesgcm.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function aesgcmEncrypt(
  plaintext: WebBuf,
  aesKey: FixedBuf<16> | FixedBuf<32>,
  iv: FixedBuf<12> = FixedBuf.fromRandom(12),
): WebBuf {
  const encrypted = aesgcm_encrypt(plaintext, aesKey.buf, iv.buf);
  return WebBuf.concat([iv.buf, WebBuf.fromUint8Array(encrypted)]);
}

export function aesgcmDecrypt(
  ciphertext: WebBuf,
  aesKey: FixedBuf<16> | FixedBuf<32>,
): WebBuf {
  if (ciphertext.length < 28) {
    throw new Error("Data must be at least 28 bytes (12 nonce + 16 tag)");
  }
  const iv = FixedBuf.fromBuf(12, ciphertext.slice(0, 12));
  const encryptedData = ciphertext.slice(12);
  return WebBuf.fromUint8Array(
    aesgcm_decrypt(encryptedData, aesKey.buf, iv.buf),
  );
}
