import { pbkdf2_sha256 } from "./rs-webbuf_pbkdf2_sha256-inline-base64/webbuf_pbkdf2_sha256.js";
import { WebBuf } from "@webbuf/webbuf";

export function pbkdf2Sha256(
  password: WebBuf,
  salt: WebBuf,
  iterations: number,
  keyLen: number,
): WebBuf {
  return WebBuf.fromUint8Array(pbkdf2_sha256(password, salt, iterations, keyLen));
}
