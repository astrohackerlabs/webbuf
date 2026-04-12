import { pbkdf2_sha256 } from "./rs-webbuf_pbkdf2_sha256-inline-base64/webbuf_pbkdf2_sha256.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function pbkdf2Sha256<N extends number>(
  password: WebBuf,
  salt: WebBuf,
  iterations: number,
  keyLen: N,
): FixedBuf<N> {
  return FixedBuf.fromBuf(keyLen, WebBuf.fromUint8Array(pbkdf2_sha256(password, salt, iterations, keyLen)));
}
