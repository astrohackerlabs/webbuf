import {
  sha256_hash,
  double_sha256_hash,
  sha256_hmac,
} from "./rs-webbuf_sha256-inline-base64/webbuf_sha256.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

export function sha256Hash(buf: WebBuf): FixedBuf<32> {
  const hash = sha256_hash(buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(hash));
}

export function doubleSha256Hash(buf: WebBuf): FixedBuf<32> {
  const hash = double_sha256_hash(buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(hash));
}

export function sha256Hmac(key: WebBuf, message: WebBuf): FixedBuf<32> {
  const mac = sha256_hmac(key, message);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(mac));
}
