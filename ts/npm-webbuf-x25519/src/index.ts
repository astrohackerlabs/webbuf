import {
  x25519_public_key_create,
  x25519_shared_secret_raw,
} from "./rs-webbuf_x25519-inline-base64/webbuf_x25519.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

/**
 * Compute the X25519 public key (RFC 7748 §5) for a 32-byte private key.
 *
 * Accepts any 32 raw bytes; clamping per RFC 7748 §5
 * ("decodeScalar25519") is applied internally — callers do not need to
 * pre-clamp.
 */
export function x25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32> {
  const pub = x25519_public_key_create(privKey.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(pub));
}

/**
 * Compute the raw 32-byte X25519 ECDH shared secret (RFC 7748 §6.1).
 *
 * Throws if the resulting shared secret is non-contributory — i.e. if
 * the peer's public key is small-order. This protects hybrid encryption
 * schemes from being collapsed to PQ-only by a malicious peer's
 * small-order public key.
 */
export function x25519SharedSecretRaw(
  privKey: FixedBuf<32>,
  pubKey: FixedBuf<32>,
): FixedBuf<32> {
  const ss = x25519_shared_secret_raw(privKey.buf, pubKey.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(ss));
}
