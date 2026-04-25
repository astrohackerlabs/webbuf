import {
  sign as raw_sign,
  verify as raw_verify,
  shared_secret,
  shared_secret_raw,
  public_key_add,
  public_key_create,
  public_key_verify,
  public_key_compress,
  public_key_decompress,
  private_key_add,
  private_key_verify,
} from "./rs-webbuf_p256-inline-base64/webbuf_p256.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

/**
 * JWK representation of a P-256 public key, suitable for
 * `crypto.subtle.importKey("jwk", jwk, ...)`.
 */
export interface P256PublicKeyJwk {
  kty: "EC";
  crv: "P-256";
  /** base64url-encoded X coordinate, no padding (43 chars) */
  x: string;
  /** base64url-encoded Y coordinate, no padding (43 chars) */
  y: string;
}

/**
 * JWK representation of a P-256 private key, suitable for
 * `crypto.subtle.importKey("jwk", jwk, ...)`. Includes the public key
 * coordinates (`x`, `y`) as required by Web Crypto.
 */
export interface P256PrivateKeyJwk extends P256PublicKeyJwk {
  /** base64url-encoded private scalar, no padding (43 chars) */
  d: string;
}

function toBase64Url(buf: WebBuf): string {
  return buf
    .toBase64()
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(s: string): WebBuf {
  const padding = (4 - (s.length % 4)) % 4;
  const padded = s + "=".repeat(padding);
  return WebBuf.fromBase64(padded.replace(/-/g, "+").replace(/_/g, "/"));
}

export function p256Sign(
  digest: FixedBuf<32>,
  privateKey: FixedBuf<32>,
  k: FixedBuf<32>,
): FixedBuf<64> {
  return FixedBuf.fromBuf(
    64,
    WebBuf.fromUint8Array(raw_sign(digest.buf, privateKey.buf, k.buf)),
  );
}

export function p256Verify(
  signature: FixedBuf<64>,
  digest: FixedBuf<32>,
  publicKey: FixedBuf<33>,
): boolean {
  try {
    raw_verify(signature.buf, digest.buf, publicKey.buf);
  } catch {
    return false;
  }
  return true;
}

export function p256SharedSecret(
  privateKey: FixedBuf<32>,
  publicKey: FixedBuf<33>,
): FixedBuf<33> {
  return FixedBuf.fromBuf(
    33,
    WebBuf.fromUint8Array(shared_secret(privateKey.buf, publicKey.buf)),
  );
}

/**
 * P-256 ECDH shared secret as the raw 32-byte X-coordinate.
 *
 * This is the SEC1 X9.63 "Z" value used as input to a KDF in NIST SP
 * 800-56A §5.7.1.2 and the IETF hybrid KEM combiners. Equivalent to
 * `p256SharedSecret` with the SEC1 prefix byte stripped — the prefix
 * is deterministic given the X-coordinate, so removing it loses no
 * entropy. Use this when feeding the ECDH output into an HKDF-based
 * key schedule.
 */
export function p256SharedSecretRaw(
  privateKey: FixedBuf<32>,
  publicKey: FixedBuf<33>,
): FixedBuf<32> {
  return FixedBuf.fromBuf(
    32,
    WebBuf.fromUint8Array(shared_secret_raw(privateKey.buf, publicKey.buf)),
  );
}

export function p256PublicKeyAdd(
  publicKey1: FixedBuf<33>,
  publicKey2: FixedBuf<33>,
): FixedBuf<33> {
  return FixedBuf.fromBuf(
    33,
    WebBuf.fromUint8Array(public_key_add(publicKey1.buf, publicKey2.buf)),
  );
}

export function p256PublicKeyCreate(privateKey: FixedBuf<32>): FixedBuf<33> {
  return FixedBuf.fromBuf(
    33,
    WebBuf.fromUint8Array(public_key_create(privateKey.buf)),
  );
}

export function p256PublicKeyVerify(publicKey: FixedBuf<33>): boolean {
  return public_key_verify(publicKey.buf);
}

export function p256PrivateKeyAdd(
  privKey1: FixedBuf<32>,
  privKey2: FixedBuf<32>,
): FixedBuf<32> {
  return FixedBuf.fromBuf(
    32,
    WebBuf.fromUint8Array(private_key_add(privKey1.buf, privKey2.buf)),
  );
}

export function p256PrivateKeyVerify(privateKey: FixedBuf<32>): boolean {
  return private_key_verify(privateKey.buf);
}

/**
 * Decompress a 33-byte SEC1 compressed P-256 public key into its 65-byte
 * uncompressed form (`0x04 || X || Y`). Useful for `crypto.subtle.importKey("raw", ...)`.
 */
export function p256PublicKeyDecompress(
  compressed: FixedBuf<33>,
): FixedBuf<65> {
  return FixedBuf.fromBuf(
    65,
    WebBuf.fromUint8Array(public_key_decompress(compressed.buf)),
  );
}

/**
 * Compress a 65-byte SEC1 uncompressed P-256 public key into its 33-byte
 * compressed form. Throws if the point is not on the curve.
 */
export function p256PublicKeyCompress(
  uncompressed: FixedBuf<65>,
): FixedBuf<33> {
  return FixedBuf.fromBuf(
    33,
    WebBuf.fromUint8Array(public_key_compress(uncompressed.buf)),
  );
}

/**
 * Convert a compressed P-256 public key to a JsonWebKey, ready to pass to
 * `crypto.subtle.importKey("jwk", jwk, ...)`.
 */
export function p256PublicKeyToJwk(
  compressed: FixedBuf<33>,
): P256PublicKeyJwk {
  const uncompressed = p256PublicKeyDecompress(compressed);
  // uncompressed is 0x04 || X(32) || Y(32)
  const x = WebBuf.fromUint8Array(uncompressed.buf.slice(1, 33));
  const y = WebBuf.fromUint8Array(uncompressed.buf.slice(33, 65));
  return {
    kty: "EC",
    crv: "P-256",
    x: toBase64Url(x),
    y: toBase64Url(y),
  };
}

/**
 * Convert a raw 32-byte P-256 private key scalar to a JsonWebKey, ready to
 * pass to `crypto.subtle.importKey("jwk", jwk, ...)`. Internally derives the
 * associated public key (Web Crypto requires `x` and `y` alongside `d`).
 */
export function p256PrivateKeyToJwk(
  privateKey: FixedBuf<32>,
): P256PrivateKeyJwk {
  const compressed = p256PublicKeyCreate(privateKey);
  const publicJwk = p256PublicKeyToJwk(compressed);
  return {
    ...publicJwk,
    d: toBase64Url(privateKey.buf),
  };
}

/**
 * Reconstruct a compressed 33-byte P-256 public key from a JsonWebKey's
 * `x` and `y` coordinates. Validates that the point is on the curve.
 */
export function p256PublicKeyFromJwk(jwk: {
  x: string;
  y: string;
}): FixedBuf<33> {
  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);
  if (x.length !== 32) {
    throw new Error(`Invalid JWK: x must decode to 32 bytes, got ${x.length}`);
  }
  if (y.length !== 32) {
    throw new Error(`Invalid JWK: y must decode to 32 bytes, got ${y.length}`);
  }
  const prefix = WebBuf.fromUint8Array(new Uint8Array([0x04]));
  const uncompressed = FixedBuf.fromBuf(65, WebBuf.concat([prefix, x, y]));
  return p256PublicKeyCompress(uncompressed);
}
