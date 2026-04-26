import {
  ed25519_public_key_create,
  ed25519_sign,
  ed25519_verify,
} from "./rs-webbuf_ed25519-inline-base64/webbuf_ed25519.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

/**
 * Derive the 32-byte Ed25519 public key from a 32-byte seed (RFC 8032
 * §5.1.5 secret key).
 *
 * The 32-byte input is the seed (what the RFC calls the secret key), not
 * the 64-byte expanded form some libraries expose. This matches OpenSSH,
 * OpenPGP, and the convention used by `ed25519-dalek 2.x`'s
 * `SigningKey::from_bytes`.
 */
export function ed25519PublicKeyCreate(privKey: FixedBuf<32>): FixedBuf<32> {
  const pub = ed25519_public_key_create(privKey.buf);
  return FixedBuf.fromBuf(32, WebBuf.fromUint8Array(pub));
}

/**
 * Sign a message with PureEdDSA (RFC 8032 §5.1.6). Produces a 64-byte
 * `(R || S)` signature.
 *
 * The signer consumes the raw message bytes directly — no prehash, no
 * Ed25519ph. Consumers who want to sign a digest should hash externally
 * and pass the digest as the `message` argument.
 *
 * PureEdDSA is deterministic: the same `(privKey, message)` pair always
 * produces the same signature.
 */
export function ed25519Sign(
  privKey: FixedBuf<32>,
  message: WebBuf,
): FixedBuf<64> {
  const sig = ed25519_sign(privKey.buf, message);
  return FixedBuf.fromBuf(64, WebBuf.fromUint8Array(sig));
}

/**
 * Verify a 64-byte PureEdDSA signature against the public key and
 * message (RFC 8032 §5.1.7).
 *
 * Returns `true` for a valid signature. Returns `false` for any
 * rejection: wrong key, tampered message, tampered signature,
 * non-canonical S, malformed point, small-order R. **Throws** only on
 * malformed-length input — that's the only failure mode treated as an
 * error; verification failure itself is a value, not an exception.
 *
 * Strict RFC 8032 §5.1.7 semantics are enforced. The wrapper calls
 * `VerifyingKey::verify_strict` (not the cofactored `verify`), which
 * rejects small-order public keys, non-canonical R, and non-canonical S.
 * This is necessary to close the universal-forgery hole that exists
 * when a malicious peer presents the identity element as their public
 * key.
 */
export function ed25519Verify(
  pubKey: FixedBuf<32>,
  message: WebBuf,
  signature: FixedBuf<64>,
): boolean {
  return ed25519_verify(pubKey.buf, message, signature.buf);
}
