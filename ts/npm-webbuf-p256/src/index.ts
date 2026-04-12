import {
  sign as raw_sign,
  verify as raw_verify,
  shared_secret,
  public_key_add,
  public_key_create,
  public_key_verify,
  private_key_add,
  private_key_verify,
} from "./rs-webbuf_p256-inline-base64/webbuf_p256.js";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";

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
