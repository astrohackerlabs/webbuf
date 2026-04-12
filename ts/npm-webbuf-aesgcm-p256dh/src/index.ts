import { aesgcmEncrypt, aesgcmDecrypt } from "@webbuf/aesgcm";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { p256SharedSecret } from "@webbuf/p256";
import { sha256Hash } from "@webbuf/sha256";

/**
 * Use Alice's private key and Bob's public key to derive a shared secret
 * (Diffie-Hellman with P-256) and use that shared secret as the encryption
 * key for AES-GCM encryption.
 *
 * Key derivation: SHA-256(P-256-ECDH(privKey, pubKey)) -> 32-byte AES-256-GCM key
 *
 * @param alicePrivKey Alice's private key. (Or Bob's private key)
 * @param bobPubKey Bob's public key. (Or Alice's public key)
 * @param plaintext The data to encrypt.
 * @param iv The nonce to use. Must be 96 bits (12 bytes).
 * @returns The encrypted data (nonce + ciphertext + auth tag).
 * @throws If there is an error encrypting the data.
 */
export function aesgcmP256dhEncrypt(
  alicePrivKey: FixedBuf<32>,
  bobPubKey: FixedBuf<33>,
  plaintext: WebBuf,
  iv?: FixedBuf<12>,
) {
  const pubKey = p256SharedSecret(alicePrivKey, bobPubKey);
  const secret = sha256Hash(pubKey.buf);
  return aesgcmEncrypt(plaintext, secret, iv);
}

/**
 * Use Alice's private key and Bob's public key to derive a shared secret
 * (Diffie-Hellman with P-256) and use that shared secret as the decryption
 * key for AES-GCM decryption.
 *
 * @param alicePrivKey Alice's private key. (Or Bob's private key)
 * @param bobPubKey Bob's public key. (Or Alice's public key)
 * @param ciphertext The data to decrypt (nonce + ciphertext + auth tag).
 * @returns The decrypted data.
 * @throws If there is an error decrypting or authentication fails.
 */
export function aesgcmP256dhDecrypt(
  alicePrivKey: FixedBuf<32>,
  bobPubKey: FixedBuf<33>,
  ciphertext: WebBuf,
) {
  const pubKey = p256SharedSecret(alicePrivKey, bobPubKey);
  const secret = sha256Hash(pubKey.buf);
  return aesgcmDecrypt(ciphertext, secret);
}
