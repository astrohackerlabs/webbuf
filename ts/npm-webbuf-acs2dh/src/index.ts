import { acs2Encrypt, acs2Decrypt } from "@webbuf/acs2";
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { sharedSecret } from "@webbuf/secp256k1";
import { sha256Hash } from "@webbuf/sha256";

/**
 * Use Alice's private key and Bob's public key to derive a shared secret
 * (Diffie-Hellman) and use that shared secret at the encryption key for ACS2
 * encryption.
 *
 * @param alicePrivKey Alice's private key. (Or Bob's private key)
 * @param bobPubKey Bob's public key. (Or Alice's public key)
 * @param plaintext The data to encrypt.
 * @param iv The initialization vector to use. Must be 128 bits.
 * @returns The encrypted data.
 * @throws If there is an error encrypting the data.
 */
export function acs2dhEncrypt(
  alicePrivKey: FixedBuf<32>,
  bobPubKey: FixedBuf<33>,
  plaintext: WebBuf,
  iv?: FixedBuf<16>,
) {
  const pubKey = sharedSecret(alicePrivKey, bobPubKey);
  const secret = sha256Hash(pubKey.buf);
  return acs2Encrypt(plaintext, secret, iv);
}

/**
 * Use Alice's private key and Bob's public key to derive a shared secret
 * (Diffie-Hellman) and use that shared secret at the decryption key for ACS2
 * decryption.
 *
 * @param alicePrivKey Alice's private key. (Or Bob's private key)
 * @param bobPubKey Bob's public key. (Or Alice's public key)
 * @param ciphertext The data to decrypt.
 * @returns The decrypted data.
 * @throws If there is an error decrypting the data.
 */
export function acs2dhDecrypt(
  alicePrivKey: FixedBuf<32>,
  bobPubKey: FixedBuf<33>,
  ciphertext: WebBuf,
) {
  const pubKey = sharedSecret(alicePrivKey, bobPubKey);
  const secret = sha256Hash(pubKey.buf);
  return acs2Decrypt(ciphertext, secret);
}
