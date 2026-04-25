/**
 * One-shot script to capture KAT vectors for issue 0004 Experiment 1.
 *
 * Outputs known-answer test vectors for:
 *   - @webbuf/aesgcm-mlkem v1 (scheme byte 0x01)
 *   - @webbuf/aesgcm-p256dh-mlkem v1 (scheme byte 0x02)
 *
 * Run from ts/npm-webbuf:
 *   tsx scripts/capture-issue-0004-kats.ts
 *
 * The output is meant to be embedded into issues/0004-hybrid-pq-encryption/
 * README.md as the byte-level test contract that the implementation
 * experiment must reproduce.
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  mlKem768KeyPairDeterministic,
  mlKem768EncapsulateDeterministic,
} from "@webbuf/mlkem";
import { p256PublicKeyCreate, p256SharedSecretRaw } from "@webbuf/p256";
import { sha256Hash, sha256Hmac } from "@webbuf/sha256";
import { aesgcmEncrypt } from "@webbuf/aesgcm";

// HKDF-SHA-256 (RFC 5869) for L=32. Two HMAC calls.
function hkdfSha256L32(
  salt: FixedBuf<32>,
  ikm: WebBuf,
  info: WebBuf,
): FixedBuf<32> {
  // Extract: PRK = HMAC-SHA-256(salt, IKM)
  const prk = sha256Hmac(salt.buf, ikm);
  // Expand for L=32: T(1) = HMAC-SHA-256(PRK, info || 0x01)[0..32]
  const t1Input = WebBuf.concat([info, WebBuf.fromArray([0x01])]);
  return sha256Hmac(prk.buf, t1Input);
}

const ZERO_SALT = FixedBuf.fromHex(
  32,
  "0000000000000000000000000000000000000000000000000000000000000000",
);

// =====================================================================
// KAT 1: @webbuf/aesgcm-mlkem v1
// =====================================================================

const d_pure = FixedBuf.fromHex(
  32,
  "0000000000000000000000000000000000000000000000000000000000000000",
);
const z_pure = FixedBuf.fromHex(
  32,
  "1111111111111111111111111111111111111111111111111111111111111111",
);
const m_pure = FixedBuf.fromHex(
  32,
  "2222222222222222222222222222222222222222222222222222222222222222",
);
const iv_pure = FixedBuf.fromHex(12, "333333333333333333333333");
const plaintext_pure = WebBuf.fromUtf8("hello, post-quantum");

const kp_pure = mlKem768KeyPairDeterministic(d_pure, z_pure);
const encap_pure = mlKem768EncapsulateDeterministic(
  kp_pure.encapsulationKey,
  m_pure,
);

const info_pure = WebBuf.fromUtf8("webbuf:aesgcm-mlkem v1");
const aesKey_pure = hkdfSha256L32(ZERO_SALT, encap_pure.sharedSecret.buf, info_pure);

// aesgcmEncrypt prepends iv to its output: result = iv || ct || tag
const aesPart_pure = aesgcmEncrypt(plaintext_pure, aesKey_pure, iv_pure);
const ciphertext_pure = WebBuf.concat([
  WebBuf.fromArray([0x01]),
  encap_pure.ciphertext.buf,
  aesPart_pure,
]);

console.log("=".repeat(70));
console.log("@webbuf/aesgcm-mlkem v1 KAT");
console.log("=".repeat(70));
console.log("d (ML-KEM seed 1) :", d_pure.toHex());
console.log("z (ML-KEM seed 2) :", z_pure.toHex());
console.log("m (encap rand)    :", m_pure.toHex());
console.log("plaintext (utf8)  : 'hello, post-quantum'");
console.log("plaintext (hex)   :", plaintext_pure.toHex());
console.log("AES-GCM IV        :", iv_pure.toHex());
console.log(
  "ML-KEM sharedSecret:",
  encap_pure.sharedSecret.toHex(),
);
console.log("derived AES key   :", aesKey_pure.toHex());
console.log("ciphertext length :", ciphertext_pure.length, "bytes");
console.log("ciphertext (hex)  :");
console.log(ciphertext_pure.toHex());

// =====================================================================
// KAT 2: @webbuf/aesgcm-p256dh-mlkem v1
// =====================================================================

const senderPriv_hyb = FixedBuf.fromHex(
  32,
  "4444444444444444444444444444444444444444444444444444444444444444",
);
const recipientPriv_hyb = FixedBuf.fromHex(
  32,
  "5555555555555555555555555555555555555555555555555555555555555555",
);
const d_hyb = FixedBuf.fromHex(
  32,
  "6666666666666666666666666666666666666666666666666666666666666666",
);
const z_hyb = FixedBuf.fromHex(
  32,
  "7777777777777777777777777777777777777777777777777777777777777777",
);
const m_hyb = FixedBuf.fromHex(
  32,
  "8888888888888888888888888888888888888888888888888888888888888888",
);
const iv_hyb = FixedBuf.fromHex(12, "999999999999999999999999");
const plaintext_hyb = WebBuf.fromUtf8("hybrid");

const senderPub_hyb = p256PublicKeyCreate(senderPriv_hyb);
const recipientPub_hyb = p256PublicKeyCreate(recipientPriv_hyb);

const kp_hyb = mlKem768KeyPairDeterministic(d_hyb, z_hyb);
const encap_hyb = mlKem768EncapsulateDeterministic(
  kp_hyb.encapsulationKey,
  m_hyb,
);

const ecdhSecret_hyb = p256SharedSecretRaw(senderPriv_hyb, recipientPub_hyb);
const ikm_hyb = WebBuf.concat([
  ecdhSecret_hyb.buf,
  encap_hyb.sharedSecret.buf,
]);

const info_hyb = WebBuf.fromUtf8("webbuf:aesgcm-p256dh-mlkem v1");
const aesKey_hyb = hkdfSha256L32(ZERO_SALT, ikm_hyb, info_hyb);

const aesPart_hyb = aesgcmEncrypt(plaintext_hyb, aesKey_hyb, iv_hyb);
const ciphertext_hyb = WebBuf.concat([
  WebBuf.fromArray([0x02]),
  encap_hyb.ciphertext.buf,
  aesPart_hyb,
]);

console.log("");
console.log("=".repeat(70));
console.log("@webbuf/aesgcm-p256dh-mlkem v1 KAT");
console.log("=".repeat(70));
console.log("sender P-256 priv :", senderPriv_hyb.toHex());
console.log("recipient P-256 priv:", recipientPriv_hyb.toHex());
console.log("recipient P-256 pub :", recipientPub_hyb.toHex());
console.log("d (ML-KEM seed 1) :", d_hyb.toHex());
console.log("z (ML-KEM seed 2) :", z_hyb.toHex());
console.log("m (encap rand)    :", m_hyb.toHex());
console.log("plaintext (utf8)  : 'hybrid'");
console.log("plaintext (hex)   :", plaintext_hyb.toHex());
console.log("AES-GCM IV        :", iv_hyb.toHex());
console.log("ECDH raw X-coord  :", ecdhSecret_hyb.toHex());
console.log(
  "ML-KEM sharedSecret:",
  encap_hyb.sharedSecret.toHex(),
);
console.log("derived AES key   :", aesKey_hyb.toHex());
console.log("ciphertext length :", ciphertext_hyb.length, "bytes");
console.log("ciphertext (hex)  :");
console.log(ciphertext_hyb.toHex());

console.log("");
console.log("=".repeat(70));
console.log("Ciphertext SHA-256 hashes (for compact embedding)");
console.log("=".repeat(70));
console.log("aesgcm-mlkem:        ", sha256Hash(ciphertext_pure).toHex());
console.log("aesgcm-p256dh-mlkem: ", sha256Hash(ciphertext_hyb).toHex());

// silence unused-var warning — senderPub_hyb captured for completeness
void senderPub_hyb;
