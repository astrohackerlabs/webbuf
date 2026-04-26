/**
 * One-shot script to capture KAT vectors for issue 0007 Experiment 4.
 *
 * Outputs known-answer test vectors for @webbuf/aesgcm-x25519dh-mlkem
 * (scheme byte 0x03), the Curve25519-flavored sibling of
 * @webbuf/aesgcm-p256dh-mlkem.
 *
 * Inputs match the issue 0004 / 0006 deterministic recipe but with
 * X25519 keys instead of P-256 keys (0x44/0x55 byte-fill seeds reused).
 * Two vectors captured:
 *
 *   - empty AAD
 *   - aad = "webbuf:test-aad-v1"
 *
 * Run from ts/npm-webbuf:
 *   tsx scripts/capture-issue-0007-aesgcm-x25519dh-mlkem-kats.ts
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import { mlKem768KeyPairDeterministic } from "@webbuf/mlkem";
import { x25519PublicKeyCreate } from "@webbuf/x25519";
import { sha256Hash } from "@webbuf/sha256";
import { _aesgcmX25519dhMlkemEncryptDeterministic } from "@webbuf/aesgcm-x25519dh-mlkem";

const KAT_AAD = WebBuf.fromUtf8("webbuf:test-aad-v1");

// Same byte-fill recipe as issue 0004's hybrid KAT, just with X25519 keys.
const senderPriv = FixedBuf.fromHex(
  32,
  "4444444444444444444444444444444444444444444444444444444444444444",
);
const recipientPriv = FixedBuf.fromHex(
  32,
  "5555555555555555555555555555555555555555555555555555555555555555",
);
const d = FixedBuf.fromHex(
  32,
  "6666666666666666666666666666666666666666666666666666666666666666",
);
const z = FixedBuf.fromHex(
  32,
  "7777777777777777777777777777777777777777777777777777777777777777",
);
const m = FixedBuf.fromHex(
  32,
  "8888888888888888888888888888888888888888888888888888888888888888",
);
const iv = FixedBuf.fromHex(12, "999999999999999999999999");
const plaintext = WebBuf.fromUtf8("hybrid");

const recipientPub = x25519PublicKeyCreate(recipientPriv);
const kp = mlKem768KeyPairDeterministic(d, z);

// =====================================================================
// KAT 1: empty AAD
// =====================================================================

const ciphertextEmpty = _aesgcmX25519dhMlkemEncryptDeterministic(
  senderPriv,
  recipientPub,
  kp.encapsulationKey,
  plaintext,
  m,
  iv,
);

console.log("=".repeat(70));
console.log("@webbuf/aesgcm-x25519dh-mlkem v1 KAT (empty AAD)");
console.log("=".repeat(70));
console.log("sender X25519 priv  :", senderPriv.toHex());
console.log("recipient X25519 priv:", recipientPriv.toHex());
console.log("recipient X25519 pub :", recipientPub.toHex());
console.log("d (ML-KEM seed 1)   :", d.toHex());
console.log("z (ML-KEM seed 2)   :", z.toHex());
console.log("m (encap rand)      :", m.toHex());
console.log("plaintext (utf8)    : 'hybrid'");
console.log("AES-GCM IV          :", iv.toHex());
console.log("AAD                 : (empty)");
console.log("ciphertext length   :", ciphertextEmpty.length, "bytes");
console.log("ciphertext prefix 8B:", ciphertextEmpty.toHex().slice(0, 16));
console.log("SHA-256(ct)         :", sha256Hash(ciphertextEmpty).toHex());

// =====================================================================
// KAT 2: non-empty AAD
// =====================================================================

const ciphertextAad = _aesgcmX25519dhMlkemEncryptDeterministic(
  senderPriv,
  recipientPub,
  kp.encapsulationKey,
  plaintext,
  m,
  iv,
  KAT_AAD,
);

console.log("");
console.log("=".repeat(70));
console.log("@webbuf/aesgcm-x25519dh-mlkem v1 KAT (with AAD)");
console.log("=".repeat(70));
console.log("sender X25519 priv  :", senderPriv.toHex());
console.log("recipient X25519 priv:", recipientPriv.toHex());
console.log("recipient X25519 pub :", recipientPub.toHex());
console.log("d (ML-KEM seed 1)   :", d.toHex());
console.log("z (ML-KEM seed 2)   :", z.toHex());
console.log("m (encap rand)      :", m.toHex());
console.log("plaintext (utf8)    : 'hybrid'");
console.log("AES-GCM IV          :", iv.toHex());
console.log("AAD (utf8)          : 'webbuf:test-aad-v1'");
console.log("AAD (hex)           :", KAT_AAD.toHex());
console.log("ciphertext length   :", ciphertextAad.length, "bytes");
console.log("SHA-256(ct)         :", sha256Hash(ciphertextAad).toHex());
