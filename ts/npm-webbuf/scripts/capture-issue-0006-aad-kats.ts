/**
 * One-shot script to capture KAT vectors for issue 0006 Experiment 2.
 *
 * Outputs known-answer test vectors for the new non-empty-AAD path of:
 *   - @webbuf/aesgcm-mlkem (scheme byte 0x01)
 *   - @webbuf/aesgcm-p256dh-mlkem (scheme byte 0x02)
 *
 * Inputs match issue 0004's deterministic recipe exactly. The only
 * additional input is `aad = "webbuf:test-aad-v1"`. Empty-AAD outputs
 * remain byte-identical to issue 0004's KATs and are not re-captured
 * here.
 *
 * Run from ts/npm-webbuf:
 *   tsx scripts/capture-issue-0006-aad-kats.ts
 */
import { WebBuf } from "@webbuf/webbuf";
import { FixedBuf } from "@webbuf/fixedbuf";
import {
  mlKem768KeyPairDeterministic,
} from "@webbuf/mlkem";
import { p256PublicKeyCreate } from "@webbuf/p256";
import { sha256Hash } from "@webbuf/sha256";
import { _aesgcmMlkemEncryptDeterministic } from "@webbuf/aesgcm-mlkem";
import { _aesgcmP256dhMlkemEncryptDeterministic } from "@webbuf/aesgcm-p256dh-mlkem";

const KAT_AAD = WebBuf.fromUtf8("webbuf:test-aad-v1");

// =====================================================================
// KAT 1: @webbuf/aesgcm-mlkem v1 with non-empty AAD
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
const ciphertext_pure = _aesgcmMlkemEncryptDeterministic(
  kp_pure.encapsulationKey,
  plaintext_pure,
  m_pure,
  iv_pure,
  KAT_AAD,
);

console.log("=".repeat(70));
console.log("@webbuf/aesgcm-mlkem v1 KAT (with AAD)");
console.log("=".repeat(70));
console.log("d (ML-KEM seed 1) :", d_pure.toHex());
console.log("z (ML-KEM seed 2) :", z_pure.toHex());
console.log("m (encap rand)    :", m_pure.toHex());
console.log("plaintext (utf8)  : 'hello, post-quantum'");
console.log("AES-GCM IV        :", iv_pure.toHex());
console.log("AAD (utf8)        : 'webbuf:test-aad-v1'");
console.log("AAD (hex)         :", KAT_AAD.toHex());
console.log("ciphertext length :", ciphertext_pure.length, "bytes");
console.log("SHA-256(ct)       :", sha256Hash(ciphertext_pure).toHex());

// =====================================================================
// KAT 2: @webbuf/aesgcm-p256dh-mlkem v1 with non-empty AAD
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

const recipientPub_hyb = p256PublicKeyCreate(recipientPriv_hyb);
const kp_hyb = mlKem768KeyPairDeterministic(d_hyb, z_hyb);

const ciphertext_hyb = _aesgcmP256dhMlkemEncryptDeterministic(
  senderPriv_hyb,
  recipientPub_hyb,
  kp_hyb.encapsulationKey,
  plaintext_hyb,
  m_hyb,
  iv_hyb,
  KAT_AAD,
);

console.log("");
console.log("=".repeat(70));
console.log("@webbuf/aesgcm-p256dh-mlkem v1 KAT (with AAD)");
console.log("=".repeat(70));
console.log("sender P-256 priv :", senderPriv_hyb.toHex());
console.log("recipient P-256 priv:", recipientPriv_hyb.toHex());
console.log("recipient P-256 pub :", recipientPub_hyb.toHex());
console.log("d (ML-KEM seed 1) :", d_hyb.toHex());
console.log("z (ML-KEM seed 2) :", z_hyb.toHex());
console.log("m (encap rand)    :", m_hyb.toHex());
console.log("plaintext (utf8)  : 'hybrid'");
console.log("AES-GCM IV        :", iv_hyb.toHex());
console.log("AAD (utf8)        : 'webbuf:test-aad-v1'");
console.log("AAD (hex)         :", KAT_AAD.toHex());
console.log("ciphertext length :", ciphertext_hyb.length, "bytes");
console.log("SHA-256(ct)       :", sha256Hash(ciphertext_hyb).toHex());
