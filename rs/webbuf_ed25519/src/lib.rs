use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Derive the 32-byte Ed25519 public key from a 32-byte seed
/// (RFC 8032 §5.1.5 secret key).
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn ed25519_public_key_create(priv_key: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&seed);
    Ok(signing_key.verifying_key().as_bytes().to_vec())
}

/// PureEdDSA signing per RFC 8032 §5.1.6. Produces a 64-byte (R || S)
/// signature. The signer consumes the raw message bytes directly — no
/// prehash.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn ed25519_sign(priv_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be exactly 32 bytes".to_string())?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// PureEdDSA verification per RFC 8032 §5.1.7. Returns `Ok(true)` for a
/// valid signature, `Ok(false)` for any rejection (wrong key, tampered
/// message, tampered signature, non-canonical S, malformed point).
/// Returns `Err` only on malformed-length input. Error message text is
/// intentionally stable so audit tests can pin against it.
///
/// `legacy_compatibility` is disabled at the crate level, so this enforces
/// strict RFC 8032 §5.1.7 semantics: signatures with non-canonical S and
/// signatures with small-order R are rejected.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn ed25519_verify(
    pub_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let pub_arr: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes".to_string())?;
    let sig_arr: [u8; 64] = signature
        .try_into()
        .map_err(|_| "signature must be exactly 64 bytes".to_string())?;

    // VerifyingKey::from_bytes can fail for non-decompressible point bytes;
    // treat that as a verification failure (Ok(false)), not a length error.
    let verifying_key = match VerifyingKey::from_bytes(&pub_arr) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let signature = Signature::from_bytes(&sig_arr);

    // verify_strict (vs. verify): rejects small-order public keys,
    // non-canonical R, and non-canonical S — the full RFC 8032 §5.1.7
    // strict-verification contract. Plain verify() admits small-order
    // pub keys (cofactored verification), which would allow universal
    // forgery against a malicious peer presenting the identity element
    // as their public key. We deliberately want strict semantics.
    Ok(verifying_key.verify_strict(message, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 8032 §7.1 TEST 1 — empty message.
    #[test]
    fn rfc_8032_7_1_test_1_empty_message() {
        let secret = hex!(
            "9d61b19deffd5a60ba844af492ec2cc4"
            "4449c5697b326919703bac031cae7f60"
        );
        let public_expected = hex!(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        );
        let message: &[u8] = b"";
        let signature_expected = hex!(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        );

        let public = ed25519_public_key_create(&secret).unwrap();
        assert_eq!(public.as_slice(), public_expected.as_slice());

        let signature = ed25519_sign(&secret, message).unwrap();
        assert_eq!(signature.as_slice(), signature_expected.as_slice());

        assert!(ed25519_verify(&public, message, &signature).unwrap());
    }

    /// RFC 8032 §7.1 TEST 2 — 1-byte message.
    #[test]
    fn rfc_8032_7_1_test_2_one_byte_message() {
        let secret = hex!(
            "4ccd089b28ff96da9db6c346ec114e0f"
            "5b8a319f35aba624da8cf6ed4fb8a6fb"
        );
        let public_expected = hex!(
            "3d4017c3e843895a92b70aa74d1b7ebc"
            "9c982ccf2ec4968cc0cd55f12af4660c"
        );
        let message = hex!("72");
        let signature_expected = hex!(
            "92a009a9f0d4cab8720e820b5f642540"
            "a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c"
            "387b2eaeb4302aeeb00d291612bb0c00"
        );

        let public = ed25519_public_key_create(&secret).unwrap();
        assert_eq!(public.as_slice(), public_expected.as_slice());

        let signature = ed25519_sign(&secret, &message).unwrap();
        assert_eq!(signature.as_slice(), signature_expected.as_slice());

        assert!(ed25519_verify(&public, &message, &signature).unwrap());
    }

    /// RFC 8032 §7.1 TEST 3 — 2-byte message.
    #[test]
    fn rfc_8032_7_1_test_3_two_byte_message() {
        let secret = hex!(
            "c5aa8df43f9f837bedb7442f31dcb7b1"
            "66d38535076f094b85ce3a2e0b4458f7"
        );
        let public_expected = hex!(
            "fc51cd8e6218a1a38da47ed00230f058"
            "0816ed13ba3303ac5deb911548908025"
        );
        let message = hex!("af82");
        let signature_expected = hex!(
            "6291d657deec24024827e69c3abe01a3"
            "0ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc659"
            "4a7c15e9716ed28dc027beceea1ec40a"
        );

        let public = ed25519_public_key_create(&secret).unwrap();
        assert_eq!(public.as_slice(), public_expected.as_slice());

        let signature = ed25519_sign(&secret, &message).unwrap();
        assert_eq!(signature.as_slice(), signature_expected.as_slice());

        assert!(ed25519_verify(&public, &message, &signature).unwrap());
    }

    /// RFC 8032 §7.1 TEST SHA(abc) — message is the SHA-512 digest of
    /// the ASCII bytes "abc".
    #[test]
    fn rfc_8032_7_1_test_sha_abc() {
        let secret = hex!(
            "833fe62409237b9d62ec77587520911e"
            "9a759cec1d19755b7da901b96dca3d42"
        );
        let public_expected = hex!(
            "ec172b93ad5e563bf4932c70e1245034"
            "c35467ef2efd4d64ebf819683467e2bf"
        );
        let message = hex!(
            "ddaf35a193617abacc417349ae204131"
            "12e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f"
        );
        let signature_expected = hex!(
            "dc2a4459e7369633a52b1bf277839a00"
            "201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e030"
            "3dca179c138ac17ad9bef1177331a704"
        );

        let public = ed25519_public_key_create(&secret).unwrap();
        assert_eq!(public.as_slice(), public_expected.as_slice());

        let signature = ed25519_sign(&secret, &message).unwrap();
        assert_eq!(signature.as_slice(), signature_expected.as_slice());

        assert!(ed25519_verify(&public, &message, &signature).unwrap());
    }

    /// Sign + verify round-trip on hard-coded seeds (no RNG dep).
    #[test]
    fn round_trip_hard_coded_seed() {
        let seed = hex!(
            "11111111111111111111111111111111"
            "11111111111111111111111111111111"
        );
        let message = b"webbuf round-trip";

        let public = ed25519_public_key_create(&seed).unwrap();
        let signature = ed25519_sign(&seed, message).unwrap();
        assert!(ed25519_verify(&public, message, &signature).unwrap());
    }

    /// PureEdDSA is deterministic: signing the same message with the
    /// same seed always produces the same signature.
    #[test]
    fn signing_is_deterministic() {
        let seed = hex!(
            "22222222222222222222222222222222"
            "22222222222222222222222222222222"
        );
        let message = b"deterministic";

        let sig1 = ed25519_sign(&seed, message).unwrap();
        let sig2 = ed25519_sign(&seed, message).unwrap();
        assert_eq!(sig1, sig2);
    }

    /// Verification rejects a tampered message.
    #[test]
    fn verify_rejects_tampered_message() {
        let seed = [3u8; 32];
        let public = ed25519_public_key_create(&seed).unwrap();
        let message = b"don't tamper with me";
        let signature = ed25519_sign(&seed, message).unwrap();

        let mut tampered = *message;
        tampered[0] ^= 0xff;
        assert!(!ed25519_verify(&public, &tampered, &signature).unwrap());
    }

    /// Verification rejects a tampered signature in either half.
    #[test]
    fn verify_rejects_tampered_signature() {
        let seed = [4u8; 32];
        let public = ed25519_public_key_create(&seed).unwrap();
        let message = b"signature tamper";
        let signature = ed25519_sign(&seed, message).unwrap();

        // Flip a byte in R (first 32 bytes).
        let mut tampered_r = signature.clone();
        tampered_r[0] ^= 0x01;
        assert!(!ed25519_verify(&public, message, &tampered_r).unwrap());

        // Flip a byte in S (last 32 bytes).
        let mut tampered_s = signature.clone();
        tampered_s[40] ^= 0x01;
        assert!(!ed25519_verify(&public, message, &tampered_s).unwrap());
    }

    /// Verification rejects a wrong public key.
    #[test]
    fn verify_rejects_wrong_public_key() {
        let seed_a = [5u8; 32];
        let seed_b = [6u8; 32];
        let pub_b = ed25519_public_key_create(&seed_b).unwrap();
        let message = b"wrong key";
        let signature = ed25519_sign(&seed_a, message).unwrap();

        assert!(!ed25519_verify(&pub_b, message, &signature).unwrap());
    }

    /// Verification gracefully rejects 32 bytes that aren't a valid
    /// Ed25519 point — returns Ok(false) rather than Err.
    #[test]
    fn verify_rejects_malformed_public_key_gracefully() {
        let bad_pub = [0xffu8; 32];
        let signature = [0u8; 64];
        let message = b"anything";

        let result = ed25519_verify(&bad_pub, message, &signature);
        assert_eq!(result, Ok(false));
    }

    /// Strict verification rejects small-order public keys, closing the
    /// universal-forgery hole that exists when using non-strict
    /// `verify()`. The identity element of Curve25519 (encoded as
    /// `01 || 00 * 31`) is a valid (decompressible) but small-order
    /// public key. Combined with an identity-R / zero-S signature, the
    /// non-strict verifier would accept ANY message under this key.
    /// `verify_strict` rejects it, so `ed25519_verify` returns
    /// `Ok(false)` for every message.
    ///
    /// See https://github.com/dalek-cryptography/curve25519-dalek/blob/main/ed25519-dalek/src/verifying.rs
    /// for the verify_strict vs. verify behavior split.
    #[test]
    fn verify_strict_rejects_small_order_public_key_universal_forgery() {
        // Identity element on Curve25519: 01 || 00 * 31.
        let weak_pub: [u8; 32] = {
            let mut p = [0u8; 32];
            p[0] = 1;
            p
        };
        // Identity-R || zero-S — the canonical universal-forgery
        // signature against the non-strict verifier.
        let forgery_sig: [u8; 64] = {
            let mut s = [0u8; 64];
            s[0] = 1;
            s
        };

        for message in [b"" as &[u8], b"hello", b"forged"] {
            let result = ed25519_verify(&weak_pub, message, &forgery_sig);
            assert_eq!(
                result,
                Ok(false),
                "small-order pub key + forgery sig must be rejected for message {:?}",
                message,
            );
        }
    }

    /// Verification gracefully rejects an all-zero R signature on a
    /// message it wasn't signed for — exercises the boundary of the
    /// strict-mode rejection without requiring a malformed length.
    #[test]
    fn verify_rejects_zero_signature() {
        let seed = [7u8; 32];
        let public = ed25519_public_key_create(&seed).unwrap();
        let zero_sig = [0u8; 64];

        let result = ed25519_verify(&public, b"hello", &zero_sig);
        assert_eq!(result, Ok(false));
    }

    /// Input-length errors produce stable, auditable error messages.
    #[test]
    fn input_length_errors() {
        let too_short: [u8; 31] = [0u8; 31];
        let too_long: [u8; 33] = [0u8; 33];
        let ok_priv: [u8; 32] = [1u8; 32];
        let ok_pub: [u8; 32] = [1u8; 32];
        let ok_sig: [u8; 64] = [1u8; 64];

        let err = ed25519_public_key_create(&too_short).unwrap_err();
        assert!(err.contains("32 bytes"));

        let err = ed25519_public_key_create(&too_long).unwrap_err();
        assert!(err.contains("32 bytes"));

        let err = ed25519_sign(&too_short, b"msg").unwrap_err();
        assert!(err.contains("private key"));
        assert!(err.contains("32 bytes"));

        let err = ed25519_verify(&too_short, b"msg", &ok_sig).unwrap_err();
        assert!(err.contains("public key"));
        assert!(err.contains("32 bytes"));

        let err = ed25519_verify(&ok_pub, b"msg", &too_short).unwrap_err();
        assert!(err.contains("signature"));
        assert!(err.contains("64 bytes"));

        // Sanity: a 33-byte signature also errors.
        let bad_sig: [u8; 65] = [0u8; 65];
        let err = ed25519_verify(&ok_pub, b"msg", &bad_sig).unwrap_err();
        assert!(err.contains("signature"));

        // ok_priv unused var avoidance
        let _ = ed25519_public_key_create(&ok_priv).unwrap();
    }
}
