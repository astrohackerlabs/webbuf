use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Compute the X25519 public key (RFC 7748 §5) for a 32-byte private key.
///
/// Any 32 bytes are accepted; clamping per RFC 7748 §5
/// ("decodeScalar25519") is applied internally by `x25519-dalek` —
/// callers do not need to pre-clamp.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn x25519_public_key_create(priv_key: &[u8]) -> Result<Vec<u8>, String> {
    let priv_arr: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be exactly 32 bytes".to_string())?;
    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

/// Compute the raw 32-byte X25519 ECDH shared secret (RFC 7748 §6.1) for
/// a 32-byte private key and a 32-byte peer public key.
///
/// Returns an error if the resulting shared secret is non-contributory
/// (i.e. the peer's public key is small-order — see RFC 7748 §6.1 and
/// Cremers & Jackson 2019). This protects hybrid encryption schemes from
/// being collapsed to PQ-only by a malicious peer's small-order public
/// key.
///
/// The error message text is intentionally stable so audit tests can
/// pin against it.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn x25519_shared_secret_raw(
    priv_key: &[u8],
    pub_key: &[u8],
) -> Result<Vec<u8>, String> {
    let priv_arr: [u8; 32] = priv_key
        .try_into()
        .map_err(|_| "private key must be exactly 32 bytes".to_string())?;
    let pub_arr: [u8; 32] = pub_key
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes".to_string())?;

    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(pub_arr);
    let shared = secret.diffie_hellman(&public);

    if !shared.was_contributory() {
        return Err(
            "X25519 shared secret is non-contributory (small-order public key)"
                .to_string(),
        );
    }

    Ok(shared.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 7748 §6.1: the worked Alice/Bob example.
    #[test]
    fn rfc_7748_6_1_alice_bob_worked_example() {
        let alice_priv = hex!(
            "77076d0a7318a57d3c16c17251b26645"
            "df4c2f87ebc0992ab177fba51db92c2a"
        );
        let alice_pub_expected = hex!(
            "8520f0098930a754748b7ddcb43ef75a"
            "0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        let bob_priv = hex!(
            "5dab087e624a8a4b79e17f8b83800ee6"
            "6f3bb1292618b6fd1c2f8b27ff88e0eb"
        );
        let bob_pub_expected = hex!(
            "de9edb7d7b7dc1b4d35b61c2ece43537"
            "3f8343c85b78674dadfc7e146f882b4f"
        );
        let shared_expected = hex!(
            "4a5d9d5ba4ce2de1728e3bf480350f25"
            "e07e21c947d19e3376f09b3c1e161742"
        );

        let alice_pub = x25519_public_key_create(&alice_priv).unwrap();
        let bob_pub = x25519_public_key_create(&bob_priv).unwrap();
        assert_eq!(alice_pub.as_slice(), alice_pub_expected.as_slice());
        assert_eq!(bob_pub.as_slice(), bob_pub_expected.as_slice());

        let ss_alice = x25519_shared_secret_raw(&alice_priv, &bob_pub).unwrap();
        let ss_bob = x25519_shared_secret_raw(&bob_priv, &alice_pub).unwrap();
        assert_eq!(ss_alice.as_slice(), shared_expected.as_slice());
        assert_eq!(ss_bob.as_slice(), shared_expected.as_slice());
    }

    /// RFC 7748 §5.2: the single-iteration test vector.
    #[test]
    fn rfc_7748_5_2_single_iteration_vector() {
        // Input scalar (= private key, accepted as-is and clamped internally).
        let scalar = hex!(
            "a546e36bf0527c9d3b16154b82465edd"
            "62144c0ac1fc5a18506a2244ba449ac4"
        );
        // Input u-coordinate (= peer public key bytes).
        let u_in = hex!(
            "e6db6867583030db3594c1a424b15f7c"
            "726624ec26b3353b10a903a6d0ab1c4c"
        );
        // Output u-coordinate (= shared secret bytes).
        let u_out_expected = hex!(
            "c3da55379de9c6908e94ea4df28d084f"
            "32eccf03491c71f754b4075577a28552"
        );

        let ss = x25519_shared_secret_raw(&scalar, &u_in).unwrap();
        assert_eq!(ss.as_slice(), u_out_expected.as_slice());
    }

    /// Cremers & Jackson, "Prime, Order Please!" (2019) and Adam Langley's
    /// curves-list notes enumerate the canonical small-order Curve25519
    /// u-coordinates. Each one must cause the contributory-check to fail
    /// in `x25519_shared_secret_raw` when used as a peer public key.
    ///
    /// See:
    ///   https://moderncrypto.org/mail-archive/curves/2017/000898.html
    ///   https://eprint.iacr.org/2019/526
    #[test]
    fn small_order_public_keys_are_rejected() {
        let small_order_points: &[[u8; 32]] = &[
            // u = 0 — the identity element.
            hex!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            // u = 1 — order-1 point.
            hex!(
                "0100000000000000000000000000000000000000000000000000000000000000"
            ),
            // 325606250916557431795983626356110631294008115727848805560023387167927233504
            hex!(
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
            ),
            // 39382357235489614581723060781553021112529911719440698176882885853963445705823
            hex!(
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"
            ),
            // p - 1 (i.e. 2^255 - 20).
            hex!(
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
            ),
            // p (i.e. 2^255 - 19).
            hex!(
                "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
            ),
            // p + 1 (i.e. 2^255 - 18).
            hex!(
                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
            ),
        ];

        // An arbitrary non-zero private key for the local side. The exact
        // bytes don't matter — what matters is that every small-order peer
        // public key produces a non-contributory shared secret regardless
        // of local-side scalar.
        let local_priv = hex!(
            "01010101010101010101010101010101"
            "01010101010101010101010101010101"
        );

        for (i, peer_pub) in small_order_points.iter().enumerate() {
            let result = x25519_shared_secret_raw(&local_priv, peer_pub);
            assert!(
                result.is_err(),
                "small-order point #{} (u = {}) should be rejected, got Ok",
                i,
                hex::encode(peer_pub),
            );
            let err = result.unwrap_err();
            assert!(
                err.contains("non-contributory"),
                "small-order point #{} rejected with unexpected message: {}",
                i,
                err,
            );
        }
    }

    /// Bit-clamping per RFC 7748 §5: bits 0/1/2 of byte 0 and bit 7 of
    /// byte 31 are forced low; bit 6 of byte 31 is forced high. Two
    /// private keys that differ only in clamped bits must produce the
    /// same public key — confirming the clamping happens internally.
    #[test]
    fn clamping_is_internal() {
        let base = hex!(
            "5dab087e624a8a4b79e17f8b83800ee6"
            "6f3bb1292618b6fd1c2f8b27ff88e0eb"
        );

        // Variant: flip bits 0, 1, 2 of byte 0 (low three bits clamped to 0).
        let mut variant_a = base;
        variant_a[0] |= 0b0000_0111;

        // Variant: clear bit 6 of byte 31 and set bit 7 of byte 31. Clamping
        // forces bit 6 high and bit 7 low.
        let mut variant_b = base;
        variant_b[31] &= 0b1011_1111;
        variant_b[31] |= 0b1000_0000;

        let pub_base = x25519_public_key_create(&base).unwrap();
        let pub_a = x25519_public_key_create(&variant_a).unwrap();
        let pub_b = x25519_public_key_create(&variant_b).unwrap();

        assert_eq!(pub_base, pub_a);
        assert_eq!(pub_base, pub_b);
    }

    /// End-to-end ECDH round-trip on hard-coded private keys (no RNG dep).
    #[test]
    fn round_trip_hard_coded_keys() {
        let priv_a = hex!(
            "11111111111111111111111111111111"
            "11111111111111111111111111111111"
        );
        let priv_b = hex!(
            "22222222222222222222222222222222"
            "22222222222222222222222222222222"
        );

        let pub_a = x25519_public_key_create(&priv_a).unwrap();
        let pub_b = x25519_public_key_create(&priv_b).unwrap();
        let ss_a = x25519_shared_secret_raw(&priv_a, &pub_b).unwrap();
        let ss_b = x25519_shared_secret_raw(&priv_b, &pub_a).unwrap();

        assert_eq!(ss_a, ss_b);
        assert_eq!(ss_a.len(), 32);
    }

    /// The error path for malformed input lengths must produce stable,
    /// auditable error messages.
    #[test]
    fn input_length_errors() {
        let too_short: [u8; 31] = [0u8; 31];
        let too_long: [u8; 33] = [0u8; 33];
        let ok_priv: [u8; 32] = [1u8; 32];

        let err = x25519_public_key_create(&too_short).unwrap_err();
        assert!(err.contains("32 bytes"));

        let err = x25519_public_key_create(&too_long).unwrap_err();
        assert!(err.contains("32 bytes"));

        let err = x25519_shared_secret_raw(&too_short, &ok_priv).unwrap_err();
        assert!(err.contains("private key"));
        assert!(err.contains("32 bytes"));

        let err = x25519_shared_secret_raw(&ok_priv, &too_short).unwrap_err();
        assert!(err.contains("public key"));
        assert!(err.contains("32 bytes"));
    }
}
