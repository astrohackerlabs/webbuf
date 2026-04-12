use p256::{
    elliptic_curve::{
        ops::{Invert, Mul, MulByGenerator, Reduce},
        point::AffineCoordinates,
        scalar::FromUintUnchecked,
        sec1::ToEncodedPoint,
        Curve, NonZeroScalar,
    },
    FieldBytes, ProjectivePoint, PublicKey, Scalar, NistP256, SecretKey, U256,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*; // Import wasm-bindgen only if the 'wasm' feature is enabled

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn private_key_verify(priv_key_buf: &[u8]) -> bool {
    if priv_key_buf.len() != 32 {
        return false;
    }
    SecretKey::from_slice(priv_key_buf).is_ok()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn public_key_verify(pub_key_buf: &[u8]) -> bool {
    // Check if the public key length is correct (33 bytes for compressed format)
    if pub_key_buf.len() != 33 {
        return false;
    }

    // Try to parse the public key and return whether it's valid
    PublicKey::from_sec1_bytes(pub_key_buf).is_ok()
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn public_key_create(priv_key_buf: &[u8]) -> Result<Vec<u8>, String> {
    if priv_key_buf.len() != 32 {
        return Err("Invalid private key: must be exactly 32 bytes".to_string());
    }
    if priv_key_buf.iter().all(|&b| b == 0) {
        return Err("Invalid private key: cannot be all zeros".to_string());
    }

    let secret_key =
        SecretKey::from_slice(priv_key_buf).map_err(|_| "Invalid private key".to_string())?;
    let secret_scalar = secret_key.to_nonzero_scalar();
    let public_key = PublicKey::from_secret_scalar(&secret_scalar);
    Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn public_key_decompress(compressed: &[u8]) -> Result<Vec<u8>, String> {
    if compressed.len() != 33 {
        return Err("Compressed public key must be exactly 33 bytes".to_string());
    }
    if compressed[0] != 0x02 && compressed[0] != 0x03 {
        return Err("Compressed public key must start with 0x02 or 0x03".to_string());
    }

    let public_key = PublicKey::from_sec1_bytes(compressed)
        .map_err(|_| "Invalid compressed public key".to_string())?;

    // to_encoded_point(false) emits 0x04 || X || Y with fixed 32-byte coordinates
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn public_key_compress(uncompressed: &[u8]) -> Result<Vec<u8>, String> {
    if uncompressed.len() != 65 {
        return Err("Uncompressed public key must be exactly 65 bytes".to_string());
    }
    if uncompressed[0] != 0x04 {
        return Err("Uncompressed public key must start with 0x04".to_string());
    }

    let public_key = PublicKey::from_sec1_bytes(uncompressed)
        .map_err(|_| "Invalid uncompressed public key".to_string())?;

    Ok(public_key.to_encoded_point(true).as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn private_key_add(priv_key_buf_1: &[u8], priv_key_buf_2: &[u8]) -> Result<Vec<u8>, String> {
    if priv_key_buf_1.len() != 32 || priv_key_buf_2.len() != 32 {
        return Err("Private keys must be exactly 32 bytes".to_string());
    }

    let secret_key_1 = SecretKey::from_slice(priv_key_buf_1)
        .map_err(|_| "Invalid first private key".to_string())?;
    let secret_key_2 = SecretKey::from_slice(priv_key_buf_2)
        .map_err(|_| "Invalid second private key".to_string())?;

    let new_secret_scalar = secret_key_1
        .to_nonzero_scalar()
        .add(&secret_key_2.to_nonzero_scalar());

    let new_secret_key = SecretKey::from_bytes(&new_secret_scalar.to_bytes())
        .map_err(|_| "Failed to create new private key".to_string())?;

    Ok(new_secret_key.to_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn public_key_add(pub_key_buf_1: &[u8], pub_key_buf_2: &[u8]) -> Result<Vec<u8>, String> {
    if pub_key_buf_1.len() != 33 || pub_key_buf_2.len() != 33 {
        return Err("Public keys must be 33 bytes in compressed format".to_string());
    }

    let pub_key_1 = PublicKey::from_sec1_bytes(pub_key_buf_1)
        .map_err(|_| "Invalid first public key".to_string())?;
    let pub_key_2 = PublicKey::from_sec1_bytes(pub_key_buf_2)
        .map_err(|_| "Invalid second public key".to_string())?;

    let combined_pub_key = ProjectivePoint::from(pub_key_1) + ProjectivePoint::from(pub_key_2);

    Ok(combined_pub_key.to_encoded_point(true).as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[allow(non_snake_case)]
pub fn sign(
    hash_buf: &[u8],     // Hash digest buffer
    priv_key_buf: &[u8], // Private key buffer
    k_buf: &[u8],        // Ephemeral scalar buffer
) -> Result<Vec<u8>, String> {
    if priv_key_buf.len() != 32 || k_buf.len() != 32 || hash_buf.len() != 32 {
        return Err("All inputs must be exactly 32 bytes".to_string());
    }
    if priv_key_buf.iter().all(|&b| b == 0)
        || k_buf.iter().all(|&b| b == 0)
        || hash_buf.iter().all(|&b| b == 0)
    {
        return Err("All inputs cannot be all zeros".to_string());
    }

    let d_uint = U256::from_be_slice(priv_key_buf);
    let k_uint = U256::from_be_slice(k_buf);
    let z_field_bytes = FieldBytes::from_slice(hash_buf);

    let d_scalar =
        NonZeroScalar::<NistP256>::from_uint(d_uint).expect("Failed to create d_scalar");
    let k_scalar =
        NonZeroScalar::<NistP256>::from_uint(k_uint).expect("Failed to create k_scalar");

    let z_scalar =
        <Scalar as Reduce<<p256::NistP256 as p256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            z_field_bytes,
        );

    let k_inv = k_scalar.invert();

    let R = ProjectivePoint::mul_by_generator(&k_scalar).to_affine();

    let r =
        <Scalar as Reduce<<p256::NistP256 as p256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &R.x(),
        );

    let mut s = *k_inv * (z_scalar + (r * d_scalar.as_ref()));

    // Normalize s to the lower half of the curve order
    let n_uint = NistP256::ORDER;
    let n = Scalar::from_uint_unchecked(n_uint);
    if s > n >> 1 {
        s = n - s;
    }

    let s_bytes = s.to_bytes();
    let r_bytes = r.to_bytes();
    let rs_bytes = [r_bytes, s_bytes].concat();
    if rs_bytes.len() != 64 {
        return Err("Failed to create signature of correct length".to_string());
    }

    Ok(rs_bytes)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn verify(
    sig_buf: &[u8],     // Signature buffer
    hash_buf: &[u8],    // Hash digest buffer
    pub_key_buf: &[u8], // Public key buffer
) -> Result<(), String> {
    if pub_key_buf.len() != 33 || hash_buf.len() != 32 || sig_buf.len() != 64 {
        return Err("All inputs must be exactly 33, 32, and 64 bytes".to_string());
    }
    if pub_key_buf.iter().all(|&b| b == 0)
        || hash_buf.iter().all(|&b| b == 0)
        || sig_buf.iter().all(|&b| b == 0)
    {
        return Err("All inputs cannot be all zeros".to_string());
    }

    let q_public_key =
        PublicKey::from_sec1_bytes(pub_key_buf).map_err(|_| "Invalid public key".to_string())?;
    let q = ProjectivePoint::from(q_public_key);

    let z = FieldBytes::from_slice(hash_buf);

    let r_bytes = &sig_buf[0..32];
    if r_bytes.iter().all(|&b| b == 0) {
        return Err("Signature r cannot be all zeros".to_string());
    }
    let s_bytes = &sig_buf[32..64];
    if s_bytes.iter().all(|&b| b == 0) {
        return Err("Signature s cannot be all zeros".to_string());
    }
    let r_field_bytes = FieldBytes::from_slice(r_bytes);
    let s_field_bytes = FieldBytes::from_slice(s_bytes);

    let z =
        <Scalar as Reduce<<p256::NistP256 as p256::elliptic_curve::Curve>::Uint>>::reduce_bytes(z);
    let r =
        <Scalar as Reduce<<p256::NistP256 as p256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            r_field_bytes,
        );
    let s =
        <Scalar as Reduce<<p256::NistP256 as p256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            s_field_bytes,
        );
    let s_inv = s.invert().expect("Failed to invert s");
    let u1 = z * s_inv;
    let u2 = r * s_inv;
    let x = ProjectivePoint::mul_by_generator(&u1) + q * u2;
    let x = x.to_affine().x();

    if r.to_bytes().to_vec() == x.to_vec() {
        Ok(())
    } else {
        Err("Signature verification failed".to_string())
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn shared_secret(priv_key_buf: &[u8], pub_key_buf: &[u8]) -> Result<Vec<u8>, String> {
    if priv_key_buf.len() != 32 {
        return Err("Private key must be exactly 32 bytes".to_string());
    }
    if pub_key_buf.len() != 33 {
        return Err("Public key must be 33 bytes in compressed format".to_string());
    }

    // Convert the private key bytes into a SecretKey
    let secret_key =
        SecretKey::from_slice(priv_key_buf).map_err(|_| "Invalid private key".to_string())?;

    // Extract the Scalar (the actual secret) from the SecretKey
    let nonzero_scalar = secret_key.to_nonzero_scalar();
    let scalar: Scalar = *nonzero_scalar;

    // Convert the public key bytes into a point
    let pub_key =
        PublicKey::from_sec1_bytes(pub_key_buf).map_err(|_| "Invalid public key".to_string())?;

    // use arithmetic: secret key = private key * public key
    let point = pub_key.as_affine();
    let secret_key = point.mul(scalar).to_affine();
    // Convert the resulting point to an encoded form (compressed)
    let encoded_point = secret_key.to_encoded_point(true); // `true` for compressed format

    // Convert the encoded point to a Vec<u8>
    Ok(encoded_point.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use webbuf_blake3;
    use hex_literal::hex;
    use rfc6979::consts::U32;
    use rfc6979::generate_k;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_private_key_verify() {
        let valid_priv_key = [0x01; 32];
        let invalid_priv_key = [0x01; 31];

        assert!(private_key_verify(&valid_priv_key));
        assert!(!private_key_verify(&invalid_priv_key));
    }

    #[test]
    fn test_public_key_create() {
        let priv_key = [0x01; 32];
        let pub_key = public_key_create(&priv_key).unwrap();

        assert_eq!(pub_key.len(), 33); // Compressed public key length
    }

    #[test]
    fn test_private_key_add() {
        let priv_key_1 = [0x01; 32];
        let priv_key_2 = [0x02; 32];

        let result = private_key_add(&priv_key_1, &priv_key_2).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_public_key_add() {
        let priv_key_1 = [0x01; 32];
        let priv_key_2 = [0x02; 32];

        let pub_key_1 = public_key_create(&priv_key_1).unwrap();
        let pub_key_2 = public_key_create(&priv_key_2).unwrap();

        let combined_pub_key = public_key_add(&pub_key_1, &pub_key_2).unwrap();
        assert_eq!(combined_pub_key.len(), 33);
    }

    #[test]
    fn test_public_key_add_homomorphism() {
        // Verify that (a+b)*G = a*G + b*G
        let priv_key_1 = [0x01; 32];
        let priv_key_2 = [0x02; 32];

        let pub_key_1 = public_key_create(&priv_key_1).unwrap();
        let pub_key_2 = public_key_create(&priv_key_2).unwrap();
        let combined_pub_key = public_key_add(&pub_key_1, &pub_key_2).unwrap();

        let combined_priv_key = private_key_add(&priv_key_1, &priv_key_2).unwrap();
        let expected_pub_key = public_key_create(&combined_priv_key).unwrap();

        assert_eq!(combined_pub_key, expected_pub_key);
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        // For several deterministic private keys, derive the compressed public key,
        // decompress it, then recompress, and verify round-trip.
        for seed in 1u8..=5 {
            let priv_key = [seed; 32];
            let compressed = public_key_create(&priv_key).unwrap();
            assert_eq!(compressed.len(), 33);

            let uncompressed = public_key_decompress(&compressed).unwrap();
            assert_eq!(uncompressed.len(), 65);
            assert_eq!(uncompressed[0], 0x04);

            let recompressed = public_key_compress(&uncompressed).unwrap();
            assert_eq!(recompressed, compressed);
        }
    }

    #[test]
    fn test_decompress_structure() {
        // Uncompressed form is 0x04 || X(32) || Y(32)
        let priv_key = [0x01; 32];
        let compressed = public_key_create(&priv_key).unwrap();
        let uncompressed = public_key_decompress(&compressed).unwrap();

        assert_eq!(uncompressed[0], 0x04);
        // X coordinate matches the compressed key's X (bytes 1..33 of both)
        assert_eq!(&uncompressed[1..33], &compressed[1..33]);
        // Y parity matches the compressed prefix
        let y_is_odd = (uncompressed[64] & 1) == 1;
        let prefix_says_odd = compressed[0] == 0x03;
        assert_eq!(y_is_odd, prefix_says_odd);
    }

    #[test]
    fn test_decompress_even_and_odd_y() {
        // Scalar 1 → generator point G. G has a known Y parity on P-256.
        // Scalar 2 → 2G with the opposite parity.
        // We don't hardcode the specific parity; we just verify both parities appear
        // across some keys, proving both 0x02 and 0x03 prefixes work.
        let mut saw_even = false;
        let mut saw_odd = false;

        for seed in 1u8..=20 {
            let priv_key = [seed; 32];
            if !private_key_verify(&priv_key) {
                continue;
            }
            let compressed = public_key_create(&priv_key).unwrap();
            match compressed[0] {
                0x02 => saw_even = true,
                0x03 => saw_odd = true,
                _ => panic!("Unexpected compressed prefix"),
            }
            // Decompress should succeed for both parities.
            let uncompressed = public_key_decompress(&compressed).unwrap();
            assert_eq!(uncompressed[0], 0x04);
        }

        assert!(saw_even, "Expected at least one key with even Y (0x02)");
        assert!(saw_odd, "Expected at least one key with odd Y (0x03)");
    }

    #[test]
    fn test_compress_rejects_wrong_prefix() {
        // Start with a valid uncompressed, change prefix to 0x05 (invalid).
        let priv_key = [0x01; 32];
        let compressed = public_key_create(&priv_key).unwrap();
        let mut uncompressed = public_key_decompress(&compressed).unwrap();
        uncompressed[0] = 0x05;
        assert!(public_key_compress(&uncompressed).is_err());
    }

    #[test]
    fn test_compress_rejects_wrong_length() {
        assert!(public_key_compress(&[0x04; 64]).is_err());
        assert!(public_key_compress(&[0x04; 66]).is_err());
        assert!(public_key_compress(&[]).is_err());
    }

    #[test]
    fn test_decompress_rejects_wrong_prefix() {
        // Build a 33-byte buffer with prefix 0x04 (invalid for compressed).
        let mut bad = [0u8; 33];
        bad[0] = 0x04;
        assert!(public_key_decompress(&bad).is_err());
    }

    #[test]
    fn test_decompress_rejects_wrong_length() {
        assert!(public_key_decompress(&[0x02; 32]).is_err());
        assert!(public_key_decompress(&[0x02; 34]).is_err());
        assert!(public_key_decompress(&[]).is_err());
    }

    #[test]
    fn test_compress_rejects_off_curve() {
        // 0x04 || X || Y where the point is not on the curve.
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        off_curve[1..33].fill(0xff);
        off_curve[33..65].fill(0xff);
        assert!(public_key_compress(&off_curve).is_err());
    }

    #[test]
    fn test_sign_and_verify() {
        let priv_key = [0x01; 32];
        let message = [0x02; 32];

        let blake3_k: [u8; 32] = webbuf_blake3::blake3_mac(&priv_key, &message)
            .unwrap()
            .try_into()
            .unwrap();

        let signature = sign(&message, &priv_key, &blake3_k).unwrap();
        assert_eq!(signature.len(), 64);

        let pub_key = public_key_create(&priv_key).unwrap();
        assert!(verify(&signature, &message, &pub_key).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let priv_key = [0x01; 32];
        let message = [0x02; 32];
        let invalid_message = [0x03; 32];

        let blake3_k: [u8; 32] = webbuf_blake3::blake3_mac(&priv_key, &message)
            .unwrap()
            .try_into()
            .unwrap();

        let signature = sign(&message, &priv_key, &blake3_k).unwrap();
        let pub_key = public_key_create(&priv_key).unwrap();

        assert!(verify(&signature, &invalid_message, &pub_key).is_err());
    }

    #[test]
    fn test_diffie_hellman_shared_secret() {
        let priv_key_1: [u8; 32] = [
            0x38, 0x49, 0x58, 0x49, 0xf8, 0x38, 0xe8, 0xd5, 0xf8, 0xc9, 0x4d, 0xf2, 0x7a, 0x3c,
            0x91, 0x8d, 0x8e, 0xe9, 0x6a, 0xbf, 0x6b, 0x74, 0x5f, 0xb5, 0x4d, 0x82, 0x1b, 0xf9,
            0x5b, 0x6e, 0x5d, 0xc3,
        ];
        let priv_key_2: [u8; 32] = [
            0x55, 0x91, 0x22, 0x55, 0x18, 0xa9, 0x19, 0xf0, 0x2a, 0x3f, 0x8c, 0x9a, 0x7a, 0x1b,
            0xc1, 0xe2, 0x9d, 0x81, 0x3c, 0xd8, 0x5a, 0x39, 0xe7, 0xaa, 0x89, 0x9d, 0xf4, 0x64,
            0x5e, 0x4a, 0x6b, 0x91,
        ];

        let pub_key_1 = public_key_create(&priv_key_1).unwrap();
        let pub_key_2 = public_key_create(&priv_key_2).unwrap();

        let shared_secret_1 = shared_secret(&priv_key_1, &pub_key_2).unwrap();
        let shared_secret_2 = shared_secret(&priv_key_2, &pub_key_1).unwrap();

        assert_eq!(shared_secret_1, shared_secret_2);
    }

    // P-256 curve order (modulus)
    const P256_MODULUS: [u8; 32] =
        hex!("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

    // Private key for testing (from RFC 6979 A.2.5 - P-256/SHA-256)
    const RFC6979_KEY: [u8; 32] =
        hex!("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");

    // Test message for RFC6979
    const RFC6979_MSG: &[u8; 6] = b"sample";

    // Expected k for RFC 6979 using P-256 and SHA-256 (from RFC 6979 A.2.5)
    const RFC6979_EXPECTED_K: [u8; 32] =
        hex!("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");

    #[test]
    fn test_sign_with_rfc6979_k() {
        let hashed_msg = Sha256::digest(RFC6979_MSG);
        let hashed_msg_bytes: [u8; 32] = hashed_msg.as_slice().try_into().unwrap();

        let k = generate_k::<Sha256, U32>(
            &RFC6979_KEY.into(),
            &P256_MODULUS.into(),
            &hashed_msg,
            b"",
        );

        assert_eq!(
            k.as_slice(),
            &RFC6979_EXPECTED_K,
            "Generated k does not match the expected k"
        );

        let custom_signature = sign(&hashed_msg_bytes, &RFC6979_KEY, k.as_slice()).unwrap();
        assert_eq!(custom_signature.len(), 64);

        let pub_key = public_key_create(&RFC6979_KEY).unwrap();
        let verified = verify(&custom_signature, &hashed_msg_bytes, &pub_key);
        assert!(
            verified.is_ok(),
            "Failed to verify signature: {:?}",
            verified
        );
    }

    #[test]
    fn test_cross_validate_with_p256_ecdsa() {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

        let hashed_msg = Sha256::digest(RFC6979_MSG);
        let hashed_msg_bytes: [u8; 32] = hashed_msg.as_slice().try_into().unwrap();

        let k = generate_k::<Sha256, U32>(
            &RFC6979_KEY.into(),
            &P256_MODULUS.into(),
            &hashed_msg,
            b"",
        );

        let custom_signature = sign(&hashed_msg_bytes, &RFC6979_KEY, k.as_slice()).unwrap();

        // Verify using p256 crate's built-in ECDSA verifier with prehashed data
        let pub_key_bytes = public_key_create(&RFC6979_KEY).unwrap();
        let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes)
            .expect("Failed to create verifying key");
        let sig = Signature::from_slice(&custom_signature)
            .expect("Failed to create signature");
        assert!(
            verifying_key.verify_prehash(&hashed_msg_bytes, &sig).is_ok(),
            "p256 crate verification failed"
        );

        // Also verify with our custom verify
        let custom_verified = verify(&custom_signature, &hashed_msg_bytes, &pub_key_bytes);
        assert!(
            custom_verified.is_ok(),
            "Custom verification failed: {:?}",
            custom_verified
        );
    }

    const N_SIG_TESTS: u32 = 50;

    #[test]
    fn test_n_sig_tests_signatures_different_private_keys() {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

        let message = b"sample";
        let hashed_msg = Sha256::digest(message);
        let hashed_msg_bytes: [u8; 32] = hashed_msg.as_slice().try_into().unwrap();

        let mut seed = b"initial seed".to_vec();

        for i in 0..N_SIG_TESTS {
            seed.push(i as u8);
            let private_key = deterministic_32_bytes(&seed);
            seed.pop();

            let k = generate_k::<Sha256, U32>(
                &private_key.into(),
                &P256_MODULUS.into(),
                &hashed_msg,
                b"",
            );

            let custom_signature = sign(&hashed_msg_bytes, &private_key, k.as_slice()).unwrap();

            // Verify with p256 crate
            let pub_key_bytes = public_key_create(&private_key).unwrap();
            let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap();
            let sig = Signature::from_slice(&custom_signature).unwrap();
            assert!(
                verifying_key.verify_prehash(&hashed_msg_bytes, &sig).is_ok(),
                "p256 crate verification failed for key {}",
                i
            );

            // Verify with custom verify
            let custom_verified = verify(&custom_signature, &hashed_msg_bytes, &pub_key_bytes);
            assert!(custom_verified.is_ok(), "Custom verification failed for key {}", i);
        }
    }

    #[test]
    fn test_n_sig_tests_signatures_different_messages() {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

        let private_key = deterministic_32_bytes(b"initial seed");

        let mut seed = b"initial seed".to_vec();

        for i in 0..N_SIG_TESTS {
            seed.push(i as u8);
            let message = deterministic_32_bytes(&seed);
            seed.pop();

            let hashed_msg = Sha256::digest(message);
            let hashed_msg_bytes: [u8; 32] = hashed_msg.as_slice().try_into().unwrap();
            let k = generate_k::<Sha256, U32>(
                &private_key.into(),
                &P256_MODULUS.into(),
                &hashed_msg,
                b"",
            );

            let custom_signature = sign(&hashed_msg_bytes, &private_key, k.as_slice()).unwrap();

            // Verify with p256 crate
            let pub_key_bytes = public_key_create(&private_key).unwrap();
            let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap();
            let sig = Signature::from_slice(&custom_signature).unwrap();
            assert!(
                verifying_key.verify_prehash(&hashed_msg_bytes, &sig).is_ok(),
                "p256 crate verification failed for msg {}",
                i
            );

            let custom_verified = verify(&custom_signature, &hashed_msg_bytes, &pub_key_bytes);
            assert!(custom_verified.is_ok(), "Custom verification failed for msg {}", i);
        }
    }

    fn deterministic_32_bytes(seed: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let result = hasher.finalize();
        result
            .as_slice()
            .try_into()
            .expect("Hash output length mismatch")
    }
}
