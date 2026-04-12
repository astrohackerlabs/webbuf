use sha2::Sha256;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: u32,
) -> Result<Vec<u8>, String> {
    if iterations == 0 {
        return Err("Iterations must be greater than 0".to_string());
    }
    if key_len == 0 {
        return Err("Key length must be greater than 0".to_string());
    }
    if key_len > 128 {
        return Err("Key length must be at most 128 bytes".to_string());
    }

    let mut output = vec![0u8; key_len as usize];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Test vectors from RFC 7914 (scrypt paper) and various PBKDF2-HMAC-SHA256 references
    // https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors

    #[test]
    fn test_pbkdf2_sha256_vector_1() {
        // password="password", salt="salt", iterations=1, keylen=32
        let result = pbkdf2_sha256(b"password", b"salt", 1, 32).unwrap();
        assert_eq!(
            result,
            hex!("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        );
    }

    #[test]
    fn test_pbkdf2_sha256_vector_2() {
        // password="password", salt="salt", iterations=2, keylen=32
        let result = pbkdf2_sha256(b"password", b"salt", 2, 32).unwrap();
        assert_eq!(
            result,
            hex!("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        );
    }

    #[test]
    fn test_pbkdf2_sha256_vector_3() {
        // password="password", salt="salt", iterations=4096, keylen=32
        let result = pbkdf2_sha256(b"password", b"salt", 4096, 32).unwrap();
        assert_eq!(
            result,
            hex!("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
    }

    #[test]
    fn test_pbkdf2_sha256_vector_4() {
        // password="passwordPASSWORDpassword", salt="saltSALTsaltSALTsaltSALTsaltSALTsalt", iterations=4096, keylen=40
        let result = pbkdf2_sha256(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
        )
        .unwrap();
        assert_eq!(
            result,
            hex!("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
        );
    }

    #[test]
    fn test_pbkdf2_sha256_vector_5() {
        // password="pass\0word", salt="sa\0lt", iterations=4096, keylen=16
        let result = pbkdf2_sha256(b"pass\0word", b"sa\0lt", 4096, 16).unwrap();
        assert_eq!(result, hex!("89b69d0516f829893c696226650a8687"));
    }

    #[test]
    fn test_empty_password() {
        let result = pbkdf2_sha256(b"", b"salt", 1, 32).unwrap();
        assert_eq!(result.len(), 32);
        // Should not be all zeros
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_empty_salt() {
        let result = pbkdf2_sha256(b"password", b"", 1, 32).unwrap();
        assert_eq!(result.len(), 32);
        assert!(result.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_various_key_lengths() {
        for key_len in [1, 16, 20, 32, 48, 64, 128] {
            let result = pbkdf2_sha256(b"password", b"salt", 1, key_len).unwrap();
            assert_eq!(result.len(), key_len as usize);
        }
    }

    #[test]
    fn test_determinism() {
        let result1 = pbkdf2_sha256(b"password", b"salt", 100, 32).unwrap();
        let result2 = pbkdf2_sha256(b"password", b"salt", 100, 32).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_different_passwords_different_output() {
        let result1 = pbkdf2_sha256(b"password1", b"salt", 1, 32).unwrap();
        let result2 = pbkdf2_sha256(b"password2", b"salt", 1, 32).unwrap();
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_different_salts_different_output() {
        let result1 = pbkdf2_sha256(b"password", b"salt1", 1, 32).unwrap();
        let result2 = pbkdf2_sha256(b"password", b"salt2", 1, 32).unwrap();
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_different_iterations_different_output() {
        let result1 = pbkdf2_sha256(b"password", b"salt", 1, 32).unwrap();
        let result2 = pbkdf2_sha256(b"password", b"salt", 2, 32).unwrap();
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_zero_iterations_rejected() {
        assert!(pbkdf2_sha256(b"password", b"salt", 0, 32).is_err());
    }

    #[test]
    fn test_zero_key_len_rejected() {
        assert!(pbkdf2_sha256(b"password", b"salt", 1, 0).is_err());
    }

    #[test]
    fn test_excessive_key_len_rejected() {
        assert!(pbkdf2_sha256(b"password", b"salt", 1, 129).is_err());
    }

    #[test]
    fn test_max_key_len_accepted() {
        let result = pbkdf2_sha256(b"password", b"salt", 1, 128).unwrap();
        assert_eq!(result.len(), 128);
    }
}
