use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn aesgcm_encrypt(
    plaintext: &[u8],
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if iv.len() != 12 {
        return Err("IV must be exactly 12 bytes".to_string());
    }

    let nonce = Nonce::from_slice(iv);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| "Invalid key".to_string())?;
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| "Encryption failed".to_string())
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| "Invalid key".to_string())?;
            cipher
                .encrypt(nonce, payload)
                .map_err(|_| "Encryption failed".to_string())
        }
        _ => Err("Key must be 16 or 32 bytes".to_string()),
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn aesgcm_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if iv.len() != 12 {
        return Err("IV must be exactly 12 bytes".to_string());
    }
    if ciphertext.len() < 16 {
        return Err("Ciphertext must be at least 16 bytes (auth tag)".to_string());
    }

    let nonce = Nonce::from_slice(iv);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|_| "Invalid key".to_string())?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| "Decryption failed: authentication error".to_string())
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| "Invalid key".to_string())?;
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| "Decryption failed: authentication error".to_string())
        }
        _ => Err("Key must be 16 or 32 bytes".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const NO_AAD: &[u8] = &[];

    // NIST SP 800-38D Test Case 1: AES-128-GCM, zero-length plaintext
    #[test]
    fn test_nist_aes128_gcm_empty_plaintext() {
        let key = hex!("00000000000000000000000000000000");
        let iv = hex!("000000000000000000000000");
        let plaintext: &[u8] = &[];

        let ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        // Empty plaintext → only 16-byte auth tag
        assert_eq!(ciphertext.len(), 16);

        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    // NIST SP 800-38D Test Case 2: AES-128-GCM with plaintext
    #[test]
    fn test_nist_aes128_gcm_with_plaintext() {
        let key = hex!("00000000000000000000000000000000");
        let iv = hex!("000000000000000000000000");
        let plaintext = hex!("00000000000000000000000000000000");

        let ciphertext = aesgcm_encrypt(&plaintext, &key, &iv, NO_AAD).unwrap();
        // 16 bytes ciphertext + 16 bytes tag
        assert_eq!(ciphertext.len(), 32);

        // Expected ciphertext (without tag): 0388dace60b6a392f328c2b971b2fe78
        assert_eq!(&ciphertext[..16], hex!("0388dace60b6a392f328c2b971b2fe78"));

        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // NIST SP 800-38D Test Case 13: AES-256-GCM, zero-length plaintext
    #[test]
    fn test_nist_aes256_gcm_empty_plaintext() {
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let iv = hex!("000000000000000000000000");
        let plaintext: &[u8] = &[];

        let ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(ciphertext.len(), 16);

        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    // NIST SP 800-38D Test Case 14: AES-256-GCM with plaintext
    #[test]
    fn test_nist_aes256_gcm_with_plaintext() {
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let iv = hex!("000000000000000000000000");
        let plaintext = hex!("00000000000000000000000000000000");

        let ciphertext = aesgcm_encrypt(&plaintext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(ciphertext.len(), 32);

        // Expected ciphertext (without tag): cea7403d4d606b6e074ec5d3baf39d18
        assert_eq!(&ciphertext[..16], hex!("cea7403d4d606b6e074ec5d3baf39d18"));

        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_aes128() {
        let key = hex!("feffe9928665731c6d6a8f9467308308");
        let iv = hex!("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-GCM!";

        let ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_aes256() {
        let key = hex!("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex!("cafebabefacedbaddecaf888");
        let plaintext = b"Hello, AES-256-GCM!";

        let ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_includes_tag() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"test";

        let ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        // plaintext length + 16-byte tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let iv = [0x03u8; 12];
        let plaintext = b"secret message";

        let ciphertext = aesgcm_encrypt(plaintext, &key1, &iv, NO_AAD).unwrap();
        assert!(aesgcm_decrypt(&ciphertext, &key2, &iv, NO_AAD).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0x01u8; 32];
        let iv = [0x02u8; 12];
        let plaintext = b"secret message";

        let mut ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        ciphertext[0] ^= 0x01; // flip one bit
        assert!(aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).is_err());
    }

    #[test]
    fn test_tampered_tag_fails() {
        let key = [0x01u8; 32];
        let iv = [0x02u8; 12];
        let plaintext = b"secret message";

        let mut ciphertext = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01; // flip one bit in tag
        assert!(aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).is_err());
    }

    #[test]
    fn test_wrong_iv_fails() {
        let key = [0x01u8; 32];
        let iv1 = [0x02u8; 12];
        let iv2 = [0x03u8; 12];
        let plaintext = b"secret message";

        let ciphertext = aesgcm_encrypt(plaintext, &key, &iv1, NO_AAD).unwrap();
        assert!(aesgcm_decrypt(&ciphertext, &key, &iv2, NO_AAD).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x01u8; 32];
        let iv = [0x02u8; 12];

        let ciphertext = aesgcm_encrypt(&[], &key, &iv, NO_AAD).unwrap();
        assert_eq!(ciphertext.len(), 16); // just the tag

        let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(decrypted.len(), 0);
    }

    #[test]
    fn test_determinism() {
        let key = [0x01u8; 32];
        let iv = [0x02u8; 12];
        let plaintext = b"deterministic test";

        let ct1 = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        let ct2 = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_different_keys_different_output() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let iv = [0x03u8; 12];
        let plaintext = b"test";

        let ct1 = aesgcm_encrypt(plaintext, &key1, &iv, NO_AAD).unwrap();
        let ct2 = aesgcm_encrypt(plaintext, &key2, &iv, NO_AAD).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_various_plaintext_sizes() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];

        for size in [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 1000] {
            let plaintext = vec![0x41u8; size];
            let ciphertext = aesgcm_encrypt(&plaintext, &key, &iv, NO_AAD).unwrap();
            assert_eq!(ciphertext.len(), size + 16);

            let decrypted = aesgcm_decrypt(&ciphertext, &key, &iv, NO_AAD).unwrap();
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_invalid_iv_length() {
        let key = [0x01u8; 32];
        assert!(aesgcm_encrypt(b"test", &key, &[0u8; 16], NO_AAD).is_err()); // 16, not 12
        assert!(aesgcm_encrypt(b"test", &key, &[0u8; 8], NO_AAD).is_err()); // 8, not 12
    }

    #[test]
    fn test_invalid_key_length() {
        let iv = [0x01u8; 12];
        assert!(aesgcm_encrypt(b"test", &[0u8; 24], &iv, NO_AAD).is_err()); // 192-bit not supported
        assert!(aesgcm_encrypt(b"test", &[0u8; 10], &iv, NO_AAD).is_err()); // invalid
    }

    #[test]
    fn test_ciphertext_too_short() {
        let key = [0x01u8; 32];
        let iv = [0x02u8; 12];
        assert!(aesgcm_decrypt(&[0u8; 15], &key, &iv, NO_AAD).is_err()); // less than 16 bytes
    }

    // ===========================================================
    // AAD tests (issue 0006 Experiment 1)
    // ===========================================================

    #[test]
    fn test_empty_aad_round_trip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"context-aware";

        let ct = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        let pt = aesgcm_decrypt(&ct, &key, &iv, NO_AAD).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_non_empty_aad_round_trip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"context-aware";
        let aad: &[u8] = b"protocol-v1:alice@a:bob@b";

        let ct = aesgcm_encrypt(plaintext, &key, &iv, aad).unwrap();
        let pt = aesgcm_decrypt(&ct, &key, &iv, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aad_mismatch_fails() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"sensitive";
        let aad_a: &[u8] = b"context-A";
        let aad_b: &[u8] = b"context-B";

        let ct = aesgcm_encrypt(plaintext, &key, &iv, aad_a).unwrap();
        assert!(aesgcm_decrypt(&ct, &key, &iv, aad_b).is_err());
    }

    #[test]
    fn test_aad_missing_on_decrypt_fails() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"sensitive";
        let aad: &[u8] = b"context";

        let ct = aesgcm_encrypt(plaintext, &key, &iv, aad).unwrap();
        assert!(aesgcm_decrypt(&ct, &key, &iv, NO_AAD).is_err());
    }

    #[test]
    fn test_aad_added_on_decrypt_fails() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"sensitive";
        let aad: &[u8] = b"context";

        let ct = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        assert!(aesgcm_decrypt(&ct, &key, &iv, aad).is_err());
    }

    #[test]
    fn test_aad_changes_tag_not_body() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"plaintext";

        let ct1 = aesgcm_encrypt(plaintext, &key, &iv, NO_AAD).unwrap();
        let ct2 = aesgcm_encrypt(plaintext, &key, &iv, b"some-context").unwrap();

        // Same length (AAD is not transmitted)
        assert_eq!(ct1.len(), ct2.len());
        // The body bytes (everything before the 16-byte tag) are
        // identical because AES-CTR with the same key/IV produces the
        // same keystream regardless of AAD.
        let body_len = ct1.len() - 16;
        assert_eq!(&ct1[..body_len], &ct2[..body_len]);
        // The tag differs because AAD changes the GHASH input.
        assert_ne!(&ct1[body_len..], &ct2[body_len..]);
    }

    #[test]
    fn test_aad_with_aes128_round_trip() {
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let plaintext = b"128-bit AES with AAD";
        let aad: &[u8] = b"context";

        let ct = aesgcm_encrypt(plaintext, &key, &iv, aad).unwrap();
        let pt = aesgcm_decrypt(&ct, &key, &iv, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_large_aad_round_trip() {
        let key = [0x42u8; 32];
        let iv = [0x01u8; 12];
        let plaintext = b"hi";
        let large_aad = vec![0x55u8; 4096];

        let ct = aesgcm_encrypt(plaintext, &key, &iv, &large_aad).unwrap();
        let pt = aesgcm_decrypt(&ct, &key, &iv, &large_aad).unwrap();
        assert_eq!(pt, plaintext);

        // Tamper with one byte of the AAD on decrypt → fails
        let mut tampered = large_aad.clone();
        tampered[2000] ^= 0x01;
        assert!(aesgcm_decrypt(&ct, &key, &iv, &tampered).is_err());
    }
}
