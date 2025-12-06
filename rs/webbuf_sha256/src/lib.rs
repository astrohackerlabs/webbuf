use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

type HmacSha256 = Hmac<Sha256>;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sha256_hash(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hasher.finalize().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn double_sha256_hash(data: &[u8]) -> Result<Vec<u8>, String> {
    let first_hash = sha256_hash(data)?;
    sha256_hash(&first_hash)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| format!("Invalid key: {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{decode, encode};

    #[test]
    fn test_sha256_hash_empty() {
        // SHA-256 of empty string
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = sha256_hash(&[]).unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_sha256_hash_abc() {
        // SHA-256 of "abc" - NIST test vector
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let result = sha256_hash(b"abc").unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_sha256_hash_long() {
        // SHA-256 of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" - NIST test vector
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        let result = sha256_hash(input).unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_double_sha256_hash() {
        // Double SHA-256 of "abc"
        // First hash: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        // Second hash of that:
        let expected = "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358";
        let result = double_sha256_hash(b"abc").unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_sha256_hmac_rfc4231_test1() {
        // RFC 4231 Test Case 1
        // Key = 0x0b repeated 20 times
        // Data = "Hi There"
        let key = decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let data = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let result = sha256_hmac(&key, data).unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_sha256_hmac_rfc4231_test2() {
        // RFC 4231 Test Case 2
        // Key = "Jefe"
        // Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        let result = sha256_hmac(key, data).unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_sha256_hmac_rfc4231_test3() {
        // RFC 4231 Test Case 3
        // Key = 0xaa repeated 20 times
        // Data = 0xdd repeated 50 times
        let key = decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let data = decode(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
        let result = sha256_hmac(&key, &data).unwrap();
        assert_eq!(encode(result), expected);
    }

    #[test]
    fn test_sha256_hmac_rfc4231_test4() {
        // RFC 4231 Test Case 4
        // Key = 0x01 0x02 ... 0x19 (25 bytes)
        // Data = 0xcd repeated 50 times
        let key = decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
        let data = decode(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        )
        .unwrap();
        let expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
        let result = sha256_hmac(&key, &data).unwrap();
        assert_eq!(encode(result), expected);
    }
}
