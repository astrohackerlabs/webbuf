use blake3::Hasher;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn blake3_hash(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    Ok(hasher.finalize().as_bytes().to_vec())
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn double_blake3_hash(data: &[u8]) -> Result<Vec<u8>, String> {
    let first_hash = blake3_hash(data)?;
    blake3_hash(&first_hash)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn blake3_mac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    // Ensure the key is exactly 32 bytes
    let key32: [u8; 32] = key
        .try_into()
        .map_err(|_| "Key must be exactly 32 bytes".to_string())?;

    let mut hasher = Hasher::new_keyed(&key32);
    hasher.update(data);
    Ok(hasher.finalize().as_bytes().to_vec())
}

/// Incremental BLAKE3 hasher that maintains state across multiple `update` calls.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct Blake3Hasher {
    inner: Hasher,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl Blake3Hasher {
    /// Create a new incremental BLAKE3 hasher.
    #[cfg_attr(feature = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self {
            inner: Hasher::new(),
        }
    }

    /// Create a new incremental BLAKE3 keyed hasher (for MAC).
    /// Key must be exactly 32 bytes.
    pub fn new_keyed(key: &[u8]) -> Result<Blake3Hasher, String> {
        let key32: [u8; 32] = key
            .try_into()
            .map_err(|_| "Key must be exactly 32 bytes".to_string())?;
        Ok(Self {
            inner: Hasher::new_keyed(&key32),
        })
    }

    /// Feed data into the hasher. Can be called multiple times.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize the hash and return the 32-byte digest.
    /// This does NOT consume the hasher — you can continue calling `update` and
    /// `finalize` again to get an extended hash of the data fed so far.
    pub fn finalize(&self) -> Vec<u8> {
        self.inner.finalize().as_bytes().to_vec()
    }

    /// Reset the hasher to its initial state, allowing reuse.
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::{decode, encode};

    #[test]
    fn test_hash() {
        let pub_key_hex = "03d03a42c710b7cf9085bd3115338f72b86f2d77859b6afe6d33b13ea8957a9722";
        let expected_pkh_hex = "38a12c6cf034632042b3b9deb2aabfdc798fac879d2f833638d59cf58549bc2d";

        let pub_key = decode(pub_key_hex).expect("Decoding failed");
        let expected_pkh = decode(expected_pkh_hex).expect("Decoding failed");

        let pkh = blake3_hash(&pub_key).unwrap();
        let pkh_hex = encode(pkh);
        let expected_pkh_hex = encode(expected_pkh);

        assert_eq!(pkh_hex, expected_pkh_hex);
    }

    #[test]
    fn test_double_hash() {
        let pub_key_hex = "0341ee98513da8509fea0c89b81aca409e56f5aaa3076fb78233850ad0e54e2628";
        let expected_pkh_hex = "51544e51d07a92f41854bd2a14d0f33dcbc936b8910eb9c699b656cd89308132";

        let pub_key = decode(pub_key_hex).expect("Decoding failed");
        let expected_pkh = decode(expected_pkh_hex).expect("Decoding failed");

        let pkh = double_blake3_hash(&pub_key).unwrap();
        let pkh_hex = encode(pkh);
        let expected_pkh_hex = encode(expected_pkh);

        assert_eq!(pkh_hex, expected_pkh_hex);
    }

    #[test]
    fn test_blake3_mac() {
        let key_str = "key";
        let key_data = key_str.as_bytes();
        let key = blake3_hash(key_data).unwrap();

        let data_str = "data";
        let data = data_str.as_bytes();
        let mac = blake3_mac(&key, data).unwrap();
        let expected_mac_hex = "438f903a8fc5997489497c30477dc32c5ece10f44049e302b85a83603960ec27";

        assert_eq!(encode(mac), expected_mac_hex);
    }

    #[test]
    fn test_incremental_hasher_matches_one_shot() {
        let data = b"hello world this is a test of incremental hashing";
        let one_shot = blake3_hash(data).unwrap();

        let mut hasher = Blake3Hasher::new();
        hasher.update(b"hello world ");
        hasher.update(b"this is a test ");
        hasher.update(b"of incremental hashing");
        let incremental = hasher.finalize();

        assert_eq!(one_shot, incremental);
    }

    #[test]
    fn test_incremental_hasher_reset() {
        let data = b"hello";
        let one_shot = blake3_hash(data).unwrap();

        let mut hasher = Blake3Hasher::new();
        hasher.update(b"some garbage data");
        hasher.reset();
        hasher.update(b"hello");
        let result = hasher.finalize();

        assert_eq!(one_shot, result);
    }

    #[test]
    fn test_incremental_keyed_hasher() {
        let key_data = blake3_hash(b"key").unwrap();
        let mac_one_shot = blake3_mac(&key_data, b"data").unwrap();

        let mut hasher = Blake3Hasher::new_keyed(&key_data).unwrap();
        hasher.update(b"da");
        hasher.update(b"ta");
        let mac_incremental = hasher.finalize();

        assert_eq!(mac_one_shot, mac_incremental);
    }
}
