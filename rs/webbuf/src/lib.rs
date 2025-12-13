use base64::{engine::general_purpose as lib_base64, Engine};
use hex::{decode as lib_hex_decode, encode as lib_hex_encode};
use base32::{Alphabet as Base32Alphabet, decode as lib_base32_decode, encode as lib_base32_encode};
use wasm_bindgen::prelude::*;

/// Remove whitespace (spaces, tabs, newlines) from the input string
fn strip_whitespace(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Encode a byte slice into a base64 string using the default engine
#[wasm_bindgen]
pub fn encode_base64(data: &[u8]) -> String {
    lib_base64::STANDARD.encode(data)
}

/// Decode a base64 string into a byte vector
/// Returns an error string if decoding fails
#[wasm_bindgen]
pub fn decode_base64_strip_whitespace(encoded: &str) -> Result<Vec<u8>, String> {
   let stripped_encoded = strip_whitespace(encoded);
    lib_base64::STANDARD
        .decode(&stripped_encoded)
        .map_err(|_| "invalid base64".to_string())
}

#[wasm_bindgen]
pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, String> {
    lib_base64::STANDARD
        .decode(encoded)
        .map_err(|_| "invalid base64".to_string())
}

/// Encode a byte slice into a hex string
#[wasm_bindgen]
pub fn encode_hex(data: &[u8]) -> String {
    lib_hex_encode(data)
}

/// Decode a hex string into a byte vector
/// Returns an error string if decoding fails
#[wasm_bindgen]
pub fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    lib_hex_decode(encoded).map_err(|_| "invalid hex".to_string())
}

// Base32 encoding/decoding functions

/// Encode a byte slice into a Crockford base32 string
#[wasm_bindgen]
pub fn encode_base32_crockford(data: &[u8]) -> String {
    lib_base32_encode(Base32Alphabet::Crockford, data)
}

/// Decode a Crockford base32 string into a byte vector
#[wasm_bindgen]
pub fn decode_base32_crockford(encoded: &str) -> Result<Vec<u8>, String> {
    lib_base32_decode(Base32Alphabet::Crockford, encoded)
        .ok_or_else(|| "invalid base32 crockford".to_string())
}

/// Encode a byte slice into an RFC4648 base32 string
#[wasm_bindgen]
pub fn encode_base32_rfc4648(data: &[u8], padding: bool) -> String {
    lib_base32_encode(Base32Alphabet::Rfc4648 { padding }, data)
}

/// Decode an RFC4648 base32 string into a byte vector
#[wasm_bindgen]
pub fn decode_base32_rfc4648(encoded: &str, padding: bool) -> Result<Vec<u8>, String> {
    lib_base32_decode(Base32Alphabet::Rfc4648 { padding }, encoded)
        .ok_or_else(|| "invalid base32 rfc4648".to_string())
}

/// Encode a byte slice into an RFC4648 lowercase base32 string
#[wasm_bindgen]
pub fn encode_base32_rfc4648_lower(data: &[u8], padding: bool) -> String {
    lib_base32_encode(Base32Alphabet::Rfc4648Lower { padding }, data)
}

/// Decode an RFC4648 lowercase base32 string into a byte vector
#[wasm_bindgen]
pub fn decode_base32_rfc4648_lower(encoded: &str, padding: bool) -> Result<Vec<u8>, String> {
    lib_base32_decode(Base32Alphabet::Rfc4648Lower { padding }, encoded)
        .ok_or_else(|| "invalid base32 rfc4648 lower".to_string())
}

/// Encode a byte slice into an RFC4648 hex base32 string
#[wasm_bindgen]
pub fn encode_base32_rfc4648_hex(data: &[u8], padding: bool) -> String {
    lib_base32_encode(Base32Alphabet::Rfc4648Hex { padding }, data)
}

/// Decode an RFC4648 hex base32 string into a byte vector
#[wasm_bindgen]
pub fn decode_base32_rfc4648_hex(encoded: &str, padding: bool) -> Result<Vec<u8>, String> {
    lib_base32_decode(Base32Alphabet::Rfc4648Hex { padding }, encoded)
        .ok_or_else(|| "invalid base32 rfc4648 hex".to_string())
}

/// Encode a byte slice into an RFC4648 hex lowercase base32 string
#[wasm_bindgen]
pub fn encode_base32_rfc4648_hex_lower(data: &[u8], padding: bool) -> String {
    lib_base32_encode(Base32Alphabet::Rfc4648HexLower { padding }, data)
}

/// Decode an RFC4648 hex lowercase base32 string into a byte vector
#[wasm_bindgen]
pub fn decode_base32_rfc4648_hex_lower(encoded: &str, padding: bool) -> Result<Vec<u8>, String> {
    lib_base32_decode(Base32Alphabet::Rfc4648HexLower { padding }, encoded)
        .ok_or_else(|| "invalid base32 rfc4648 hex lower".to_string())
}

/// Encode a byte slice into a z-base-32 string
#[wasm_bindgen]
pub fn encode_base32_z(data: &[u8]) -> String {
    lib_base32_encode(Base32Alphabet::Z, data)
}

/// Decode a z-base-32 string into a byte vector
#[wasm_bindgen]
pub fn decode_base32_z(encoded: &str) -> Result<Vec<u8>, String> {
    lib_base32_decode(Base32Alphabet::Z, encoded)
        .ok_or_else(|| "invalid base32 z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_base64() {
        let input = b"Hello, world!";
        let expected_output = "SGVsbG8sIHdvcmxkIQ==";
        let result = encode_base64(input);
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_decode_base64_valid() {
        let input = "SGVsbG8sIHdvcmxkIQ==";
        let expected_output = b"Hello, world!";
        let result = decode_base64(input).unwrap();
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_decode_base64_invalid() {
        let input = "invalid_base64";
        let result = decode_base64(input);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "invalid base64");
    }

    #[test]
    fn test_encode_hex() {
        let input = b"Hello, world!";
        let expected_output = "48656c6c6f2c20776f726c6421";
        let result = encode_hex(input);
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_decode_hex_valid() {
        let input = "48656c6c6f2c20776f726c6421";
        let expected_output = b"Hello, world!";
        let result = decode_hex(input).unwrap();
        assert_eq!(result, expected_output);
    }

    #[test]
    fn test_decode_hex_invalid() {
        let input = "zzzz";
        let result = decode_hex(input);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "invalid hex");
    }

    // Base32 tests

    #[test]
    fn test_encode_base32_crockford() {
        let input = b"Hello, world!";
        let result = encode_base32_crockford(input);
        assert_eq!(result, "91JPRV3F5GG7EVVJDHJ22");
    }

    #[test]
    fn test_decode_base32_crockford() {
        let input = "91JPRV3F5GG7EVVJDHJ22";
        let result = decode_base32_crockford(input).unwrap();
        assert_eq!(result, b"Hello, world!");
    }

    #[test]
    fn test_decode_base32_crockford_case_insensitive() {
        // Crockford is case insensitive
        let result = decode_base32_crockford("91jprv3f5gg7evvjdhj22").unwrap();
        assert_eq!(result, b"Hello, world!");
    }

    #[test]
    fn test_decode_base32_crockford_ilo_normalization() {
        // I, L -> 1 and O -> 0
        let result1 = decode_base32_crockford("IiLlOo").unwrap();
        let result2 = decode_base32_crockford("111100").unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_encode_base32_rfc4648_with_padding() {
        let input = b"Hello, world!";
        let result = encode_base32_rfc4648(input, true);
        assert_eq!(result, "JBSWY3DPFQQHO33SNRSCC===");
    }

    #[test]
    fn test_encode_base32_rfc4648_without_padding() {
        let input = b"Hello, world!";
        let result = encode_base32_rfc4648(input, false);
        assert_eq!(result, "JBSWY3DPFQQHO33SNRSCC");
    }

    #[test]
    fn test_decode_base32_rfc4648_with_padding() {
        let input = "JBSWY3DPFQQHO33SNRSCC===";
        let result = decode_base32_rfc4648(input, true).unwrap();
        assert_eq!(result, b"Hello, world!");
    }

    #[test]
    fn test_decode_base32_rfc4648_without_padding() {
        let input = "JBSWY3DPFQQHO33SNRSCC";
        let result = decode_base32_rfc4648(input, false).unwrap();
        assert_eq!(result, b"Hello, world!");
    }

    #[test]
    fn test_encode_base32_z() {
        let input = b"Hello, world!";
        let result = encode_base32_z(input);
        // z-base-32 uses a different alphabet
        assert!(!result.is_empty());
    }

    #[test]
    fn test_base32_roundtrip_all_alphabets() {
        let input = b"Test data for roundtrip";

        // Crockford roundtrip
        let encoded = encode_base32_crockford(input);
        let decoded = decode_base32_crockford(&encoded).unwrap();
        assert_eq!(decoded, input);

        // RFC4648 roundtrip with padding
        let encoded = encode_base32_rfc4648(input, true);
        let decoded = decode_base32_rfc4648(&encoded, true).unwrap();
        assert_eq!(decoded, input);

        // RFC4648 roundtrip without padding
        let encoded = encode_base32_rfc4648(input, false);
        let decoded = decode_base32_rfc4648(&encoded, false).unwrap();
        assert_eq!(decoded, input);

        // RFC4648 Lower roundtrip
        let encoded = encode_base32_rfc4648_lower(input, true);
        let decoded = decode_base32_rfc4648_lower(&encoded, true).unwrap();
        assert_eq!(decoded, input);

        // RFC4648 Hex roundtrip
        let encoded = encode_base32_rfc4648_hex(input, true);
        let decoded = decode_base32_rfc4648_hex(&encoded, true).unwrap();
        assert_eq!(decoded, input);

        // RFC4648 Hex Lower roundtrip
        let encoded = encode_base32_rfc4648_hex_lower(input, true);
        let decoded = decode_base32_rfc4648_hex_lower(&encoded, true).unwrap();
        assert_eq!(decoded, input);

        // Z roundtrip
        let encoded = encode_base32_z(input);
        let decoded = decode_base32_z(&encoded).unwrap();
        assert_eq!(decoded, input);
    }
}
