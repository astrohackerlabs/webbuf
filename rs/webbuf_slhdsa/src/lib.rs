use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, Signature, SigningKey, VerifyingKey,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

macro_rules! slhdsa_impl {
    ($param:ty, $n:expr, $vk_size:expr, $sk_size:expr, $sig_size:expr,
     $keypair_fn:ident, $sign_fn:ident, $verify_fn:ident) => {
        /// Deterministically generate a keypair from three n-byte seeds.
        ///
        /// Per FIPS 205 SLH-Keygen-internal, takes (sk_seed, sk_prf, pk_seed).
        /// Returns `pk || sk` concatenated.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $keypair_fn(
            sk_seed: &[u8],
            sk_prf: &[u8],
            pk_seed: &[u8],
        ) -> Result<Vec<u8>, String> {
            if sk_seed.len() != $n {
                return Err(format!("sk_seed must be exactly {} bytes", $n));
            }
            if sk_prf.len() != $n {
                return Err(format!("sk_prf must be exactly {} bytes", $n));
            }
            if pk_seed.len() != $n {
                return Err(format!("pk_seed must be exactly {} bytes", $n));
            }
            let sk = SigningKey::<$param>::slh_keygen_internal(sk_seed, sk_prf, pk_seed);
            let vk: &VerifyingKey<$param> = sk.as_ref();
            let vk_bytes = vk.to_bytes();
            let sk_bytes = sk.to_bytes();
            let mut out = Vec::with_capacity(vk_bytes.len() + sk_bytes.len());
            out.extend_from_slice(&vk_bytes);
            out.extend_from_slice(&sk_bytes);
            Ok(out)
        }

        /// Sign a message using the FIPS 205 internal sign primitive.
        ///
        /// `sk_bytes` is the FIPS 205 secret key encoding. `message` is the
        /// raw message bytes. `opt_rand` is either empty (deterministic
        /// variant: uses pk_seed as the randomizer) or exactly n bytes (hedged
        /// variant: caller-provided randomizer).
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $sign_fn(
            sk_bytes: &[u8],
            message: &[u8],
            opt_rand: &[u8],
        ) -> Result<Vec<u8>, String> {
            if sk_bytes.len() != $sk_size {
                return Err(format!("sk must be exactly {} bytes", $sk_size));
            }
            if !opt_rand.is_empty() && opt_rand.len() != $n {
                return Err(format!(
                    "opt_rand must be empty or exactly {} bytes",
                    $n
                ));
            }
            let sk = SigningKey::<$param>::try_from(sk_bytes)
                .map_err(|_| "invalid sk".to_string())?;
            let opt_rand_arg = if opt_rand.is_empty() {
                None
            } else {
                Some(opt_rand)
            };
            let sig = sk.slh_sign_internal(&[message], opt_rand_arg);
            Ok(sig.to_bytes().to_vec())
        }

        /// Verify a signature using the FIPS 205 internal verify primitive.
        ///
        /// Returns true if the signature is valid for the message and
        /// verifying key, false otherwise.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $verify_fn(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> bool {
            if vk_bytes.len() != $vk_size {
                return false;
            }
            if sig_bytes.len() != $sig_size {
                return false;
            }
            let vk = match VerifyingKey::<$param>::try_from(vk_bytes) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let sig = match Signature::<$param>::try_from(sig_bytes) {
                Ok(s) => s,
                Err(_) => return false,
            };
            vk.slh_verify_internal(&[message], &sig).is_ok()
        }
    };
}

// SHA2 family
slhdsa_impl!(Sha2_128s, 16, 32, 64, 7856,
    slh_dsa_sha2_128s_keypair, slh_dsa_sha2_128s_sign_internal, slh_dsa_sha2_128s_verify_internal);
slhdsa_impl!(Sha2_128f, 16, 32, 64, 17088,
    slh_dsa_sha2_128f_keypair, slh_dsa_sha2_128f_sign_internal, slh_dsa_sha2_128f_verify_internal);
slhdsa_impl!(Sha2_192s, 24, 48, 96, 16224,
    slh_dsa_sha2_192s_keypair, slh_dsa_sha2_192s_sign_internal, slh_dsa_sha2_192s_verify_internal);
slhdsa_impl!(Sha2_192f, 24, 48, 96, 35664,
    slh_dsa_sha2_192f_keypair, slh_dsa_sha2_192f_sign_internal, slh_dsa_sha2_192f_verify_internal);
slhdsa_impl!(Sha2_256s, 32, 64, 128, 29792,
    slh_dsa_sha2_256s_keypair, slh_dsa_sha2_256s_sign_internal, slh_dsa_sha2_256s_verify_internal);
slhdsa_impl!(Sha2_256f, 32, 64, 128, 49856,
    slh_dsa_sha2_256f_keypair, slh_dsa_sha2_256f_sign_internal, slh_dsa_sha2_256f_verify_internal);

// SHAKE family
slhdsa_impl!(Shake128s, 16, 32, 64, 7856,
    slh_dsa_shake_128s_keypair, slh_dsa_shake_128s_sign_internal, slh_dsa_shake_128s_verify_internal);
slhdsa_impl!(Shake128f, 16, 32, 64, 17088,
    slh_dsa_shake_128f_keypair, slh_dsa_shake_128f_sign_internal, slh_dsa_shake_128f_verify_internal);
slhdsa_impl!(Shake192s, 24, 48, 96, 16224,
    slh_dsa_shake_192s_keypair, slh_dsa_shake_192s_sign_internal, slh_dsa_shake_192s_verify_internal);
slhdsa_impl!(Shake192f, 24, 48, 96, 35664,
    slh_dsa_shake_192f_keypair, slh_dsa_shake_192f_sign_internal, slh_dsa_shake_192f_verify_internal);
slhdsa_impl!(Shake256s, 32, 64, 128, 29792,
    slh_dsa_shake_256s_keypair, slh_dsa_shake_256s_sign_internal, slh_dsa_shake_256s_verify_internal);
slhdsa_impl!(Shake256f, 32, 64, 128, 49856,
    slh_dsa_shake_256f_keypair, slh_dsa_shake_256f_sign_internal, slh_dsa_shake_256f_verify_internal);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha2_128f_round_trip() {
        let sk_seed = [0u8; 16];
        let sk_prf = [1u8; 16];
        let pk_seed = [2u8; 16];
        let msg = b"hello, hash-based world";

        let keypair = slh_dsa_sha2_128f_keypair(&sk_seed, &sk_prf, &pk_seed).unwrap();
        assert_eq!(keypair.len(), 32 + 64);

        let vk = &keypair[..32];
        let sk = &keypair[32..];

        let sig = slh_dsa_sha2_128f_sign_internal(sk, msg, &[]).unwrap();
        assert_eq!(sig.len(), 17088);

        assert!(slh_dsa_sha2_128f_verify_internal(vk, msg, &sig));
        assert!(!slh_dsa_sha2_128f_verify_internal(vk, b"different", &sig));
    }

    #[test]
    fn test_shake_192s_round_trip() {
        let sk_seed = [3u8; 24];
        let sk_prf = [4u8; 24];
        let pk_seed = [5u8; 24];
        let rnd = [6u8; 24];
        let msg = b"shake 192s";

        let keypair = slh_dsa_shake_192s_keypair(&sk_seed, &sk_prf, &pk_seed).unwrap();
        assert_eq!(keypair.len(), 48 + 96);

        let vk = &keypair[..48];
        let sk = &keypair[48..];

        let sig = slh_dsa_shake_192s_sign_internal(sk, msg, &rnd).unwrap();
        assert_eq!(sig.len(), 16224);

        assert!(slh_dsa_shake_192s_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_sha2_256f_round_trip() {
        let sk_seed = [7u8; 32];
        let sk_prf = [8u8; 32];
        let pk_seed = [9u8; 32];
        let msg = b"high security";

        let keypair = slh_dsa_sha2_256f_keypair(&sk_seed, &sk_prf, &pk_seed).unwrap();
        assert_eq!(keypair.len(), 64 + 128);

        let vk = &keypair[..64];
        let sk = &keypair[64..];

        let sig = slh_dsa_sha2_256f_sign_internal(sk, msg, &[]).unwrap();
        assert_eq!(sig.len(), 49856);

        assert!(slh_dsa_sha2_256f_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_deterministic_signing() {
        let sk_seed = [0u8; 16];
        let sk_prf = [0u8; 16];
        let pk_seed = [0u8; 16];
        let msg = b"deterministic";

        let keypair = slh_dsa_sha2_128f_keypair(&sk_seed, &sk_prf, &pk_seed).unwrap();
        let sk = &keypair[32..];

        let sig1 = slh_dsa_sha2_128f_sign_internal(sk, msg, &[]).unwrap();
        let sig2 = slh_dsa_sha2_128f_sign_internal(sk, msg, &[]).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let sk_seed = [1u8; 16];
        let sk_prf = [2u8; 16];
        let pk_seed = [3u8; 16];
        let msg = b"test";

        let keypair = slh_dsa_sha2_128f_keypair(&sk_seed, &sk_prf, &pk_seed).unwrap();
        let vk = &keypair[..32];
        let sk = &keypair[32..];

        let mut sig = slh_dsa_sha2_128f_sign_internal(sk, msg, &[]).unwrap();
        sig[0] ^= 0xff;
        assert!(!slh_dsa_sha2_128f_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_bad_inputs() {
        let short = [0u8; 8];
        let ok = [0u8; 16];
        assert!(slh_dsa_sha2_128f_keypair(&short, &ok, &ok)
            .unwrap_err()
            .contains("sk_seed"));
        assert!(slh_dsa_sha2_128f_sign_internal(&[0u8; 100], b"x", &[])
            .unwrap_err()
            .contains("sk"));
        assert!(!slh_dsa_sha2_128f_verify_internal(&[0u8; 100], b"x", &[0u8; 17088]));
    }
}
