use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, KeyGen,
    MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey, B32,
};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

fn slice_to_b32(b: &[u8], name: &str) -> Result<B32, String> {
    if b.len() != 32 {
        return Err(format!("{} must be exactly 32 bytes", name));
    }
    let mut out = B32::default();
    out.copy_from_slice(b);
    Ok(out)
}

macro_rules! mldsa_impl {
    (
        $kem:ty,
        $keypair_fn:ident,
        $sign_fn:ident,
        $verify_fn:ident,
        $sign_context_fn:ident,
        $verify_context_fn:ident,
        $sign_hedged_fn:ident
    ) => {
        /// Deterministically generate a keypair from a 32-byte seed.
        ///
        /// Returns `vk || sk` (concatenated public key + expanded secret key
        /// per FIPS 204).
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $keypair_fn(seed: &[u8]) -> Result<Vec<u8>, String> {
            let xi = slice_to_b32(seed, "seed")?;
            let kp = <$kem as KeyGen>::from_seed(&xi);
            let exp_sk = kp.signing_key();
            let vk = exp_sk.verifying_key();
            let vk_bytes = vk.encode();
            #[allow(deprecated)]
            let sk_bytes = exp_sk.to_expanded();
            let mut out = Vec::with_capacity(vk_bytes.len() + sk_bytes.len());
            out.extend_from_slice(&vk_bytes);
            out.extend_from_slice(&sk_bytes);
            Ok(out)
        }

        /// Sign a message using the FIPS 204 internal sign primitive.
        ///
        /// `sk_bytes` is the expanded FIPS 204 secret key encoding,
        /// `message` is the raw message bytes (no context, no domain
        /// separation), and `rnd` is the 32-byte randomness per FIPS 204
        /// §6.2 ML-DSA.Sign_internal.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $sign_fn(sk_bytes: &[u8], message: &[u8], rnd: &[u8]) -> Result<Vec<u8>, String> {
            let mut sk_arr: ExpandedSigningKeyBytes<$kem> = Default::default();
            if sk_bytes.len() != sk_arr.len() {
                return Err(format!("sk must be exactly {} bytes", sk_arr.len()));
            }
            sk_arr.copy_from_slice(sk_bytes);
            #[allow(deprecated)]
            let sk = ExpandedSigningKey::<$kem>::from_expanded(&sk_arr);
            let rnd_b32 = slice_to_b32(rnd, "rnd")?;
            let sig = sk.sign_internal(&[message], &rnd_b32);
            Ok(sig.encode().to_vec())
        }

        /// Verify a signature using the FIPS 204 internal verify primitive.
        ///
        /// Returns true if the signature is valid for the message and
        /// verifying key, false otherwise. Never errors — invalid keys or
        /// signatures simply produce false.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $verify_fn(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> bool {
            let mut vk_arr: EncodedVerifyingKey<$kem> = Default::default();
            if vk_bytes.len() != vk_arr.len() {
                return false;
            }
            vk_arr.copy_from_slice(vk_bytes);
            let vk = VerifyingKey::<$kem>::decode(&vk_arr);
            let mut sig_arr: EncodedSignature<$kem> = Default::default();
            if sig_bytes.len() != sig_arr.len() {
                return false;
            }
            sig_arr.copy_from_slice(sig_bytes);
            let sig = match Signature::<$kem>::decode(&sig_arr) {
                Some(s) => s,
                None => return false,
            };
            vk.verify_internal(message, &sig)
        }

        /// Sign a message using the FIPS 204 message-level ML-DSA.Sign
        /// deterministic variant with context separation.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $sign_context_fn(
            sk_bytes: &[u8],
            message: &[u8],
            context: &[u8],
        ) -> Result<Vec<u8>, String> {
            let mut sk_arr: ExpandedSigningKeyBytes<$kem> = Default::default();
            if sk_bytes.len() != sk_arr.len() {
                return Err(format!("sk must be exactly {} bytes", sk_arr.len()));
            }
            sk_arr.copy_from_slice(sk_bytes);
            #[allow(deprecated)]
            let sk = ExpandedSigningKey::<$kem>::from_expanded(&sk_arr);
            let sig = sk
                .sign_deterministic(message, context)
                .map_err(|_| "context must be at most 255 bytes".to_string())?;
            Ok(sig.encode().to_vec())
        }

        /// Verify a signature using the FIPS 204 message-level ML-DSA.Verify
        /// algorithm with context separation.
        ///
        /// Returns true if the signature is valid for the message, context,
        /// and verifying key. Invalid keys, signatures, or contexts return
        /// false.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $verify_context_fn(
            vk_bytes: &[u8],
            message: &[u8],
            sig_bytes: &[u8],
            context: &[u8],
        ) -> bool {
            let mut vk_arr: EncodedVerifyingKey<$kem> = Default::default();
            if vk_bytes.len() != vk_arr.len() {
                return false;
            }
            vk_arr.copy_from_slice(vk_bytes);
            let vk = VerifyingKey::<$kem>::decode(&vk_arr);
            let mut sig_arr: EncodedSignature<$kem> = Default::default();
            if sig_bytes.len() != sig_arr.len() {
                return false;
            }
            sig_arr.copy_from_slice(sig_bytes);
            let sig = match Signature::<$kem>::decode(&sig_arr) {
                Some(s) => s,
                None => return false,
            };
            vk.verify_with_context(message, context, &sig)
        }

        /// Sign a message using the FIPS 204 message-level ML-DSA.Sign hedged
        /// variant with caller-supplied randomness.
        ///
        /// `addrnd` is a 32-byte randomness value. The TypeScript wrapper
        /// generates this with `crypto.getRandomValues` via
        /// `FixedBuf.fromRandom(32)`. Equivalent to `sign_randomized` in the
        /// upstream `ml-dsa` crate, but reachable without the `rand_core`
        /// feature: we manually construct `M' = 0x00 || ctx_len || ctx || M`
        /// per FIPS 204 §5.4 and call the public `sign_internal(Mp, rnd)`.
        /// Both paths converge on the same `raw_sign_mu` call.
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $sign_hedged_fn(
            sk_bytes: &[u8],
            message: &[u8],
            context: &[u8],
            addrnd: &[u8],
        ) -> Result<Vec<u8>, String> {
            let mut sk_arr: ExpandedSigningKeyBytes<$kem> = Default::default();
            if sk_bytes.len() != sk_arr.len() {
                return Err(format!("sk must be exactly {} bytes", sk_arr.len()));
            }
            if context.len() > 255 {
                return Err("context must be at most 255 bytes".to_string());
            }
            sk_arr.copy_from_slice(sk_bytes);
            #[allow(deprecated)]
            let sk = ExpandedSigningKey::<$kem>::from_expanded(&sk_arr);
            let rnd_b32 = slice_to_b32(addrnd, "addrnd")?;
            let ctx_len_byte = [context.len() as u8];
            let mp: [&[u8]; 4] = [&[0u8], &ctx_len_byte, context, message];
            let sig = sk.sign_internal(&mp, &rnd_b32);
            Ok(sig.encode().to_vec())
        }
    };
}

mldsa_impl!(
    MlDsa44,
    ml_dsa_44_keypair,
    ml_dsa_44_sign_internal,
    ml_dsa_44_verify_internal,
    ml_dsa_44_sign,
    ml_dsa_44_verify,
    ml_dsa_44_sign_hedged
);
mldsa_impl!(
    MlDsa65,
    ml_dsa_65_keypair,
    ml_dsa_65_sign_internal,
    ml_dsa_65_verify_internal,
    ml_dsa_65_sign,
    ml_dsa_65_verify,
    ml_dsa_65_sign_hedged
);
mldsa_impl!(
    MlDsa87,
    ml_dsa_87_keypair,
    ml_dsa_87_sign_internal,
    ml_dsa_87_verify_internal,
    ml_dsa_87_sign,
    ml_dsa_87_verify,
    ml_dsa_87_sign_hedged
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_44_round_trip() {
        let seed = [0u8; 32];
        let rnd = [1u8; 32];
        let msg = b"hello, post-quantum world";

        let keypair = ml_dsa_44_keypair(&seed).unwrap();
        let vk_size = 1312;
        let sk_size = 2560;
        assert_eq!(keypair.len(), vk_size + sk_size);

        let vk = &keypair[..vk_size];
        let sk = &keypair[vk_size..];

        let sig = ml_dsa_44_sign_internal(sk, msg, &rnd).unwrap();
        assert_eq!(sig.len(), 2420);

        assert!(ml_dsa_44_verify_internal(vk, msg, &sig));
        assert!(!ml_dsa_44_verify_internal(vk, b"different message", &sig));
    }

    #[test]
    fn test_ml_dsa_65_round_trip() {
        let seed = [2u8; 32];
        let rnd = [3u8; 32];
        let msg = b"medium security signature";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let vk_size = 1952;
        let sk_size = 4032;
        assert_eq!(keypair.len(), vk_size + sk_size);

        let vk = &keypair[..vk_size];
        let sk = &keypair[vk_size..];

        let sig = ml_dsa_65_sign_internal(sk, msg, &rnd).unwrap();
        assert_eq!(sig.len(), 3309);

        assert!(ml_dsa_65_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_ml_dsa_87_round_trip() {
        let seed = [4u8; 32];
        let rnd = [5u8; 32];
        let msg = b"high security signature";

        let keypair = ml_dsa_87_keypair(&seed).unwrap();
        let vk_size = 2592;
        let sk_size = 4896;
        assert_eq!(keypair.len(), vk_size + sk_size);

        let vk = &keypair[..vk_size];
        let sk = &keypair[vk_size..];

        let sig = ml_dsa_87_sign_internal(sk, msg, &rnd).unwrap();
        assert_eq!(sig.len(), 4627);

        assert!(ml_dsa_87_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_deterministic_signing() {
        let seed = [0u8; 32];
        let rnd = [0u8; 32];
        let msg = b"deterministic";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let sk = &keypair[1952..];

        let sig1 = ml_dsa_65_sign_internal(sk, msg, &rnd).unwrap();
        let sig2 = ml_dsa_65_sign_internal(sk, msg, &rnd).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let seed = [0u8; 32];
        let rnd = [1u8; 32];
        let msg = b"test";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let vk = &keypair[..1952];
        let sk = &keypair[1952..];

        let mut sig = ml_dsa_65_sign_internal(sk, msg, &rnd).unwrap();
        sig[0] ^= 0xff;
        assert!(!ml_dsa_65_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_bad_inputs() {
        let short = [0u8; 16];
        let rnd = [0u8; 32];
        assert!(ml_dsa_65_keypair(&short).unwrap_err().contains("32 bytes"));
        assert!(ml_dsa_65_sign_internal(&[0u8; 100], b"x", &rnd)
            .unwrap_err()
            .contains("sk"));
        assert!(!ml_dsa_65_verify_internal(&[0u8; 100], b"x", &[0u8; 3309]));
    }

    #[test]
    fn test_message_level_context_signing() {
        let seed = [9u8; 32];
        let msg = b"context-aware message";
        let ctx = b"webbuf";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let vk = &keypair[..1952];
        let sk = &keypair[1952..];

        let sig = ml_dsa_65_sign(sk, msg, ctx).unwrap();
        assert!(ml_dsa_65_verify(vk, msg, &sig, ctx));
        assert!(!ml_dsa_65_verify(vk, msg, &sig, b"wrong"));
        assert!(!ml_dsa_65_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_message_level_long_context_rejected() {
        let seed = [10u8; 32];
        let msg = b"context too long";
        let long_ctx = [0u8; 256];

        let keypair = ml_dsa_44_keypair(&seed).unwrap();
        let vk = &keypair[..1312];
        let sk = &keypair[1312..];

        assert!(ml_dsa_44_sign(sk, msg, &long_ctx).is_err());
        assert!(!ml_dsa_44_verify(vk, msg, &[0u8; 2420], &long_ctx));
    }

    #[test]
    fn test_ml_dsa_44_hedged_round_trip() {
        let seed = [11u8; 32];
        let addrnd = [12u8; 32];
        let msg = b"hedged 44";
        let ctx = b"webbuf";

        let keypair = ml_dsa_44_keypair(&seed).unwrap();
        let vk = &keypair[..1312];
        let sk = &keypair[1312..];

        let sig = ml_dsa_44_sign_hedged(sk, msg, ctx, &addrnd).unwrap();
        assert_eq!(sig.len(), 2420);
        assert!(ml_dsa_44_verify(vk, msg, &sig, ctx));
        assert!(!ml_dsa_44_verify(vk, msg, &sig, b"wrong"));
        assert!(!ml_dsa_44_verify_internal(vk, msg, &sig));
    }

    #[test]
    fn test_ml_dsa_65_hedged_round_trip() {
        let seed = [13u8; 32];
        let addrnd = [14u8; 32];
        let msg = b"hedged 65";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let vk = &keypair[..1952];
        let sk = &keypair[1952..];

        let sig = ml_dsa_65_sign_hedged(sk, msg, b"", &addrnd).unwrap();
        assert_eq!(sig.len(), 3309);
        assert!(ml_dsa_65_verify(vk, msg, &sig, b""));
    }

    #[test]
    fn test_ml_dsa_87_hedged_round_trip() {
        let seed = [15u8; 32];
        let addrnd = [16u8; 32];
        let msg = b"hedged 87";

        let keypair = ml_dsa_87_keypair(&seed).unwrap();
        let vk = &keypair[..2592];
        let sk = &keypair[2592..];

        let sig = ml_dsa_87_sign_hedged(sk, msg, b"", &addrnd).unwrap();
        assert_eq!(sig.len(), 4627);
        assert!(ml_dsa_87_verify(vk, msg, &sig, b""));
    }

    #[test]
    fn test_hedged_differs_from_deterministic() {
        let seed = [17u8; 32];
        let addrnd = [18u8; 32];
        let msg = b"hedged vs deterministic";
        let ctx = b"compare";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let sk = &keypair[1952..];

        let det_sig = ml_dsa_65_sign(sk, msg, ctx).unwrap();
        let hedged_sig = ml_dsa_65_sign_hedged(sk, msg, ctx, &addrnd).unwrap();
        assert_ne!(det_sig, hedged_sig);
    }

    /// Load-bearing regression test: confirms our manually constructed
    /// `M' = 0x00 || ctx_len || ctx || M` matches what `sign_deterministic`
    /// builds via `MuBuilder::new(tr, ctx).message(M)`. If this test ever
    /// fails after an `ml-dsa` upgrade, the byte-equivalence reasoning in
    /// issue 0003 has broken and the wrapper needs to be revisited.
    #[test]
    fn test_hedged_with_zero_rnd_matches_deterministic() {
        let seed = [19u8; 32];
        let zero_rnd = [0u8; 32];
        let msg = b"zero-rnd equivalence";
        let ctx = b"context";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let sk = &keypair[1952..];

        let det_sig = ml_dsa_65_sign(sk, msg, ctx).unwrap();
        let hedged_zero_sig = ml_dsa_65_sign_hedged(sk, msg, ctx, &zero_rnd).unwrap();
        assert_eq!(det_sig, hedged_zero_sig);
    }

    #[test]
    fn test_hedged_with_empty_context_matches_zero_rnd_no_ctx() {
        let seed = [20u8; 32];
        let zero_rnd = [0u8; 32];
        let msg = b"empty ctx";

        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let sk = &keypair[1952..];

        let det_sig = ml_dsa_65_sign(sk, msg, b"").unwrap();
        let hedged_zero_sig = ml_dsa_65_sign_hedged(sk, msg, b"", &zero_rnd).unwrap();
        assert_eq!(det_sig, hedged_zero_sig);
    }

    #[test]
    fn test_hedged_bad_inputs() {
        let seed = [21u8; 32];
        let keypair = ml_dsa_65_keypair(&seed).unwrap();
        let sk = &keypair[1952..];

        // wrong addrnd length
        let short_rnd = [0u8; 16];
        assert!(ml_dsa_65_sign_hedged(sk, b"msg", b"", &short_rnd)
            .unwrap_err()
            .contains("addrnd"));

        // context too long
        let long_ctx = [0u8; 256];
        let rnd = [0u8; 32];
        assert!(ml_dsa_65_sign_hedged(sk, b"msg", &long_ctx, &rnd)
            .unwrap_err()
            .contains("255"));

        // malformed sk
        assert!(ml_dsa_65_sign_hedged(&[0u8; 100], b"msg", b"", &rnd)
            .unwrap_err()
            .contains("sk"));
    }
}
