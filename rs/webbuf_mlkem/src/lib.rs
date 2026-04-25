use ml_kem::{
    kem::Decapsulate, Encoded, EncodedSizeUser, EncapsulateDeterministic, KemCore, MlKem1024,
    MlKem512, MlKem768, B32,
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

fn slice_to_encoded<T: EncodedSizeUser>(b: &[u8], name: &str) -> Result<Encoded<T>, String> {
    let mut out: Encoded<T> = Encoded::<T>::default();
    if b.len() != out.len() {
        return Err(format!("{} must be exactly {} bytes", name, out.len()));
    }
    out.copy_from_slice(b);
    Ok(out)
}

macro_rules! mlkem_impl {
    ($mod_name:ident, $kem:ty, $keypair_fn:ident, $encap_fn:ident, $decap_fn:ident) => {
        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $keypair_fn(d: &[u8], z: &[u8]) -> Result<Vec<u8>, String> {
            let d_b32 = slice_to_b32(d, "d")?;
            let z_b32 = slice_to_b32(z, "z")?;
            let (dk, ek) = <$kem as KemCore>::generate_deterministic(&d_b32, &z_b32);
            let ek_bytes = ek.as_bytes();
            let dk_bytes = dk.as_bytes();
            let mut out = Vec::with_capacity(ek_bytes.len() + dk_bytes.len());
            out.extend_from_slice(&ek_bytes);
            out.extend_from_slice(&dk_bytes);
            Ok(out)
        }

        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $encap_fn(ek_bytes: &[u8], m: &[u8]) -> Result<Vec<u8>, String> {
            let ek_encoded =
                slice_to_encoded::<<$kem as KemCore>::EncapsulationKey>(ek_bytes, "ek")?;
            let ek = <$kem as KemCore>::EncapsulationKey::from_bytes(&ek_encoded);
            let m_b32 = slice_to_b32(m, "m")?;
            let (ct, ss): (ml_kem::Ciphertext<$kem>, ml_kem::SharedKey<$kem>) = ek
                .encapsulate_deterministic(&m_b32)
                .map_err(|e| format!("encapsulate failed: {:?}", e))?;
            let mut out = Vec::with_capacity(ct.len() + ss.len());
            out.extend_from_slice(&ct);
            out.extend_from_slice(&ss);
            Ok(out)
        }

        #[cfg_attr(feature = "wasm", wasm_bindgen)]
        pub fn $decap_fn(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, String> {
            let dk_encoded =
                slice_to_encoded::<<$kem as KemCore>::DecapsulationKey>(dk_bytes, "dk")?;
            let dk = <$kem as KemCore>::DecapsulationKey::from_bytes(&dk_encoded);
            let mut ct_arr: ml_kem::Ciphertext<$kem> = Default::default();
            if ct_bytes.len() != ct_arr.len() {
                return Err(format!("ct must be exactly {} bytes", ct_arr.len()));
            }
            ct_arr.copy_from_slice(ct_bytes);
            let ss = dk
                .decapsulate(&ct_arr)
                .map_err(|e| format!("decapsulate failed: {:?}", e))?;
            Ok(ss.to_vec())
        }
    };
}

mlkem_impl!(
    mlkem512,
    MlKem512,
    ml_kem_512_keypair,
    ml_kem_512_encapsulate,
    ml_kem_512_decapsulate
);

mlkem_impl!(
    mlkem768,
    MlKem768,
    ml_kem_768_keypair,
    ml_kem_768_encapsulate,
    ml_kem_768_decapsulate
);

mlkem_impl!(
    mlkem1024,
    MlKem1024,
    ml_kem_1024_keypair,
    ml_kem_1024_encapsulate,
    ml_kem_1024_decapsulate
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_round_trip() {
        let d = [0u8; 32];
        let z = [1u8; 32];
        let m = [2u8; 32];

        let keypair = ml_kem_768_keypair(&d, &z).unwrap();
        let ek_size = 1184;
        let dk_size = 2400;
        assert_eq!(keypair.len(), ek_size + dk_size);

        let ek = &keypair[..ek_size];
        let dk = &keypair[ek_size..];

        let encap = ml_kem_768_encapsulate(ek, &m).unwrap();
        let ct_size = 1088;
        assert_eq!(encap.len(), ct_size + 32);
        let ct = &encap[..ct_size];
        let ss_send = &encap[ct_size..];

        let ss_recv = ml_kem_768_decapsulate(dk, ct).unwrap();
        assert_eq!(ss_send, ss_recv.as_slice());
    }

    #[test]
    fn test_ml_kem_512_round_trip() {
        let d = [3u8; 32];
        let z = [4u8; 32];
        let m = [5u8; 32];

        let keypair = ml_kem_512_keypair(&d, &z).unwrap();
        let ek_size = 800;
        let dk_size = 1632;
        assert_eq!(keypair.len(), ek_size + dk_size);

        let ek = &keypair[..ek_size];
        let dk = &keypair[ek_size..];

        let encap = ml_kem_512_encapsulate(ek, &m).unwrap();
        let ct_size = 768;
        assert_eq!(encap.len(), ct_size + 32);
        let ct = &encap[..ct_size];
        let ss_send = &encap[ct_size..];

        let ss_recv = ml_kem_512_decapsulate(dk, ct).unwrap();
        assert_eq!(ss_send, ss_recv.as_slice());
    }

    #[test]
    fn test_ml_kem_1024_round_trip() {
        let d = [6u8; 32];
        let z = [7u8; 32];
        let m = [8u8; 32];

        let keypair = ml_kem_1024_keypair(&d, &z).unwrap();
        let ek_size = 1568;
        let dk_size = 3168;
        assert_eq!(keypair.len(), ek_size + dk_size);

        let ek = &keypair[..ek_size];
        let dk = &keypair[ek_size..];

        let encap = ml_kem_1024_encapsulate(ek, &m).unwrap();
        let ct_size = 1568;
        assert_eq!(encap.len(), ct_size + 32);
        let ct = &encap[..ct_size];
        let ss_send = &encap[ct_size..];

        let ss_recv = ml_kem_1024_decapsulate(dk, ct).unwrap();
        assert_eq!(ss_send, ss_recv.as_slice());
    }

    #[test]
    fn test_bad_seed_rejected() {
        let short = [0u8; 16];
        let z = [0u8; 32];
        let err = ml_kem_768_keypair(&short, &z).unwrap_err();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn test_bad_ek_rejected() {
        let m = [0u8; 32];
        let bad_ek = [0u8; 100];
        let err = ml_kem_768_encapsulate(&bad_ek, &m).unwrap_err();
        assert!(err.contains("ek"));
    }
}
