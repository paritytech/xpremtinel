use curve25519_dalek::scalar::Scalar;
use blake2;
use blake2b_simd::Params;
use hkdf;
use key::Key;


// 5.2
pub(crate) fn hash(inputs: &[&[u8]]) -> Scalar {
    let mut state = Params::new().hash_length(64).to_state();
    for i in inputs {
        state.update(i);
    }
    let hash = state.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hash.as_bytes());
    Scalar::from_bytes_mod_order_wide(&bytes)
}


// 5.4
pub(crate) fn kdf(input: &[u8]) -> Key {
    let kdf = hkdf::Hkdf::<blake2::Blake2b>::extract(None, input);
    let mut k = [0; 32];
    kdf.expand(b"pre", &mut k).expect("32 < 255 * 64");
    Key::new(k)
}

