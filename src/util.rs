// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

use curve25519_dalek::scalar::Scalar;
use blake2;
use blake2b_simd::Params;
use hkdf;
use key::Key;


// 5.2
pub(crate) fn hash<'a, I, T>(inputs: I) -> Scalar
where
    I: IntoIterator<Item=T> + Copy,
    T: AsRef<[u8]>
{
    let mut state = Params::new().hash_length(64).to_state();
    for i in inputs {
        state.update(i.as_ref());
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

