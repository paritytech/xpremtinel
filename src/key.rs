// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

use std::ops::Deref;

/// Symmetric encryption/decryption key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key([u8; 32]);

impl Key {
    pub(crate) fn new(xs: [u8; 32]) -> Self {
        Key(xs)
    }
}

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}


/// A value which must only be used once for an encryption key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce([u8; 12]);

impl Nonce {
    pub fn new(xs: [u8; 12]) -> Self {
        Nonce(xs)
    }
}

impl Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}

