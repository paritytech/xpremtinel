// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

use std::{self, fmt};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// Empty collection or iterator.
    Empty,
    /// The capsule is invalid.
    InvalidCapsule,
    /// Failed to verify proof.
    Proof,
    /// Failed to verify signature.
    Signature,
    /// Error when decrypting ciphertext.
    Decrypt,
    /// Error when encrypting plaintext.
    Encrypt,
    /// Error during serialisation.
    Serialise
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Empty => f.write_str("empty"),
            Error::InvalidCapsule => f.write_str("invalid capsule"),
            Error::Proof => f.write_str("proof verification failed"),
            Error::Signature => f.write_str("signature verification failed"),
            Error::Decrypt => f.write_str("decrypt error"),
            Error::Encrypt => f.write_str("encrypt error"),
            Error::Serialise => f.write_str("failed to serialise")
        }
    }
}

impl std::error::Error for Error {}

