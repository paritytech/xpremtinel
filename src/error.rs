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
            Error::Decrypt => f.write_str("decrypt error"),
            Error::Encrypt => f.write_str("encrypt error"),
            Error::Serialise => f.write_str("failed to serialise")
        }
    }
}

impl std::error::Error for Error {}

