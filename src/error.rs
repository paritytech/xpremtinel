use std::{error, fmt};

#[derive(Debug)]
pub enum Error {
    Empty,
    InvalidCapsule,
    Decrypt,
    Encrypt,
    Serialise
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Empty => f.write_str("empty"),
            Error::InvalidCapsule => f.write_str("invalid capsule"),
            Error::Decrypt => f.write_str("decrypt error"),
            Error::Encrypt => f.write_str("encrypt error"),
            Error::Serialise => f.write_str("failed to serialise")
        }
    }
}

impl error::Error for Error {}

