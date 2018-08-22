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

