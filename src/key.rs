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


