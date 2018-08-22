use curve25519_dalek;
use rand::{Rng, CryptoRng};
use serde::{
    de::{self, Deserialize, Deserializer, Visitor, Unexpected},
    ser::{Serialize, Serializer}
};
use std::{fmt, ops::{Deref, DerefMut}};

// Wrapper type to add `Serialize`/`Deserialize` impls to `Scalar`.
#[derive(Copy, Clone)]
pub(crate) struct Scalar(pub(crate) curve25519_dalek::scalar::Scalar);

impl Scalar {
    pub(crate) fn random<R>(rng: &mut R) -> Self
    where
        R: Rng + CryptoRng
    {
        Scalar(curve25519_dalek::scalar::Scalar::random(rng))
    }

    pub(crate) fn from_bytes_mod_order_wide(b: &[u8; 64]) -> Self {
        Scalar(curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(b))
    }

    pub(crate) fn one() -> Scalar {
        Scalar(curve25519_dalek::scalar::Scalar::one())
    }
}

impl Deref for Scalar {
    type Target = curve25519_dalek::scalar::Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Scalar {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize  for Scalar {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ScalarVisitor;

        impl<'de> Visitor<'de> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("scalar value")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() != 32 {
                    return Err(de::Error::invalid_value(Unexpected::Bytes(v), &"32 bytes"))
                }
                let mut a = [0; 32];
                (&mut a).copy_from_slice(v);
                let s = curve25519_dalek::scalar::Scalar::from_canonical_bytes(a)
                    .ok_or_else(|| {
                        de::Error::invalid_value(Unexpected::Bytes(v), &"canonical scalar bytes")
                    })?;
                Ok(Scalar(s))
            }

            fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                self.visit_bytes(v)
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }
        }

        d.deserialize_bytes(ScalarVisitor)
    }
}

