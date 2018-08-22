use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use serde::{
    de::{self, Deserialize, Deserializer, Visitor, SeqAccess, MapAccess, Unexpected},
    ser::{Serialize, Serializer, SerializeStruct}
};
use std::{fmt, ops::{Deref, DerefMut}};

// Wrapper type to add `Serialize`/`Deserialize` impls to `RistrettoPoint`.
#[derive(Clone)]
pub(crate) struct Point(pub(crate) RistrettoPoint);

impl Deref for Point {
    type Target = RistrettoPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Point {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Serialize  for Point {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut state = s.serialize_struct("Point", 1)?;
        state.serialize_field("p", &self.0.compress().as_bytes())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Point {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all="lowercase")]
        enum Field { P };

        struct PointVisitor;

        impl<'de> Visitor<'de> for PointVisitor {
            type Value = Point;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct Point")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let c = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let p =  CompressedRistretto(c)
                    .decompress()
                    .ok_or_else(|| {
                        de::Error::invalid_value(Unexpected::Bytes(&c[..]), &"compressed ristretto point")
                    })?;
                Ok(Point(p))
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut p = None;
                while let Some(Field::P) = map.next_key()? {
                    if p.is_some() {
                        return Err(de::Error::duplicate_field("p"));
                    }
                    p = Some(map.next_value()?);
                }
                let p = p.ok_or_else(|| de::Error::missing_field("p"))?;
                let p = CompressedRistretto(p)
                    .decompress()
                    .ok_or_else(|| {
                        de::Error::invalid_value(Unexpected::Bytes(&p[..]), &"compressed ristretto point")
                    })?;
                Ok(Point(p))
            }
        }

        const FIELDS: &[&str] = &["p"];
        d.deserialize_struct("Point", FIELDS, PointVisitor)
    }
}
