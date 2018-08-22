use keypair::PublicKey;
use point::Point;
use scalar::Scalar;
use subtle::ConstantTimeEq;
use util::hash;
use g;

// 3.2.3
#[derive(Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub(crate) E: Point,
    pub(crate) V: Point,
    pub(crate) s: Scalar
}

impl Capsule {
    // 3.2.3
    pub fn check(&self) -> bool {
        let expected = &g * &self.s;
        let h = hash(&[self.E.compress().as_bytes(), self.V.compress().as_bytes()]);
        expected.ct_eq(&(*self.V + *self.E * *h)).unwrap_u8() == 1 // cf. 2.1 and RFC 6090 (App. E)
    }
}

// 3.2.4
#[derive(Clone, Serialize, Deserialize)]
pub struct CapsuleFrag {
    pub(crate) E_1: Point,
    pub(crate) V_1: Point,
    pub(crate) id: Scalar,
    pub(crate) pk_x: PublicKey
}

