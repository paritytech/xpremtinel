use keypair::PublicKey;
use point::Point;
use scalar::Scalar;
use subtle::ConstantTimeEq;
use util::hash;
use g;

/// The capsule is created by data producers using `PublicKey::encapsulate`.
/// It will allow deriving the symmetric encryption key again.
///
// 3.2.3
#[derive(Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub(crate) E: Point,
    pub(crate) V: Point,
    pub(crate) s: Scalar
}

impl Capsule {
    /// Check, that this capsule is valid.
    ///
    // 3.2.3
    pub fn check(&self) -> bool {
        let expected = &g * &self.s;
        let h = hash(&[self.E.compress().as_bytes(), self.V.compress().as_bytes()]);
        expected.ct_eq(&(*self.V + *self.E * *h)).unwrap_u8() == 1 // cf. 2.1 and RFC 6090 (App. E)
    }
}


/// A capsule fragment is created by a proxy node using `KeyFragment::re_encapsulate`.
/// It contains part of the data which will allow Bob to decrypt ciphertext encrypted
/// with Alice's public key if she generated re-encryption keys and distributed them to
/// the proxy.
///
// 3.2.4
#[derive(Clone, Serialize, Deserialize)]
pub struct CapsuleFragment {
    pub(crate) E_1: Point,
    pub(crate) V_1: Point,
    pub(crate) id: Scalar,
    pub(crate) pk_x: PublicKey
}

