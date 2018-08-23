use curve25519_dalek::{scalar::Scalar, ristretto::RistrettoPoint};
use keypair::PublicKey;
use subtle::ConstantTimeEq;
use util::hash;
use g;

/// The capsule is created by data producers using `PublicKey::encapsulate`.
/// It will allow deriving the symmetric encryption key again.
///
// 3.2.3
#[derive(Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub(crate) E: RistrettoPoint,
    pub(crate) V: RistrettoPoint,
    pub(crate) s: Scalar
}

impl Capsule {
    /// Check, that this capsule is valid.
    ///
    // 3.2.3
    pub fn check(&self) -> bool {
        let expected = &g * &self.s;
        let h = hash(&[self.E.compress().as_bytes(), self.V.compress().as_bytes()]);
        expected.ct_eq(&(self.V + self.E * h)).unwrap_u8() == 1 // cf. 2.1 and RFC 6090 (App. E)
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
    pub(crate) E_1: RistrettoPoint,
    pub(crate) V_1: RistrettoPoint,
    pub(crate) id: Scalar,
    pub(crate) pk_x: PublicKey,
    pub(crate) pi: Proof
}


/// Proof of re-encryption correctness.
// 4.1
#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub(crate) E_2: RistrettoPoint,
    pub(crate) V_2: RistrettoPoint,
    pub(crate) U_2: RistrettoPoint,
    pub(crate) U_1: RistrettoPoint,
    pub(crate) z_1: Scalar,
    pub(crate) z_2: Scalar,
    pub(crate) p: Scalar
}

