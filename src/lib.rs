#![allow(non_snake_case, non_upper_case_globals)]

extern crate blake2; // needed for Digest impl
extern crate blake2b_simd;
extern crate curve25519_dalek;
extern crate hkdf;
#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate subtle;

use blake2b_simd::Params;
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar
};
use rand::prelude::*;
use subtle::ConstantTimeEq;


// Generator element g (cf. section 3.2.1).
const g: RistrettoBasepointTable = constants::RISTRETTO_BASEPOINT_TABLE;

// Generator element U in compressed form (cf. section 3.2.1).
const U_COMPRESSED: CompressedRistretto =
    CompressedRistretto(
        [0x0C,0xAF,0x94,0xD5,0x1E,0x45,0xBA,0x71,0xE5,0x61,0xF6,0x58,0x61,0x05,0x82,0x93,
         0xE9,0xE2,0x8F,0x80,0xE8,0x0B,0x83,0x53,0x64,0x40,0xC0,0xD3,0xF0,0x52,0x99,0x61]
    );

lazy_static! {
    // Generator element U (as basepoint table to speed up scalar multiplication)
    static ref U: RistrettoBasepointTable = {
        let basepoint = U_COMPRESSED.decompress().unwrap();
        RistrettoBasepointTable::create(&basepoint)
    };
}


// Symmetric key K
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key(Vec<u8>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


pub struct SecretKey {
    scalar: Scalar
}

impl SecretKey {
    // 3.2.3
    pub fn decapsulate(&self, cap: &Capsule) -> Option<Key> {
        if !cap.check() {
            return None
        }
        Some(kdf(((cap.E + cap.V) * &self.scalar).compress().as_bytes()))
    }
}


pub struct PublicKey {
    point: RistrettoPoint,
    compressed: CompressedRistretto
}

impl PublicKey {
    // 3.2.3
    pub fn encapsulate(&self) -> (Key, Capsule) {
        let r = Scalar::random(&mut thread_rng());
        let u = Scalar::random(&mut thread_rng());
        let E = &g * &r;
        let V = &g * &u;
        let s = u + r * hash(&[E.compress().as_bytes(), V.compress().as_bytes()]);
        let k = kdf((&self.point * &(r + u)).compress().as_bytes());
        let c = Capsule { E, V, s };
        (k, c)
    }
}


/// Re-encryption key fragment (cf. section 3.2.2 (6f))
pub struct Kfrag {
    id: Scalar,
    rk: Scalar,
    pk_x: PublicKey,
    u_1: CompressedRistretto,
    z_1: Scalar,
    z_2: Scalar
}


// 3.2.3
pub struct Capsule {
    E: RistrettoPoint,
    V: RistrettoPoint,
    s: Scalar
}

impl Capsule {
    // 3.2.3
    pub fn check(&self) -> bool {
        let expected = &g * &self.s;
        let h = hash(&[self.E.compress().as_bytes(), self.V.compress().as_bytes()]);
        expected.ct_eq(&(&self.V + &(self.E * &h))).unwrap_u8() == 1 // cf. 2.1 and RFC 6090 (App. E)
    }
}


pub struct Keypair {
    secret: SecretKey,
    public: PublicKey
}

impl Keypair {
    // 3.2.2 (KeyGen)
    pub fn new() -> Self {
        let s = Scalar::random(&mut thread_rng());
        let p = &g * &s;
        let c = p.compress();
        Keypair {
            secret: SecretKey { scalar: s },
            public: PublicKey { point: p, compressed: c }
        }
    }

    // 3.2.2 (ReKeyGen)
    pub fn rekey(&self, pk_b: &PublicKey) -> Kfrag {
        // 3.2.2 (1):
        let ephemeral = Keypair::new();

        // 3.2.2 (2):
        let shared_x_b = (&ephemeral.secret.scalar * &pk_b.point).compress();
        let d = hash(&[
            ephemeral.public.compressed.as_bytes(),
            pk_b.compressed.as_bytes(),
            shared_x_b.as_bytes()
        ]);

        // 3.2.2 (3): TODO: t > 1
        let f_0 = &self.secret.scalar * &d.invert();
        let f_1 = Scalar::random(&mut thread_rng());

        // 3.2.2 (4):
        let f = |x: &Scalar| f_0 + f_1 * x; // TODO: t > 1

        // 3.2.2 (5):
        let shared_a_b = (&self.secret.scalar * &pk_b.point).compress();
        let D = hash(&[
            self.public.compressed.as_bytes(),
            pk_b.compressed.as_bytes(),
            shared_a_b.as_bytes()
        ]);

        // 3.2.2 (6a)
        let id = Scalar::random(&mut thread_rng());
        let y  = Scalar::random(&mut thread_rng());

        // 3.2.2 (6b)
        let sk = hash(&[id.as_bytes(), D.as_bytes()]);
        let Y = (&g * &y).compress();

        // 3.2.2 (6c):
        let rk = f(&sk);

        // 3.2.2 (6d):
        let U_1 = (&rk * &*U).compress();

        // 3.2.2 (6e):
        let z_1 = hash(&[
            Y.as_bytes(),
            id.as_bytes(),
            self.public.compressed.as_bytes(),
            pk_b.compressed.as_bytes(),
            U_1.as_bytes(),
            ephemeral.public.compressed.as_bytes()
        ]);

        let z_2 = y - self.secret.scalar * z_1;

        Kfrag { id, rk, pk_x: ephemeral.public, u_1: U_1, z_1, z_2 }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }
}


// 5.2
fn hash(inputs: &[&[u8]]) -> Scalar {
    let mut state = Params::new().hash_length(64).to_state();
    for i in inputs {
        state.update(i);
    }
    let hash = state.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(hash.as_bytes());
    Scalar::from_bytes_mod_order_wide(&bytes)
}

// 5.4
fn kdf(input: &[u8]) -> Key {
    let kdf = hkdf::Hkdf::<blake2::Blake2b>::extract(None, input);
    Key(kdf.expand(b"pre", 64))
}


