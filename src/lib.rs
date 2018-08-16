#![allow(non_snake_case, non_upper_case_globals)]

extern crate blake2; // needed for `Digest` impl
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


// Note: Ristretto is a technique for constructing prime order elliptic curve groups with
// non-malleable encodings. See https://ristretto.group for details. `curve25519_dalek`
// provides a ristretto implementation for Curve25519.


// Generator element `g` (cf. section 3.2.1).
const g: RistrettoBasepointTable = constants::RISTRETTO_BASEPOINT_TABLE;

lazy_static! {
    // Generator element `U` (cf. section 3.2.1).
    static ref U: RistrettoBasepointTable = {
        // Fix some random basepoint as `U`.
        // (For elliptic curves with prime order, every element is a generator.)
        let basepoint =
            CompressedRistretto([
                0x0C, 0xAF, 0x94, 0xD5, 0x1E, 0x45, 0xBA, 0x71,
                0xE5, 0x61, 0xF6, 0x58, 0x61, 0x05, 0x82, 0x93,
                0xE9, 0xE2, 0x8F, 0x80, 0xE8, 0x0B, 0x83, 0x53,
                0x64, 0x40, 0xC0, 0xD3, 0xF0, 0x52, 0x99, 0x61
            ])
            .decompress()
            .expect("valid ristretto point");
        // Create a basepoint table to speed up scalar multiplication:
        RistrettoBasepointTable::create(&basepoint)
    };
}


// Symmetric encryption/decryption key `K`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key(Vec<u8>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}


#[derive(Debug)]
pub enum Error {
    InvalidCapsule
}


#[derive(Clone)]
pub struct SecretKey {
    scalar: Scalar
}

impl SecretKey {
    // 3.2.3
    pub fn decapsulate(&self, cap: &Capsule) -> Result<Key, Error> {
        if !cap.check() {
            return Err(Error::InvalidCapsule)
        }
        Ok(kdf(((cap.E + cap.V) * &self.scalar).compress().as_bytes()))
    }
}


#[derive(Clone)]
pub struct PublicKey {
    point: RistrettoPoint,
    compressed: CompressedRistretto // `point` in compressed form
}

impl PublicKey {
    // 3.2.3
    pub fn encapsulate(&self) -> (Key, Capsule) {
        let r = Scalar::random(&mut thread_rng());
        let u = Scalar::random(&mut thread_rng());
        let E = &g * &r;
        let V = &g * &u;
        let s = u + r * hash(&[E.compress().as_bytes(), V.compress().as_bytes()]);
        let k = kdf((self.point * &(r + u)).compress().as_bytes());
        let c = Capsule { E, V, s };
        (k, c)
    }
}


/// Re-encryption key fragment (cf. section 3.2.2 (6f))
#[allow(dead_code)]
pub struct Kfrag {
    id: Scalar,
    rk: Scalar,
    pk_x: PublicKey,
    u_1: CompressedRistretto,
    z_1: Scalar,
    z_2: Scalar
}

impl Kfrag {
    // 3.2.4 (ReEncapsulate)
    pub fn re_encapsulate(&self, cap: &Capsule) -> Result<CapsuleFrag, Error> {
        if !cap.check() {
            return Err(Error::InvalidCapsule)
        }
        let E_1 = cap.E * &self.rk;
        let V_1 = cap.V * &self.rk;
        Ok(CapsuleFrag { E_1, V_1, id: self.id, pk_x: self.pk_x.clone() })
    }
}


// 3.2.4
pub struct CapsuleFrag {
    E_1: RistrettoPoint,
    V_1: RistrettoPoint,
    id: Scalar,
    pk_x: PublicKey
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
        expected.ct_eq(&(self.V + self.E * &h)).unwrap_u8() == 1 // cf. 2.1 and RFC 6090 (App. E)
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

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    // 3.2.2 (ReKeyGen)
    pub fn rekey(&self, pk_b: &PublicKey, n: usize, t: usize) -> Vec<Kfrag> {
        assert!(t >  0);
        assert!(n >= t);

        // 3.2.2 (1):
        let ephemeral = Keypair::new(); // (x_a, X_a)

        // 3.2.2 (2):
        let d = hash(&[
            ephemeral.public.compressed.as_bytes(),
            pk_b.compressed.as_bytes(),
            (pk_b.point * &ephemeral.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.2 (3 & 4):
        let f = |mut x: Scalar| {
            let mut y = self.secret.scalar * d.invert(); // f_0
            for _ in 0 .. t - 1 {
                let f_i = Scalar::random(&mut thread_rng()); // (3)
                y += f_i * x;
                x *= x
            }
            y
        };

        // 3.2.2 (5):
        let D = hash(&[
            self.public.compressed.as_bytes(),
            pk_b.compressed.as_bytes(),
            (pk_b.point * &self.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.2 (6a)
        let mut KF = Vec::with_capacity(n);
        for _ in 0 .. n {
            let id = Scalar::random(&mut thread_rng());
            let y  = Scalar::random(&mut thread_rng());

            // 3.2.2 (6b)
            let sx = hash(&[id.as_bytes(), D.as_bytes()]);
            let Y = (&g * &y).compress();

            // 3.2.2 (6c):
            let rk = f(sx);

            // 3.2.2 (6d):
            let U_1 = (&*U * &rk).compress();

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

            KF.push(Kfrag { id, rk, pk_x: ephemeral.public.clone(), u_1: U_1, z_1, z_2 })
        }
        KF
    }

    // 3.2.4 (DecapsulateFrags)
    pub fn decapsulate_frags(&self, pk_a: &PublicKey, cfrags: &[CapsuleFrag]) -> Key {
        // 3.2.4 (1):
        let D = hash(&[
            pk_a.compressed.as_bytes(),
            self.public.compressed.as_bytes(),
            (pk_a.point * &self.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.4 (2):
        let mut S = Vec::with_capacity(cfrags.len());
        for cfrag_i in cfrags {
            let sx_i = hash(&[cfrag_i.id.as_bytes(), D.as_bytes()]);
            S.push(sx_i);
        }
        let L: Vec<Scalar> = S.iter()
            .enumerate()
            .fold(Vec::with_capacity(cfrags.len()), |mut L, (i, sx_i)| {
                let lam_i_s = S.iter()
                    .enumerate()
                    .filter_map(|(j, sx_j)| {
                        if i != j {
                            Some(sx_j.invert() * (sx_j - sx_i))
                        } else {
                            None
                        }
                    })
                    .product();
                L.push(lam_i_s);
                L
            });

        // 3.2.4 (3):
        let E_prime: RistrettoPoint =
            cfrags.iter().zip(L.iter())
                .map(|(cfrag_i, lam_i_s)| cfrag_i.E_1 * lam_i_s)
                .sum(); // cf. 2.1 and RFC 6090 (App. E)

        let V_prime: RistrettoPoint =
            cfrags.iter().zip(L.iter())
                .map(|(cfrag_i, lam_i_s)| cfrag_i.V_1 * lam_i_s)
                .sum(); // cf. 2.1 and RFC 6090 (App. E)

        // 3.2.4 (4):
        let d = {
            let X_a = &cfrags[0].pk_x; // all fragments share the same ephemeral public key
            hash(&[
                X_a.compressed.as_bytes(),
                self.public.compressed.as_bytes(),
                (X_a.point * &self.secret.scalar).compress().as_bytes()
            ])
        };

        // 3.2.4 (5):
        kdf(((E_prime + V_prime) * &d).compress().as_bytes()) // cf. 2.1 and RFC 6090 (App. E)
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

