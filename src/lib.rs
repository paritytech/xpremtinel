//! Implementation of "Umbral" \[1\], a threshold proxy re-encryption scheme.
//!
//! Alice and Bob are represented by their keypairs (a, g^a) and (b, g^b). Alice wishes
//! Bob to be able to decrypt messages encrypted for her, but does not want to distribute
//! extra keys to enable this. Instead, entities which encrypt messages using Alice's
//! public key g^a, create a symmetric encryption key:
//!
//! ```text
//!     k = kdf((g^a)^(r+u)) // with r and u being random scalars mod group order
//! ```
//!
//! as well as a key "capsule":
//!
//! ```text
//!     c = (g^r, g^r, u + r * hash(g^u, g^r))
//! ```
//!
//! Note that k and c can be created without Alice's involvement, requiring only her
//! public key. The capsule c is put as associated data into the AEAD encrypted message
//! which uses k for encryption.
//!
//! Alice herself can de-encapsulate k given c with her private key a
//!
//! ```text
//!     k = kdf((g^r * g^u)^a)
//!       = kdf((g^(r+u))^a)
//!       = kdf((g^a)^(r+u))
//! ```
//!
//! Given Bob's public key g^b, Alice can also create a re-encryption key.
//!
//! ```text
//!     let (x, g^x) be an ephemeral keypair;
//!     d = hash(g^x, g^b, (g^b)^x) // Diffie-Hellman exchange
//!     rk = a / d
//!     (g^x, rk) // the re-encryption key bundle
//! ```
//!
//! Alice can then send the re-encryption key bundle to a third party (the "proxy"), which has
//! access to Alice's encrypted messages, and inform it to give Bob decryption rights over her
//! messages.
//!
//! On incoming messages, the proxy extracts the capsule c and uses the re-encryption key bundle
//! to compute:
//!
//! ```text
//!     cf = ((g^r)^rk, (g^u)^rk, g^x)
//! ```
//!
//! which it hands over to Bob together with the encrypted message (without c).
//! Bob, using his secret key b and cf, derives k as follows:
//!
//! ```text
//!     d = hash(g^x, g^b, (g^x)^b)
//!     k = kdf(((g^r)^rk * (g^u)^rk)^d)
//!       = kdf(((g^r)^(a/d) * (g^u)^(a/d))^d)
//!       = kdf(((g^r)^((a/d)*d) * (g^u)^((a/d)*d)))
//!       = kdf(((g^r)^a * (g^u)^a))
//!       = kdf(((g^a)^r * (g^a)^u))
//!       = kdf(((g^a)^(r+u)))
//! ```
//!
//! The Umbral scheme extends this basic approach by applying Shamir's secret sharing technique
//! to the re-encryption key, which is split into fragments, requiring a threshold number of
//! fragments in order to reconstruct the secret.
//!
//! Implementation note
//! -------------------
//!
//! This library uses the excellent `dalek_curve25519` \[2\] crate to implement elliptic curve
//! operations. In particular, `dalek_curve25519` implements the ristretto technique \[3\],
//! which constructs prime order elliptic curve groups with non-malleable encodings, in order
//! to provide a prime order group based on Curve25519.
//!
//! --------------------------------------------------------------------------------------
//! \[1\]: David Nuñez: "Umbral: A threshold proxy re-encryption scheme",
//!        https://github.com/nucypher/umbral-doc
//!
//! \[2\]: https://github.com/dalek-cryptography/curve25519-dalek
//!
//! \[3\]: https://ristretto.group

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
    Empty,
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
#[derive(Clone)]
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

        // 3.2.2 (3):
        let mut coeff = Vec::with_capacity(t - 1);
        for _ in 0 .. t - 1 {
            coeff.push(Scalar::random(&mut thread_rng()))
        }

        let f_0 = self.secret.scalar * d.invert(); // the secret to share

        // 3.2.2 (4):
        let f = |mut x: Scalar| {
            let mut y = f_0;
            for i in 0 .. t - 1 {
                y += coeff[i] * x;
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
    pub fn decapsulate_frags(&self, pk_a: &PublicKey, cfrags: &[CapsuleFrag]) -> Result<Key, Error> {
        if cfrags.is_empty() {
            return Err(Error::Empty)
        }

        // 3.2.4 (1):
        let D = hash(&[
            pk_a.compressed.as_bytes(),
            self.public.compressed.as_bytes(),
            (pk_a.point * &self.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.4 (2):
        let mut S = Vec::new();
        for cfrag_i in cfrags {
            let sx_i = hash(&[cfrag_i.id.as_bytes(), D.as_bytes()]);
            S.push(sx_i);
        }

        // 3.2.4 (3):
        let mut cfrags = cfrags.to_vec();
        let (E_prime, V_prime) = interpol(&S, &mut cfrags);

        // 3.2.4 (4):
        let d = {
            let cfrag = &cfrags[0]; // all fragments share the same ephemeral public key:
            hash(&[
                cfrag.pk_x.compressed.as_bytes(),
                self.public.compressed.as_bytes(),
                (cfrag.pk_x.point * &self.secret.scalar).compress().as_bytes()
            ])
        };

        // 3.2.4 (5):
        Ok(kdf(((E_prime + V_prime) * &d).compress().as_bytes())) // cf. 2.1 and RFC 6090 (App. E)
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

// https://en.wikipedia.org/wiki/Neville%27s_algorithm
fn interpol(sx: &[Scalar], cfs: &mut Vec<CapsuleFrag>) -> (RistrettoPoint, RistrettoPoint) {
    for d in 1 .. sx.len() {
        for i in 0 .. sx.len() - d {
            let j = i + d;
            let num_e = sx[j] * cfs[i].E_1 - sx[i] * cfs[i + 1].E_1;
            let num_v = sx[j] * cfs[i].V_1 - sx[i] * cfs[i + 1].V_1;
            let den = (sx[j] - sx[i]).invert();
            cfs[i].E_1 = num_e * den;
            cfs[i].V_1 = num_v * den;
        }
    }
    (cfs[0].E_1, cfs[0].V_1)
}

