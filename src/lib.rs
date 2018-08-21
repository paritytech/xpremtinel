//! Implementation of "Umbral" \[1\], a threshold proxy re-encryption scheme.
//!
//! Alice and Bob are represented by their keypairs (a, g^a) and (b, g^b). Alice wishes
//! Bob to be able to decrypt messages encrypted for her, but does not want to distribute
//! extra keys to enable this. Instead, entities which encrypt messages using Alice's
//! public key g^a, create a symmetric encryption key:
//!
//! ```text
//! k = kdf((g^a)^(r+u)) // with r and u being random scalars mod group order
//! ```
//!
//! as well as a key "capsule":
//!
//! ```text
//! c = (g^r, g^r, u + r * hash(g^u, g^r))
//! ```
//!
//! Note that k and c can be created without Alice's involvement, requiring only her
//! public key. The capsule c is used as associated data in the AEAD encrypted message
//! which uses k for encryption.
//!
//! Alice herself can de-encapsulate k given c with her private key a
//!
//! ```text
//! k = kdf((g^r * g^u)^a)
//!   = kdf((g^(r+u))^a)
//!   = kdf((g^a)^(r+u))
//! ```
//!
//! Given Bob's public key g^b, Alice can also create a re-encryption key.
//!
//! ```text
//! let (x, g^x) be an ephemeral keypair;
//! d = hash(g^x, g^b, (g^b)^x) // Diffie-Hellman exchange
//! rk = a / d
//! (g^x, rk) // the re-encryption key bundle
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
//! cf = ((g^r)^rk, (g^u)^rk, g^x)
//! ```
//!
//! which it hands over to Bob together with the encrypted message.
//! Bob, using his secret key b and cf, derives k as follows:
//!
//! ```text
//! d = hash(g^x, g^b, (g^x)^b)
//! k = kdf(((g^r)^rk * (g^u)^rk)^d)
//!   = kdf(((g^r)^(a/d) * (g^u)^(a/d))^d)
//!   = kdf(((g^r)^((a/d)*d) * (g^u)^((a/d)*d)))
//!   = kdf(((g^r)^a * (g^u)^a))
//!   = kdf(((g^a)^r * (g^a)^u))
//!   = kdf(((g^a)^(r+u)))
//! ```
//!
//! Obviously it would be trivial for the proxy and Bob to join forces and recover Alice's secret
//! key a. Therefore, the Umbral scheme extends the basic approach by applying Shamir's secret
//! sharing technique to the re-encryption key, which is split into fragments, requiring a
//! threshold number of fragments in order to reconstruct the secret. This then requires at least
//! t proxies and Bob to collaborate in order to recover Alice's secret.
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
extern crate ring;
extern crate smallvec;
extern crate subtle;

use blake2b_simd::Params;
use curve25519_dalek::{
    constants,
    ristretto::{CompressedRistretto, RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul
};
use rand::prelude::*;
use ring::aead;
use smallvec::SmallVec;
use subtle::ConstantTimeEq;
use std::{fmt, iter, ops::Deref};

type Vector<T> = SmallVec<[T; 8]>;

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


#[derive(Debug)]
pub enum Error {
    Empty,
    InvalidCapsule,
    Decrypt,
    Encrypt,
    Deserialise(&'static str)
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Empty => f.write_str("empty"),
            Error::InvalidCapsule => f.write_str("invalid capsule"),
            Error::Decrypt => f.write_str("decrypt error"),
            Error::Encrypt => f.write_str("encrypt error"),
            Error::Deserialise(m) => write!(f, "deserialisation error: {}", m)
        }
    }
}

impl std::error::Error for Error {}


// Symmetric encryption/decryption key `K`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
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

    pub fn decrypt<'a>(&self, nonce: &[u8; 12], cap: &Capsule, cipher: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let k = self.decapsulate(cap)?;
        let ok = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Decrypt)?;
        let ad = cap.serialise();
        Ok(&aead::open_in_place(&ok, nonce, &ad, 0, cipher).map_err(|_| Error::Decrypt)?[..])
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
        let rng = &mut thread_rng();
        let r = Scalar::random(rng);
        let u = Scalar::random(rng);
        let E = &g * &r;
        let V = &g * &u;
        let s = u + r * hash(&[E.compress().as_bytes(), V.compress().as_bytes()]);
        let k = kdf((self.point * &(r + u)).compress().as_bytes());
        let c = Capsule { E, V, s };
        (k, c)
    }

    pub fn encrypt(&self, nonce: &[u8; 12], mut msg: Vec<u8>) -> Result<(Capsule, Vec<u8>), Error> {
        let (k, cap) = self.encapsulate();

        let sk = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Encrypt)?;
        let tl = aead::CHACHA20_POLY1305.tag_len();
        let ad = cap.serialise();

        msg.extend(iter::repeat(0).take(tl));
        let out_len = aead::seal_in_place(&sk, nonce, &ad, &mut msg, tl).map_err(|_| Error::Encrypt)?;
        msg.truncate(out_len);

        Ok((cap, msg))
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
#[derive(Clone)]
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

    pub fn serialise(&self) -> [u8; 96] {
        let mut b = [0; 96];
        let ce = self.E.compress();
        (&mut b[0..32]).copy_from_slice(ce.as_bytes());
        let ve = self.V.compress();
        (&mut b[32..64]).copy_from_slice(ve.as_bytes());
        (&mut b[64..96]).copy_from_slice(self.s.as_bytes());
        b
    }

    pub fn deserialise(input: &[u8]) -> Result<Self, Error> {
        if input.len() != 96 {
            return Err(Error::Deserialise("invalid input length"))
        }
        let mut b = [0; 32];
        (&mut b).copy_from_slice(&input[0..32]);
        let ce = CompressedRistretto(b);
        (&mut b).copy_from_slice(&input[32..64]);
        let ve = CompressedRistretto(b);
        (&mut b).copy_from_slice(&input[64..96]);
        let s = Scalar::from_canonical_bytes(b).ok_or(Error::Deserialise("scalar not canonical"))?;
        Ok(Self {
            E: ce.decompress().ok_or(Error::Deserialise("failed to decompress E"))?,
            V: ve.decompress().ok_or(Error::Deserialise("failed to decompress V"))?,
            s
        })
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

        let rng = &mut thread_rng();

        // 3.2.2 (1):
        let ephemeral = Keypair::new(); // (x_a, X_a)

        // 3.2.2 (2):
        let d = hash(&[
            ephemeral.public.compressed.as_bytes(),
            pk_b.compressed.as_bytes(),
            (pk_b.point * &ephemeral.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.2 (3):
        let mut coeff = Vector::with_capacity(t - 1);
        for _ in 0 .. t - 1 {
            coeff.push(Scalar::random(rng))
        }

        let f_0 = self.secret.scalar * d.invert(); // the secret to share

        // 3.2.2 (4):
        let f = |x: Scalar| {
            let mut y = f_0;
            let mut k = x;
            for i in 0 .. t - 1 {
                y += coeff[i] * k;
                k *= x
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
        let mut KF = Vector::with_capacity(n);
        for _ in 0 .. n {
            let id = Scalar::random(rng);
            let y  = Scalar::random(rng);

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
        KF.into_vec()
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
        let mut S = Vector::with_capacity(cfrags.len());
        for cfrag_i in cfrags {
            let sx_i = hash(&[cfrag_i.id.as_bytes(), D.as_bytes()]);
            S.push(sx_i);
        }

        // 3.2.4 (3):
        let mut numer = Vector::with_capacity(S.len());
        let mut denum = Vector::with_capacity(S.len());
        for i in 0 .. S.len() {
            let (n, d) = S.iter()
                .enumerate()
                .fold((Scalar::one(), Scalar::one()), |(n, d), (j, s)| {
                    if i == j {
                        return (n, d)
                    }
                    (n * s, d * (s - S[i]))
                });
            numer.push(cfrags[i].E_1 * n + cfrags[i].V_1 * n);
            denum.push(d.invert());
        }
        let point = RistrettoPoint::multiscalar_mul(&denum, &numer);

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
        Ok(kdf((point * &d).compress().as_bytes())) // cf. 2.1 and RFC 6090 (App. E)
    }

    pub fn decrypt<'a>(&self, pk_a: &PublicKey, nonce: &[u8; 12], cap: &Capsule, cfrags: &[CapsuleFrag], cipher: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let k = self.decapsulate_frags(pk_a, cfrags)?;
        let ok = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Decrypt)?;
        let ad = cap.serialise();
        Ok(&aead::open_in_place(&ok, nonce, &ad, 0, cipher).map_err(|_| Error::Decrypt)?[..])
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
    let mut k = [0; 32];
    kdf.expand(b"pre", &mut k).expect("32 < 255 * 64");
    Key(k)
}

