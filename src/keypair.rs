// Copyright 2018 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

use bincode;
use capsule::{Capsule, CapsuleFragment, Proof};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
use error::{Error, Result};
use key::{Key, Nonce};
use rand::prelude::*;
use ring::aead;
use smallvec::SmallVec;
use std::iter;
use util::{hash, kdf};
use {g, U};


type Vector<T> = SmallVec<[T; 8]>;


/// A keypair contains a secret key (a scalar value) and a public key (a point on Curve25519).
/// Alice and Bob are represented by their keypairs. When Alice wants to allow Bob to read messages
/// encrypted with her public key, she can use `Keypair::rekey` to create *n* `KeyFragments` each of
/// which she gives to one proxy node. Each proxy instance can transform an incoming `Capsule` into
/// a `CapsuleFragment`. Bob needs *t* of those fragments, the capsule itself and the corresponding
/// ciphertext in order to be able to decrypt it.
#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey
}

impl Keypair {
    /// Creates a fresh pair of public and secret key.
    ///
    // 3.2.2 (KeyGen)
    pub fn new() -> Self {
        let s = Scalar::random(&mut thread_rng());
        let p = &g * &s;
        Keypair {
            secret: SecretKey { scalar: s },
            public: PublicKey { point: p }
        }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Given a public key, create *n* re-encryption key fragments, out of which *t*
    /// are sufficient to generate capsule fragments which can be used for decrypting
    /// ciphertext encrypted with this keypair's public key.
    /// Each key fragment is used by a proxy node to create capsule fragments.
    ///
    /// Please ensure that *n* >= *t* > 0
    ///
    // 3.2.2 (ReKeyGen)
    pub fn rekey(&self, pk_b: &PublicKey, n: usize, t: usize) -> Vec<KeyFragment> {
        assert!(t >  0);
        assert!(n >= t);

        let rng = &mut thread_rng();

        // 3.2.2 (1):
        let ephemeral = Keypair::new(); // (x_a, X_a)

        // 3.2.2 (2):
        let d = hash(&[
            ephemeral.public.point.compress().as_bytes(),
            pk_b.point.compress().as_bytes(),
            (pk_b.point * ephemeral.secret.scalar).compress().as_bytes()
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
            for c in coeff.iter().take(t - 1) {
                y  += *c * k;
                k *= x
            }
            y
        };

        // 3.2.2 (5):
        let D = hash(&[
            self.public.point.compress().as_bytes(),
            pk_b.point.compress().as_bytes(),
            (pk_b.point * self.secret.scalar).compress().as_bytes()
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
            let U_1 = &*U * &rk;

            // 3.2.2 (6e) (Schnorr signature):
            let z_1 = hash(&[
                Y.as_bytes(),
                id.as_bytes(),
                self.public.point.compress().as_bytes(),
                pk_b.point.compress().as_bytes(),
                U_1.compress().as_bytes(),
                ephemeral.public.point.compress().as_bytes()
            ]);
            let z_2 = y - self.secret.scalar * z_1;

            let kfrag = KeyFragment {
                id,
                rk,
                pk_x: ephemeral.public.clone(),
                U_1,
                z_1,
                z_2
            };

            KF.push(kfrag)
        }
        KF.into_vec()
    }

    /// Reconstruct the symmetric encryption key, given the public key used for encryption
    /// and at least *t* out of *n* capsule fragments.
    /// This operation would be executed by Bob, once he has collected the necessary number
    /// of capsule fragments. Used by `Keypair::decrypt` to decrypt ciphertext. On its own
    /// this method is part of the Umbral KEM construction.
    ///
    // 3.2.4 (DecapsulateFrags)
    pub fn decapsulate_frags<'a, I>(&self, pk_a: &PublicKey, cap: &Capsule, cfrags: I) -> Result<Key>
    where
        I: IntoIterator<Item=&'a CapsuleFragment> + Copy
    {
        let cfrag_0 =
            if let Some(cf) = cfrags.into_iter().next() {
                cf
            } else {
                return Err(Error::Empty)
            };

        // proof verification (4.2)

        let E_compress = cap.E.compress();
        let V_compress = cap.V.compress();
        for cfrag_i in cfrags {
            // 4.1 (1) (Schnorr signature verification)
            let r_v = &g * &cfrag_i.pi.z_2 + pk_a.point * cfrag_i.pi.z_1;
            let e_v = hash(&[r_v.compress().as_bytes(),
                cfrag_i.id.as_bytes(),
                pk_a.point.compress().as_bytes(),
                self.public.point.compress().as_bytes(),
                cfrag_i.pi.U_1.compress().as_bytes(),
                cfrag_i.pk_x.point.compress().as_bytes()
            ]);
            if e_v != cfrag_i.pi.z_1 {
                return Err(Error::Signature)
            }

            // 4.2 (2)
            let h = hash(&[
                E_compress.as_bytes(),
                cfrag_i.E_1.compress().as_bytes(),
                cfrag_i.pi.E_2.compress().as_bytes(),
                V_compress.as_bytes(),
                cfrag_i.V_1.compress().as_bytes(),
                cfrag_i.pi.V_2.compress().as_bytes(),
                U.basepoint().compress().as_bytes(),
                cfrag_i.pi.U_1.compress().as_bytes(),
                cfrag_i.pi.U_2.compress().as_bytes()
            ]);

            // 4.2 (3)
            if cap.E * cfrag_i.pi.p != cfrag_i.pi.E_2 + cfrag_i.E_1 * h {
                return Err(Error::Proof)
            }
            if cap.V * cfrag_i.pi.p != cfrag_i.pi.V_2 + cfrag_i.V_1 * h {
                return Err(Error::Proof)
            }
            if &*U * &cfrag_i.pi.p != cfrag_i.pi.U_2 + cfrag_i.pi.U_1 * h {
                return Err(Error::Proof)
            }
        }

        // 3.2.4 (1):
        let D = hash(&[
            pk_a.point.compress().as_bytes(),
            self.public.point.compress().as_bytes(),
            (pk_a.point * self.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.4 (2):
        let mut S = Vector::new();
        for cfrag_i in cfrags {
            let sx_i = hash(&[cfrag_i.id.as_bytes(), D.as_bytes()]);
            S.push(sx_i);
        }

        // 3.2.4 (3):
        let nd = S.iter()
            .zip(cfrags)
            .enumerate()
            .fold(Vector::with_capacity(S.len()), |mut nd, (i, (sx_i, cfrag))| {
                let (n, d) = S.iter().enumerate()
                    .fold((Scalar::one(), Scalar::one()), |(n, d), (j, sx_j)| {
                        if i == j {
                            (n, d)
                        } else {
                            (n * *sx_j, d * (*sx_j - *sx_i))
                        }
                    });
                nd.push((cfrag.E_1 * n + cfrag.V_1 * n, d.invert()));
                nd
            });
        let numers = nd.iter().map(|nd| nd.0);
        let denums = nd.iter().map(|nd| nd.1);
        let point = RistrettoPoint::multiscalar_mul(denums, numers);

        // 3.2.4 (4):
        let d = hash(&[
            cfrag_0.pk_x.point.compress().as_bytes(),
            self.public.point.compress().as_bytes(),
            (cfrag_0.pk_x.point * self.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.4 (5):
        Ok(kdf((point * d).compress().as_bytes())) // cf. 2.1 and RFC 6090 (App. E)
    }

    /// Decrypt ciphertext encrypted with public key `pk_a` and the given nonce.
    /// In order to succeed, we need at least *t* out of *n* cpasule fragments from *t* proxies
    /// plus the capsule itself that was generated during encryption.
    /// This operation would be executed by Bob, once he has collected the necessary number
    /// of capsule fragments. Internally this method uses `Keypair::decapsulate_frags` to get the
    /// symmetric key.
    pub fn decrypt<'a, 'b, I>(&self, pk_a: &PublicKey, n: &Nonce, c: &Capsule, cfrags: I, ciph: &'a mut [u8]) -> Result<&'a [u8]>
    where
        I: IntoIterator<Item=&'b CapsuleFragment> + Copy
    {
        let k = self.decapsulate_frags(pk_a, c, cfrags)?;
        let ok = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Decrypt)?;
        let ad = bincode::serialize(c).map_err(|_| Error::Serialise)?;
        Ok(&aead::open_in_place(&ok, n, &ad, 0, ciph).map_err(|_| Error::Decrypt)?[..])
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey {
    scalar: Scalar
}

impl SecretKey {
    /// Restore the symmetric encryption key from the capsule.
    /// This operation would be executed by Alice, the data owner whose public key
    /// was used in the first place to create the symmetric encryption key.
    /// This method is used by `SecretKey::decrypt`. On its own it is part of the Umbral
    /// KEM construction.
    ///
    // 3.2.3
    pub fn decapsulate(&self, cap: &Capsule) -> Result<Key> {
        if !cap.check() {
            return Err(Error::InvalidCapsule)
        }
        Ok(kdf(((cap.E + cap.V) * self.scalar).compress().as_bytes()))
    }

    /// Decrypt a message encrypted with the public key corresponding to this secret key.
    /// This method uses `SecretKey::decapsulate` to derive the symmetric encryption key.
    pub fn decrypt<'a>(&self, n: &Nonce, cap: &Capsule, cipher: &'a mut [u8]) -> Result<&'a [u8]> {
        let k = self.decapsulate(cap)?;
        let ok = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Decrypt)?;
        let ad = bincode::serialize(cap).map_err(|_| Error::Serialise)?;
        Ok(&aead::open_in_place(&ok, n, &ad, 0, cipher).map_err(|_| Error::Decrypt)?[..])
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    point: RistrettoPoint
}

impl PublicKey {
    /// Create a fresh symmetric encryption key plus a capsule which allows to derive this
    /// symmetric key again. This operation would be executed by anyone who wants to produce
    /// data for Alice, using her public key. Used by `PublicKey::encrypt`. On its own it is
    /// part of the Umbral KEM construction.
    ///
    // 3.2.3
    pub fn encapsulate(&self) -> (Key, Capsule) {
        let rng = &mut thread_rng();
        let r = Scalar::random(rng);
        let u = Scalar::random(rng);
        let E = &g * &r;
        let V = &g * &u;
        let s = u + r * hash(&[E.compress().as_bytes(), V.compress().as_bytes()]);
        let k = kdf((self.point * (r + u)).compress().as_bytes());
        let c = Capsule { E, V, s };
        (k, c)
    }

    /// Encrypt some message with this public key.
    /// The returned capsule allows deriving the decryption key for the ciphertext.
    /// Uses `PublicKey::encapsulate` to create the symmetric encryption key.
    pub fn encrypt(&self, n: &Nonce, msg: &mut Vec<u8>) -> Result<Capsule> {
        let (k, cap) = self.encapsulate();

        let sk = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Encrypt)?;
        let tl = aead::CHACHA20_POLY1305.tag_len();
        let ad = bincode::serialize(&cap).map_err(|_| Error::Serialise)?;

        msg.extend(iter::repeat(0).take(tl));
        let out_len = aead::seal_in_place(&sk, n, &ad, msg, tl).map_err(|_| Error::Encrypt)?;
        msg.truncate(out_len);

        Ok(cap)
    }
}


/// Re-encryption key fragment.
/// This key fragment belongs to one proxy node, which uses it on incoming key capsules to
/// create a capsule fragment, which Bob can use for recovering the symmetric encryption key.
///
// Cf. section 3.2.2 (6f)
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyFragment {
    id: Scalar,
    rk: Scalar,
    pk_x: PublicKey,
    U_1: RistrettoPoint,
    z_1: Scalar,
    z_2: Scalar
}

impl KeyFragment {
    /// Create a capsule fragment, *t* of which are needed for a successult decryption of
    /// ciphertext by Bob.
    ///
    // 3.2.4 (ReEncapsulate)
    pub fn re_encapsulate(&self, cap: &Capsule) -> Result<CapsuleFragment> {
        if !cap.check() {
            return Err(Error::InvalidCapsule)
        }
        let E_1 = cap.E * self.rk;
        let V_1 = cap.V * self.rk;

        let rng = &mut thread_rng();

        // proof generation (4.1)

        // 4.1 (1)
        let t = Scalar::random(rng);

        // 4.1 (2)
        let E_2 = cap.E * t;
        let V_2 = cap.V * t;
        let U_2 = &*U * &t;

        // 4.1 (3)
        let h = hash(&[
            cap.E.compress().as_bytes(),
            E_1.compress().as_bytes(),
            E_2.compress().as_bytes(),
            cap.V.compress().as_bytes(),
            V_1.compress().as_bytes(),
            V_2.compress().as_bytes(),
            U.basepoint().compress().as_bytes(),
            self.U_1.compress().as_bytes(),
            U_2.compress().as_bytes()
        ]);

        // 4.1 (4)
        let p = t + h * self.rk;

        Ok(CapsuleFragment {
            E_1,
            V_1,
            id: self.id,
            pk_x: self.pk_x.clone(),
            pi: Proof {
                E_2,
                V_2,
                U_2,
                U_1: self.U_1,
                z_1: self.z_1,
                z_2: self.z_2,
                p
            }
        })
    }
}


#[cfg(test)]
mod attacks {
    use super::*;

    // Bob and the proxy team up to recover Alice's secret key.
    #[test]
    fn collusion_bob_proxy_1() -> Result<()> {
        let alice = Keypair::new();
        let bob = Keypair::new();

        // The proxy possesses kfrag. It contains rk = a / d for t = 1.
        let kfrag = &alice.rekey(bob.public(), 1, 1)[0];

        let d = {
            hash(&[
                kfrag.pk_x.point.compress().as_bytes(),
                bob.public.point.compress().as_bytes(),
                (kfrag.pk_x.point * bob.secret.scalar).compress().as_bytes()
            ])
        };

        // The collusion: The proxy gave Bob its key fragment. Now Bob can recover Alice's secret:
        let a = kfrag.rk * d;
        assert_eq!(a.as_bytes(), alice.secret().scalar.as_bytes());

        Ok(())
    }


    // Bob and t out of n proxies team up to recover Alice's secret key.
    #[test]
    fn collusion_bob_proxy_n_t() -> Result<()> {
        let alice = Keypair::new();
        let bob = Keypair::new();

        let n = 6;
        let t = 3;

        let kfrags = alice.rekey(bob.public(), n, t);

        let pk_x = &kfrags[0].pk_x; // the ephemeral public key is shared over all fragments

        let d = {
            hash(&[
                pk_x.point.compress().as_bytes(),
                bob.public.point.compress().as_bytes(),
                (pk_x.point * bob.secret.scalar).compress().as_bytes()
            ])
        };

        let D = hash(&[
            alice.public().point.compress().as_bytes(),
            bob.public().point.compress().as_bytes(),
            (alice.public().point * bob.secret().scalar).compress().as_bytes()
        ]);

        // Bob recomputes the xs of the polynomial
        let mut S = Vector::with_capacity(kfrags.len());
        for kf in &kfrags[0 .. t] {
            let sx_i = hash(&[kf.id.as_bytes(), D.as_bytes()]);
            S.push(sx_i);
        }

        // Bob recomputes the re-encryption key by interpolating the polynomial with
        // the key fragments, the t proxies gave to him.
        let mut numer = Vector::with_capacity(S.len());
        let mut denum = Vector::with_capacity(S.len());
        for i in 0 .. S.len() {
            let (n, d) = S.iter()
                .enumerate()
                .fold((Scalar::one(), Scalar::one()), |(n, d), (j, s)| {
                    if i == j {
                        return (n, d)
                    }
                    (n * *s, d * (*s - S[i]))
                });
            numer.push(kfrags[i].rk * n);
            denum.push(d.invert());
        }
        let mut rk = Scalar::zero();
        for (n, d) in numer.iter().zip(denum.iter()) {
            rk += n * d
        }

        // Finally, Bob is able to recover Alice's secret:
        let a = rk * d;
        assert_eq!(a.as_bytes(), alice.secret().scalar.as_bytes());

        Ok(())
    }
}
