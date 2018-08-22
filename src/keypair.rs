use bincode;
use capsule::{Capsule, CapsuleFrag};
use curve25519_dalek::{ristretto::RistrettoPoint, traits::MultiscalarMul};
use error::Error;
use key::Key;
use point::Point;
use rand::prelude::*;
use ring::aead;
use scalar::Scalar;
use smallvec::SmallVec;
use std::iter;
use util::{hash, kdf};
use {g, U};

type Vector<T> = SmallVec<[T; 8]>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey
}

impl Keypair {
    /// Creates a fresh public and private key.
    // 3.2.2 (KeyGen)
    pub fn new() -> Self {
        let s = Scalar::random(&mut thread_rng());
        let p = &g * &s;
        Keypair {
            secret: SecretKey { scalar: s },
            public: PublicKey { point: Point(p) }
        }
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Given a public key, create `n` re-encryption key fragments, out of which `t`
    /// are sufficient to generate capsule fragments which can be used for decrypting
    /// ciphertext encrypted with this keypair's public key.
    ///
    /// Each key fragment is used by a proxy node to create capsule fragments.
    // 3.2.2 (ReKeyGen)
    pub fn rekey(&self, pk_b: &PublicKey, n: usize, t: usize) -> Vec<Kfrag> {
        assert!(t >  0);
        assert!(n >= t);

        let rng = &mut thread_rng();

        // 3.2.2 (1):
        let ephemeral = Keypair::new(); // (x_a, X_a)

        // 3.2.2 (2):
        let d = hash(&[
            ephemeral.public.point.compress().as_bytes(),
            pk_b.point.compress().as_bytes(),
            (*pk_b.point * *ephemeral.secret.scalar).compress().as_bytes()
        ]);

        // 3.2.2 (3):
        let mut coeff = Vector::with_capacity(t - 1);
        for _ in 0 .. t - 1 {
            coeff.push(Scalar::random(rng))
        }

        let f_0 = *self.secret.scalar * d.invert(); // the secret to share

        // 3.2.2 (4):
        let f = |x: Scalar| {
            let mut y = f_0;
            let mut k = x;
            for c in coeff.iter().take(t - 1) {
                y  += (**c) * (*k);
                *k *= *x
            }
            Scalar(y)
        };

        // 3.2.2 (5):
        let D = hash(&[
            self.public.point.compress().as_bytes(),
            pk_b.point.compress().as_bytes(),
            (*pk_b.point * *self.secret.scalar).compress().as_bytes()
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

            // 3.2.2 (6e):
            let z_1 = hash(&[
                Y.as_bytes(),
                id.as_bytes(),
                self.public.point.compress().as_bytes(),
                pk_b.point.compress().as_bytes(),
                U_1.compress().as_bytes(),
                ephemeral.public.point.compress().as_bytes()
            ]);

            let z_2 = Scalar((*y) - *self.secret.scalar * (*z_1));

            KF.push(Kfrag { id, rk, pk_x: ephemeral.public.clone(), u_1: Point(U_1), z_1, z_2 })
        }
        KF.into_vec()
    }

    /// Reconstruct the symmetric encryption key, given the public key used for encryption
    /// and at least `t` out of `n` capsule fragments.
    // 3.2.4 (DecapsulateFrags)
    pub fn decapsulate_frags(&self, pk_a: &PublicKey, cfrags: &[CapsuleFrag]) -> Result<Key, Error> {
        if cfrags.is_empty() {
            return Err(Error::Empty)
        }

        // 3.2.4 (1):
        let D = hash(&[
            pk_a.point.compress().as_bytes(),
            self.public.point.compress().as_bytes(),
            (*pk_a.point * *self.secret.scalar).compress().as_bytes()
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
                    (Scalar((*n) * (**s)), Scalar((*d) * ((**s) - (*S[i]))))
                });
            numer.push((*cfrags[i].E_1) * (*n) + (*cfrags[i].V_1) * (*n));
            denum.push(d.invert());
        }
        let point = RistrettoPoint::multiscalar_mul(&denum, &numer);

        // 3.2.4 (4):
        let d = {
            let cfrag = &cfrags[0]; // all fragments share the same ephemeral public key:
            hash(&[
                cfrag.pk_x.point.compress().as_bytes(),
                self.public.point.compress().as_bytes(),
                (*cfrag.pk_x.point * *self.secret.scalar).compress().as_bytes()
            ])
        };

        // 3.2.4 (5):
        Ok(kdf((point * *d).compress().as_bytes())) // cf. 2.1 and RFC 6090 (App. E)
    }

    /// Decrypt ciphertext encrypted with public key `pk_a` and the given none.
    /// In order to succeed, we need at least `t` out of `n` cpasule fragments from `t` proxies
    /// plus the capsule itself that was generated during encryption.
    pub fn decrypt<'a>(&self, pk_a: &PublicKey, nonce: &[u8; 12], cap: &Capsule, cfrags: &[CapsuleFrag], cipher: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let k = self.decapsulate_frags(pk_a, cfrags)?;
        let ok = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Decrypt)?;
        let ad = bincode::serialize(cap).map_err(|_| Error::Serialise)?;
        Ok(&aead::open_in_place(&ok, nonce, &ad, 0, cipher).map_err(|_| Error::Decrypt)?[..])
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecretKey {
    scalar: Scalar
}

impl SecretKey {
    /// Restore the symmetric encryption key from the capsule.
    // 3.2.3
    pub fn decapsulate(&self, cap: &Capsule) -> Result<Key, Error> {
        if !cap.check() {
            return Err(Error::InvalidCapsule)
        }
        Ok(kdf(((*cap.E + *cap.V) * *self.scalar).compress().as_bytes()))
    }

    pub fn decrypt<'a>(&self, nonce: &[u8; 12], cap: &Capsule, cipher: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let k = self.decapsulate(cap)?;
        let ok = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Decrypt)?;
        let ad = bincode::serialize(cap).map_err(|_| Error::Serialise)?;
        Ok(&aead::open_in_place(&ok, nonce, &ad, 0, cipher).map_err(|_| Error::Decrypt)?[..])
    }
}


#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    point: Point
}

impl PublicKey {
    // 3.2.3
    pub fn encapsulate(&self) -> (Key, Capsule) {
        let rng = &mut thread_rng();
        let r = Scalar::random(rng);
        let u = Scalar::random(rng);
        let E = &g * &r;
        let V = &g * &u;
        let s = *u + *r * (*hash(&[E.compress().as_bytes(), V.compress().as_bytes()]));
        let k = kdf((*self.point * (*r + *u)).compress().as_bytes());
        let c = Capsule { E: Point(E), V: Point(V), s: Scalar(s) };
        (k, c)
    }

    pub fn encrypt(&self, nonce: &[u8; 12], msg: &mut Vec<u8>) -> Result<Capsule, Error> {
        let (k, cap) = self.encapsulate();

        let sk = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &k).map_err(|_| Error::Encrypt)?;
        let tl = aead::CHACHA20_POLY1305.tag_len();
        let ad = bincode::serialize(&cap).map_err(|_| Error::Serialise)?;

        msg.extend(iter::repeat(0).take(tl));
        let out_len = aead::seal_in_place(&sk, nonce, &ad, msg, tl).map_err(|_| Error::Encrypt)?;
        msg.truncate(out_len);

        Ok(cap)
    }
}


/// Re-encryption key fragment
// Cf. section 3.2.2 (6f)
#[derive(Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Kfrag {
    id: Scalar,
    rk: Scalar,
    pk_x: PublicKey,
    u_1: Point,
    z_1: Scalar,
    z_2: Scalar
}

impl Kfrag {
    // 3.2.4 (ReEncapsulate)
    pub fn re_encapsulate(&self, cap: &Capsule) -> Result<CapsuleFrag, Error> {
        if !cap.check() {
            return Err(Error::InvalidCapsule)
        }
        let E_1 = *cap.E * *self.rk;
        let V_1 = *cap.V * *self.rk;
        Ok(CapsuleFrag { E_1: Point(E_1), V_1: Point(V_1), id: self.id, pk_x: self.pk_x.clone() })
    }
}

