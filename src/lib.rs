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

extern crate bincode;
extern crate blake2; // needed for `Digest` impl
extern crate blake2b_simd;
extern crate curve25519_dalek;
extern crate hkdf;
#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate smallvec;
extern crate subtle;

mod capsule;
mod error;
mod key;
mod keypair;
mod point;
mod scalar;
mod util;

use curve25519_dalek::{constants, ristretto::{CompressedRistretto, RistrettoBasepointTable}};

pub use capsule::{Capsule, CapsuleFragment};
pub use error::Error;
pub use key::{Key, Nonce};
pub use keypair::{Keypair, SecretKey, PublicKey, KeyFragment};


// Generator element `g` (cf. section 3.2.1).
pub(crate) const g: RistrettoBasepointTable = constants::RISTRETTO_BASEPOINT_TABLE;

lazy_static! {
    // Generator element `U` (cf. section 3.2.1).
    pub(crate) static ref U: RistrettoBasepointTable = {
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

