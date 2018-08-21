extern crate pre;
extern crate rand;

use rand::{distributions::Standard, Rng, thread_rng};

#[test]
fn encapsulate_decapsulate() -> Result<(), pre::Error> {
    let alice = pre::Keypair::new();
    let (k_e, cap) = alice.public().encapsulate();

    let k_d = alice.secret().decapsulate(&cap)?;
    assert_eq!(k_e, k_d);

    let k_r = thread_rng().sample_iter(&Standard).take(64).collect::<Vec<_>>();
    assert_ne!(k_e.as_ref(), k_r.as_slice());
    Ok(())
}


#[test]
fn rekey() -> Result<(), pre::Error> {
    fn rekey_n_t(n: usize, t: usize) -> Result<(), pre::Error> {
        let alice = pre::Keypair::new();
        let bob = pre::Keypair::new();

        let (k, cap) = alice.public().encapsulate();
        let kfrags = alice.rekey(bob.public(), n, t);
        let mut cfrags = Vec::with_capacity(kfrags.len());
        for kfrag_i in kfrags {
            cfrags.push(kfrag_i.re_encapsulate(&cap)?)
        }
        assert_eq!(k, bob.decapsulate_frags(alice.public(), &cfrags[..t])?, "n={}, t={}", n, t);
        Ok(())
    }

    for n in 1 ..= 6 {
        for t in 1 ..= n {
            rekey_n_t(n, t)?;
        }
    }

    Ok(())
}


#[test]
fn encrypt_decrypt() -> Result<(), pre::Error> {
    let alice = pre::Keypair::new();
    let message = b"hello world";
    let nonce = b"123456789012";
    let (capsule, mut cipher) = alice.public().encrypt(nonce, message.to_vec())?;
    let plaintext = alice.secret().decrypt(nonce, &capsule, &mut cipher)?;
    assert_eq!(message, plaintext);
    Ok(())
}


#[test]
fn roundtrip() -> Result<(), pre::Error> {
    let alice = pre::Keypair::new();
    let bob = pre::Keypair::new();

    let message = b"hello world";
    let nonce = b"123456789012";

    let (capsule, mut cipher) = alice.public().encrypt(nonce, message.to_vec())?;

    let kfrags = alice.rekey(bob.public(), 19, 7);
    let mut cfrags = Vec::with_capacity(kfrags.len());
    for kfrag_i in kfrags {
        cfrags.push(kfrag_i.re_encapsulate(&capsule)?)
    }

    let plaintext = bob.decrypt(alice.public(), nonce, &capsule, &cfrags[..7], &mut cipher)?;
    assert_eq!(message, plaintext);
    Ok(())
}


