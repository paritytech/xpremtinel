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

fn rekey_n_t(n: usize, t: usize) -> Result<(), pre::Error> {
    let alice = pre::Keypair::new();
    let bob = pre::Keypair::new();

    let (k, cap) = alice.public().encapsulate();
    let kfrags = alice.rekey(bob.public(), n, t);
    let mut cfrags = Vec::with_capacity(kfrags.len());
    for kfrag_i in kfrags {
        cfrags.push(kfrag_i.re_encapsulate(&cap)?)
    }
    assert_eq!(k, bob.decapsulate_frags(alice.public(), &cfrags[0..t])?);
    Ok(())
}

#[test]
fn rekey() -> Result<(), pre::Error> {
    rekey_n_t(1, 1)?;
    rekey_n_t(2, 2)?;
    rekey_n_t(3, 3)?;
    // rekey_n_t(4, 4)?; // FIXME
    rekey_n_t(2, 1)?;
    rekey_n_t(3, 1)?;
    rekey_n_t(4, 1)?;
    rekey_n_t(3, 2)?;
    rekey_n_t(4, 2)?;
    rekey_n_t(4, 3)?;
    rekey_n_t(6, 3)?;
    Ok(())
}

