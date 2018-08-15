extern crate pre;
extern crate rand;

use rand::{distributions::Standard, Rng, thread_rng};

#[test]
fn encapsulate_decapsulate() {
    let alice = pre::Keypair::new();
    let (k_e, cap) = alice.public().encapsulate();

    let k_d = alice.secret().decapsulate(&cap).unwrap();
    assert_eq!(k_e, k_d);

    let k_r = thread_rng().sample_iter(&Standard).take(64).collect::<Vec<_>>();
    assert_ne!(k_e.as_ref(), k_r.as_slice())
}


