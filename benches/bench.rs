use criterion::{criterion_group, criterion_main, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rune_ring::{generate_shared_a, keygen, ring_sign, ring_verify, RUNE_128};

fn sign_verify_benchmark(c: &mut Criterion) {
    let params = &RUNE_128;
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let a = generate_shared_a(params, &mut rng);
    let mut ring = Vec::with_capacity(3);
    let mut keys = Vec::with_capacity(3);

    for _ in 0..3 {
        let (pk, sk) = keygen(&a, params, &mut rng).expect("fresh shared a is valid");
        ring.push(pk);
        keys.push(sk);
    }

    c.bench_function("sign_k3", |b| {
        b.iter(|| {
            let mut local_rng = ChaCha20Rng::seed_from_u64(100);
            ring_sign(
                b"benchmark message",
                1,
                &keys[1],
                &ring,
                params,
                &mut local_rng,
            )
            .expect("benchmark signing succeeds")
        });
    });

    let mut sign_rng = ChaCha20Rng::seed_from_u64(101);
    let sig = ring_sign(
        b"benchmark message",
        1,
        &keys[1],
        &ring,
        params,
        &mut sign_rng,
    )
    .expect("benchmark signing succeeds");

    c.bench_function("verify_k3", |b| {
        b.iter(|| {
            ring_verify(b"benchmark message", &sig, &ring, params)
                .expect("benchmark verification does not error")
        });
    });
}

criterion_group!(benches, sign_verify_benchmark);
criterion_main!(benches);
