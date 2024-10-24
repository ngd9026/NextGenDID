use criterion::{black_box, criterion_group, criterion_main, Criterion};
use vrf::openssl::{CipherSuite, ECVRF};
use vrf::VRF;
use hex;

fn benchmark_prove(c: &mut Criterion) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let message = b"sample";

    c.bench_function("VRF Prove - SECP256K1_SHA256_TAI", |b| {
        b.iter(|| {
            let _ = vrf.prove(black_box(&secret_key), black_box(message)).unwrap();
        });
    });
}

fn benchmark_verify(c: &mut Criterion) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let message = b"sample";
    let proof = vrf.prove(&secret_key, message).unwrap();

    c.bench_function("VRF Verify - SECP256K1_SHA256_TAI", |b| {
        b.iter(|| {
            let _ = vrf.verify(black_box(&public_key), black_box(&proof), black_box(message)).unwrap();
        });
    });
}

fn benchmark_sign_counter_init(c: &mut Criterion) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    c.bench_function("VRF Sign Counter Init - SECP256K1_SHA256_TAI", |b| {
        b.iter(|| {
            let _ = vrf.sign_counter_init(black_box(&secret_key)).unwrap();
        });
    });

}
fn benchmark_validate_counter_init_signature(c: &mut Criterion) {
    let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();
    let secret_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let public_key = vrf.derive_public_key(&secret_key).unwrap();
    let signature = vrf.sign_counter_init(&secret_key).unwrap();

    c.bench_function("VRF Validate Counter Init Signature - SECP256K1_SHA256_TAI", |b| {
        b.iter(|| {
            let _ = vrf.validate_counter_init_signature(black_box(&public_key), black_box(&signature)).unwrap();
        });
    });
}

criterion_group!(
    benches, 
    benchmark_prove, 
    benchmark_verify, 
    benchmark_sign_counter_init, 
    benchmark_validate_counter_init_signature
);
criterion_main!(benches);
