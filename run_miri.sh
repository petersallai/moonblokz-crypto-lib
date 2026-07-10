# Only bls-bls12_381-bls has unsafe code (bls_bls12_381_bls_signer.rs); the
# other three backends are pure safe Rust and gain nothing from Miri.
cargo +nightly miri test --no-default-features --features bls-bls12_381-bls
