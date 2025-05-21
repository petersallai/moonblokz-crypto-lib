cargo llvm-cov clean
cargo llvm-cov clean
rm target/lcov.info
cargo llvm-cov nextest --no-report --no-default-features --features bls-bls12_381-bls --output-path ./target/lcov.info
cargo llvm-cov nextest --no-report --no-default-features --features schnorr-malachite --output-path ./target/lcov.info
cargo llvm-cov nextest --no-report --no-default-features --features schnorr-num-bigint-dig --output-path ./target/lcov.info
cargo llvm-cov report --lcov --output-path ./target/lcov.info
