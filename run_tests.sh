#!/bin/sh
# Runs the gates for every backend feature: tests with coverage, clippy and rustfmt.
# The crate forbids `unsafe` (`#![forbid(unsafe_code)]`), so there is no Miri gate.
set -e
cargo fmt --check
cargo llvm-cov clean
rm -f target/lcov.info
for backend in schnorr bls-min-sig bls-min-pk; do
    cargo clippy --all-targets --no-default-features --features "$backend" -- -D warnings
    cargo llvm-cov nextest --no-report --no-default-features --features "$backend" --output-path ./target/lcov.info
done
cargo llvm-cov report --lcov --output-path ./target/lcov.info
