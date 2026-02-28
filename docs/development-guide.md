# Development Guide

## Prerequisites

- Rust toolchain with Cargo
- Recommended for coverage flow: `cargo-llvm-cov`, `cargo-nextest`

## Build

```sh
cd /Users/slp/moonblokz/moonblokz-crypto-lib
cargo build
```

## Test Commands

```sh
cargo test
cargo test --no-default-features --features schnorr-malachite
cargo test --no-default-features --features schnorr-num-bigint-dig
cargo test --no-default-features --features bls-bls12_381-bls
./run_tests.sh
```

## Common Tasks

- Validate feature exclusivity behavior when changing `Cargo.toml` features.
- Add tests for positive and negative crypto behavior paths.
- Keep `no_std` constraints intact.

## Coding Conventions

- Standard rustfmt formatting and naming conventions.
- Preserve trait-level API compatibility unless explicitly planning a breaking change.
