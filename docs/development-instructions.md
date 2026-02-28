# Development Instructions

## Prerequisites

- Rust toolchain with Cargo (Rust 2024 edition project).
- Optional tools used by project script:
  - `cargo-llvm-cov`
  - `cargo-nextest`

## Setup

```sh
cd /Users/slp/moonblokz/moonblokz-crypto-lib
cargo build
```

## Feature-Scoped Build/Test Commands

```sh
cargo test
cargo test --no-default-features --features schnorr-malachite
cargo test --no-default-features --features schnorr-num-bigint-dig
cargo test --no-default-features --features bls-bls12_381-bls
```

## Full Feature Matrix + Coverage

```sh
./run_tests.sh
```

`run_tests.sh` workflow:
- `cargo llvm-cov clean`
- Removes `target/lcov.info`
- Runs `cargo llvm-cov nextest` per feature variant
- Generates consolidated LCOV report

## Development Rules

- Keep `#![no_std]` compatibility.
- Enable exactly one crypto implementation feature at build time.
- Keep shared trait surface in `src/lib.rs` stable unless intentionally breaking.
- Add both positive and negative tests for behavior changes.
