# Contribution Guide

## Scope and Constraints

- Keep the crate `no_std` friendly.
- Maintain compile-time one-feature-only exclusivity model.
- Preserve stable trait surface in `src/lib.rs`.

## Testing Requirements

Run at least:

```sh
cargo test
cargo test --no-default-features --features schnorr-malachite
cargo test --no-default-features --features schnorr-num-bigint-dig
cargo test --no-default-features --features bls-bls12_381-bls
```

For coverage matrix:

```sh
./run_tests.sh
```

## Change Documentation

- Include which feature variants were validated.
- Note serialization-size or compatibility-impacting changes explicitly.
- Keep changes behavior-scoped and easy to review.
