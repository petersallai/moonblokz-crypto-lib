# Repository Guidelines

## Design Goals (MoonBlokz Part VI)
- Prioritize `no_std`, microcontroller-friendly crypto paths (RP2040-class constraints).
- Optimize for small on-chain/radio payloads: compact signatures and compact serialized aggregation.
- Prefer fast verification over fast signing (verification dominates node workload).
- Preserve aggregation support for approval/evidence workflows.
- Keep implementations swappable at compile time through feature flags.

## Project Structure & Module Organization
- `src/lib.rs` defines public traits, feature gates, and re-exports.
- `src/schnorr_malachite_signer.rs`, `src/schnorr_num_bigint_dig_signer.rs`, and `src/bls_bls12_381_bls_signer.rs` hold algorithm-specific implementations.
- Tests live inline under `#[cfg(test)]` in `src/lib.rs` (no separate `tests/` directory).
- `run_tests.sh` runs multi-feature coverage with `cargo llvm-cov` and `nextest`.

## Build, Test, and Development Commands
- `cargo build --no-default-features --features schnorr-num-bigint-dig` builds a specific implementation.
- `cargo test` runs the default feature test suite.
- `cargo test --no-default-features --features schnorr-malachite` runs tests for a single feature.
- `./run_tests.sh` generates multi-feature coverage and writes `target/lcov.info`.
- `cargo doc --open` builds local API docs (see README).

## Coding Style & Naming Conventions
- Rust 2024 edition, `#![no_std]` crate; keep code `no_std`-friendly.
- Use rustfmt defaults (4-space indentation) and standard Rust naming: `snake_case` for modules/functions, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep feature-gated code behind the existing feature flags; only one crypto feature should be enabled at a time.
- Avoid introducing heap-dependent APIs for core signature flows unless strictly necessary.

## Crypto Architecture Conventions
- Keep the two-layer feature model intact:
  - Algorithm layer: `schnorr` / `bls`.
  - Implementation layer: `schnorr-malachite`, `schnorr-num-bigint-dig`, `bls-bls12_381-bls`.
- Maintain compile-time exclusivity checks (`compile_error!`) for “exactly one implementation enabled”.
- Preserve shared trait-level API across implementations (`Crypto`, `PublicKey`, `Signature`, `MultiSignature`, `AggregatedSignature`) to keep embedding projects unchanged.
- Preserve algorithm-dependent constant sizes in `src/lib.rs` when changing serialization formats.

## Algorithm Notes From Part VI
- Schnorr:
  - Uses deterministic nonce generation (tagged hash + counter) rather than runtime RNG dependence.
  - Uses “half-aggregation”: aggregate scalar parts while keeping per-signer public nonces for challenge recomputation.
  - Current serialized aggregated-size model is `n*32 + 32 + 2` (plus signer identifiers at protocol level).
- BLS:
  - Kept as a wrapper implementation (`bls12_381-bls` ecosystem) and retained as a swappable option.
- Tradeoff direction from the article: design for replaceability first, so future algorithm/library swaps do not require upstream API changes.

## Testing Guidelines
- Tests use Rust’s built-in test harness in `src/lib.rs`.
- Prefer adding coverage for key types: signing, verification, serialization, and aggregation.
- If adding a new feature or signer, include at least one positive and one negative test and run the relevant feature-specific command.
- Do not rely on `cargo test` alone for crypto changes; it only validates the default feature.
- For behavior changes, run all feature variants via `./run_tests.sh`.

## Commit & Pull Request Guidelines
- Commit messages are short, sentence-style updates (e.g., “Added more unit tests”, “Update signature aggregation…”). Keep them descriptive without prefixes.
- PRs should describe the feature flag used for testing and include the command output (or `run_tests.sh`) when behavior changes.

## Security & Configuration Tips
- Only one crypto feature can be enabled at a time; use `--no-default-features` to avoid conflicts.
- Default feature is `schnorr-malachite` (see `Cargo.toml`).
- If touching `schnorr-num-bigint-dig`, remember it depends on the repository’s forked source configured in `Cargo.toml`.
- If shipping binaries that include `schnorr-malachite`, review LGPL-3.0 relinking/rebuild obligations described in the article context.

## Further Information
- MoonBlokz Series Part VI (Medium): https://medium.com/moonblokz/moonblokz-series-part-vi-crypto-algorithms-942d4a28fdc7
