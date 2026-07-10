# Repository Guidelines

## Design Goals (MoonBlokz Part VI)
- Prioritize `no_std`, microcontroller-friendly crypto paths (RP2040-class constraints).
- Optimize for small on-chain and radio payloads: compact signatures and bounded aggregated-signature serialization.
- Prefer fast verification over fast signing (verification dominates node workload).
- Preserve support for aggregation-ready signatures and aggregated approval evidence workflows.
- Keep implementations swappable at compile time through feature flags.

## Project Structure & Module Organization
- `src/lib.rs` defines public traits, constants, feature gates, compile-time checks, and re-exports.
- `src/schnorr_malachite_signer.rs`, `src/schnorr_num_bigint_dig_signer.rs`, and `src/schnorr_crypto_bigint_signer.rs` hold Schnorr backend implementations.
- `src/bls_bls12_381_bls_signer.rs` holds the BLS backend implementation.
- Tests live inline under `#[cfg(test)]` in `src/lib.rs` (no separate `tests/` directory).
- `run_tests.sh` runs multi-feature coverage with `cargo llvm-cov` and `nextest`.

## Build, Test, and Development Commands
- `cargo build --no-default-features --features schnorr-malachite` builds the default Schnorr backend explicitly.
- `cargo build --no-default-features --features schnorr-num-bigint-dig` builds the alternate big-integer Schnorr backend.
- `cargo build --no-default-features --features schnorr-crypto-bigint` builds the fixed-width arithmetic Schnorr backend.
- `cargo build --no-default-features --features bls-bls12_381-bls` builds the BLS backend.
- `cargo test` runs the default feature test suite only.
- `cargo test --no-default-features --features <feature>` runs tests for one selected backend.
- `./run_tests.sh` generates multi-feature coverage and writes `target/lcov.info`.
- `cargo doc --open` builds local API docs (see README).

## Coding Style & Naming Conventions
- Rust 2024 edition, `#![no_std]` crate; keep code `no_std`-friendly.
- Use rustfmt defaults (4-space indentation) and standard Rust naming: `snake_case` for modules/functions, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep feature-gated code behind the existing feature flags; only one concrete crypto backend should be enabled at a time.
- Avoid introducing heap-dependent APIs for core signature flows unless strictly necessary.

## Crypto Architecture Conventions
- Keep the two-layer feature model intact:
  - Algorithm family layer: `schnorr` / `bls`.
  - Concrete backend layer: `schnorr-malachite`, `schnorr-num-bigint-dig`, `schnorr-crypto-bigint`, `bls-bls12_381-bls`.
- Maintain compile-time exclusivity checks (`compile_error!`) for “exactly one implementation enabled”.
- Preserve the shared public API across implementations (`Crypto`, `PublicKey`, `Signature`, `MultiSignature`, `AggregatedSignature`) to keep embedding projects unchanged.
- Preserve algorithm-dependent constant sizes in `src/lib.rs` when changing serialization formats.
- Keep terminology consistent:
  - `Signature` = ordinary single-signer artifact
  - `MultiSignature` = aggregation-ready single-signer artifact
  - `AggregatedSignature` = combined multi-party evidence artifact

## Algorithm Notes From Part VI and Current Code
- Schnorr:
  - Uses deterministic nonce generation (tagged hash + counter) rather than runtime RNG dependence.
  - Uses deterministically weighted aggregation with stored per-signer `r` components.
  - Uses compact `x`-only public-key serialization with even-`y` reconstruction.
  - In public API terms, `sign()` and `multi_sign()` differ by role type even when underlying math is shared.
- BLS:
  - Is kept as a wrapper implementation (`bls12_381-bls` ecosystem) and retained as a swappable option.
  - Provides constant-sized aggregated-signature bodies aside from the count prefix.
- Tradeoff direction from the article and current crate structure: design for replaceability first, so future algorithm or library swaps do not require upstream API changes.

## Testing Guidelines
- Tests use Rust’s built-in test harness in `src/lib.rs`.
- Prefer adding coverage for key behaviors: signing, verification, serialization, aggregation, and negative validation cases.
- If adding a new backend or changing behavior, include at least one positive and one negative test and run the relevant feature-specific command.
- Do not rely on `cargo test` alone for crypto changes; it only validates the default backend.
- For behavior changes, run all supported backend variants via `./run_tests.sh`.
- If touching byte-level serialization or aggregation semantics, consider adding or updating regression vectors.

## Commit & Pull Request Guidelines
- Commit messages are short, sentence-style updates (e.g., “Added more unit tests”, “Update signature aggregation…”). Keep them descriptive without prefixes.
- PRs should describe the backend feature(s) used for testing and include the command output or `run_tests.sh` result when behavior changes.

## Security & Configuration Tips
- Only one crypto backend feature can be enabled at a time; use `--no-default-features` to avoid conflicts.
- Default feature is `schnorr-malachite` (see `Cargo.toml`).
- If touching `schnorr-num-bigint-dig`, remember it depends on the repository’s forked source configured in `Cargo.toml`.
- If shipping binaries that include `schnorr-malachite`, review LGPL-3.0 relinking or rebuild obligations described in the article context and dependency licenses.
- Distinguish clearly between the crate’s own license metadata and the licenses of enabled dependencies.

## Further Information
- MoonBlokz Series Part VI (Medium): https://medium.com/moonblokz/moonblokz-series-part-vi-crypto-algorithms-942d4a28fdc7
