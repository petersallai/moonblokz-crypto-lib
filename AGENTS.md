# Repository Guidelines

## Design Goals (MoonBlokz Part VI)
- Prioritize `no_std`, microcontroller-friendly crypto paths (RP2040-class constraints).
- Optimize for small on-chain and radio payloads: compact signatures and bounded aggregated-signature serialization.
- Prefer fast verification over fast signing (verification dominates node workload).
- Preserve support for aggregation-ready signatures and aggregated approval evidence workflows.
- Keep the Schnorr / BLS choice selectable at compile time through feature flags.
- Use audited, pure-Rust, `no_std`, allocation-free curve libraries only (no C code).

## Project Structure & Module Organization
- `src/lib.rs` defines public traits, constants, feature gates, compile-time checks, re-exports and the cross-backend tests.
- `src/schnorr_k256_signer.rs` implements `schnorr` (BIP-340 through `k256`, the DEC-194 aggregate, the proof of possession).
- `src/bls_zkcrypto_signer.rs` implements `bls-min-sig` and `bls-min-pk` (zkcrypto `bls12_381`) through one generic core over a private `Variant` trait.
- Tests live inline under `#[cfg(test)]` (no separate `tests/` directory).
- `run_tests.sh` runs fmt, then clippy and `cargo llvm-cov nextest` for every scheme.

## Build, Test, and Development Commands
- `cargo build` builds `schnorr`, the default.
- `cargo build --no-default-features --features bls-min-sig` (or `bls-min-pk`) builds a BLS scheme.
- `cargo test` runs the default scheme only; `cargo test --no-default-features --features <scheme>` runs one scheme.
- `./run_tests.sh` is the gate: fmt, clippy `-D warnings` and coverage for all three schemes, writing `target/lcov.info`.
- `cargo doc --open` builds local API docs.

## Coding Style & Naming Conventions
- Rust 2024 edition, `#![no_std]` crate; keep code `no_std`-friendly.
- Use rustfmt defaults (4-space indentation) and standard Rust naming: `snake_case` for modules/functions, `PascalCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Keep feature-gated code behind the existing feature flags; exactly one scheme is enabled at a time.
- No heap and no `unsafe` (`#![forbid(unsafe_code)]`); fixed-size byte arrays at the API.

## Crypto Architecture Conventions
- Feature names say the scheme, not the implementation (DEC-246): `schnorr`, `bls-min-sig`, `bls-min-pk`; `bls` is a private helper feature that cannot be selected alone.
- Maintain the compile-time exclusivity checks (`compile_error!`) for "exactly one scheme enabled".
- Preserve the shared public API across schemes (`Crypto`, `PublicKey`, `Signature`, `MultiSignature`, `AggregatedSignature`, `CryptoTrait`) so embedding projects stay unchanged.
- Keep the scheme-dependent constant sizes in `src/lib.rs` in step with the serialization.
- Keep terminology consistent:
  - `Signature` = ordinary single-signer artifact
  - `MultiSignature` = aggregation-ready single-signer artifact
  - `AggregatedSignature` = combined multi-party evidence artifact

## Algorithm Notes
- Schnorr (`schnorr`):
  - BIP-340 single signatures, deterministic (zero auxiliary randomness), x-only 32 B keys.
  - DEC-194 aggregate: weights from the tagged hashes `MoonBlokz/aggregate` and `MoonBlokz/weight` bound to all nonces, all keys and the message; `count (u16, big-endian) ‖ s ‖ r_i`; the full point equation is checked one signer at a time (no MSM, for stack).
  - Proof of possession: a BIP-340 signature over the bytes `MoonBlokz/pop ‖ key`.
- BLS (`bls-min-sig`, `bls-min-pk`):
  - IETF BLS signature draft, proof-of-possession suite, in both size variants; private key is a 32 B big-endian scalar.
  - `KeyValidate` refuses the identity and non-subgroup points; aggregation needs every key to carry a verified proof of possession (`PopProve` / `PopVerify` DSTs).
  - Aggregate: `count (u16, big-endian) ‖ point`, constant-sized.

## Testing Guidelines
- Tests use Rust’s built-in test harness in `src/lib.rs`.
- Prefer adding coverage for key behaviors: signing, verification, serialization, aggregation, and negative validation cases.
- If adding a new backend or changing behavior, include at least one positive and one negative test and run the relevant feature-specific command.
- Do not rely on `cargo test` alone for crypto changes; it only validates the default scheme.
- For behavior changes, run all three schemes via `./run_tests.sh`.
- If touching byte-level serialization or aggregation semantics, consider adding or updating regression vectors.

## Commit & Pull Request Guidelines
- Commit messages are short, sentence-style updates (e.g., “Added more unit tests”, “Update signature aggregation…”). Keep them descriptive without prefixes.
- PRs should describe the backend feature(s) used for testing and include the command output or `run_tests.sh` result when behavior changes.

## Security & Configuration Tips
- Only one scheme can be enabled at a time; use `--no-default-features` to select a BLS scheme.
- Default feature is `schnorr` (see `Cargo.toml`).
- `k256` and `bls12_381` are MIT / Apache-2.0; distinguish the crate's own license from its dependencies'.

## Further Information
- MoonBlokz Series Part VI (Medium): https://medium.com/moonblokz/moonblokz-series-part-vi-crypto-algorithms-942d4a28fdc7
