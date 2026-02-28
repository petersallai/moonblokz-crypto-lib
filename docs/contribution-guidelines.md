# Contribution Guidelines

Consolidated from repository docs (`AGENTS.md`, `README.md`).

## Code Standards

- Rustfmt defaults (4 spaces), standard Rust naming conventions.
- Preserve `no_std` and bounded behavior expectations.
- Avoid unnecessary heap-dependent APIs in core signature paths.

## Architecture Constraints

- Maintain two-layer feature model (`schnorr`/`bls` algorithm layer, implementation layer features).
- Preserve compile-time exclusivity (exactly one implementation enabled).
- Keep trait-level API compatibility across implementations.

## Testing Expectations

- Add tests in `src/lib.rs` under existing harness.
- Include positive + negative tests for changed behavior.
- Validate all feature variants, not default-only:
  - `cargo test`
  - `cargo test --no-default-features --features ...`
  - `./run_tests.sh`

## Change Submission Notes

- Keep commits behavior-scoped and descriptive.
- Include executed test commands and feature flags in PR notes.
