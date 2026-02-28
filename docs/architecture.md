# Architecture

## Executive Summary

`moonblokz-crypto-lib` is a `no_std` Rust library providing a stable cryptographic signing/verification interface with compile-time swappable backends. The crate uses feature-gated modules to select one implementation at build time while preserving a shared trait API for downstream MoonBlokz components.

## Technology Stack

- Language: Rust (edition 2024)
- Build/package: Cargo
- Core crypto dependencies (feature-gated):
  - Schnorr: `malachite-*` or `num-bigint-dig` + `num-traits`
  - BLS: `bls12_381-bls` + `dusk-*`
- Hash utility for Schnorr paths: `sha2`

## Architecture Pattern

- Pattern: Feature-gated strategy/wrapper library
- Project type: `library` (single-part monolith)
- Key properties:
  - Stable trait boundary in `src/lib.rs`
  - Backend implementations in isolated modules
  - Compile-time exclusivity (`compile_error!`) enforces exactly one implementation

## Public Contract Layer

The primary integration boundary is in `src/lib.rs`:
- Traits: `CryptoTrait`, `PublicKeyTrait`, `SignatureTrait`, `MultiSignatureTrait`, `AggregatedSignatureTrait`
- Shared error type: `CryptoError`
- Algorithm-dependent size constants and bounded aggregation buffer constants

This layer is designed for backend replaceability without upstream API churn.

## Backend Modules

- `src/schnorr_malachite_signer.rs`
- `src/schnorr_num_bigint_dig_signer.rs`
- `src/bls_bls12_381_bls_signer.rs`

Selection is compile-time via features:
- `schnorr-malachite` (default)
- `schnorr-num-bigint-dig`
- `bls-bls12_381-bls`

## Data/Serialization Architecture

- Signature/public-key sizes are algorithm-dependent constants.
- Aggregated signatures use bounded serialization limits (`MAX_AGGREGATED_SIGNATURES`, `MAX_AGGREGATED_SIGNATURE_BYTES`).
- Design emphasis aligns with MoonBlokz Part VI priorities: compact payloads, verification efficiency, and deterministic behavior for constrained devices.

## API Design

- Library API exposes signing, verification, multi-signature creation, aggregation, and aggregated verification.
- No network/API server surface; this is an in-process dependency API only.

## Source Tree (Relevant)

- `Cargo.toml`: dependencies and feature matrix
- `src/lib.rs`: entrypoint, trait contracts, feature checks
- `src/*_signer.rs`: implementation modules
- `run_tests.sh`: feature-matrix test orchestration

## Development Workflow

- Build/test with one active implementation feature.
- Validate default and all non-default feature paths.
- Use `run_tests.sh` for coverage-oriented matrix execution.

## Deployment/Distribution

- Distributed as a Cargo dependency (git/crate usage model).
- No runtime deployment manifests (Docker/k8s/service) expected.

## Testing Strategy

- Unit/integration-style tests are embedded in `src/lib.rs` under `#[cfg(test)]`.
- Test coverage targets:
  - positive/negative signing and verification
  - serialization/deserialization
  - aggregate signature behavior and edge cases
- Feature-specific validation required beyond default `cargo test`.

## Constraints and Invariants

- `#![no_std]` must remain intact.
- Exactly one implementation feature must be enabled.
- Shared trait API compatibility should be preserved for downstream users.
- Changes to serialization constants require coordinated tests and compatibility notes.
