# API Contracts

This repository is a Rust library crate and does not expose network/API server endpoints.

## Public API Surface (Library)

Primary contracts are trait-based interfaces in `src/lib.rs`:
- `CryptoTrait`
- `PublicKeyTrait`
- `SignatureTrait`
- `MultiSignatureTrait`
- `AggregatedSignatureTrait`

## Contract Notes

- Backend implementation is selected at compile-time via Cargo features.
- Exactly one implementation feature must be enabled.
- Error model for contract operations is represented by `CryptoError`.

## Not Applicable

- HTTP methods/routes
- Request/response payload schemas
- Auth middleware or token-based API security
