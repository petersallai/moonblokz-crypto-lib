# Component Inventory

This is a library crate, so "components" are code modules and contract types rather than UI units.

## Contract Components

- `CryptoTrait`
- `PublicKeyTrait`
- `SignatureTrait`
- `MultiSignatureTrait`
- `AggregatedSignatureTrait`
- `CryptoError`

## Implementation Components

- `schnorr_malachite_signer`
- `schnorr_num_bigint_dig_signer`
- `bls_bls12_381_bls_signer`

## Supporting Components

- Feature flags in `Cargo.toml`
- Compile-time exclusivity checks in `src/lib.rs`
- In-crate tests under `#[cfg(test)]`

## Reusability Notes

- Contract components are intended for stable downstream integration.
- Implementation components are swappable at compile-time, not runtime.
