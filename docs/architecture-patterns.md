# Architecture Patterns

## Part: core (`moonblokz-crypto-lib`)

## Primary Pattern

- Pattern: **Feature-gated strategy/wrapper library**
- Classification basis: `project_type_id=library` with algorithm + implementation selection via Cargo features.

## Structural Characteristics

- Public contract layer in `src/lib.rs` (traits and constants):
  - `CryptoTrait`, `PublicKeyTrait`, `SignatureTrait`, `MultiSignatureTrait`, `AggregatedSignatureTrait`
- Implementation modules behind feature flags:
  - `schnorr_malachite_signer`
  - `schnorr_num_bigint_dig_signer`
  - `bls_bls12_381_bls_signer`
- Compile-time exclusivity policy:
  - Exactly one implementation feature enabled
  - Build fails if none or multiple are enabled

## Runtime/Platform Pattern

- `no_std` deterministic library pattern for constrained systems.
- No runtime service/process responsibilities; consumed as embedded/downstream dependency.

## Crypto Design Pattern (from code + user-provided Part VI context)

- API-stable algorithm swappability:
  - keep shared trait-level surface stable across backends.
- Verification-oriented optimization direction (Schnorr favored in current MoonBlokz context).
- Aggregation-capable signature model with bounded serialized output constants.

## Documentation Implications for Remaining Steps

- Architecture docs should emphasize boundary between stable trait API and backend implementations.
- Development/docs should preserve compile-time feature discipline and per-feature test validation.
- Any future feature work should be modeled as additive slices that avoid unnecessary trait/API breakage.
