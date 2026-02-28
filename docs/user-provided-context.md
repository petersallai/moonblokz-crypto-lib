# User-Provided Context

## Explicit User Guidance

- Exclude all files under `docs/moonblokz_crypto_bmad_output/**` from project documentation inventory.
- Use MoonBlokz Series Part VI article as reference context:
  - https://medium.com/moonblokz/moonblokz-series-part-vi-crypto-algorithms-942d4a28fdc7

## Context Extracted From Part VI (for this scan)

- Design priorities: compact signatures/public keys, verification efficiency on microcontrollers, aggregation support, and no_std viability.
- Hardware reference: RP2040-class constraints are central to algorithm tradeoffs.
- Algorithm strategy: keep crypto implementation swappable at compile time; avoid upstream API churn.
- MoonBlokz direction: Schnorr chosen for current performance profile, BLS retained as swappable option.
- Cargo-feature model: one implementation selected at compile time; minimize unnecessary code in embedded binaries.

## Documentation Focus Implication

- Emphasize feature-gated architecture and compile-time exclusivity.
- Emphasize no_std and constrained-device behavior in architecture/development docs.
- Preserve and document stable trait/API contracts across implementation backends.
