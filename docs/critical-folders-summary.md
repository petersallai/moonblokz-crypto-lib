# Critical Folders Summary

## `/src`
- Purpose: Core crate source code and all crypto implementations.
- Critical files:
  - `lib.rs`: stable public trait boundary, constants, and compile-time exclusivity checks.
  - backend modules (`schnorr_*`, `bls_*`): concrete implementation details selected via features.

## `/docs`
- Purpose: project-local documentation workspace.
- Current notable subtree:
  - `docs/moonblokz_crypto_bmad_output/` contains b-mad artifacts used for planning/tracking (excluded from existing documentation inventory per user instruction).
