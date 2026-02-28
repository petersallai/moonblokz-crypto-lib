# Source Tree Analysis

Project root: `/Users/slp/moonblokz/moonblokz-crypto-lib`

```text
moonblokz-crypto-lib/
├── Cargo.toml                      # Crate manifest, dependencies, feature gates
├── Cargo.lock                      # Locked dependency graph
├── README.md                       # Public usage and examples
├── AGENTS.md                       # Repository-specific engineering constraints
├── run_tests.sh                    # Feature-matrix test/coverage runner
├── src/
│   ├── lib.rs                      # Library entrypoint; trait API, constants, feature re-exports
│   ├── schnorr_malachite_signer.rs # Schnorr implementation (malachite backend)
│   ├── schnorr_num_bigint_dig_signer.rs # Schnorr implementation (num-bigint-dig backend)
│   └── bls_bls12_381_bls_signer.rs # BLS wrapper implementation backend
└── docs/
    └── moonblokz_crypto_bmad_output/ # Local b-mad planning artifacts (excluded from existing-doc inventory by user request)
```

## Entry Points

- `src/lib.rs` is the canonical crate entrypoint.
- No binary entrypoint in source (`src/main.rs` absent).

## Integration-Relevant Paths

- Public integration boundary: trait API + type re-exports in `src/lib.rs`.
- Feature-selected implementation modules in `src/*.rs`.
- Integration test workflow entrypoint: `run_tests.sh`.

## Notes

- `target/` and `.git/` were excluded from documentation tree detail as generated/runtime metadata directories.
