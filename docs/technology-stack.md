# Technology Stack

## Part: core (`moonblokz-crypto-lib`)

| Category | Technology | Version | Justification |
|---|---|---:|---|
| Language | Rust | 2024 edition | Declared in `Cargo.toml`; crate-level `#![no_std]` in `src/lib.rs`. |
| Package/Build | Cargo | N/A | Standard Rust crate layout with `Cargo.toml` and feature flags. |
| Crate Type | Library (`moonblokz-crypto`) | 1.0.0 | Package metadata defines reusable crypto library, not binary app. |
| Crypto Hash | `sha2` | 0.10 | Optional dependency enabled by Schnorr internal feature. |
| Schnorr impl A | `malachite-base`, `malachite-nz` | 0.6 | Feature `schnorr-malachite`; optimized for speed tradeoff on target HW context. |
| Schnorr impl B | `num-bigint-dig` (fork), `num-traits` | git, 0.2 | Feature `schnorr-num-bigint-dig`; alternate size/perf profile. |
| BLS impl | `bls12_381-bls`, `dusk-bls12_381`, `dusk-bytes` | 0.5, 0.14, 0.1.7 | Feature `bls-bls12_381-bls`; keeps BLS as swappable option. |
| Testing | Rust `#[test]` + `cargo llvm-cov nextest` | N/A | Tests live in `src/lib.rs`; `run_tests.sh` runs all feature variants. |
| Feature Model | Compile-time feature selection | N/A | Exactly one implementation enforced via `compile_error!` guards. |

## Project Type Match

- Detected `project_type_id`: `library`
- Detection signals: `Cargo.toml`, `src/lib.rs`, `#![no_std]`, no application runtime entrypoint.

## External Context Applied (User-Requested)

Reference: MoonBlokz Series Part VI (Medium, May 26, 2025)
- Priority signals used in this documentation pass: compact signatures/keys, verification efficiency on RP2040-class devices, aggregation support, and algorithm swappability via compile-time selection.
