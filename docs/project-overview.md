# Project Overview

## Project

- Name: `moonblokz-crypto-lib` (`moonblokz-crypto` crate)
- Type: single-part monolith library
- Language: Rust (2024)
- Runtime model: `no_std`

## Purpose

Provides signing, verification, multi-signature, and aggregated-signature primitives for MoonBlokz with swappable compile-time implementations (Schnorr/BLS backends) while preserving a stable API surface for consumers.

## Executive Summary

The repository is architected as a feature-gated crypto library optimized for constrained environments. Core contracts are centralized in `src/lib.rs`, while concrete algorithm/library implementations are isolated in dedicated modules and selected at compile time. Compile-time guards enforce exactly one active implementation.

## Tech Stack Snapshot

- Rust + Cargo
- Feature-gated dependencies for Schnorr and BLS implementations
- Inline Rust test suite with feature-matrix coverage script (`run_tests.sh`)

## Key Documents

- `architecture.md`
- `source-tree-analysis.md`
- `development-guide.md`
- `component-inventory.md`
- `contribution-guide.md`

## Repository Structure

- `/src`: contract and implementation modules
- `Cargo.toml`: dependency + feature model
- `run_tests.sh`: feature coverage flow
