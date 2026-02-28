# Integration Architecture

This repository is documented as a single-part monolith library.

## Integration Pattern

- In-process dependency integration via Cargo.
- Downstream MoonBlokz crates consume the trait-stable API from `src/lib.rs`.
- Concrete backend selected by compile-time feature flag.

## Intra-Repository Part Integration

Not applicable: no separate client/server/services parts inside this repository.

## Integration Constraints

- Preserve compile-time one-feature-only invariant.
- Preserve `no_std` compatibility for constrained targets.
- Preserve trait-level API compatibility for consumers.
