# Data Models

This project has no database or ORM persistence layer.

## Core Data Types (Library-Level)

Defined through trait contracts and backend-specific concrete types:
- `PublicKey`
- `Signature`
- `MultiSignature`
- `AggregatedSignature`

## Serialization Model

- Algorithm-dependent constant sizes are defined in `src/lib.rs`.
- Aggregated signatures expose bounded serialization behavior via constants and `serialized_len()`.

## Not Applicable

- Tables/entities
- Migrations
- Relational/NoSQL schema
