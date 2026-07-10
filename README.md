# MoonBlokz Crypto Library

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The MoonBlokz Crypto Library provides the cryptographic subsystem used by MoonBlokz for message signing, verification, and compact multi-party approval evidence. It supports both Schnorr and BLS algorithm families behind one compile-time-selected public API.

The library is designed for the MoonBlokz operating environment:

- constrained devices,
- `no_std` compatibility,
- low-bandwidth radio communication,
- compact serialized artifacts,
- and bounded aggregation behavior.

For BLS, the library acts as a wrapper around the `bls-bls12_381-bls` ecosystem. For Schnorr, the library contains its own implementations with multiple arithmetic backends.

Comprehensive background about MoonBlokz and the cryptographic design direction can be found in the [MoonBlokz article series](https://medium.com/@peter.sallai/moonblokz-series-part-i-building-a-hyper-local-blockchain-2f385b763c65). Part VI discusses the cryptographic design space.

---

## Features

Concrete backend features:

- `schnorr-malachite`: Schnorr implementation using the Malachite arithmetic libraries.
- `schnorr-num-bigint-dig`: Schnorr implementation using the `num-bigint-dig` arithmetic stack.
- `schnorr-crypto-bigint`: Schnorr implementation using the `crypto-bigint` arithmetic stack.
- `bls-bls12_381-bls`: BLS implementation using the `bls12_381-bls` ecosystem.

Internal family features used by the crate:

- `schnorr`
- `bls`

**Important:** Exactly one concrete crypto backend feature must be enabled at a time.

Current default feature:

- `schnorr-malachite`

---

## Signature Roles

The public API distinguishes three artifact roles:

- `Signature`: ordinary single-signer authorization artifact.
- `MultiSignature`: aggregation-ready single-signer artifact intended for later combination.
- `AggregatedSignature`: combined multi-party evidence artifact.

This distinction is semantic at the public API level across all backends, even where backend internals differ.

---

## Usage

Add the crate to your `Cargo.toml` and enable exactly one backend feature:

```toml
[dependencies]
moonblokz-crypto = { version = "1.0", default-features = false, features = ["schnorr-malachite"] }
# moonblokz-crypto = { version = "1.0", default-features = false, features = ["schnorr-num-bigint-dig"] }
# moonblokz-crypto = { version = "1.0", default-features = false, features = ["schnorr-crypto-bigint"] }
# moonblokz-crypto = { version = "1.0", default-features = false, features = ["bls-bls12_381-bls"] }
```

If you select a non-default backend, keep `default-features = false` so only one concrete implementation is active.

---

## Example

Single signature and verification:

```rust
use moonblokz_crypto::{Crypto, CryptoTrait};

fn main() {
    let private_key = [1u8; 32];
    let signer = Crypto::new(private_key).expect("Failed to create signer");
    let message = b"Hello, world!";
    let signature = signer.sign(message);
    assert!(signer.verify_signature(message, &signature, signer.public_key()));
}
```

Aggregation-ready signatures and aggregated verification:

```rust
use moonblokz_crypto::{Crypto, CryptoTrait};

fn main() {
    let private_key1 = [1u8; 32];
    let private_key2 = [2u8; 32];
    let signer1 = Crypto::new(private_key1).expect("Failed to create signer 1");
    let signer2 = Crypto::new(private_key2).expect("Failed to create signer 2");
    let message = b"Hello, world!";

    let sig1 = signer1.multi_sign(message);
    let sig2 = signer2.multi_sign(message);

    let aggregated = signer1
        .aggregate_signatures(&[&sig1, &sig2], message)
        .expect("Aggregation failed");

    let public_keys = [signer1.public_key(), signer2.public_key()];
    assert!(signer1.verify_aggregated_signature(message, &aggregated, &public_keys));
}
```

---

## Public API Shape

The crate re-exports backend-specific implementations under one stable public surface:

- `Crypto`
- `PublicKey`
- `Signature`
- `MultiSignature`
- `AggregatedSignature`

The main behavior is available through `CryptoTrait` and the corresponding artifact traits.

---

## Architecture

Conceptually, the crate works like this:

```text
Message + PrivateKey
    ├─ sign() ───────────────────────────────▶ Signature
    └─ multi_sign() ─────────────────────────▶ MultiSignature
                                                  │
                                                  └─ aggregate_signatures() ─▶ AggregatedSignature

Message + PublicKey ─────────────────────────────▶ verify_signature(Signature)
Message + PublicKey ─────────────────────────────▶ verify_multi_signature(MultiSignature)
Message + PublicKeys[] ──────────────────────────▶ verify_aggregated_signature(AggregatedSignature)
```

At build time, exactly one backend provides these same public types and operations.

### Current backend structure

- `src/lib.rs` defines traits, constants, compile-time feature checks, and re-exports.
- `src/schnorr_malachite_signer.rs` implements one Schnorr backend.
- `src/schnorr_num_bigint_dig_signer.rs` implements one Schnorr backend.
- `src/schnorr_crypto_bigint_signer.rs` implements one Schnorr backend.
- `src/bls_bls12_381_bls_signer.rs` implements the BLS backend.

---

## Implementation Notes

- The crate is `#![no_std]`.
- Backend choice is compile-time selected through Cargo features.
- The library uses bounded aggregation with `MAX_AGGREGATED_SIGNATURES = 50`.
- Aggregated-signature serialization is family-dependent:
  - Schnorr aggregated signatures contain a count, one combined scalar-like value, and one `r` component per signer.
  - BLS aggregated signatures are constant-sized aside from the count prefix.
- In the Schnorr family, `sign()` and `multi_sign()` share the same underlying signing math and differ in returned role type.

---

## Testing

The library includes test coverage for:

- signing and verification,
- serialization and deserialization,
- aggregation and aggregated verification,
- positive and negative validation cases,
- and backend-specific regression vectors for `schnorr-crypto-bigint`.

Useful commands:

```sh
cargo test
cargo test --no-default-features --features schnorr-malachite
cargo test --no-default-features --features schnorr-num-bigint-dig
cargo test --no-default-features --features schnorr-crypto-bigint
cargo test --no-default-features --features bls-bls12_381-bls
./run_tests.sh
```

**Note:** `cargo test` alone validates only the default backend.

See the local API documentation with:

```sh
cargo doc --open
```

---

## Related Documentation

For the MoonBlokz knowledge-base view of this crate, see:

- `moonblokz-info/moonblokz-crypto-concept.md`
- `moonblokz-info/moonblokz-crypto-algorythm.md`
- `moonblokz-info/moonblokz-crypto-implementation.md`

---

## License

This library is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Enabled dependencies may use different licenses. Check dependency licensing before distributing binaries or selecting a backend.

---

## Authors

- Peter Sallai (Bad Access)
