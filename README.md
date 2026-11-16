# MoonBlokz Crypto Library

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The MoonBlokz Crypto Library provides the cryptographic subsystem used by MoonBlokz for message signing, verification, and compact multi-party approval evidence. It supports both Schnorr and BLS algorithm families behind one compile-time-selected public API.

The library is designed for the MoonBlokz operating environment:

- constrained devices,
- `no_std` compatibility,
- low-bandwidth radio communication,
- compact serialized artifacts,
- and bounded aggregation behavior.

Both families sit on audited, pure-Rust curve libraries with no C code and no allocator: Schnorr is BIP-340 on secp256k1 through `k256`, and BLS is the IETF proof-of-possession suite on BLS12-381 through zkcrypto `bls12_381`. The crate adds the MoonBlokz aggregate format on top (DEC-194 for Schnorr) and proofs of possession for key registration.

Comprehensive background about MoonBlokz and the cryptographic design direction can be found in the [MoonBlokz article series](https://medium.com/@peter.sallai/moonblokz-series-part-i-building-a-hyper-local-blockchain-2f385b763c65). Part VI discusses the cryptographic design space.

---

## Features

Exactly one backend feature is enabled at a time. The names say the scheme, not the implementation:

| Feature | Scheme | Signature | Public key | Aggregate (40 signers) |
|---|---|---:|---:|---:|
| `schnorr` (default) | BIP-340 Schnorr, secp256k1 (`k256`) | 64 B | 32 B | 34 + 32 × 40 B |
| `bls-min-sig` | BLS12-381, IETF PoP suite, signatures in G1 (`bls12_381`) | 48 B | 96 B | 50 B |
| `bls-min-pk` | BLS12-381, IETF PoP suite, keys in G1 (`bls12_381`) | 96 B | 48 B | 98 B |

`bls` is a private helper feature that the two BLS features turn on; it cannot be selected alone. The private key is 32 bytes for every scheme (big-endian scalar for BLS).

---

## Signature Roles

The public API distinguishes three artifact roles:

- `Signature`: ordinary single-signer authorization artifact.
- `MultiSignature`: aggregation-ready single-signer artifact intended for later combination.
- `AggregatedSignature`: combined multi-party evidence artifact.

This distinction is semantic at the public API level across all backends, even where backend internals differ.

---

## Usage

```toml
[dependencies]
moonblokz-crypto = { version = "1.0" } # `schnorr`, the default
# moonblokz-crypto = { version = "1.0", default-features = false, features = ["bls-min-sig"] }
# moonblokz-crypto = { version = "1.0", default-features = false, features = ["bls-min-pk"] }
```

Keep `default-features = false` when selecting a BLS scheme, so only one backend is active.

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
use moonblokz_crypto::{Crypto, CryptoTrait, PublicKeyTrait};

fn main() {
    let private_key1 = [1u8; 32];
    let private_key2 = [2u8; 32];
    let signer1 = Crypto::new(private_key1).expect("Failed to create signer 1");
    let signer2 = Crypto::new(private_key2).expect("Failed to create signer 2");
    let message = b"Hello, world!";

    let sig1 = signer1.multi_sign(message);
    let sig2 = signer2.multi_sign(message);

    // Schnorr binds every weight to all signers' keys (DEC-194); BLS ignores them.
    let key_bytes = [signer1.public_key().serialize(), signer2.public_key().serialize()];
    let aggregated = signer1
        .aggregate_signatures(&[&sig1, &sig2], &key_bytes, message)
        .expect("Aggregation failed");

    let public_keys = [signer1.public_key(), signer2.public_key()];
    assert!(signer1.verify_aggregated_signature(message, &aggregated, &public_keys));
}
```

Proof of possession, for registering a new key (DEC-248):

```rust
use moonblokz_crypto::{Crypto, CryptoTrait};

fn main() {
    let new_key = Crypto::new([3u8; 32]).expect("Failed to create signer");
    let proof = new_key.prove_possession();
    assert!(new_key.verify_possession(new_key.public_key(), &proof));
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
PrivateKey ─ prove_possession() ──────────────────▶ Signature  ─▶ verify_possession(PublicKey)
```

At build time, exactly one backend provides these same public types and operations.

### Current backend structure

- `src/lib.rs` defines traits, constants, compile-time feature checks, re-exports and the cross-backend tests.
- `src/schnorr_k256_signer.rs` implements `schnorr`: BIP-340 signing and verification, the DEC-194 aggregate and the proof of possession.
- `src/bls_zkcrypto_signer.rs` implements `bls-min-sig` and `bls-min-pk` through one generic core over a private `Variant` trait.

---

## Implementation Notes

- The crate is `#![no_std]`, `#![forbid(unsafe_code)]` and allocation-free; every backend links on `thumbv6m-none-eabi` without a global allocator.
- Aggregation is bounded: `MAX_AGGREGATED_SIGNATURES = 50`.
- Schnorr signing is deterministic (BIP-340 with zero auxiliary randomness). The aggregate is `count (u16, big-endian) ‖ s ‖ r_1 … r_k`; each signer's weight is a tagged hash over all nonces, all keys and the message, and verification checks the full point equation one signer at a time (no multi-scalar multiplication, to keep the stack small).
- A BLS aggregate is `count (u16, big-endian) ‖ point`; a key is accepted only after `KeyValidate` (the identity is refused) and, before it is aggregated, a verified proof of possession.
- A proof of possession signs the key in a domain of its own (`MoonBlokz/pop` for Schnorr, the IETF PoP DST for BLS), so no ordinary signature can serve as one.

---

## Testing

The tests cover signing and verification, serialization, aggregation and its refusals, proofs of possession, and known-answer vectors: the BIP-340 vectors and a pinned DEC-194 aggregate for `schnorr`; RFC 9380 hash-to-curve, an Ethereum consensus vector and a cross-check against `blst` for the BLS schemes.

```sh
cargo test                                               # schnorr
cargo test --no-default-features --features bls-min-sig
cargo test --no-default-features --features bls-min-pk
./run_tests.sh                                           # fmt, clippy and coverage for every scheme
```

`cargo test` alone validates only the default scheme. The crate has no `unsafe`, so there is no Miri gate.

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

`k256` and `bls12_381` are MIT / Apache-2.0 dual-licensed.

---

## Authors

- Peter Sallai (Bad Access)
