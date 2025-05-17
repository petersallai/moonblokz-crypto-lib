# Moonblokz Crypto Library

[![Crates.io](https://img.shields.io/crates/v/moonblokz-crypto.svg)](https://crates.io/crates/moonblokz-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Moonblokz Crypto Library provides cryptographic functionalities for signing and verifying messages using different algorithms. It supports Schnorr signatures and BLS signatures, allowing for both single and multi-signature operations.

Detailed information about MoonBlokz and the cryptographic algorithms used can be found in the [Moonblokz article series](https://medium.com/@peter.sallai/moonblokz-series-part-i-building-a-hyper-local-blockchain-2f385b763c65).

---

## Features

- `schnorr-malachite`: Schnorr signature implementation using the Malachite library.
- `schnorr-num-bigint-dig`: Schnorr signature implementation using the Num BigInt Dig library.
- `bls-bls12_381-bls`: BLS signature implementation using the BLS12-381 library.

**Note:** Only one crypto implementation feature can be enabled at a time.

---

## Usage

Add the crate to your `Cargo.toml` and enable the desired feature:

```toml
[dependencies]
moonblokz-crypto = { version = "0.9.0", features = ["schnorr-malachite"] }
# moonblokz-crypto = { version = "0.9.0", features = ["schnorr-num-bigint-dig"] }
# moonblokz-crypto = { version = "0.9.0", features = ["bls-bls12_381-bls"] }
```

---

## Example

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

---

## API Overview

- `CryptoTrait`: Trait for cryptographic signers (key management, signing, verification, aggregation).
- `SignatureTrait`, `MultiSignatureTrait`, `AggregatedSignatureTrait`: Traits for signature types.
- `PublicKeyTrait`: Trait for public key operations.
- `CryptoError`: Error type for cryptographic operations.

See the [documentation](https://docs.rs/moonblokz-crypto) for full API details.

---

## Testing

The library includes a comprehensive test suite covering:
- Basic signing and verification
- Serialization/deserialization of keys and signatures
- Multi-signature aggregation and verification
- Negative tests for invalid signatures, keys, and messages

Run tests with:

```sh
cargo test
```

---

## License

This library is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
Dependent libraries use different licenses. Please check it before usage.

---

## Authors

- Peter Sallai (Bad Access)
