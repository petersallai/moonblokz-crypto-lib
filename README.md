# MoonBlokz Crypto Library

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The MoonBlokz Crypto Library offers cryptographic functionalities for signing and verifying messages using various algorithms. It supports both Schnorr and BLS signatures, enabling single and multi-signature operations. This library is specifically designed to meet the needs of the MoonBlokz blockchain, which is tailored for radio communication and microcontrollers [https://www.moonblokz.com](https://www.moonblokz.com). For BLS signatures, the library acts as a wrapper around the "bls-bls12_381-bls" crate, while it includes its own implementation for Schnorr signatures.

Comprehensive details about MoonBlokz and the cryptographic algorithms used can be found in the [MoonBlokz article series](https://medium.com/@peter.sallai/moonblokz-series-part-i-building-a-hyper-local-blockchain-2f385b763c65). Part VI of the series discusses the crypto algorithms utilized.

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
moonblokz-crypto = { version = "1.0", features = ["schnorr-malachite"], default-features=false }
# moonblokz-crypto = { version = "1.0", features = ["schnorr-num-bigint-dig"],default-features=false  }
# moonblokz-crypto = { version = "1.0", features = ["bls-bls12_381-bls"], default-features=false  }
```

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

Aggregated signatures:

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
    let aggregated = signer1.aggregate_signatures(&[&sig1, &sig2], message).expect("Aggregation failed");
    let public_keys = [signer1.public_key(), signer2.public_key()];
    assert!(signer1.verify_aggregated_signature(message, &aggregated, &public_keys));
}
```
---

## Architecture

The structure of different structs in this crate are the following:
```

              ┌────────────────────────┐                  
              │                        │                  
              │  Message, Private Key  │                  
              │                        │                  
              └────────────────────────┘                  
                           │                              
             ┌────sign─────┴──multi_sign───┐              
             │                             │              
             ▼                             ▼              
┌────────────────────────┐    ┌────────────────────────┐  
│                        │    │                        ├┐ 
│       Signature        │    │     MultiSignature     │├┐
│                        │    │                        │││
└────────────────────────┘    └┬───────────────────────┘││
             ▲                 └┬───────────────────────┘│
             │                  └────────────────────────┘
             │                               │            
             │                     aggregate_signatures   
             │                               ▼            
             │                  ┌────────────────────────┐
             │                  │                        │
     verify_signature           │  AggregatedSignature   │
             │                  │                        │
             │                  └────────────────────────┘
             │                               ▲            
             │                               │            
             │              ┌────────────────┘            
             │      verify_aggregated_signature           
             │              │                             
             │ ┌────────────────────────┐                 
             │ │                        │                 
             └─│  Message, PublicKey(s) │                 
               │                        │                 
               └────────────────────────┘                 

```

To create a Signature or a MultiSignature, both a message and a private key are required. A Signature is the simpler of the two options and can be verified using the message and a PublicKey. A MultiSignature can also be generated from a message and a private key, allowing multiple signatures to be combined into an AggregatedSignature. This AggregatedSignature can be verified using the original message and a list of PublicKeys.

See the documentation (cargo doc --open) for full API details.

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
Dependent libraries use different licenses. Please check it before using.

---

## Authors

- Peter Sallai (Bad Access)
