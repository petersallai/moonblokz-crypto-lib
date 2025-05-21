#![no_std]

//! Moonblokz Crypto Library
//! <https://www.moonblokz.com>
//! This library provides cryptographic functionalities for signing and verifying messages using different algorithms.
//! It supports Schnorr signatures and BLS signatures, allowing for both single and multi-signature operations.
//! Detailed information about MoonBlok are available in an article series, available at: <https://medium.com/@peter.sallai/moonblokz-series-part-i-building-a-hyper-local-blockchain-2f385b763c65>
//! In the sixth part of the series, I discuss the cryptographic algorithms used in MoonBlokz.
//!
//! # Features
//! - `schnorr-malachite`: Use the Schnorr signature implementation from the Malachite library.
//! - `schnorr-num-bigint-dig`: Use the Schnorr signature implementation from the Num BigInt Dig library.
//! - `bls-bls12_381-bls`: Use the BLS signature implementation from the BLS12-381 library.
//!
//! # Usage
//! To use this library, you need to enable one of the features in your `Cargo.toml` file.
//! Possible features are:
//! ```toml
//! [dependencies]
//! moonblokz-crypto = { version = "0.1", features = ["schnorr-malachite"] }
//! // moonblokz-crypto = { version = "0.1", features = ["schnorr-num-bigint-dig"] }
//! // moonblokz-crypto = { version = "0.1", features = ["bls-bls12_381-bls"] }
//!
//! You can then use the library to create signers, sign messages, and verify signatures.
//!
//! # Example
//! ```rust
//! use moonblokz_crypto::{Crypto, CryptoTrait};
//!
//! fn main() {
//!     let private_key = [1u8; 32];
//!     let signer = Crypto::new(private_key).expect("Failed to create signer");
//!     let message = b"Hello, world!";
//!     let signature = signer.sign(message);
//!     assert!(signer.verify_signature(message, &signature, signer.public_key()));
//! }
//! }
//!
//! # License
//! This library is licensed under the MIT License.
//! See the [LICENSE](LICENSE) file for more details.
//!
//! # Authors
//! - Peter Sallai (Bad Access)
//!

extern crate alloc;
use alloc::vec::Vec;
#[cfg(any(
    all(feature = "schnorr-malachite", any(feature = "schnorr-num-bigint-dig", feature = "bls-bls12_381-bls")),
    all(feature = "schnorr-num-bigint-dig", any(feature = "schnorr-malachite", feature = "bls-bls12_381-bls")),
    all(feature = "bls-bls12_381-bls", any(feature = "schnorr-malachite", feature = "schnorr-num-bigint-dig")),
))]
compile_error!("Only one crypto implementation feature can be enabled at a time");

#[cfg(not(any(feature = "schnorr-malachite", feature = "schnorr-num-bigint-dig", feature = "bls-bls12_381-bls")))]
compile_error!("At least one crypto implementation feature must be enabled");

#[cfg(feature = "schnorr")]
///Single signature size (in bytes)
pub const SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "schnorr")]
///Multi signature size (in bytes)
pub const MULTI_SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "schnorr")]
///Size of the public key (in bytes)
pub const PUBLIC_KEY_SIZE: usize = 32;
#[cfg(feature = "schnorr")]
///Size of the private key (in bytes)
pub const PRIVATE_KEY_SIZE: usize = 32;
#[cfg(feature = "schnorr")]
///Contant parts's size in an aggregated signature (in bytes)
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 34;
#[cfg(feature = "schnorr")]
///Signature count dependent parts's size in an aggregated signature (in bytes)
pub const AGGREGATED_SIGNATURE_VARIABLE_SIZE: usize = 32;

#[cfg(feature = "bls")]
///Single signature size (in bytes)
pub const SIGNATURE_SIZE: usize = 48;
#[cfg(feature = "bls")]
///Multi signature size (in bytes)
pub const MULTI_SIGNATURE_SIZE: usize = 48;
#[cfg(feature = "bls")]
///Size of the public key (in bytes)
pub const PUBLIC_KEY_SIZE: usize = 96;
#[cfg(feature = "bls")]
///Size of the private key (in bytes)
pub const PRIVATE_KEY_SIZE: usize = 32;
#[cfg(feature = "bls")]
///Contant parts's size in an aggregated signature (in bytes)
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 50;
#[cfg(feature = "bls")]
///Signature count dependent parts's size in an aggregated signature (in bytes)
pub const AGGREGATED_SIGNATURE_VARIABLE_SIZE: usize = 0;

#[cfg(feature = "schnorr-malachite")]
pub mod schnorr_malachite_signer;
#[cfg(feature = "schnorr-malachite")]
pub use schnorr_malachite_signer::AggregatedSignature;
#[cfg(feature = "schnorr-malachite")]
pub use schnorr_malachite_signer::Crypto;
#[cfg(feature = "schnorr-malachite")]
pub use schnorr_malachite_signer::MultiSignature;
#[cfg(feature = "schnorr-malachite")]
pub use schnorr_malachite_signer::PublicKey;
#[cfg(feature = "schnorr-malachite")]
pub use schnorr_malachite_signer::Signature;

#[cfg(feature = "schnorr-num-bigint-dig")]
pub mod schnorr_num_bigint_dig_signer;
#[cfg(feature = "schnorr-num-bigint-dig")]
pub use schnorr_num_bigint_dig_signer::AggregatedSignature;
#[cfg(feature = "schnorr-num-bigint-dig")]
pub use schnorr_num_bigint_dig_signer::Crypto;
#[cfg(feature = "schnorr-num-bigint-dig")]
pub use schnorr_num_bigint_dig_signer::MultiSignature;
#[cfg(feature = "schnorr-num-bigint-dig")]
pub use schnorr_num_bigint_dig_signer::PublicKey;
#[cfg(feature = "schnorr-num-bigint-dig")]
pub use schnorr_num_bigint_dig_signer::Signature;

#[cfg(feature = "bls-bls12_381-bls")]
pub mod bls_bls12_381_bls_signer;
#[cfg(feature = "bls-bls12_381-bls")]
pub use bls_bls12_381_bls_signer::AggregatedSignature;
#[cfg(feature = "bls-bls12_381-bls")]
pub use bls_bls12_381_bls_signer::Crypto;
#[cfg(feature = "bls-bls12_381-bls")]
pub use bls_bls12_381_bls_signer::MultiSignature;
#[cfg(feature = "bls-bls12_381-bls")]
pub use bls_bls12_381_bls_signer::PublicKey;
#[cfg(feature = "bls-bls12_381-bls")]
pub use bls_bls12_381_bls_signer::Signature;

/// An error type for cryptographic operations.
pub enum CryptoError {
    /// An error indicating that the private key is invalid.
    InvalidPrivateKey,
    /// An error indicating that the public key is invalid.
    InvalidPublicKey,
    /// An error indicating that the signature is invalid.
    InvalidSignature,
}

/// A trait representing a cryptographic signature.
/// Provides methods to create a signature from bytes and serialize it back to bytes.
pub trait SignatureTrait: Sized {
    /// Creates a new signature from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the signature.
    ///
    /// # Returns
    /// * `Ok(Self)` if the signature is valid.
    /// * `Err(CryptoError::InvalidSignature)` if the signature is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the signature into a fixed-size byte array.
    ///
    /// # Returns
    /// A `[u8; SIGNATURE_SIZE]` array containing the serialized signature.
    fn serialize(&self) -> &[u8; SIGNATURE_SIZE];
}

/// A trait representing a single multi-signature (can be aggregated)
/// Provides methods to create, serialize multi-signatures.
pub trait MultiSignatureTrait: Sized {
    /// Creates a new aggregated signature from a byte slice. Only multi-signature can be aggregated into an aggregated signature.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the aggregated signature.
    ///
    /// # Returns
    /// * `Ok(Self)` if the aggregated signature is valid.
    /// * `Err(CryptoError::InvalidSignature)` if the aggregated signature is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the aggregated signature into a vector of bytes.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the serialized aggregated signature.
    fn serialize(&self) -> &[u8; MULTI_SIGNATURE_SIZE];
}

/// A trait representing an aggregated cryptographic signature.
/// Provides methods to create, serialize, and retrieve the count of aggregated signatures.
pub trait AggregatedSignatureTrait: Sized {
    /// Creates a new aggregated signature from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the aggregated signature.
    ///
    /// # Returns
    /// * `Ok(Self)` if the aggregated signature is valid.
    /// * `Err(CryptoError::InvalidSignature)` if the aggregated signature is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the aggregated signature into a fixed-size byte array.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the serialized aggregated signature.
    fn serialize(&self) -> Vec<u8>;

    fn get_count(&self) -> usize;
}

/// A trait representing a public key in cryptographic operations.
/// Provides methods to create a public key from bytes and serialize it back to bytes.
pub trait PublicKeyTrait: Sized {
    /// Creates a new public key from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the public key.
    ///
    /// # Returns
    /// * `Ok(Self)` if the public key is valid.
    /// * `Err(CryptoError::InvalidPublicKey)` if the public key is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the public key into a fixed-size byte array.
    ///
    /// # Returns
    /// A reference to a `[u8; PUBLIC_KEY_SIZE]` array containing the serialized public key.
    fn serialize(&self) -> &[u8; PUBLIC_KEY_SIZE];
}

/// A trait representing a cryptographic signer.
/// Provides methods for key management, signing, and verifying messages.
pub trait CryptoTrait: Sized {
    /// Creates a new signer instance from a private key.
    ///
    /// # Arguments
    /// * `private_key_bytes` - A `[u8; PRIVATE_KEY_SIZE]` array representing the private key.
    ///
    /// # Returns
    /// * `Ok(Self)` if the private key is valid.
    /// * `Err(CryptoError::InvalidPrivateKey)` if the private key is invalid.
    fn new(private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError>;

    /// Retrieves the public key associated with the signer.
    ///
    /// # Returns
    /// A reference to the `PublicKey`.
    fn public_key(&self) -> &PublicKey;

    /// Signs a message using the private key.
    ///
    /// # Arguments
    /// * `message` - A slice of bytes representing the message to be signed.
    ///
    /// # Returns
    /// A `Signature` object containing the generated signature.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Creates a multi-signature for a message using the private key.
    ///
    /// # Arguments
    /// * `message` - A slice of bytes representing the message to be signed.
    ///
    /// # Returns
    /// A `MultiSignature` object containing the generated multi-signature.
    fn multi_sign(&self, message: &[u8]) -> MultiSignature;

    /// Verifies a multi-signature against a message and a public key.
    ///
    /// # Arguments
    /// * `message` - A slice of bytes representing the message.
    /// * `multi_signature` - A reference to the `MultiSignature` to be verified.
    /// * `public_key` - A reference to the `PublicKey` to verify against.
    /// # Returns
    /// * `true` if the multi-signature is valid.
    /// * `false` otherwise.
    ///
    fn verify_multi_signature(&self, message: &[u8], multi_signature: &MultiSignature, public_key: &PublicKey) -> bool;
    /// Verifies a signature against a message and a public key.
    ///
    /// # Arguments
    /// * `message` - A slice of bytes representing the message.
    /// * `signature` - A reference to the `Signature` to be verified.
    /// * `public_key` - A reference to the `PublicKey` to verify against.
    ///
    /// # Returns
    /// * `true` if the signature is valid.
    /// * `false` otherwise.
    fn verify_signature(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> bool;

    /// Aggregates multiple individual multi-signatures into a single aggregated signature.
    ///
    /// # Arguments
    /// * `signatures` - A slice of references to `MultiSignature` objects to be aggregated.
    /// * `message` - A slice of bytes representing the message that was signed.
    ///
    /// # Returns
    /// * `Ok(AggregatedSignature)` if aggregation is successful.
    /// * `Err(CryptoError)` if aggregation fails.
    fn aggregate_signatures(&self, signatures: &[&MultiSignature], message: &[u8]) -> Result<AggregatedSignature, CryptoError>;

    /// Verifies an aggregated signature against a message and a set of public keys.
    ///
    /// # Arguments
    /// * `message` - A slice of bytes representing the message.
    /// * `aggregated_signature` - A reference to the `AggregatedSignature` to be verified.
    /// * `public_keys` - A slice of references to `PublicKey` objects to verify against.
    ///
    /// # Returns
    /// * `true` if the aggregated signature is valid.
    /// * `false` otherwise.
    fn verify_aggregated_signature(&self, message: &[u8], aggregated_signature: &AggregatedSignature, public_keys: &[&PublicKey]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let public_key = signer.public_key();
        let message = b"Hello, world!";
        let signature = signer.sign(message);
        assert!(signer.verify_signature(message, &signature, &public_key));
    }

    #[test]
    fn test_negative() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let public_key = signer.public_key();
        let message = b"Hello, world!";
        let message2 = b"Hello, world2!";
        let signature = signer.sign(message);
        assert!(signer.verify_signature(message2, &signature, &public_key) == false);
    }

    #[test]
    fn test_aggregate() {
        let private_key_1 = [1u8; PRIVATE_KEY_SIZE];
        let private_key_2 = [2u8; PRIVATE_KEY_SIZE];

        let signer_1 = if let Ok(signer) = Crypto::new(private_key_1) {
            signer
        } else {
            panic!("Failed to create signer 1")
        };

        let signer_2 = if let Ok(signer) = Crypto::new(private_key_2) {
            signer
        } else {
            panic!("Failed to create signer 2")
        };
        let public_key_1 = signer_1.public_key();
        let public_key_2 = signer_2.public_key();
        let message = b"Hello, world!";
        let signature_1 = signer_1.multi_sign(message);
        let signature_2 = signer_2.multi_sign(message);

        let aggregated_signature_result = signer_1.aggregate_signatures(&[&signature_1, &signature_2], message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys = [public_key_1, public_key_2];
        assert!(signer_1.verify_aggregated_signature(message, &aggregated_signature, &public_keys));
    }

    #[test]
    fn test_aggregate_one() {
        let private_key_1 = [1u8; PRIVATE_KEY_SIZE];

        let signer_1 = if let Ok(signer) = Crypto::new(private_key_1) {
            signer
        } else {
            panic!("Failed to create signer 1")
        };

        let public_key_1 = signer_1.public_key();
        let message = b"Hello, world!";
        let signature_1 = signer_1.multi_sign(message);
        let aggregated_signature_result = signer_1.aggregate_signatures(&[&signature_1], message);
        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };
        let public_keys = [public_key_1];
        assert!(signer_1.verify_aggregated_signature(message, &aggregated_signature, &public_keys));
    }

    #[test]
    fn test_aggregate_negative_message_change() {
        let private_key_1 = [1u8; PRIVATE_KEY_SIZE];
        let private_key_2 = [2u8; PRIVATE_KEY_SIZE];

        let signer_1 = if let Ok(signer) = Crypto::new(private_key_1) {
            signer
        } else {
            panic!("Failed to create signer 1")
        };

        let signer_2 = if let Ok(signer) = Crypto::new(private_key_2) {
            signer
        } else {
            panic!("Failed to create signer 2")
        };
        let public_key_1 = signer_1.public_key();
        let public_key_2 = signer_2.public_key();
        let message = b"Hello, world!";
        let signature_1 = signer_1.multi_sign(message);
        let signature_2 = signer_2.multi_sign(message);
        let message2 = b"Hello, world2!";
        let aggregated_signature_result = signer_1.aggregate_signatures(&[&signature_1, &signature_2], message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys = [public_key_1, public_key_2];
        assert!(signer_1.verify_aggregated_signature(message2, &aggregated_signature, &public_keys) == false);
    }

    #[test]
    fn test_aggregate_negative_pk_change() {
        let private_key_1 = [1u8; PRIVATE_KEY_SIZE];
        let private_key_2 = [2u8; PRIVATE_KEY_SIZE];
        let private_key_3 = [3u8; PRIVATE_KEY_SIZE];

        let signer_1 = if let Ok(signer) = Crypto::new(private_key_1) {
            signer
        } else {
            panic!("Failed to create signer 1")
        };

        let signer_2 = if let Ok(signer) = Crypto::new(private_key_2) {
            signer
        } else {
            panic!("Failed to create signer 2")
        };

        let signer_3 = if let Ok(signer) = Crypto::new(private_key_3) {
            signer
        } else {
            panic!("Failed to create signer 2")
        };

        let public_key_1 = signer_1.public_key();
        let public_key_3 = signer_3.public_key();
        let message = b"Hello, world!";
        let signature_1 = signer_1.multi_sign(message);
        let signature_2 = signer_2.multi_sign(message);
        let aggregated_signature_result = signer_1.aggregate_signatures(&[&signature_1, &signature_2], message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys = [public_key_1, public_key_3];
        assert!(signer_1.verify_aggregated_signature(message, &aggregated_signature, &public_keys) == false);
    }

    #[test]
    fn test_multiple_single_signatures() {
        const TEST_COUNT: usize = 10;
        //setup test inputs
        let mut signers = Vec::<Crypto>::new();

        for i in 0..TEST_COUNT {
            let private_key = [(i + 1) as u8; 32];
            if let Ok(signer) = Crypto::new(private_key) {
                signers.push(signer);
            } else {
                panic!("Failed to create signer");
            }
        }

        let mut signatures = Vec::<Signature>::new();
        let message = b"Hello, world!";

        //do signing TEST_COUNT times
        for i in 0..TEST_COUNT {
            let signer = &signers[i];
            let signature = signer.sign(message);
            signatures.push(signature);
        }

        //verify signatures
        for i in 0..TEST_COUNT {
            let signer = &signers[i];
            let signature = &signatures[i];
            assert!(signer.verify_signature(message, signature, signer.public_key()));
        }
    }

    #[test]
    fn test_signature_serialization() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let message = b"Hello, world!";
        let signature = signer.sign(message);
        let serialized_signature = signature.serialize();
        let deserialized_signature_result = Signature::new(serialized_signature);
        let deserialized_signature = match deserialized_signature_result {
            Ok(sig) => sig,
            Err(_) => panic!("Failed to deserialize signature"),
        };
        assert!(signer.verify_signature(message, &deserialized_signature, signer.public_key()));
    }

    #[test]
    fn test_signature_deserialization_negative() {
        let invalid_signature = [0u8; SIGNATURE_SIZE - 1];
        assert!(Signature::new(&invalid_signature).is_err());
    }

    #[test]
    fn test_multi_signature_serialization() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let message = b"Hello, world!";
        let multi_signature = signer.multi_sign(message);
        let serialized_multi_signature = multi_signature.serialize();
        let deserialized_multi_signature_result = MultiSignature::new(serialized_multi_signature);
        let deserialized_multi_signature = match deserialized_multi_signature_result {
            Ok(sig) => sig,
            Err(_) => panic!("Failed to deserialize multi-signature"),
        };
        assert!(signer.verify_multi_signature(message, &deserialized_multi_signature, signer.public_key()));
    }

    #[test]
    fn test_multi_signature_deserialization_negative() {
        let invalid_multi_signature = [0u8; MULTI_SIGNATURE_SIZE - 1];
        assert!(MultiSignature::new(&invalid_multi_signature).is_err());
    }

    #[test]
    fn test_aggregated_signature_serialization() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let message = b"Hello, world!";
        let signature = signer.multi_sign(message);
        let aggregated_signature_result = signer.aggregate_signatures(&[&signature], message);
        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };
        let serialized_aggregated_signature = aggregated_signature.serialize();
        let deserialized_aggregated_signature_result = AggregatedSignature::new(&serialized_aggregated_signature);
        let deserialized_aggregated_signature = match deserialized_aggregated_signature_result {
            Ok(sig) => sig,
            Err(_) => panic!("Failed to deserialize aggregated signature"),
        };
        assert!(signer.verify_aggregated_signature(message, &deserialized_aggregated_signature, &[signer.public_key()]));
    }

    #[test]
    fn test_aggregated_signature_deserialization_negative() {
        let invalid_aggregated_signature = [0u8; AGGREGATED_SIGNATURE_CONSTANT_SIZE - 1];
        assert!(AggregatedSignature::new(&invalid_aggregated_signature).is_err());
    }

    #[test]
    fn test_aggregated_signature_count() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let message = b"Hello, world!";
        let signature = signer.multi_sign(message);
        let aggregated_signature_result = signer.aggregate_signatures(&[&signature], message);
        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };
        assert_eq!(aggregated_signature.get_count(), 1);
    }

    #[test]
    fn test_aggregated_signature_count_multiple() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let message = b"Hello, world!";
        let signature1 = signer.multi_sign(message);
        let signature2 = signer.multi_sign(message);
        let aggregated_signature_result = signer.aggregate_signatures(&[&signature1, &signature2], message);
        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };
        assert_eq!(aggregated_signature.get_count(), 2);
    }

    #[test]
    fn test_public_key_serialization() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let public_key = signer.public_key();
        let serialized_public_key = public_key.serialize();
        let deserialized_public_key_result = PublicKey::new(serialized_public_key);
        let deserialized_public_key = match deserialized_public_key_result {
            Ok(key) => key,
            Err(_) => panic!("Failed to deserialize public key"),
        };
        assert_eq!(public_key.serialize(), deserialized_public_key.serialize());
    }

    #[test]
    fn test_public_key_deserialization_negative() {
        let invalid_public_key = [0u8; PUBLIC_KEY_SIZE - 1];
        assert!(PublicKey::new(&invalid_public_key).is_err());
    }

    #[test]
    fn test_aggregate_signature_empty() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let message = b"Hello, world!";
        let aggregated_signature_result = signer.aggregate_signatures(&[], message);
        assert!(aggregated_signature_result.is_err());
    }

    #[test]
    fn test_multi_signature_negative_verify_message_change() {
        let private_key = [1u8; PRIVATE_KEY_SIZE];
        let signer = if let Ok(signer) = Crypto::new(private_key) {
            signer
        } else {
            panic!("Failed to create signer")
        };
        let public_key = signer.public_key();
        let message = b"Hello, world!";
        let message2 = b"Hello, world2!";
        let multi_signature = signer.multi_sign(message);
        assert!(signer.verify_multi_signature(message2, &multi_signature, public_key) == false);
    }

    #[test]
    fn test_aggregated_signature_empty_public_keys() {
        let private_key_1 = [1u8; PRIVATE_KEY_SIZE];
        let private_key_2 = [2u8; PRIVATE_KEY_SIZE];

        let signer_1 = if let Ok(signer) = Crypto::new(private_key_1) {
            signer
        } else {
            panic!("Failed to create signer 1")
        };

        let signer_2 = if let Ok(signer) = Crypto::new(private_key_2) {
            signer
        } else {
            panic!("Failed to create signer 2")
        };

        let message = b"Hello, world!";
        let signature_1 = signer_1.multi_sign(message);
        let signature_2 = signer_2.multi_sign(message);

        let aggregated_signature_result = signer_1.aggregate_signatures(&[&signature_1, &signature_2], message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        assert!(signer_1.verify_aggregated_signature(message, &aggregated_signature, &[]) == false);
    }
}
