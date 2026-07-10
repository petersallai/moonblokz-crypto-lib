#![no_std]

//! MoonBlokz Crypto Library
//! <https://www.moonblokz.com>
//!
//! This crate provides the cryptographic subsystem used by MoonBlokz for message signing,
//! verification, and compact multi-party approval evidence.
//!
//! It supports two algorithm families behind one compile-time-selected public API:
//!
//! - Schnorr
//! - BLS
//!
//! The library is designed for the MoonBlokz operating environment:
//!
//! - constrained devices,
//! - `no_std` compatibility,
//! - low-bandwidth radio communication,
//! - compact serialized artifacts,
//! - and bounded aggregated-signature behavior.
//!
//! Detailed background is available in the MoonBlokz article series:
//! <https://medium.com/@peter.sallai/moonblokz-series-part-i-building-a-hyper-local-blockchain-2f385b763c65>
//! Part VI discusses the cryptographic design space used by MoonBlokz.
//!
//! # Features
//!
//! Concrete backend features:
//!
//! - `schnorr-malachite`
//! - `schnorr-num-bigint-dig`
//! - `schnorr-crypto-bigint`
//! - `bls-bls12_381-bls`
//!
//! Internal family features used by the crate:
//!
//! - `schnorr`
//! - `bls`
//!
//! Exactly one concrete backend feature must be enabled at a time.
//!
//! # Signature Roles
//!
//! The public API distinguishes three artifact roles:
//!
//! - `Signature`: ordinary single-signer authorization artifact.
//! - `MultiSignature`: aggregation-ready single-signer artifact intended for later combination.
//! - `AggregatedSignature`: combined multi-party evidence artifact.
//!
//! # Usage
//!
//! Enable exactly one backend feature in `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! moonblokz-crypto = { version = "1.0", default-features = false, features = ["schnorr-malachite"] }
//! # moonblokz-crypto = { version = "1.0", default-features = false, features = ["schnorr-num-bigint-dig"] }
//! # moonblokz-crypto = { version = "1.0", default-features = false, features = ["schnorr-crypto-bigint"] }
//! # moonblokz-crypto = { version = "1.0", default-features = false, features = ["bls-bls12_381-bls"] }
//! ```
//!
//! # Example
//!
//! ```rust
//! use moonblokz_crypto::{Crypto, CryptoTrait};
//!
//! fn main() {
//!     let private_key = [1u8; 32];
//!     let signer = match Crypto::new(private_key) {
//!         Ok(signer) => signer,
//!         Err(_) => panic!("Failed to create signer"),
//!     };
//!     let message = b"Hello, world!";
//!     let signature = signer.sign(message);
//!     assert!(signer.verify_signature(message, &signature, signer.public_key()));
//! }
//! ```
//!
//! For aggregation-ready signatures and aggregated verification, see the crate README.
//!
//! # License
//!
//! This library is licensed under the MIT License.
//! See the [LICENSE](LICENSE) file for details.
//!
//! Enabled dependencies may use different licenses. Check dependency licensing before
//! distributing binaries or selecting a backend.
//!
//! # Authors
//!
//! - Peter Sallai (Bad Access)
//!

#[cfg(any(
    all(feature = "schnorr-malachite", any(feature = "schnorr-num-bigint-dig", feature = "schnorr-crypto-bigint", feature = "bls-bls12_381-bls")),
    all(feature = "schnorr-num-bigint-dig", any(feature = "schnorr-malachite", feature = "schnorr-crypto-bigint", feature = "bls-bls12_381-bls")),
    all(feature = "schnorr-crypto-bigint", any(feature = "schnorr-malachite", feature = "schnorr-num-bigint-dig", feature = "bls-bls12_381-bls")),
    all(feature = "bls-bls12_381-bls", any(feature = "schnorr-malachite", feature = "schnorr-num-bigint-dig", feature = "schnorr-crypto-bigint")),
))]
compile_error!("Only one crypto implementation feature can be enabled at a time");

#[cfg(not(any(feature = "schnorr-malachite", feature = "schnorr-num-bigint-dig", feature = "schnorr-crypto-bigint", feature = "bls-bls12_381-bls")))]
compile_error!("At least one crypto implementation feature must be enabled");

#[cfg(feature = "schnorr")]
/// Size of a `Signature` in bytes.
pub const SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "schnorr")]
/// Size of a `MultiSignature` in bytes.
pub const MULTI_SIGNATURE_SIZE: usize = 64;
#[cfg(feature = "schnorr")]
/// Size of a `PublicKey` in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;
#[cfg(feature = "schnorr")]
/// Size of a private key in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;
#[cfg(feature = "schnorr")]
/// Constant-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 34;
#[cfg(feature = "schnorr")]
/// Per-signer variable-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_VARIABLE_SIZE: usize = 32;

#[cfg(feature = "bls")]
/// Size of a `Signature` in bytes.
pub const SIGNATURE_SIZE: usize = 48;
#[cfg(feature = "bls")]
/// Size of a `MultiSignature` in bytes.
pub const MULTI_SIGNATURE_SIZE: usize = 48;
#[cfg(feature = "bls")]
/// Size of a `PublicKey` in bytes.
pub const PUBLIC_KEY_SIZE: usize = 96;
#[cfg(feature = "bls")]
/// Size of a private key in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;
#[cfg(feature = "bls")]
/// Constant-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 50;
#[cfg(feature = "bls")]
/// Per-signer variable-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_VARIABLE_SIZE: usize = 0;

/// Maximum number of signer contributions supported in an `AggregatedSignature`.
pub const MAX_AGGREGATED_SIGNATURES: usize = 50;
/// Maximum serialized size of an `AggregatedSignature` in bytes.
pub const MAX_AGGREGATED_SIGNATURE_BYTES: usize = AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE * MAX_AGGREGATED_SIGNATURES;

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

#[cfg(feature = "schnorr-crypto-bigint")]
pub mod schnorr_crypto_bigint_signer;
#[cfg(feature = "schnorr-crypto-bigint")]
pub use schnorr_crypto_bigint_signer::AggregatedSignature;
#[cfg(feature = "schnorr-crypto-bigint")]
pub use schnorr_crypto_bigint_signer::Crypto;
#[cfg(feature = "schnorr-crypto-bigint")]
pub use schnorr_crypto_bigint_signer::MultiSignature;
#[cfg(feature = "schnorr-crypto-bigint")]
pub use schnorr_crypto_bigint_signer::PublicKey;
#[cfg(feature = "schnorr-crypto-bigint")]
pub use schnorr_crypto_bigint_signer::Signature;

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

/// A trait representing a `Signature`.
///
/// A `Signature` is the ordinary single-signer authorization artifact in the public API.
pub trait SignatureTrait: Sized {
    /// Creates a `Signature` from serialized bytes.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the serialized signature.
    ///
    /// # Returns
    /// * `Ok(Self)` if the signature is valid.
    /// * `Err(CryptoError::InvalidSignature)` if the signature is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the `Signature` into its fixed-size byte representation.
    fn serialize(&self) -> &[u8; SIGNATURE_SIZE];
}

/// A trait representing a `MultiSignature`.
///
/// In the public API, `MultiSignature` is the aggregation-ready single-signer artifact.
pub trait MultiSignatureTrait: Sized {
    /// Creates a `MultiSignature` from serialized bytes.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the serialized aggregation-ready signature.
    ///
    /// # Returns
    /// * `Ok(Self)` if the `MultiSignature` is valid.
    /// * `Err(CryptoError::InvalidSignature)` if the `MultiSignature` is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the `MultiSignature` into its fixed-size byte representation.
    fn serialize(&self) -> &[u8; MULTI_SIGNATURE_SIZE];
}

/// A trait representing an `AggregatedSignature`.
///
/// An `AggregatedSignature` is the combined multi-party evidence artifact in the public API.
pub trait AggregatedSignatureTrait: Sized {
    /// Creates an `AggregatedSignature` from serialized bytes.
    ///
    /// # Arguments
    /// * `bytes` - A slice of bytes representing the serialized aggregated signature.
    ///
    /// # Returns
    /// * `Ok(Self)` if the aggregated signature is valid.
    /// * `Err(CryptoError::InvalidSignature)` if the aggregated signature is invalid.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError>;

    /// Serializes the `AggregatedSignature` into the provided output buffer.
    ///
    /// # Returns
    /// The number of bytes written to `out`.
    fn serialize(&self, out: &mut [u8]) -> Result<usize, CryptoError>;

    /// Returns the number of signer contributions encoded in this aggregated signature.
    fn get_count(&self) -> usize;
    /// Returns the serialized length of this aggregated signature.
    fn serialized_len(&self) -> usize;
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

/// A trait representing the main cryptographic interface.
/// Provides methods for key management, signing, verification, and aggregation.
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

    /// Retrieves the public key associated with this signer.
    fn public_key(&self) -> &PublicKey;

    /// Creates a `Signature` for a message.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Creates a `MultiSignature` for a message.
    ///
    /// `MultiSignature` is the aggregation-ready single-signer artifact in the public API.
    fn multi_sign(&self, message: &[u8]) -> MultiSignature;

    /// Verifies a `MultiSignature` against a message and a public key.
    fn verify_multi_signature(&self, message: &[u8], multi_signature: &MultiSignature, public_key: &PublicKey) -> bool;
    /// Verifies a `Signature` against a message and a public key.
    fn verify_signature(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> bool;

    /// Aggregates multiple aggregation-ready signatures into one `AggregatedSignature`.
    fn aggregate_signatures(&self, signatures: &[&MultiSignature], message: &[u8]) -> Result<AggregatedSignature, CryptoError>;

    /// Verifies an `AggregatedSignature` against a message and a set of public keys.
    fn verify_aggregated_signature(&self, message: &[u8], aggregated_signature: &AggregatedSignature, public_keys: &[&PublicKey]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array;

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

        let signatures = [&signature_1, &signature_2];
        let aggregated_signature_result = signer_1.aggregate_signatures(&signatures, message);

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
        let signatures = [&signature_1];
        let aggregated_signature_result = signer_1.aggregate_signatures(&signatures, message);
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
        let signatures = [&signature_1, &signature_2];
        let aggregated_signature_result = signer_1.aggregate_signatures(&signatures, message);

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
        let signatures = [&signature_1, &signature_2];
        let aggregated_signature_result = signer_1.aggregate_signatures(&signatures, message);

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
        let signers: [Crypto; TEST_COUNT] = array::from_fn(|i| {
            let private_key = [(i + 1) as u8; 32];
            match Crypto::new(private_key) {
                Ok(signer) => signer,
                Err(_) => panic!("Failed to create signer"),
            }
        });

        let message = b"Hello, world!";
        let signatures: [Signature; TEST_COUNT] = array::from_fn(|i| signers[i].sign(message));

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
        let signatures = [&signature];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, message);
        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };
        let mut serialized_aggregated_signature = [0u8; MAX_AGGREGATED_SIGNATURE_BYTES];
        let serialized_len = match aggregated_signature.serialize(&mut serialized_aggregated_signature) {
            Ok(len) => len,
            Err(_) => panic!("Failed to serialize aggregated signature"),
        };
        let deserialized_aggregated_signature_result = AggregatedSignature::new(&serialized_aggregated_signature[..serialized_len]);
        let deserialized_aggregated_signature = match deserialized_aggregated_signature_result {
            Ok(sig) => sig,
            Err(_) => panic!("Failed to deserialize aggregated signature"),
        };
        let public_keys = [signer.public_key()];
        assert!(signer.verify_aggregated_signature(message, &deserialized_aggregated_signature, &public_keys));
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
        let signatures = [&signature];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, message);
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
        let signatures = [&signature1, &signature2];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, message);
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
        let signatures: [&MultiSignature; 0] = [];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, message);
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

        let signatures = [&signature_1, &signature_2];
        let aggregated_signature_result = signer_1.aggregate_signatures(&signatures, message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys: [&PublicKey; 0] = [];
        assert!(signer_1.verify_aggregated_signature(message, &aggregated_signature, &public_keys) == false);
    }

    #[cfg(feature = "schnorr-crypto-bigint")]
    #[test]
    fn test_crypto_bigint_regression_vectors() {
        let private_key_1 = [1u8; PRIVATE_KEY_SIZE];
        let private_key_2 = [2u8; PRIVATE_KEY_SIZE];
        let message = b"Hello, world!";

        let signer_1 = match Crypto::new(private_key_1) {
            Ok(v) => v,
            Err(_) => panic!("failed signer_1"),
        };
        let signer_2 = match Crypto::new(private_key_2) {
            Ok(v) => v,
            Err(_) => panic!("failed signer_2"),
        };

        let signature = signer_1.sign(message);
        let expected_signature: [u8; 64] = [
            0x85, 0x6c, 0xea, 0x9f, 0xc1, 0xaf, 0x2d, 0x26, 0x22, 0x06, 0x99, 0xeb, 0x49, 0x0f, 0xf2, 0x65, 0x51, 0xdf, 0x4d, 0x91,
            0xd9, 0x24, 0xff, 0x47, 0xf0, 0x04, 0x8d, 0x62, 0x0b, 0x24, 0x7f, 0x3c, 0x0a, 0x48, 0xe8, 0x2e, 0x8f, 0xe3, 0x1c, 0xa5,
            0x82, 0xfa, 0xa4, 0x33, 0xf9, 0x9d, 0xc8, 0xa4, 0x91, 0xbf, 0xeb, 0x74, 0x99, 0x11, 0x94, 0xe2, 0x41, 0x26, 0xde, 0x9b,
            0x79, 0x1b, 0x46, 0x94,
        ];
        assert_eq!(signature.serialize(), &expected_signature);

        let sig1 = signer_1.multi_sign(message);
        let sig2 = signer_2.multi_sign(message);
        let aggregated = match signer_1.aggregate_signatures(&[&sig1, &sig2], message) {
            Ok(v) => v,
            Err(_) => panic!("failed aggregate"),
        };
        let mut out = [0u8; MAX_AGGREGATED_SIGNATURE_BYTES];
        let n = match aggregated.serialize(&mut out) {
            Ok(v) => v,
            Err(_) => panic!("failed serialize"),
        };
        let expected_count = 2usize;
        let expected_r1: [u8; 32] = [
            0x85, 0x6c, 0xea, 0x9f, 0xc1, 0xaf, 0x2d, 0x26, 0x22, 0x06, 0x99, 0xeb, 0x49, 0x0f, 0xf2, 0x65, 0x51, 0xdf, 0x4d, 0x91,
            0xd9, 0x24, 0xff, 0x47, 0xf0, 0x04, 0x8d, 0x62, 0x0b, 0x24, 0x7f, 0x3c,
        ];
        let expected_r2: [u8; 32] = [
            0xec, 0x23, 0xca, 0x57, 0xc7, 0x34, 0x47, 0x8e, 0xb8, 0xfe, 0x8b, 0xb8, 0x2d, 0xd9, 0xdf, 0x60, 0x14, 0xcf, 0xaf, 0x70,
            0xd8, 0x6f, 0x51, 0x1e, 0x7d, 0x9f, 0xbf, 0x4d, 0xc4, 0x48, 0x9f, 0x05,
        ];

        assert_eq!(n, 98);
        assert_eq!(u16::from_le_bytes([out[0], out[1]]) as usize, expected_count);
        assert_ne!(&out[2..34], &[0u8; 32]); // aggregated scalar must be non-zero bytes
        assert_eq!(&out[34..66], &expected_r1);
        assert_eq!(&out[66..98], &expected_r2);
    }
}
