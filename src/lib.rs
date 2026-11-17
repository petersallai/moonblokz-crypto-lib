#![no_std]
#![forbid(unsafe_code)]

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
//! Exactly one backend feature is enabled at a time; the names say the scheme,
//! not the implementation:
//!
//! - `schnorr` (default): BIP-340 Schnorr on secp256k1, built on `k256`.
//! - `bls-min-sig`: BLS12-381, IETF proof-of-possession suite, 48 B signatures
//!   in G1 and 96 B keys in G2, built on `bls12_381`.
//! - `bls-min-pk`: the same suite with 48 B keys in G1 and 96 B signatures in G2.
//!
//! Every backend is `no_std` and allocation-free.
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
//! moonblokz-crypto = { version = "1.0" } # `schnorr`, the default
//! # moonblokz-crypto = { version = "1.0", default-features = false, features = ["bls-min-sig"] }
//! # moonblokz-crypto = { version = "1.0", default-features = false, features = ["bls-min-pk"] }
//! ```
//!
//! # Example
//!
//! ```rust
//! use moonblokz_crypto::{Crypto, CryptoTrait};
//!
//! let private_key = [1u8; 32];
//! let signer = match Crypto::new(private_key) {
//!     Ok(signer) => signer,
//!     Err(_) => panic!("Failed to create signer"),
//! };
//! let message = b"Hello, world!";
//! let signature = signer.sign(message);
//! assert!(signer.verify_signature(message, &signature, signer.public_key()));
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
    all(
        feature = "schnorr",
        any(feature = "bls-min-sig", feature = "bls-min-pk")
    ),
    all(feature = "bls-min-sig", feature = "bls-min-pk"),
))]
compile_error!("Enable exactly one of the features `schnorr`, `bls-min-sig`, `bls-min-pk`");

#[cfg(not(any(feature = "schnorr", feature = "bls-min-sig", feature = "bls-min-pk")))]
compile_error!("Enable one of the features `schnorr`, `bls-min-sig`, `bls-min-pk`");

#[cfg(all(
    feature = "bls",
    not(any(feature = "bls-min-sig", feature = "bls-min-pk"))
))]
compile_error!("`bls` is a private helper feature: enable `bls-min-sig` or `bls-min-pk`");

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
/// Constant-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 34;
#[cfg(feature = "schnorr")]
/// Per-signer variable-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_VARIABLE_SIZE: usize = 32;

#[cfg(feature = "bls-min-sig")]
/// Size of a `Signature` in bytes.
pub const SIGNATURE_SIZE: usize = 48;
#[cfg(feature = "bls-min-sig")]
/// Size of a `MultiSignature` in bytes.
pub const MULTI_SIGNATURE_SIZE: usize = 48;
#[cfg(feature = "bls-min-sig")]
/// Size of a `PublicKey` in bytes.
pub const PUBLIC_KEY_SIZE: usize = 96;
#[cfg(feature = "bls-min-sig")]
/// Constant-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 50;

#[cfg(feature = "bls-min-pk")]
/// Size of a `Signature` in bytes.
pub const SIGNATURE_SIZE: usize = 96;
#[cfg(feature = "bls-min-pk")]
/// Size of a `MultiSignature` in bytes.
pub const MULTI_SIGNATURE_SIZE: usize = 96;
#[cfg(feature = "bls-min-pk")]
/// Size of a `PublicKey` in bytes.
pub const PUBLIC_KEY_SIZE: usize = 48;
#[cfg(feature = "bls-min-pk")]
/// Constant-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_CONSTANT_SIZE: usize = 98;

#[cfg(feature = "bls")]
/// Per-signer variable-size portion of an `AggregatedSignature` in bytes.
pub const AGGREGATED_SIGNATURE_VARIABLE_SIZE: usize = 0;

/// Size of a private key in bytes.
pub const PRIVATE_KEY_SIZE: usize = 32;

/// The build's signature scheme as the chain names it (configuration ID 33
/// `signature_scheme`, DEC-252): 0 `schnorr`, 1 `bls-min-sig`, 2 `bls-min-pk`.
#[cfg(feature = "schnorr")]
pub const SIGNATURE_SCHEME: u8 = 0;
/// The build's signature scheme as the chain names it (configuration ID 33
/// `signature_scheme`, DEC-252): 0 `schnorr`, 1 `bls-min-sig`, 2 `bls-min-pk`.
#[cfg(feature = "bls-min-sig")]
pub const SIGNATURE_SCHEME: u8 = 1;
/// The build's signature scheme as the chain names it (configuration ID 33
/// `signature_scheme`, DEC-252): 0 `schnorr`, 1 `bls-min-sig`, 2 `bls-min-pk`.
#[cfg(feature = "bls-min-pk")]
pub const SIGNATURE_SCHEME: u8 = 2;

/// Maximum number of signer contributions supported in an `AggregatedSignature`.
pub const MAX_AGGREGATED_SIGNATURES: usize = 50;
/// Maximum serialized size of an `AggregatedSignature` in bytes.
pub const MAX_AGGREGATED_SIGNATURE_BYTES: usize = AGGREGATED_SIGNATURE_CONSTANT_SIZE
    + AGGREGATED_SIGNATURE_VARIABLE_SIZE * MAX_AGGREGATED_SIGNATURES;

#[cfg(feature = "schnorr")]
pub mod schnorr_k256_signer;
#[cfg(feature = "schnorr")]
pub use schnorr_k256_signer::{AggregatedSignature, Crypto, MultiSignature, PublicKey, Signature};

#[cfg(all(test, feature = "bls"))]
mod bls_eth_vectors;
#[cfg(feature = "bls")]
pub mod bls_zkcrypto_signer;
#[cfg(feature = "bls")]
pub use bls_zkcrypto_signer::{AggregatedSignature, Crypto, MultiSignature, PublicKey, Signature};

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
///
/// **Invariant (every backend, every constructor):** a `MultiSignature` value always holds
/// a well-formed signature; on BLS a point of the prime-order subgroup other than the
/// identity. [`MultiSignatureTrait::new`] and [`CryptoTrait::multi_sign`] are the only
/// ways to obtain one, and the value is opaque. [`CryptoTrait::aggregate_signatures`]
/// relies on it: BLS decompresses the contributions without repeating the subgroup check
/// (Story 6.17 AC0). A new constructor must keep it.
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
    ///
    /// # Panics
    ///
    /// The Schnorr backend panics if BIP-340 signing fails for all 256 auxiliary bytes it
    /// tries (a zero nonce each time): probability about 2⁻²⁰⁴⁸. The same holds for
    /// [`CryptoTrait::multi_sign`] and [`CryptoTrait::prove_possession`]. BLS signing does
    /// not panic.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Creates a `MultiSignature` for a message.
    ///
    /// `MultiSignature` is the aggregation-ready single-signer artifact in the public API.
    fn multi_sign(&self, message: &[u8]) -> MultiSignature;

    /// Verifies a `MultiSignature` against a message and a public key.
    fn verify_multi_signature(
        &self,
        message: &[u8],
        multi_signature: &MultiSignature,
        public_key: &PublicKey,
    ) -> bool;
    /// Verifies a `Signature` against a message and a public key.
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool;

    /// Aggregates aggregation-ready signatures on one message into one `AggregatedSignature`.
    ///
    /// `public_keys[i]` is the serialized key of the signer of `signatures[i]`, in the same
    /// order. Schnorr binds every weight to all nonces, all keys and the message (DEC-194);
    /// BLS ignores the keys. Empty input, more than `MAX_AGGREGATED_SIGNATURES` signatures
    /// and a length mismatch are errors.
    ///
    /// The caller verifies every contribution against its key before aggregating, and
    /// ensures the signers are distinct: neither is checked here, so an invalid
    /// contribution or key yields an aggregate that never verifies, and a repeated signer
    /// is counted twice. Each contribution is taken as the validated point the
    /// [`MultiSignatureTrait`] invariant guarantees, not re-validated; a sum that is the
    /// identity is refused.
    fn aggregate_signatures(
        &self,
        signatures: &[&MultiSignature],
        public_keys: &[&[u8; PUBLIC_KEY_SIZE]],
        message: &[u8],
    ) -> Result<AggregatedSignature, CryptoError>;

    /// Verifies an `AggregatedSignature` against a message and the signers' public keys,
    /// in the order the signatures were aggregated.
    ///
    /// Precondition for BLS: every key carries a verified proof of possession
    /// ([`CryptoTrait::verify_possession`]); the proof-of-possession suite has no rogue-key
    /// coefficients. Schnorr half-aggregation does not need it (each signature binds its own
    /// key through its challenge). Signer distinctness is the caller's check: a repeated key
    /// is not refused.
    fn verify_aggregated_signature(
        &self,
        message: &[u8],
        aggregated_signature: &AggregatedSignature,
        public_keys: &[&PublicKey],
    ) -> bool;

    /// Proves possession of this signer's private key: a `Signature` over the signer's own
    /// public key in a domain of its own. BLS separates it by the suite's PoP DST, so no
    /// ordinary signature is a proof. Schnorr separates it by message: the proof signs
    /// `"MoonBlokz/pop" ‖ key`, so an ordinary signature over exactly those bytes is one too;
    /// MoonBlokz never signs such a message, and Schnorr aggregation does not rely on it.
    fn prove_possession(&self) -> Signature;

    /// Verifies a proof of possession made by [`CryptoTrait::prove_possession`] for `public_key`.
    fn verify_possession(&self, public_key: &PublicKey, proof: &Signature) -> bool;
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
        assert!(signer.verify_signature(message, &signature, public_key));
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
        assert!(!signer.verify_signature(message2, &signature, public_key));
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

        let keys = [
            signer_1.public_key().serialize(),
            signer_2.public_key().serialize(),
        ];
        let aggregated_signature_result =
            signer_1.aggregate_signatures(&signatures, &keys, message);

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

        let keys = [signer_1.public_key().serialize()];
        let aggregated_signature_result =
            signer_1.aggregate_signatures(&signatures, &keys, message);
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

        let keys = [
            signer_1.public_key().serialize(),
            signer_2.public_key().serialize(),
        ];
        let aggregated_signature_result =
            signer_1.aggregate_signatures(&signatures, &keys, message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys = [public_key_1, public_key_2];
        assert!(!signer_1.verify_aggregated_signature(
            message2,
            &aggregated_signature,
            &public_keys
        ));
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

        let keys = [
            signer_1.public_key().serialize(),
            signer_2.public_key().serialize(),
        ];
        let aggregated_signature_result =
            signer_1.aggregate_signatures(&signatures, &keys, message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys = [public_key_1, public_key_3];
        assert!(!signer_1.verify_aggregated_signature(
            message,
            &aggregated_signature,
            &public_keys
        ));
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
        assert!(signer.verify_multi_signature(
            message,
            &deserialized_multi_signature,
            signer.public_key()
        ));
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

        let keys = [signer.public_key().serialize()];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, &keys, message);
        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };
        let mut serialized_aggregated_signature = [0u8; MAX_AGGREGATED_SIGNATURE_BYTES];
        let serialized_len =
            match aggregated_signature.serialize(&mut serialized_aggregated_signature) {
                Ok(len) => len,
                Err(_) => panic!("Failed to serialize aggregated signature"),
            };
        let deserialized_aggregated_signature_result =
            AggregatedSignature::new(&serialized_aggregated_signature[..serialized_len]);
        let deserialized_aggregated_signature = match deserialized_aggregated_signature_result {
            Ok(sig) => sig,
            Err(_) => panic!("Failed to deserialize aggregated signature"),
        };
        let public_keys = [signer.public_key()];
        assert!(signer.verify_aggregated_signature(
            message,
            &deserialized_aggregated_signature,
            &public_keys
        ));
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

        let keys = [signer.public_key().serialize()];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, &keys, message);
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

        let keys = [
            signer.public_key().serialize(),
            signer.public_key().serialize(),
        ];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, &keys, message);
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
        let keys: [&[u8; PUBLIC_KEY_SIZE]; 0] = [];
        let aggregated_signature_result = signer.aggregate_signatures(&signatures, &keys, message);
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
        assert!(!signer.verify_multi_signature(message2, &multi_signature, public_key));
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

        let keys = [
            signer_1.public_key().serialize(),
            signer_2.public_key().serialize(),
        ];
        let aggregated_signature_result =
            signer_1.aggregate_signatures(&signatures, &keys, message);

        let aggregated_signature = match aggregated_signature_result {
            Ok(signature) => signature,
            Err(_) => panic!("Failed to aggregate signature"),
        };

        let public_keys: [&PublicKey; 0] = [];
        assert!(!signer_1.verify_aggregated_signature(
            message,
            &aggregated_signature,
            &public_keys
        ));
    }

    fn signer(seed: u8) -> Crypto {
        match Crypto::new([seed; PRIVATE_KEY_SIZE]) {
            Ok(signer) => signer,
            Err(_) => panic!("failed to create signer {seed}"),
        }
    }

    /// The code the chain configuration names (ID 33) matches the build's sizes.
    #[test]
    fn signature_scheme_matches_the_sizes() {
        let expected = match (SIGNATURE_SIZE, PUBLIC_KEY_SIZE) {
            (64, 32) => 0,
            (48, 96) => 1,
            (96, 48) => 2,
            _ => panic!("unknown scheme sizes"),
        };
        assert_eq!(SIGNATURE_SCHEME, expected);
    }

    #[test]
    fn possession_round_trip() {
        let a = signer(1);
        let proof = a.prove_possession();
        assert!(a.verify_possession(a.public_key(), &proof));
        let parsed = match Signature::new(proof.serialize()) {
            Ok(sig) => sig,
            Err(_) => panic!("proof does not parse"),
        };
        assert!(signer(9).verify_possession(a.public_key(), &parsed));
    }

    #[test]
    fn possession_refuses_another_keys_proof() {
        let a = signer(1);
        let b = signer(2);
        assert!(!a.verify_possession(b.public_key(), &a.prove_possession()));
    }

    #[test]
    fn possession_is_not_an_ordinary_signature() {
        let a = signer(1);
        let key = a.public_key().serialize();
        // An ordinary signature over the key bytes is not a proof ...
        assert!(!a.verify_possession(a.public_key(), &a.sign(key)));
        // ... and a proof is not an ordinary signature over the key bytes.
        assert!(!a.verify_signature(key, &a.prove_possession(), a.public_key()));
    }

    /// Schnorr separates the proof by message only (DEC-248): an ordinary signature over
    /// `"MoonBlokz/pop" ‖ key` is a proof. Pinned so the documented limit stays true.
    #[cfg(feature = "schnorr")]
    #[test]
    fn schnorr_possession_is_separated_by_message() {
        let a = signer(1);
        let mut message = [0u8; 13 + PUBLIC_KEY_SIZE];
        message[..13].copy_from_slice(b"MoonBlokz/pop");
        message[13..].copy_from_slice(a.public_key().serialize());
        assert!(a.verify_possession(a.public_key(), &a.sign(&message)));
    }

    #[test]
    fn aggregate_refuses_a_key_count_mismatch() {
        let a = signer(1);
        let b = signer(2);
        let message = b"m";
        let (sa, sb) = (a.multi_sign(message), b.multi_sign(message));
        let one_key = [a.public_key().serialize()];
        assert!(
            a.aggregate_signatures(&[&sa, &sb], &one_key, message)
                .is_err()
        );
    }

    #[test]
    fn aggregate_verification_refuses_a_wrong_key_a_dropped_signer_and_for_schnorr_a_wrong_order() {
        let signers = [signer(1), signer(2), signer(3)];
        let message = b"order matters";
        let sigs: [MultiSignature; 3] = core::array::from_fn(|i| signers[i].multi_sign(message));
        let keys = [
            signers[0].public_key().serialize(),
            signers[1].public_key().serialize(),
            signers[2].public_key().serialize(),
        ];
        let agg = match signers[0].aggregate_signatures(
            &[&sigs[0], &sigs[1], &sigs[2]],
            &keys,
            message,
        ) {
            Ok(agg) => agg,
            Err(_) => panic!("aggregate"),
        };
        let pk = |i: usize| signers[i].public_key();
        assert!(signers[0].verify_aggregated_signature(message, &agg, &[pk(0), pk(1), pk(2)]));
        // The Schnorr weights bind the order (DEC-194); a BLS sum does not depend on it.
        #[cfg(feature = "schnorr")]
        assert!(!signers[0].verify_aggregated_signature(message, &agg, &[pk(1), pk(0), pk(2)]));
        let other = signer(4);
        assert!(!signers[0].verify_aggregated_signature(
            message,
            &agg,
            &[pk(0), other.public_key(), pk(2)]
        ));
        assert!(!signers[0].verify_aggregated_signature(message, &agg, &[pk(0), pk(1)]));
        // Aggregated in another order, verified in the original order.
        let swapped_keys = [keys[1], keys[0], keys[2]];
        let swapped = match signers[0].aggregate_signatures(
            &[&sigs[1], &sigs[0], &sigs[2]],
            &swapped_keys,
            message,
        ) {
            Ok(agg) => agg,
            Err(_) => panic!("aggregate"),
        };
        #[cfg(feature = "schnorr")]
        assert!(!signers[0].verify_aggregated_signature(message, &swapped, &[pk(0), pk(1), pk(2)]));
        assert!(signers[0].verify_aggregated_signature(message, &swapped, &[pk(1), pk(0), pk(2)]));
    }

    #[test]
    fn aggregated_signature_refuses_a_zero_count() {
        // A valid aggregate with only its count zeroed: the count rule alone refuses it.
        let (a, b) = (signer(1), signer(2));
        let message = b"m";
        let (sa, sb) = (a.multi_sign(message), b.multi_sign(message));
        let keys = [a.public_key().serialize(), b.public_key().serialize()];
        let agg = match a.aggregate_signatures(&[&sa, &sb], &keys, message) {
            Ok(agg) => agg,
            Err(_) => panic!("aggregate"),
        };
        let mut bytes = [0u8; MAX_AGGREGATED_SIGNATURE_BYTES];
        let len = match agg.serialize(&mut bytes) {
            Ok(len) => len,
            Err(_) => panic!("serialize"),
        };
        assert!(AggregatedSignature::new(&bytes[..len]).is_ok());
        bytes[..2].copy_from_slice(&[0, 0]);
        assert!(AggregatedSignature::new(&bytes[..len]).is_err());
    }

    /// DEC-194 / DEC-235 specifics of the Schnorr aggregate.
    #[cfg(feature = "schnorr")]
    mod dec194 {
        use super::super::*;
        use super::signer;

        const Q: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        fn two_signer_aggregate(message: &[u8]) -> ([u8; 98], [Crypto; 2]) {
            let signers = [signer(1), signer(2)];
            let sigs = [
                signers[0].multi_sign(message),
                signers[1].multi_sign(message),
            ];
            let keys = [
                signers[0].public_key().serialize(),
                signers[1].public_key().serialize(),
            ];
            let agg = match signers[0].aggregate_signatures(&[&sigs[0], &sigs[1]], &keys, message) {
                Ok(agg) => agg,
                Err(_) => panic!("aggregate"),
            };
            let mut out = [0u8; 98];
            assert_eq!(agg.serialize(&mut out).ok(), Some(98));
            (out, signers)
        }

        fn verifies(bytes: &[u8], signers: &[Crypto; 2], message: &[u8]) -> bool {
            match AggregatedSignature::new(bytes) {
                Ok(agg) => signers[0].verify_aggregated_signature(
                    message,
                    &agg,
                    &[signers[0].public_key(), signers[1].public_key()],
                ),
                Err(_) => false,
            }
        }

        fn sub_mod_q(s: &[u8; 32]) -> [u8; 32] {
            // q − s, big-endian, for 0 < s < q.
            let mut out = [0u8; 32];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let v = Q[i] as i16 - s[i] as i16 - borrow;
                borrow = if v < 0 { 1 } else { 0 };
                out[i] = (v + 256 * borrow) as u8;
            }
            out
        }

        #[test]
        fn layout_is_big_endian_count_s_then_r_values() {
            let message = b"layout";
            let (bytes, signers) = two_signer_aggregate(message);
            assert_eq!(&bytes[..2], &[0, 2]);
            let first = signers[0].multi_sign(message);
            assert_eq!(&bytes[34..66], &first.serialize()[..32]);
            assert!(verifies(&bytes, &signers, message));
        }

        #[test]
        fn the_negated_aggregate_is_refused() {
            // The old x-only comparison accepted −s; the full point check does not.
            let message = b"negation";
            let (mut bytes, signers) = two_signer_aggregate(message);
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes[2..34]);
            bytes[2..34].copy_from_slice(&sub_mod_q(&s));
            assert!(!verifies(&bytes, &signers, message));
        }

        #[test]
        fn s_at_or_above_the_order_is_refused() {
            let message = b"range";
            let (mut bytes, signers) = two_signer_aggregate(message);
            bytes[2..34].copy_from_slice(&Q);
            assert!(!verifies(&bytes, &signers, message));
            bytes[2..34].copy_from_slice(&[0xFF; 32]);
            assert!(!verifies(&bytes, &signers, message));
        }

        #[test]
        fn an_unliftable_r_is_refused() {
            let message = b"lift";
            let (mut bytes, signers) = two_signer_aggregate(message);
            bytes[34..66].copy_from_slice(&[0xFF; 32]); // ≥ p
            assert!(!verifies(&bytes, &signers, message));
            let (mut bytes, signers) = two_signer_aggregate(message);
            // x = 5 is not the x coordinate of a secp256k1 point (5³ + 7 is a non-residue).
            let mut x = [0u8; 32];
            x[31] = 5;
            bytes[66..98].copy_from_slice(&x);
            assert!(!verifies(&bytes, &signers, message));
        }

        #[test]
        fn a_changed_message_is_refused() {
            let (bytes, signers) = two_signer_aggregate(b"original");
            assert!(!verifies(&bytes, &signers, b"changed"));
        }
    }

    // Official BIP-340 test vectors (https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv),
    // transcribed from k256 0.14.0's own tests (`src/schnorr.rs`). Signing goes through the
    // trait for the vectors with zero auxiliary randomness (0 and 15-18); verification covers
    // all 19, a parse failure counting as "invalid".
    #[cfg(feature = "schnorr")]
    mod bip340 {
        use super::super::*;

        fn hex<const N: usize>(s: &str) -> [u8; N] {
            let mut out = [0u8; N];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }

        fn hex_vec(s: &str, out: &mut [u8]) -> usize {
            for (i, byte) in out.iter_mut().take(s.len() / 2).enumerate() {
                *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
            }
            s.len() / 2
        }

        fn verifies(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            let (Ok(key), Ok(signature)) = (PublicKey::new(key), Signature::new(signature)) else {
                return false;
            };
            let verifier = Crypto::new([1u8; PRIVATE_KEY_SIZE]).ok().unwrap();
            verifier.verify_signature(message, &signature, &key)
        }

        /// (index, secret key, public key, aux_rand, message, signature)
        const SIGN: [(u8, &str, &str, &str, &str, &str); 4] = [
            (
                0,
                "0000000000000000000000000000000000000000000000000000000000000003",
                "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            ),
            (
                1,
                "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            ),
            (
                2,
                "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
                "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
                "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
                "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            ),
            (
                3,
                "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
                "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            ),
        ];

        /// (index, public key, message, signature, valid)
        const VERIFY: [(u8, &str, &str, &str, bool); 11] = [
            (
                4,
                "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
                "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
                "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
                true,
            ),
            (
                5,
                "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                false,
            ),
            (
                6,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
                false,
            ),
            (
                7,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
                false,
            ),
            (
                8,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
                false,
            ),
            (
                9,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
                false,
            ),
            (
                10,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
                false,
            ),
            (
                11,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                false,
            ),
            (
                12,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                false,
            ),
            (
                13,
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                false,
            ),
            (
                14,
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                false,
            ),
        ];

        /// Secret key of vectors 15-18 (aux_rand is zero).
        const EXT_KEY: &str = "0340034003400340034003400340034003400340034003400340034003400340";
        /// (index, message, signature)
        const EXT: [(u8, &str, &str); 4] = [
            (
                15,
                "",
                "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
            ),
            (
                16,
                "11",
                "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
            ),
            (
                17,
                "0102030405060708090A0B0C0D0E0F1011",
                "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
            ),
            (
                18,
                "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
                "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
            ),
        ];

        #[test]
        fn bip340_signing_through_the_trait() {
            // Vector 0 uses zero aux_rand, so the trait's deterministic signing must match it.
            let (index, secret, public, aux, message, signature) = SIGN[0];
            assert_eq!(
                aux,
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
            let signer = Crypto::new(hex::<32>(secret)).ok().unwrap();
            assert_eq!(
                signer.public_key().serialize(),
                &hex::<32>(public),
                "key {index}"
            );
            let produced = signer.sign(&hex::<32>(message));
            assert_eq!(
                produced.serialize(),
                &hex::<64>(signature),
                "signature {index}"
            );
            assert_eq!(
                signer.multi_sign(&hex::<32>(message)).serialize(),
                &hex::<64>(signature)
            );

            let signer = Crypto::new(hex::<32>(EXT_KEY)).ok().unwrap();
            for (index, message, signature) in EXT {
                let mut buf = [0u8; 100];
                let len = hex_vec(message, &mut buf);
                let produced = signer.sign(&buf[..len]);
                assert_eq!(
                    produced.serialize(),
                    &hex::<64>(signature),
                    "signature {index}"
                );
            }
        }

        #[test]
        fn bip340_verification_vectors() {
            for (index, _, public, _, message, signature) in SIGN {
                assert!(
                    verifies(&hex(public), &hex::<32>(message), &hex(signature)),
                    "vector {index}"
                );
            }
            for (index, public, message, signature, valid) in VERIFY {
                assert_eq!(
                    verifies(&hex(public), &hex::<32>(message), &hex(signature)),
                    valid,
                    "vector {index}"
                );
            }
            let key = *Crypto::new(hex::<32>(EXT_KEY))
                .ok()
                .unwrap()
                .public_key()
                .serialize();
            for (index, message, signature) in EXT {
                let mut buf = [0u8; 100];
                let len = hex_vec(message, &mut buf);
                assert!(
                    verifies(&key, &buf[..len], &hex(signature)),
                    "vector {index}"
                );
            }
        }
    }
}
