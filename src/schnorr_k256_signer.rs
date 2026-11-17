//! BIP-340 Schnorr signatures on secp256k1, built on `k256` (DEC-235, Story 6.16).
//!
//! Single signatures are BIP-340 as implemented by `k256` 0.14: 32-byte x-only keys,
//! 64-byte `r ‖ s` signatures, big-endian, deterministic (zero auxiliary randomness).
//! `MultiSignature` is the same signature, used as an aggregation contribution.
//!
//! The aggregate is DEC-194's deterministically weighted half-aggregation over
//! signatures on one message, with fixed-width big-endian encodings:
//!
//! - `seed = H_tag("MoonBlokz/aggregate", r₁ ‖ … ‖ r_k ‖ P₁ ‖ … ‖ P_k ‖ m)`;
//! - `wᵢ = (int(H_tag("MoonBlokz/weight", seed ‖ i as u32)) mod (q − 1)) + 1`;
//! - `s = Σ wᵢ·sᵢ mod q`, serialized as `count u16 ‖ s ‖ r₁ … r_k`;
//! - verification checks `s·G = Σ wᵢ·Rᵢ + Σ (wᵢ·eᵢ)·Pᵢ` with `Rᵢ = lift_x(rᵢ)` and the
//!   BIP-340 challenge `eᵢ`, as a full point equation.
//!
//! `H_tag` is BIP-340's tagged hash, `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data)`, and `q`
//! is the group order. No multiscalar call is used: two scalar multiplications per
//! signer keep the verification frame small (D2).

use crate::{
    AGGREGATED_SIGNATURE_CONSTANT_SIZE, AGGREGATED_SIGNATURE_VARIABLE_SIZE,
    AggregatedSignatureTrait, CryptoError, CryptoTrait, MAX_AGGREGATED_SIGNATURES,
    MULTI_SIGNATURE_SIZE, MultiSignatureTrait, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, PublicKeyTrait,
    SIGNATURE_SIZE, SignatureTrait,
};
use k256::elliptic_curve::{PrimeField, group::Group, ops::Reduce};
use k256::schnorr::signature::hazmat::PrehashSigner;
use k256::schnorr::{Signature as Bip340Signature, SigningKey, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};

/// The proof-of-possession domain tag (D6, DEC-248): a proof is a BIP-340 signature over
/// `POP_TAG ‖ public key` (45 bytes). The separation is by message: an ordinary signature
/// over exactly those bytes is a proof too. No MoonBlokz message has that form
/// (transactions start with their type byte, blocks with the version, supports with
/// `MBSUP`, chain configurations with their entry count), and Schnorr aggregation does not
/// rely on the proof.
const POP_TAG: &[u8] = b"MoonBlokz/pop";
/// `count ‖ s` and the per-signer `r` of the serialized aggregate.
const CONSTANT: usize = AGGREGATED_SIGNATURE_CONSTANT_SIZE;
const R: usize = AGGREGATED_SIGNATURE_VARIABLE_SIZE;
const AGGREGATE_TAG: &[u8] = b"MoonBlokz/aggregate";
const WEIGHT_TAG: &[u8] = b"MoonBlokz/weight";
const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

/// `q − 1`, where `q` is the secp256k1 group order.
const ORDER_MINUS_ONE: U256 =
    U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");

/// A BIP-340 signature, `r ‖ s`, 32 bytes each, big-endian.
pub struct Signature {
    bytes: [u8; SIGNATURE_SIZE],
}

/// An aggregation contribution: a BIP-340 signature on the aggregated message.
pub struct MultiSignature {
    bytes: [u8; MULTI_SIGNATURE_SIZE],
}

/// A 32-byte x-only BIP-340 public key, validated when it is parsed.
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

/// A DEC-194 aggregate: `count`, `s` and the signers' `r` values in aggregation order.
pub struct AggregatedSignature {
    count: usize,
    s: [u8; 32],
    r: [[u8; 32]; MAX_AGGREGATED_SIGNATURES],
}

/// A signer holding a BIP-340 signing key and its serialized public key.
pub struct Crypto {
    signing_key: SigningKey,
    public_key: PublicKey,
}

/// Parses a 64-byte BIP-340 signature (rejects `r ≥ p`, `s ≥ q`, `r = 0`, `s = 0`).
fn parse_signature(bytes: &[u8]) -> Option<Bip340Signature> {
    Bip340Signature::try_from(bytes).ok()
}

/// Lifts a 32-byte x coordinate to the point with even y (BIP-340 `lift_x`).
fn lift_x(x: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(&FieldBytes::from(*x)).ok()
}

/// A SHA-256 state primed with BIP-340's tag prefix `SHA256(tag) ‖ SHA256(tag)`.
fn tagged(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher
}

fn hash_bytes(hasher: Sha256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The 32-byte big-endian value `(h mod (q − 1)) + 1`, in `[1, q − 1]`.
///
/// One conditional subtraction suffices: `h < 2²⁵⁶ < 2(q − 1)`.
fn weight_value(h: U256) -> U256 {
    let reduced = if h >= ORDER_MINUS_ONE {
        h.wrapping_sub(&ORDER_MINUS_ONE)
    } else {
        h
    };
    reduced.wrapping_add(&U256::ONE)
}

fn scalar_from_be(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_repr(FieldBytes::from(bytes)).into_option()
}

/// The weight of signer `index` under `seed`.
fn weight(seed: &[u8; 32], index: usize) -> Scalar {
    let mut hasher = tagged(WEIGHT_TAG);
    hasher.update(seed);
    hasher.update((index as u32).to_be_bytes());
    let value = weight_value(U256::from_be_slice(&hash_bytes(hasher)));
    // A value in [1, q − 1] is always a canonical scalar.
    scalar_from_be(value.to_be_bytes().into()).unwrap_or(Scalar::ONE)
}

/// The aggregate seed over the signers' `r` values, their keys and the message.
fn aggregate_seed<'a>(
    rs: impl Iterator<Item = &'a [u8; 32]>,
    keys: impl Iterator<Item = &'a [u8; PUBLIC_KEY_SIZE]>,
    message: &[u8],
) -> [u8; 32] {
    let mut hasher = tagged(AGGREGATE_TAG);
    for r in rs {
        hasher.update(r);
    }
    for key in keys {
        hasher.update(key);
    }
    hasher.update(message);
    hash_bytes(hasher)
}

/// The BIP-340 challenge `int(H_tag("BIP0340/challenge", r ‖ P ‖ m)) mod q`.
fn challenge(r: &[u8; 32], key: &[u8; PUBLIC_KEY_SIZE], message: &[u8]) -> Scalar {
    let mut hasher = tagged(CHALLENGE_TAG);
    hasher.update(r);
    hasher.update(key);
    hasher.update(message);
    <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(hash_bytes(hasher)))
}

fn pop_message(key: &[u8; PUBLIC_KEY_SIZE]) -> [u8; POP_TAG.len() + PUBLIC_KEY_SIZE] {
    let mut message = [0u8; POP_TAG.len() + PUBLIC_KEY_SIZE];
    message[..POP_TAG.len()].copy_from_slice(POP_TAG);
    message[POP_TAG.len()..].copy_from_slice(key);
    message
}

fn verify_bytes(message: &[u8], signature: &[u8], key: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    match (parse_signature(signature), lift_x(key)) {
        (Some(signature), Some(key)) => key.verify_raw(message, &signature).is_ok(),
        _ => false,
    }
}

impl SignatureTrait for Signature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; SIGNATURE_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        parse_signature(&bytes).ok_or(CryptoError::InvalidSignature)?;
        Ok(Self { bytes })
    }

    fn serialize(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl MultiSignatureTrait for MultiSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; MULTI_SIGNATURE_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        parse_signature(&bytes).ok_or(CryptoError::InvalidSignature)?;
        Ok(Self { bytes })
    }

    fn serialize(&self) -> &[u8; MULTI_SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl PublicKeyTrait for PublicKey {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        lift_x(&bytes).ok_or(CryptoError::InvalidPublicKey)?;
        Ok(Self { bytes })
    }

    fn serialize(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

impl AggregatedSignatureTrait for AggregatedSignature {
    /// Parses `count u16 ‖ s ‖ r₁ … r_count` (big-endian) from the front of `bytes`;
    /// trailing bytes are left to the caller (`serialized_len`). A count of 0 or above
    /// `MAX_AGGREGATED_SIGNATURES` is refused.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < CONSTANT {
            return Err(CryptoError::InvalidSignature);
        }
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if count == 0 || count > MAX_AGGREGATED_SIGNATURES || bytes.len() < CONSTANT + R * count {
            return Err(CryptoError::InvalidSignature);
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[2..CONSTANT]);
        let mut r = [[0u8; 32]; MAX_AGGREGATED_SIGNATURES];
        for (i, slot) in r.iter_mut().take(count).enumerate() {
            slot.copy_from_slice(&bytes[CONSTANT + R * i..CONSTANT + R * (i + 1)]);
        }
        Ok(Self { count, s, r })
    }

    fn serialize(&self, out: &mut [u8]) -> Result<usize, CryptoError> {
        let len = self.serialized_len();
        if out.len() < len {
            return Err(CryptoError::InvalidSignature);
        }
        out[..2].copy_from_slice(&(self.count as u16).to_be_bytes());
        out[2..CONSTANT].copy_from_slice(&self.s);
        for (i, r) in self.r.iter().take(self.count).enumerate() {
            out[CONSTANT + R * i..CONSTANT + R * (i + 1)].copy_from_slice(r);
        }
        Ok(len)
    }

    fn get_count(&self) -> usize {
        self.count
    }

    fn serialized_len(&self) -> usize {
        CONSTANT + R * self.count
    }
}

impl Crypto {
    fn sign_bytes(&self, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
        // `sign_prehash` is BIP-340 with zero auxiliary randomness, retrying with another
        // auxiliary byte only if the nonce is 0; failing all 256 tries has probability
        // about 2⁻²⁰⁴⁸ (documented on `CryptoTrait::sign`).
        let signature: Bip340Signature = self
            .signing_key
            .sign_prehash(message)
            .expect("BIP-340 signing fails only with negligible probability");
        signature.to_bytes()
    }
}

impl CryptoTrait for Crypto {
    fn new(private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(&FieldBytes::from(private_key_bytes))
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let public_key = PublicKey {
            bytes: signing_key.verifying_key().to_bytes().into(),
        };
        Ok(Self {
            signing_key,
            public_key,
        })
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            bytes: self.sign_bytes(message),
        }
    }

    fn multi_sign(&self, message: &[u8]) -> MultiSignature {
        MultiSignature {
            bytes: self.sign_bytes(message),
        }
    }

    fn verify_multi_signature(
        &self,
        message: &[u8],
        multi_signature: &MultiSignature,
        public_key: &PublicKey,
    ) -> bool {
        verify_bytes(message, &multi_signature.bytes, &public_key.bytes)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        verify_bytes(message, &signature.bytes, &public_key.bytes)
    }

    fn aggregate_signatures(
        &self,
        signatures: &[&MultiSignature],
        public_keys: &[&[u8; PUBLIC_KEY_SIZE]],
        message: &[u8],
    ) -> Result<AggregatedSignature, CryptoError> {
        let count = signatures.len();
        if count == 0 || count > MAX_AGGREGATED_SIGNATURES || public_keys.len() != count {
            return Err(CryptoError::InvalidSignature);
        }
        let mut r = [[0u8; 32]; MAX_AGGREGATED_SIGNATURES];
        for (slot, signature) in r.iter_mut().zip(signatures) {
            slot.copy_from_slice(&signature.bytes[..32]);
        }
        let seed = aggregate_seed(r.iter().take(count), public_keys.iter().copied(), message);
        let mut s = Scalar::ZERO;
        for (i, signature) in signatures.iter().enumerate() {
            let mut s_bytes = [0u8; 32];
            s_bytes.copy_from_slice(&signature.bytes[32..]);
            let s_i = scalar_from_be(s_bytes).ok_or(CryptoError::InvalidSignature)?;
            s += weight(&seed, i) * s_i;
        }
        Ok(AggregatedSignature {
            count,
            s: s.to_repr().into(),
            r,
        })
    }

    fn verify_aggregated_signature(
        &self,
        message: &[u8],
        aggregated_signature: &AggregatedSignature,
        public_keys: &[&PublicKey],
    ) -> bool {
        let count = aggregated_signature.count;
        if count == 0 || count > MAX_AGGREGATED_SIGNATURES || public_keys.len() != count {
            return false;
        }
        let Some(s) = scalar_from_be(aggregated_signature.s) else {
            return false;
        };
        let rs = &aggregated_signature.r[..count];
        let seed = aggregate_seed(rs.iter(), public_keys.iter().map(|k| &k.bytes), message);
        let mut sum = ProjectivePoint::IDENTITY;
        for (i, (r, key)) in rs.iter().zip(public_keys).enumerate() {
            let (Some(r_point), Some(key_point)) = (lift_x(r), lift_x(&key.bytes)) else {
                return false;
            };
            let w = weight(&seed, i);
            let e = challenge(r, &key.bytes, message);
            sum += ProjectivePoint::from(*r_point.as_affine()) * w;
            sum += ProjectivePoint::from(*key_point.as_affine()) * (w * e);
        }
        (ProjectivePoint::GENERATOR * s - sum).is_identity().into()
    }

    fn prove_possession(&self) -> Signature {
        self.sign(&pop_message(&self.public_key.bytes))
    }

    fn verify_possession(&self, public_key: &PublicKey, proof: &Signature) -> bool {
        verify_bytes(
            &pop_message(&public_key.bytes),
            &proof.bytes,
            &public_key.bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u256(hex: &str) -> U256 {
        U256::from_be_hex(hex)
    }

    #[test]
    fn weight_reduction_boundaries() {
        // q − 2, q − 1, q and 2²⁵⁶ − 1: every result is in [1, q − 1].
        let q_minus_2 = u256("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD036413F");
        let q = u256("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        assert_eq!(weight_value(q_minus_2), ORDER_MINUS_ONE);
        assert_eq!(weight_value(ORDER_MINUS_ONE), U256::ONE);
        assert_eq!(weight_value(q), U256::from_u64(2));
        let max = U256::MAX;
        let expected = max.wrapping_sub(&ORDER_MINUS_ONE).wrapping_add(&U256::ONE);
        assert_eq!(weight_value(max), expected);
        assert!(weight_value(max) < ORDER_MINUS_ONE.wrapping_add(&U256::ONE));
        assert_eq!(weight_value(U256::ZERO), U256::ONE);
    }

    #[test]
    fn lift_x_refuses_off_curve_and_out_of_range_x() {
        let mut five = [0u8; 32];
        five[31] = 5;
        assert!(lift_x(&five).is_none(), "5³ + 7 must be a non-residue");
        assert!(lift_x(&[0xFF; 32]).is_none(), "x ≥ p");
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(lift_x(&one).is_some(), "x = 1 is on the curve");
    }

    /// A DEC-194 aggregate pinned once (keys `[1; 32]` and `[2; 32]`, message
    /// `"Hello, world!"`): a change to the seed, the weights or the layout changes it.
    #[test]
    fn pinned_aggregate_vector() {
        const EXPECTED: [u8; 98] = [
            0x00, 0x02, 0x8d, 0x78, 0x7f, 0x11, 0x40, 0x78, 0x74, 0x78, 0x8b, 0x97, 0x34, 0x26,
            0x40, 0xe8, 0x04, 0xa9, 0xb0, 0x4b, 0xc1, 0x05, 0x7b, 0x57, 0xf6, 0x46, 0x10, 0xec,
            0x7b, 0xf8, 0xbe, 0xe2, 0x37, 0x54, 0xc2, 0xa9, 0x9c, 0x7c, 0x32, 0xfe, 0x4c, 0x8d,
            0x22, 0x2b, 0xe7, 0x83, 0xe0, 0x89, 0x76, 0x40, 0xe3, 0x7b, 0x3e, 0x7f, 0x8c, 0xb0,
            0xce, 0xda, 0xe4, 0x75, 0x69, 0xa6, 0xe2, 0x0c, 0xcc, 0x53, 0xbf, 0x8a, 0x69, 0x1d,
            0x4a, 0x49, 0x34, 0xcf, 0xbf, 0xb3, 0xf4, 0x7d, 0xb6, 0x28, 0x46, 0x58, 0x42, 0x2a,
            0xe6, 0x4d, 0x82, 0xdd, 0x32, 0xb3, 0x7d, 0x5e, 0x1e, 0xb8, 0x7e, 0xbb, 0x77, 0xbb,
        ];
        let message = b"Hello, world!";
        let a = Crypto::new([1u8; 32]).ok().unwrap();
        let b = Crypto::new([2u8; 32]).ok().unwrap();
        let (sa, sb) = (a.multi_sign(message), b.multi_sign(message));
        let keys = [a.public_key().serialize(), b.public_key().serialize()];
        let agg = a
            .aggregate_signatures(&[&sa, &sb], &keys, message)
            .ok()
            .unwrap();
        let mut out = [0u8; 98];
        assert_eq!(agg.serialize(&mut out).ok(), Some(98));
        assert_eq!(out, EXPECTED);
        assert!(a.verify_aggregated_signature(message, &agg, &[a.public_key(), b.public_key()]));
    }

    #[test]
    fn tagged_hash_matches_bip340_challenge_of_k256() {
        // A signature made by k256 verifies through our own challenge computation:
        // s·G − e·P = R, with e from `challenge`.
        let signer = Crypto::new([7u8; 32]).ok().unwrap();
        let message = b"tagged hash cross-check";
        let signature = signer.sign(message);
        let mut r = [0u8; 32];
        r.copy_from_slice(&signature.bytes[..32]);
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature.bytes[32..]);
        let s = scalar_from_be(s_bytes).unwrap();
        let e = challenge(&r, &signer.public_key.bytes, message);
        let key = lift_x(&signer.public_key.bytes).unwrap();
        let r_point = lift_x(&r).unwrap();
        let lhs = ProjectivePoint::GENERATOR * s - ProjectivePoint::from(*key.as_affine()) * e;
        assert_eq!(lhs, ProjectivePoint::from(*r_point.as_affine()));
    }
}
