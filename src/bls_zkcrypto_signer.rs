//! BLS12-381 signatures, the IETF proof-of-possession ciphersuites, built on zkcrypto
//! `bls12_381` (DEC-247, Story 6.16).
//!
//! Two build-time variants share one core; only the group choice, the domain separation
//! tags and the sizes differ:
//!
//! - `bls-min-sig`: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_`, 48-byte signatures in
//!   G1, 96-byte keys in G2;
//! - `bls-min-pk`: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, 48-byte keys in G1,
//!   96-byte signatures in G2.
//!
//! Signatures on one message aggregate by plain sums and are verified against the sum of
//! the keys (FastAggregateVerify). That is rogue-key safe only for keys whose proof of
//! possession was verified ([`CryptoTrait::verify_possession`], the suite's
//! `PopProve` / `PopVerify` with its own DST). Keys and signatures are validated when they
//! are parsed: decompression with the subgroup check, and the identity is refused.
//!
//! Private keys are 32-byte big-endian integers `1 ≤ sk < r`. Integers in the aggregate
//! (`count u16`) are big-endian, as in the Schnorr backend.

use crate::{
    AGGREGATED_SIGNATURE_CONSTANT_SIZE, AggregatedSignatureTrait, CryptoError, CryptoTrait,
    MAX_AGGREGATED_SIGNATURES, MULTI_SIGNATURE_SIZE, MultiSignatureTrait, PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE, PublicKeyTrait, SIGNATURE_SIZE, SignatureTrait,
};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};

/// The group-dependent part of a ciphersuite. Everything else is written once below.
trait Variant {
    /// A signature point.
    type Sig;
    /// A public-key point.
    type Key;
    /// A running sum of signatures.
    type SigSum;
    /// A running sum of keys.
    type KeySum;

    const SIGNATURE_DST: &'static [u8];
    const POP_DST: &'static [u8];

    /// Decompresses with the subgroup check and refuses the identity.
    fn parse_sig(bytes: &[u8; SIGNATURE_SIZE]) -> Option<Self::Sig>;
    fn parse_key(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Option<Self::Key>;
    fn key_of(sk: &Scalar) -> [u8; PUBLIC_KEY_SIZE];
    /// `sk · H(message)` in the signature group, serialized.
    fn sign(sk: &Scalar, message: &[u8], dst: &[u8]) -> [u8; SIGNATURE_SIZE];
    /// `e(signature, generator) == e(H(message), key)` with the arguments in the
    /// variant's groups.
    fn pairing_check(key: &Self::Key, message: &[u8], dst: &[u8], sig: &Self::Sig) -> bool;

    fn sig_sum() -> Self::SigSum;
    fn add_sig(sum: &mut Self::SigSum, sig: &Self::Sig);
    fn sig_of_sum(sum: &Self::SigSum) -> [u8; SIGNATURE_SIZE];
    fn key_sum() -> Self::KeySum;
    fn add_key(sum: &mut Self::KeySum, key: &Self::Key);
    /// The summed key, or `None` when it is the identity.
    fn key_of_sum(sum: &Self::KeySum) -> Option<Self::Key>;
}

#[cfg(feature = "bls-min-sig")]
fn hash_g1(message: &[u8], dst: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve([message], dst)
}

#[cfg(feature = "bls-min-pk")]
fn hash_g2(message: &[u8], dst: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve([message], dst)
}

fn g1_from_bytes(bytes: &[u8; 48]) -> Option<G1Affine> {
    let point = Option::<G1Affine>::from(G1Affine::from_compressed(bytes))?;
    (!bool::from(point.is_identity())).then_some(point)
}

fn g2_from_bytes(bytes: &[u8; 96]) -> Option<G2Affine> {
    let point = Option::<G2Affine>::from(G2Affine::from_compressed(bytes))?;
    (!bool::from(point.is_identity())).then_some(point)
}

/// Signatures in G1, keys in G2.
#[cfg(feature = "bls-min-sig")]
struct MinSig;

#[cfg(feature = "bls-min-sig")]
impl Variant for MinSig {
    type Sig = G1Affine;
    type Key = G2Affine;
    type SigSum = G1Projective;
    type KeySum = G2Projective;

    const SIGNATURE_DST: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
    const POP_DST: &'static [u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    fn parse_sig(bytes: &[u8; SIGNATURE_SIZE]) -> Option<G1Affine> {
        g1_from_bytes(bytes)
    }
    fn parse_key(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Option<G2Affine> {
        g2_from_bytes(bytes)
    }
    fn key_of(sk: &Scalar) -> [u8; PUBLIC_KEY_SIZE] {
        G2Affine::from(G2Affine::generator() * sk).to_compressed()
    }
    fn sign(sk: &Scalar, message: &[u8], dst: &[u8]) -> [u8; SIGNATURE_SIZE] {
        G1Affine::from(hash_g1(message, dst) * sk).to_compressed()
    }
    fn pairing_check(key: &G2Affine, message: &[u8], dst: &[u8], sig: &G1Affine) -> bool {
        let hashed = G1Affine::from(hash_g1(message, dst));
        pairing(sig, &G2Affine::generator()) == pairing(&hashed, key)
    }
    fn sig_sum() -> G1Projective {
        G1Projective::identity()
    }
    fn add_sig(sum: &mut G1Projective, sig: &G1Affine) {
        *sum += sig;
    }
    fn sig_of_sum(sum: &G1Projective) -> [u8; SIGNATURE_SIZE] {
        G1Affine::from(sum).to_compressed()
    }
    fn key_sum() -> G2Projective {
        G2Projective::identity()
    }
    fn add_key(sum: &mut G2Projective, key: &G2Affine) {
        *sum += key;
    }
    fn key_of_sum(sum: &G2Projective) -> Option<G2Affine> {
        let key = G2Affine::from(sum);
        (!bool::from(key.is_identity())).then_some(key)
    }
}

/// Keys in G1, signatures in G2.
#[cfg(feature = "bls-min-pk")]
struct MinPk;

#[cfg(feature = "bls-min-pk")]
impl Variant for MinPk {
    type Sig = G2Affine;
    type Key = G1Affine;
    type SigSum = G2Projective;
    type KeySum = G1Projective;

    const SIGNATURE_DST: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const POP_DST: &'static [u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    fn parse_sig(bytes: &[u8; SIGNATURE_SIZE]) -> Option<G2Affine> {
        g2_from_bytes(bytes)
    }
    fn parse_key(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Option<G1Affine> {
        g1_from_bytes(bytes)
    }
    fn key_of(sk: &Scalar) -> [u8; PUBLIC_KEY_SIZE] {
        G1Affine::from(G1Affine::generator() * sk).to_compressed()
    }
    fn sign(sk: &Scalar, message: &[u8], dst: &[u8]) -> [u8; SIGNATURE_SIZE] {
        G2Affine::from(hash_g2(message, dst) * sk).to_compressed()
    }
    fn pairing_check(key: &G1Affine, message: &[u8], dst: &[u8], sig: &G2Affine) -> bool {
        let hashed = G2Affine::from(hash_g2(message, dst));
        pairing(&G1Affine::generator(), sig) == pairing(key, &hashed)
    }
    fn sig_sum() -> G2Projective {
        G2Projective::identity()
    }
    fn add_sig(sum: &mut G2Projective, sig: &G2Affine) {
        *sum += sig;
    }
    fn sig_of_sum(sum: &G2Projective) -> [u8; SIGNATURE_SIZE] {
        G2Affine::from(sum).to_compressed()
    }
    fn key_sum() -> G1Projective {
        G1Projective::identity()
    }
    fn add_key(sum: &mut G1Projective, key: &G1Affine) {
        *sum += key;
    }
    fn key_of_sum(sum: &G1Projective) -> Option<G1Affine> {
        let key = G1Affine::from(sum);
        (!bool::from(key.is_identity())).then_some(key)
    }
}

#[cfg(feature = "bls-min-sig")]
type Suite = MinSig;
#[cfg(feature = "bls-min-pk")]
type Suite = MinPk;

/// A BLS signature in the variant's signature group, compressed.
pub struct Signature {
    bytes: [u8; SIGNATURE_SIZE],
}

/// An aggregation contribution: the same signature as [`Signature`].
pub struct MultiSignature {
    bytes: [u8; MULTI_SIGNATURE_SIZE],
}

/// A validated public key in the variant's key group, compressed.
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

/// The sum of `count` signatures on one message, serialized as `count u16 ‖ signature`.
pub struct AggregatedSignature {
    count: usize,
    bytes: [u8; SIGNATURE_SIZE],
}

/// A signer holding the secret scalar and its serialized public key.
pub struct Crypto {
    secret: Scalar,
    public_key: PublicKey,
}

fn verify_bytes(
    key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
    dst: &[u8],
    sig: &[u8; SIGNATURE_SIZE],
) -> bool {
    match (Suite::parse_key(key), Suite::parse_sig(sig)) {
        (Some(key), Some(sig)) => Suite::pairing_check(&key, message, dst, &sig),
        _ => false,
    }
}

impl SignatureTrait for Signature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; SIGNATURE_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        Suite::parse_sig(&bytes).ok_or(CryptoError::InvalidSignature)?;
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
        Suite::parse_sig(&bytes).ok_or(CryptoError::InvalidSignature)?;
        Ok(Self { bytes })
    }

    fn serialize(&self) -> &[u8; MULTI_SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl PublicKeyTrait for PublicKey {
    /// KeyValidate: decompression with the subgroup check, and the identity is refused.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        Suite::parse_key(&bytes).ok_or(CryptoError::InvalidPublicKey)?;
        Ok(Self { bytes })
    }

    fn serialize(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

impl AggregatedSignatureTrait for AggregatedSignature {
    /// Parses `count u16 ‖ signature` (big-endian count) from the front of `bytes`;
    /// trailing bytes are left to the caller. A count of 0 or above
    /// `MAX_AGGREGATED_SIGNATURES` and an invalid point are refused.
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < AGGREGATED_SIGNATURE_CONSTANT_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if count == 0 || count > MAX_AGGREGATED_SIGNATURES {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sig = [0u8; SIGNATURE_SIZE];
        sig.copy_from_slice(&bytes[2..AGGREGATED_SIGNATURE_CONSTANT_SIZE]);
        Suite::parse_sig(&sig).ok_or(CryptoError::InvalidSignature)?;
        Ok(Self { count, bytes: sig })
    }

    fn serialize(&self, out: &mut [u8]) -> Result<usize, CryptoError> {
        if out.len() < AGGREGATED_SIGNATURE_CONSTANT_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        out[..2].copy_from_slice(&(self.count as u16).to_be_bytes());
        out[2..AGGREGATED_SIGNATURE_CONSTANT_SIZE].copy_from_slice(&self.bytes);
        Ok(AGGREGATED_SIGNATURE_CONSTANT_SIZE)
    }

    fn get_count(&self) -> usize {
        self.count
    }

    fn serialized_len(&self) -> usize {
        AGGREGATED_SIGNATURE_CONSTANT_SIZE
    }
}

impl CryptoTrait for Crypto {
    /// `private_key_bytes` is the big-endian integer `sk`, `1 ≤ sk < r`.
    fn new(private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
        let mut little_endian = private_key_bytes;
        little_endian.reverse();
        let secret = Option::<Scalar>::from(Scalar::from_bytes(&little_endian))
            .filter(|sk| *sk != Scalar::zero())
            .ok_or(CryptoError::InvalidPrivateKey)?;
        Ok(Self {
            public_key: PublicKey {
                bytes: Suite::key_of(&secret),
            },
            secret,
        })
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            bytes: Suite::sign(&self.secret, message, Suite::SIGNATURE_DST),
        }
    }

    fn multi_sign(&self, message: &[u8]) -> MultiSignature {
        MultiSignature {
            bytes: Suite::sign(&self.secret, message, Suite::SIGNATURE_DST),
        }
    }

    fn verify_multi_signature(
        &self,
        message: &[u8],
        multi_signature: &MultiSignature,
        public_key: &PublicKey,
    ) -> bool {
        verify_bytes(
            &public_key.bytes,
            message,
            Suite::SIGNATURE_DST,
            &multi_signature.bytes,
        )
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        verify_bytes(
            &public_key.bytes,
            message,
            Suite::SIGNATURE_DST,
            &signature.bytes,
        )
    }

    /// Sums the signatures; the keys are not needed (the proof-of-possession suite has no
    /// key coefficients) and only their count is checked.
    fn aggregate_signatures(
        &self,
        signatures: &[&MultiSignature],
        public_keys: &[&[u8; PUBLIC_KEY_SIZE]],
        _message: &[u8],
    ) -> Result<AggregatedSignature, CryptoError> {
        let count = signatures.len();
        if count == 0 || count > MAX_AGGREGATED_SIGNATURES || public_keys.len() != count {
            return Err(CryptoError::InvalidSignature);
        }
        let mut sum = Suite::sig_sum();
        for signature in signatures {
            let point = Suite::parse_sig(&signature.bytes).ok_or(CryptoError::InvalidSignature)?;
            Suite::add_sig(&mut sum, &point);
        }
        Ok(AggregatedSignature {
            count,
            bytes: Suite::sig_of_sum(&sum),
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
        let mut sum = Suite::key_sum();
        for key in public_keys {
            let Some(point) = Suite::parse_key(&key.bytes) else {
                return false;
            };
            Suite::add_key(&mut sum, &point);
        }
        let (Some(key), Some(sig)) = (
            Suite::key_of_sum(&sum),
            Suite::parse_sig(&aggregated_signature.bytes),
        ) else {
            return false;
        };
        Suite::pairing_check(&key, message, Suite::SIGNATURE_DST, &sig)
    }

    /// `PopProve`: `sk · H_pop(public key)` with the suite's proof-of-possession DST.
    fn prove_possession(&self) -> Signature {
        Signature {
            bytes: Suite::sign(&self.secret, &self.public_key.bytes, Suite::POP_DST),
        }
    }

    /// `PopVerify`: KeyValidate on `public_key` and the pairing check under the PoP DST.
    fn verify_possession(&self, public_key: &PublicKey, proof: &Signature) -> bool {
        verify_bytes(
            &public_key.bytes,
            &public_key.bytes,
            Suite::POP_DST,
            &proof.bytes,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// Signer with `sk = 7` (big-endian), the key of the cross-check.
    fn seven() -> Crypto {
        let mut sk = [0u8; PRIVATE_KEY_SIZE];
        sk[31] = 7;
        match Crypto::new(sk) {
            Ok(signer) => signer,
            Err(_) => panic!("sk = 7"),
        }
    }

    const CROSS_CHECK_MESSAGE: &[u8] = b"MoonBlokz BLS cross-check";

    // Pinned after a one-off cross-check against `blst` 0.3 (`min_sig` / `min_pk`, same
    // suites and DSTs), run outside the workspace on 2026-11-16 (Story 6.16 AC2). The same
    // run reproduced the Ethereum consensus-spec signing vector used below.
    #[cfg(feature = "bls-min-sig")]
    #[test]
    fn min_sig_matches_the_blst_cross_check() {
        let signer = seven();
        assert_eq!(
            signer.public_key().serialize(),
            &hex::<96>(
                "8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c"
            )
        );
        assert_eq!(
            signer.sign(CROSS_CHECK_MESSAGE).serialize(),
            &hex::<48>(
                "8c0da230a951f4920309dfb85fc47aa51b02bff101ef11627850c7865f0ad60806258e184b0a9331e5373c769309ee25"
            )
        );
        assert_eq!(
            signer.prove_possession().serialize(),
            &hex::<48>(
                "b4ec459579d966ad44a0cf1aa27c37f456e5a11317596832db43ddcf725a2ce27243495241d962425da8554bd4407f71"
            )
        );
    }

    #[cfg(feature = "bls-min-pk")]
    #[test]
    fn min_pk_matches_the_blst_cross_check() {
        let signer = seven();
        assert_eq!(
            signer.public_key().serialize(),
            &hex::<48>(
                "b928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb7"
            )
        );
        assert_eq!(
            signer.sign(CROSS_CHECK_MESSAGE).serialize(),
            &hex::<96>(
                "b94edb9e54230070d971457ec949107c3fa072deb59bb3d8408f955fef1c6c2fd3bbd533f387678e398cb9c0dc47b5811311f2995cfdb64f50d520bd3db9cb6bfe65957f8a7a07d58d35fbde0a420048e17558e4a6da9ba487eecd9cda40fe01"
            )
        );
        assert_eq!(
            signer.prove_possession().serialize(),
            &hex::<96>(
                "aa1ec06827a64d47a2312ac512cdfcc6e27414f8fb661de6c5ecdcfa251273946ca7e189de32490b01226ea1ae91904314a7ff34e302e6df7a02b0ecbf05fef02a030d91d835f9dd795ff09fcd2df4875c794fdf9ee01457e383efe5d718e98c"
            )
        );
    }

    /// Ethereum consensus-spec BLS `sign` vector (min-pk, POP suite): private key
    /// `263dbd79…40e3`, a 32-byte zero message
    /// (<https://github.com/ethereum/bls12-381-tests>, generated by the consensus specs).
    #[cfg(feature = "bls-min-pk")]
    #[test]
    fn min_pk_matches_an_ethereum_consensus_vector() {
        let signer = match Crypto::new(hex::<32>(
            "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        )) {
            Ok(signer) => signer,
            Err(_) => panic!("key"),
        };
        assert_eq!(
            signer.sign(&[0u8; 32]).serialize(),
            &hex::<96>(
                "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55"
            )
        );
    }

    /// RFC 9380 Appendix J.9.1 (`BLS12381G1_XMD:SHA-256_SSWU_RO_`), the hash to G1 that
    /// min-sig signs with.
    #[cfg(feature = "bls-min-sig")]
    #[test]
    fn hash_to_g1_matches_rfc9380() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        let empty = G1Affine::from(hash_g1(b"", dst)).to_uncompressed();
        assert_eq!(
            empty,
            hex::<96>(
                "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a108ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"
            )
        );
        let abc = G1Affine::from(hash_g1(b"abc", dst)).to_uncompressed();
        assert_eq!(
            abc,
            hex::<96>(
                "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f69030b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"
            )
        );
    }

    /// RFC 9380 Appendix J.10.1 (`BLS12381G2_XMD:SHA-256_SSWU_RO_`), the hash to G2 that
    /// min-pk signs with.
    #[cfg(feature = "bls-min-pk")]
    #[test]
    fn hash_to_g2_matches_rfc9380() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        let empty = G2Affine::from(hash_g2(b"", dst)).to_uncompressed();
        assert_eq!(
            empty,
            hex::<192>(
                "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d60503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92"
            )
        );
        let abc = G2Affine::from(hash_g2(b"abc", dst)).to_uncompressed();
        assert_eq!(
            abc,
            hex::<192>(
                "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e600aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd161787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48"
            )
        );
    }

    fn signer(seed: u8) -> Crypto {
        match Crypto::new([seed; PRIVATE_KEY_SIZE]) {
            Ok(signer) => signer,
            Err(_) => panic!("signer"),
        }
    }

    #[test]
    fn identity_and_garbage_keys_are_refused() {
        // The compressed identity: compression and infinity flags set, rest zero.
        let mut identity = [0u8; PUBLIC_KEY_SIZE];
        identity[0] = 0xC0;
        assert!(PublicKey::new(&identity).is_err());
        // All-zero bytes lack the compression flag.
        assert!(PublicKey::new(&[0u8; PUBLIC_KEY_SIZE]).is_err());
        let mut sig_identity = [0u8; SIGNATURE_SIZE];
        sig_identity[0] = 0xC0;
        assert!(Signature::new(&sig_identity).is_err());
    }

    #[test]
    fn private_keys_are_big_endian_and_bounded() {
        assert!(Crypto::new([0u8; PRIVATE_KEY_SIZE]).is_err(), "zero");
        assert!(Crypto::new([0xFF; PRIVATE_KEY_SIZE]).is_err(), "≥ r");
        let mut one = [0u8; PRIVATE_KEY_SIZE];
        one[31] = 1;
        let signer = match Crypto::new(one) {
            Ok(signer) => signer,
            Err(_) => panic!("sk = 1"),
        };
        // sk = 1 gives the key group's generator.
        #[cfg(feature = "bls-min-sig")]
        assert_eq!(
            signer.public_key().serialize(),
            &G2Affine::generator().to_compressed()
        );
        #[cfg(feature = "bls-min-pk")]
        assert_eq!(
            signer.public_key().serialize(),
            &G1Affine::generator().to_compressed()
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_the_pop_dst() {
        let a = signer(1);
        let message = *a.public_key().serialize();
        let ordinary = a.sign(&message);
        assert!(!a.verify_possession(a.public_key(), &ordinary));
        assert!(a.verify_possession(a.public_key(), &a.prove_possession()));
    }

    #[test]
    fn a_forged_message_does_not_verify() {
        // The old backend's h0 = hash_to_scalar(m)·G made σ(m₂) = σ(m₁)·t(m₂)/t(m₁)
        // computable; with hash-to-curve no such relation is known. Here: a signature on
        // m₁ does not verify on m₂, and neither does any scalar multiple tried.
        let a = signer(3);
        let sig = a.sign(b"m1");
        assert!(!a.verify_signature(b"m2", &sig, a.public_key()));
    }

    #[test]
    fn aggregate_of_forty_verifies_and_a_missing_key_fails() {
        let message = b"approval";
        let signers: [Crypto; 40] = core::array::from_fn(|i| signer(i as u8 + 1));
        let sigs: [MultiSignature; 40] = core::array::from_fn(|i| signers[i].multi_sign(message));
        let sig_refs: [&MultiSignature; 40] = core::array::from_fn(|i| &sigs[i]);
        let key_bytes: [&[u8; PUBLIC_KEY_SIZE]; 40] =
            core::array::from_fn(|i| signers[i].public_key().serialize());
        let agg = match signers[0].aggregate_signatures(&sig_refs, &key_bytes, message) {
            Ok(agg) => agg,
            Err(_) => panic!("aggregate"),
        };
        let keys: [&PublicKey; 40] = core::array::from_fn(|i| signers[i].public_key());
        assert!(signers[0].verify_aggregated_signature(message, &agg, &keys));
        assert!(!signers[0].verify_aggregated_signature(message, &agg, &keys[..39]));
        assert!(!signers[0].verify_aggregated_signature(b"other", &agg, &keys));
    }
}
