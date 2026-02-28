use core::mem::MaybeUninit;
use bls12_381_bls::{MultisigPublicKey, MultisigSignature as BLS_MultiSignature, PublicKey as BLS_PublicKey, SecretKey, Signature as BLS_Signature};
use dusk_bytes::Serializable;

use crate::AGGREGATED_SIGNATURE_CONSTANT_SIZE;
use crate::AggregatedSignatureTrait;
use crate::MULTI_SIGNATURE_SIZE;
use crate::MultiSignatureTrait;
use crate::PRIVATE_KEY_SIZE;
use crate::PUBLIC_KEY_SIZE;
use crate::PublicKeyTrait;
use crate::SIGNATURE_SIZE;
use crate::MAX_AGGREGATED_SIGNATURES;

use crate::CryptoError;
use crate::CryptoTrait;
use crate::SignatureTrait;

pub struct PublicKey {
    bls_public_key: BLS_PublicKey,
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKeyTrait for PublicKey {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidPublicKey);
        }

        let public_key_bytes: [u8; PUBLIC_KEY_SIZE] = bytes[0..PUBLIC_KEY_SIZE].try_into().map_err(|_| CryptoError::InvalidPublicKey)?;
        let bls_public_key = BLS_PublicKey::from_bytes(&public_key_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(PublicKey {
            bls_public_key,
            bytes: public_key_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

pub struct Signature {
    bls_signature: BLS_Signature,
    bytes: [u8; SIGNATURE_SIZE],
}

impl SignatureTrait for Signature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; SIGNATURE_SIZE] = bytes[0..SIGNATURE_SIZE].try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let bls_signature = BLS_Signature::from_bytes(&signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Signature {
            bls_signature,
            bytes: signature_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::SIGNATURE_SIZE] {
        &self.bytes
    }
}

pub struct MultiSignature {
    bls_multi_signature: BLS_MultiSignature,
    bytes: [u8; MULTI_SIGNATURE_SIZE],
}

impl MultiSignatureTrait for MultiSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < MULTI_SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; SIGNATURE_SIZE] = bytes[0..SIGNATURE_SIZE].try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let bls_multi_signature = BLS_MultiSignature::from_bytes(&signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(MultiSignature {
            bls_multi_signature,
            bytes: signature_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::MULTI_SIGNATURE_SIZE] {
        return &self.bytes;
    }
}

pub struct AggregatedSignature {
    bls_aggregated_signature: BLS_MultiSignature,
    count: usize,
    bytes: [u8; AGGREGATED_SIGNATURE_CONSTANT_SIZE],
}

impl AggregatedSignatureTrait for AggregatedSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < AGGREGATED_SIGNATURE_CONSTANT_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let count_slice: [u8; 2] = bytes[0..2].try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let count = u16::from_le_bytes(count_slice);

        let signature_bytes: [u8; SIGNATURE_SIZE] = bytes[2..50].try_into().map_err(|_| CryptoError::InvalidSignature)?;

        let bls_aggregated_signature = BLS_MultiSignature::from_bytes(&signature_bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(AggregatedSignature {
            bls_aggregated_signature: bls_aggregated_signature,
            count: count as usize,
            bytes: bytes[0..AGGREGATED_SIGNATURE_CONSTANT_SIZE]
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature)?,
        })
    }

    fn serialize(&self, out: &mut [u8]) -> Result<usize, CryptoError> {
        if out.len() < AGGREGATED_SIGNATURE_CONSTANT_SIZE {
            return Err(CryptoError::InvalidSignature);
        }
        out[0..AGGREGATED_SIGNATURE_CONSTANT_SIZE].copy_from_slice(&self.bytes);
        Ok(AGGREGATED_SIGNATURE_CONSTANT_SIZE)
    }

    fn get_count(&self) -> usize {
        self.count
    }

    fn serialized_len(&self) -> usize {
        AGGREGATED_SIGNATURE_CONSTANT_SIZE
    }
}

pub struct Crypto {
    private_key: SecretKey,
    public_key: PublicKey,
}

impl CryptoTrait for Crypto {
    fn new(private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
        let secret_key = SecretKey::from_bytes(&private_key_bytes).map_err(|_| CryptoError::InvalidPrivateKey)?;
        let bls_public_key = BLS_PublicKey::from(&secret_key);
        let public_key = PublicKey {
            bls_public_key,
            bytes: bls_public_key.to_bytes(),
        };

        Ok(Crypto {
            private_key: secret_key,
            public_key: public_key,
        })
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let bls_signature = self.private_key.sign(message);
        let signature = Signature {
            bls_signature,
            bytes: bls_signature.to_bytes(),
        };
        signature
    }

    fn multi_sign(&self, message: &[u8]) -> MultiSignature {
        let bls_multi_signature = self.private_key.sign_multisig(&self.public_key.bls_public_key, message);
        MultiSignature {
            bls_multi_signature,
            bytes: bls_multi_signature.to_bytes(),
        }
    }

    fn verify_signature(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        public_key.bls_public_key.verify(&signature.bls_signature, message).is_ok()
    }

    fn verify_multi_signature(&self, message: &[u8], multi_signature: &MultiSignature, public_key: &PublicKey) -> bool {
        let bls_public_keys = [public_key.bls_public_key.clone()];

        let bls_aggregated_public_key = if let Ok(bls_aggregated_public_key) = MultisigPublicKey::aggregate(&bls_public_keys) {
            bls_aggregated_public_key
        } else {
            return false;
        };
        bls_aggregated_public_key.verify(&multi_signature.bls_multi_signature, message).is_ok()
    }

    fn aggregate_signatures(&self, signatures: &[&MultiSignature], _message: &[u8]) -> Result<AggregatedSignature, CryptoError> {
        if signatures.is_empty() || signatures.len() > MAX_AGGREGATED_SIGNATURES {
            return Err(CryptoError::InvalidSignature);
        }

        let first_signature = signatures[0].bls_multi_signature.clone();
        let aggregated_bls_signature = if signatures.len() > 1 {
            let mut bls_multi_signatures: [MaybeUninit<BLS_MultiSignature>; MAX_AGGREGATED_SIGNATURES] =
                unsafe { MaybeUninit::uninit().assume_init() };
            for (index, signature) in signatures.iter().enumerate().skip(1) {
                bls_multi_signatures[index - 1].write(signature.bls_multi_signature.clone());
            }
            let others_len = signatures.len() - 1;
            let others_ptr = bls_multi_signatures.as_ptr() as *const BLS_MultiSignature;
            let others = unsafe { core::slice::from_raw_parts(others_ptr, others_len) };
            first_signature.aggregate(others)
        } else {
            first_signature
        };

        let mut aggregated_signature_bytes = [0; AGGREGATED_SIGNATURE_CONSTANT_SIZE];
        aggregated_signature_bytes[0..2].copy_from_slice(&(signatures.len() as u16).to_le_bytes());
        aggregated_signature_bytes[2..50].copy_from_slice(&aggregated_bls_signature.to_bytes());

        Ok(AggregatedSignature {
            bls_aggregated_signature: aggregated_bls_signature,
            count: signatures.len(),
            bytes: aggregated_signature_bytes,
        })
    }

    fn verify_aggregated_signature(&self, message: &[u8], aggregated_signature: &AggregatedSignature, public_keys: &[&PublicKey]) -> bool {
        if aggregated_signature.get_count() != public_keys.len() || public_keys.len() > MAX_AGGREGATED_SIGNATURES {
            return false;
        }

        let mut bls_public_keys: [MaybeUninit<BLS_PublicKey>; MAX_AGGREGATED_SIGNATURES] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for (index, public_key) in public_keys.iter().enumerate() {
            bls_public_keys[index].write(public_key.bls_public_key.clone());
        }
        let keys_ptr = bls_public_keys.as_ptr() as *const BLS_PublicKey;
        let bls_public_keys = unsafe { core::slice::from_raw_parts(keys_ptr, public_keys.len()) };

        let bls_aggregated_public_key = if let Ok(bls_aggregated_public_key) = MultisigPublicKey::aggregate(&bls_public_keys) {
            bls_aggregated_public_key
        } else {
            return false;
        };
        bls_aggregated_public_key
            .verify(&aggregated_signature.bls_aggregated_signature, message)
            .is_ok()
    }
}
