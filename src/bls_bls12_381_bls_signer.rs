extern crate alloc;
use alloc::vec::Vec;
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

    fn serialize(&self) -> Vec<u8> {
        return self.bytes.to_vec();
    }

    fn get_count(&self) -> usize {
        self.count
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

    fn aggregate_signatures(&self, signatures: &[&MultiSignature], _: &[u8]) -> Result<AggregatedSignature, CryptoError> {
        if signatures.is_empty() {
            return Err(CryptoError::InvalidSignature);
        };

        let first_signature = signatures[0].bls_multi_signature.clone();

        let mut bls_multi_signatures = Vec::<BLS_MultiSignature>::new();
        for i in 1..signatures.len() {
            bls_multi_signatures.push(signatures[i].bls_multi_signature);
        }

        let aggregated_bls_signature = first_signature.aggregate(&bls_multi_signatures);

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
        let mut bls_public_keys = Vec::<BLS_PublicKey>::new();
        for i in 0..public_keys.len() {
            bls_public_keys.push(public_keys[i].bls_public_key);
        }

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
