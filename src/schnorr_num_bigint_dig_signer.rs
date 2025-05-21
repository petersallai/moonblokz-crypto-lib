extern crate alloc;
use alloc::vec::Vec;
use num_bigint_dig::{BigInt, ModInverse, Sign};
use num_traits::One;
use num_traits::Zero;
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};

use crate::AGGREGATED_SIGNATURE_CONSTANT_SIZE;
use crate::AGGREGATED_SIGNATURE_VARIABLE_SIZE;
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

const B: i32 = 7;

#[derive(Clone, PartialEq, Eq)]
pub struct Point {
    x: BigInt,
    y: BigInt,
}

pub struct PublicKey {
    point: Point,
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKeyTrait for PublicKey {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < PUBLIC_KEY_SIZE {
            return Err(CryptoError::InvalidPublicKey);
        }

        let public_key_bytes: [u8; 32] = bytes[0..32].try_into().map_err(|_| CryptoError::InvalidPublicKey)?;

        let point = Self::calculate_public_key_point(&public_key_bytes)?;
        Ok(PublicKey {
            point: point,
            bytes: public_key_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

impl PublicKey {
    fn new_from_point(point: Point) -> Self {
        let (_, public_key_vec) = &point.x.to_bytes_le();
        let mut public_key_bytes: [u8; 32] = [0; 32];
        let public_key_slice = &public_key_vec[0..public_key_vec.len().min(32)];
        public_key_bytes[0..public_key_slice.len()].copy_from_slice(public_key_slice);
        PublicKey {
            point: point,
            bytes: public_key_bytes,
        }
    }
    fn calculate_public_key_point(public_key_bytes: &[u8; 32]) -> Result<Point, CryptoError> {
        let p = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
        let x = BigInt::from_bytes_le(Sign::Plus, public_key_bytes);
        let y_sq = (&x * &x * &x + BigInt::from(B)) % &p;
        let y = y_sq.modpow(&((&p + 1u32) / 4u32), &p);

        if x >= p {
            //x value in public key is not a valid coordinate because it is not less than the elliptic curve field size
            return Err(CryptoError::InvalidPublicKey);
        }

        let y = if &y * &y % &p != y_sq {
            //public key is not a valid x coordinate on the curve
            return Err(CryptoError::InvalidPublicKey);
        } else if (&y % 2u32).is_zero() {
            y
        } else {
            &p - y
        };

        Ok(Point { x: x, y })
    }
}

pub struct Signature {
    r: BigInt,
    s: BigInt,
    bytes: [u8; SIGNATURE_SIZE],
}

impl SignatureTrait for Signature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; 64] = bytes[0..64].try_into().map_err(|_| CryptoError::InvalidSignature)?;

        let r = BigInt::from_bytes_le(Sign::Plus, &signature_bytes[0..32]);
        let s = BigInt::from_bytes_le(Sign::Plus, &signature_bytes[32..64]);

        Ok(Signature { r, s, bytes: signature_bytes })
    }

    fn serialize(&self) -> &[u8; crate::SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl Signature {
    fn new_from_rs(r: BigInt, s: BigInt) -> Self {
        let mut sig: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
        let (_, r_bytes) = &r.to_bytes_le();
        let (_, s_bytes) = &s.to_bytes_le();

        let mut r_end = r_bytes.len();
        if r_end > 32 {
            r_end = 32;
        }
        let mut s_end = s_bytes.len();
        if s_end > 32 {
            s_end = 32;
        }
        sig[0..r_end].copy_from_slice(&r_bytes[0..r_end]);
        sig[32..32 + s_end].copy_from_slice(&s_bytes[0..s_end]);
        Signature { r, s, bytes: sig }
    }
}

pub struct MultiSignature {
    r: BigInt,
    s: BigInt,
    bytes: [u8; MULTI_SIGNATURE_SIZE],
}

impl MultiSignatureTrait for MultiSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; 64] = bytes[0..64].try_into().map_err(|_| CryptoError::InvalidSignature)?;

        let r = BigInt::from_bytes_le(Sign::Plus, &signature_bytes[0..32]);
        let s = BigInt::from_bytes_le(Sign::Plus, &signature_bytes[32..64]);

        Ok(MultiSignature { r, s, bytes: signature_bytes })
    }

    fn serialize(&self) -> &[u8; crate::MULTI_SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl MultiSignature {
    fn new_from_rs(r: BigInt, s: BigInt) -> Self {
        let mut sig: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
        let (_, r_bytes) = &r.to_bytes_le();
        let (_, s_bytes) = &s.to_bytes_le();

        let mut r_end = r_bytes.len();
        if r_end > 32 {
            r_end = 32;
        }
        let mut s_end = s_bytes.len();
        if s_end > 32 {
            s_end = 32;
        }
        sig[0..r_end].copy_from_slice(&r_bytes[0..r_end]);
        sig[32..32 + s_end].copy_from_slice(&s_bytes[0..s_end]);
        MultiSignature { r, s, bytes: sig }
    }
}

pub struct AggregatedSignature {
    r: Vec<BigInt>,
    r_bytes: Vec<[u8; 32]>,
    s: BigInt,
}

impl AggregatedSignatureTrait for AggregatedSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 2 {
            return Err(CryptoError::InvalidSignature);
        }

        let count_slice: [u8; 2] = bytes[0..2].try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let count = u16::from_le_bytes(count_slice);

        if bytes.len() < AGGREGATED_SIGNATURE_VARIABLE_SIZE * count as usize + AGGREGATED_SIGNATURE_CONSTANT_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let s_bytes: [u8; 32] = bytes[2..34].try_into().map_err(|_| CryptoError::InvalidSignature)?;
        let s = BigInt::from_bytes_le(Sign::Plus, &s_bytes);

        let mut r = Vec::<BigInt>::new();
        let mut r_bytes = Vec::<[u8; 32]>::new();

        for i in 0..count {
            let start = 34 + i as usize * 32;
            let end = start + 32;
            r_bytes.push(bytes[start..end].try_into().map_err(|_| CryptoError::InvalidSignature)?);
            let r_i = BigInt::from_bytes_le(Sign::Plus, &bytes[start..end]);
            r.push(r_i);
        }

        Ok(AggregatedSignature { r, r_bytes, s })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE * self.r.len());
        result.extend_from_slice(&(self.r.len() as u16).to_le_bytes());
        let (_, s_bytes) = &self.s.to_bytes_le();
        result.extend_from_slice(s_bytes);
        for r_byte in &self.r_bytes {
            result.extend_from_slice(r_byte);
        }
        result
    }

    fn get_count(&self) -> usize {
        self.r.len()
    }
}

pub struct Crypto {
    p: BigInt,
    n: BigInt,
    g: Point,
    private_key: BigInt,
    private_key_bytes: [u8; 32],
    public_key: PublicKey,
}

impl Crypto {
    fn inverse(&self, a: &BigInt, m: &BigInt) -> BigInt {
        a.mod_inverse(m).unwrap()
    }

    //Calculate the double of the given point
    fn double(&self, point: &Point) -> Point {
        let slope = (3 * &point.x * &point.x * self.inverse(&(2 * &point.y), &self.p)) % &self.p;
        let mut x = (&slope * &slope - 2 * &point.x) % &self.p;
        let mut y = (slope * (&point.x - &x) - &point.y) % &self.p;
        if y < BigInt::zero() {
            y = y + &self.p;
        }
        if x < BigInt::zero() {
            x = x + &self.p;
        }

        Point { x, y }
    }

    //Add two points
    fn add(&self, point1: &Point, point2: &Point) -> Point {
        if point1 == point2 {
            return self.double(point1);
        }

        let slope = ((&point1.y - &point2.y) * self.inverse(&(&point1.x - &point2.x), &self.p)) % &self.p;
        let mut x = (&slope * &slope - &point1.x - &point2.x) % &self.p;
        let mut y = (slope * (&point1.x - &x) - &point1.y) % &self.p;
        if y < BigInt::zero() {
            y = y + &self.p;
        }

        if x < BigInt::zero() {
            x = x + &self.p;
        }

        Point { x, y }
    }

    // Point multiplication with scalar k
    // k is a scalar and point is a point on the elliptic curve
    // This function uses the double-and-add algorithm to perform scalar multiplication
    fn multiply(&self, k: &BigInt, point: &Point) -> Point {
        let mut result = point.clone();
        let bits = k.to_str_radix(2);
        for bit in bits.chars().skip(1) {
            result = self.double(&result);
            if bit == '1' {
                result = self.add(&result, point);
            }
        }
        result
    }

    // Tagged hash function using SHA256
    fn tagged_hash(&self, tag_bytes: &[u8], message1: &[u8], message2: &[u8], message3: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tag_bytes);
        hasher.update(message1);
        hasher.update(message2);
        hasher.update(message3);
        hasher.finalize_fixed().into()
    }

    fn point_from_x(&self, x: &BigInt) -> Result<Point, CryptoError> {
        let y_sq = (x * x * x + B) % &self.p;
        let mut y = y_sq.modpow(&((&self.p + 1) / 4), &self.p);

        if x >= &self.p {
            //x value in public key is not a valid coordinate because it is not less than the elliptic curve field size
            return Err(CryptoError::InvalidSignature);
        }

        y = if &y * &y % &self.p != y_sq {
            //public key is not a valid x coordinate on the curve
            return Err(CryptoError::InvalidSignature);
        } else if (&y % 2) == BigInt::zero() {
            y
        } else {
            &self.p - &y
        };

        Ok(Point { x: x.clone(), y: y })
    }

    fn sign_common(&self, message: &[u8]) -> (BigInt, BigInt) {
        //deterministic nonce generation
        let mut k0: BigInt;
        let mut counter = 0u32;
        loop {
            let counter_bytes = counter.to_le_bytes();
            k0 = BigInt::from_bytes_le(Sign::Plus, &self.tagged_hash(b"nonce", &self.private_key_bytes, &message, &counter_bytes)) % &self.n;

            if k0 > BigInt::zero() {
                break;
            }
            counter += 1;
        }

        let random_point = self.multiply(&k0, &self.g);
        let k = if (&random_point.y % 2) == BigInt::zero() { k0 } else { &self.n - k0 };

        let (_, random_bytes) = random_point.x.to_bytes_le();

        let e = BigInt::from_bytes_le(Sign::Plus, &self.tagged_hash(b"challenge", &random_bytes, &self.public_key.bytes, message)) % &self.n;

        let r = random_point.x;

        let mut s = (&k + &e * &self.private_key) % &self.n;
        if s < BigInt::zero() {
            s = s + &self.n;
        }
        (r, s)
    }

    fn verify_common(&self, message: &[u8], r: &BigInt, s: &BigInt, signature_bytes: [u8; 64], public_key: &PublicKey) -> bool {
        if r >= &self.p || s >= &self.n {
            //r value in signature is not less than the elliptic curve field size or s value in signature is not less than the number of points on the elliptic curve
            return false;
        }

        let e = BigInt::from_bytes_le(Sign::Plus, &self.tagged_hash(b"challenge", &signature_bytes[0..32], &public_key.bytes, message)) % &self.n;

        let point1 = self.multiply(s, &self.g);
        let point2 = self.multiply(&(&self.n - e), &public_key.point);
        let point3 = self.add(&point1, &point2);

        if &point3.x == r {
            return true;
        } else {
            return false;
        }
    }
}

impl CryptoTrait for Crypto {
    fn new(private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
        let p = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap();
        let n = BigInt::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
        let g = Point {
            x: BigInt::parse_bytes(b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16).unwrap(),
            y: BigInt::parse_bytes(b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16).unwrap(),
        };

        let private_key_int = BigInt::from_bytes_le(Sign::Plus, &private_key_bytes);
        if private_key_int < BigInt::one() || private_key_int >= n {
            return Err(CryptoError::InvalidPrivateKey);
        }

        let placeholder_point = Point {
            x: BigInt::zero(),
            y: BigInt::zero(),
        };

        let placeholder_public_key = PublicKey {
            point: placeholder_point,
            bytes: [0; 32],
        };

        let mut new_self = Self {
            p,
            n,
            g,
            private_key: private_key_int,
            private_key_bytes,
            //temporary public key, we calculate the real one some lines below
            public_key: placeholder_public_key,
        };

        let mut public_key_point = new_self.multiply(&new_self.private_key, &new_self.g);
        if &public_key_point.y % 2 != BigInt::zero() {
            public_key_point.y = &new_self.p - &public_key_point.y;
            new_self.private_key = &new_self.n - &new_self.private_key;
        };

        if public_key_point.x <= BigInt::zero() || public_key_point.x >= new_self.p {
            return Err(CryptoError::InvalidPublicKey);
        }
        new_self.public_key = PublicKey::new_from_point(public_key_point);

        Ok(new_self)
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let (r, s) = self.sign_common(message);
        let signature = Signature::new_from_rs(r, s);
        signature
    }

    fn multi_sign(&self, message: &[u8]) -> MultiSignature {
        let (r, s) = self.sign_common(message);
        let multi_signature = MultiSignature::new_from_rs(r, s);
        multi_signature
    }

    fn verify_signature(&self, message: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        let r = &signature.r;
        let s = &signature.s;
        let signature_bytes = signature.bytes;
        self.verify_common(message, r, s, signature_bytes, public_key)
    }

    fn verify_multi_signature(&self, message: &[u8], multi_signature: &MultiSignature, public_key: &PublicKey) -> bool {
        let r = &multi_signature.r;
        let s = &multi_signature.s;
        let signature_bytes = multi_signature.bytes;
        self.verify_common(message, r, s, signature_bytes, public_key)
    }

    fn aggregate_signatures(&self, signatures: &[&MultiSignature], message: &[u8]) -> Result<AggregatedSignature, CryptoError> {
        let mut r = Vec::<BigInt>::new();
        let mut r_bytes = Vec::<[u8; 32]>::new();
        let mut s = BigInt::zero();

        //calculate the sum of r values to use in the initial seed of the random number generation
        let mut r_sum = BigInt::zero();

        if signatures.len() < 1 {
            return Err(CryptoError::InvalidSignature);
        }

        for signature in signatures.iter() {
            r_sum = (r_sum + &signature.r) % &self.p;
            r.push(signature.r.clone());
            r_bytes.push(signature.bytes[0..32].try_into().unwrap());
        }

        let (_, r_sum_bytes) = &r_sum.to_bytes_le();
        //generate the initial random sedd using the sum of r values and the message
        let initial_random_seed = self.tagged_hash(b"aggregate", &r_sum_bytes, &r_sum_bytes, &message);

        //calculate the sum of s values (multiplid by the generated random number) to use in the aggregated signature
        //the random number should be betwen 1 and n-1
        let mut i: u32 = 0;
        for signature in signatures.iter() {
            let (_, i_bytes) = BigInt::from(i as u32).to_bytes_le();
            //calculate the random number using the initial seed and the sequence number
            let random_number = BigInt::from_bytes_le(Sign::Plus, &self.tagged_hash(b"rand", &initial_random_seed, &i_bytes, &i_bytes)) % (&self.n - 1) + 1;
            s = (s + &signature.s * random_number) % &self.n;
            i += 1;
        }
        Ok(AggregatedSignature { r, r_bytes, s })
    }

    fn verify_aggregated_signature(&self, message: &[u8], aggregated_signature: &AggregatedSignature, public_keys: &[&PublicKey]) -> bool {
        //calculate the sum of r values to use in the initial seed of the random number generation
        let mut r_sum = BigInt::zero();
        for r in aggregated_signature.r.iter() {
            r_sum = (r_sum + r) % &self.p;
        }
        let (_, r_initrand_sum_bytes) = &r_sum.to_bytes_le();
        let initial_random_seed = self.tagged_hash(b"aggregate", &r_initrand_sum_bytes, &r_initrand_sum_bytes, &message);

        //calculate the sum of r values (multiplid by the generated random number) and the sum ok public keys multiplied by (n-ex)
        let mut r_point_sum = Point {
            x: BigInt::zero(),
            y: BigInt::zero(),
        };
        let mut pk_point_sum: Point = Point {
            x: BigInt::zero(),
            y: BigInt::zero(),
        };
        for i in 0..aggregated_signature.get_count() {
            if &aggregated_signature.r[i] >= &self.p || &aggregated_signature.s >= &self.n {
                //r value in signature is not less than the elliptic curve field size or s value in signature is not less than the number of points on the elliptic curve
                return false;
            }

            //calculate the random number using the initial seed and the sequence number
            let (_, i_bytes) = BigInt::from(i as u32).to_bytes_le();
            let random_number = BigInt::from_bytes_le(Sign::Plus, &self.tagged_hash(b"rand", &initial_random_seed, &i_bytes, &i_bytes)) % (&self.n - 1) + 1;

            let r_point = if let Ok(r_point) = self.point_from_x(&aggregated_signature.r[i]) {
                r_point
            } else {
                return false;
            };

            let r_point_multiplied = self.multiply(&random_number, &r_point);

            if i > 0 {
                r_point_sum = self.add(&r_point_sum, &r_point_multiplied);
            } else {
                r_point_sum = r_point_multiplied;
            }

            //calculate the challenge
            let e = BigInt::from_bytes_le(
                Sign::Plus,
                &self.tagged_hash(b"challenge", &aggregated_signature.r_bytes[i], &public_keys[i].bytes, message),
            ) % &self.n;

            let pk_point = self.multiply(&((&self.n - e) * &random_number), &public_keys[i].point);
            if i > 0 {
                pk_point_sum = self.add(&pk_point_sum, &pk_point);
            } else {
                pk_point_sum = pk_point;
            }
        }
        let g_point = self.multiply(&aggregated_signature.s, &self.g);

        let sum_point = self.add(&pk_point_sum, &g_point);

        if &sum_point.x == &r_point_sum.x {
            return true;
        } else {
            return false;
        }
    }
}
