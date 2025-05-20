extern crate alloc;
use alloc::vec::Vec;
use malachite_base::num::arithmetic::traits::ModInverse;
use malachite_base::num::arithmetic::traits::*;
use malachite_base::num::conversion::traits::FromStringBase;
use malachite_base::num::conversion::traits::SaturatingFrom;
use malachite_base::num::conversion::traits::ToStringBase;
use malachite_base::num::{arithmetic::traits::ModPow, conversion::traits::PowerOf2Digits};
use malachite_nz::integer::Integer;
use malachite_nz::integer::arithmetic::sign;
use malachite_nz::natural::Natural;
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

const ONE_NAT: Natural = Natural::const_from(1);
const TWO: Integer = Integer::const_from_unsigned(2);
const TWO_NAT: Natural = Natural::const_from(2);
const THREE: Integer = Integer::const_from_unsigned(3);
const FOUR_NAT: Natural = Natural::const_from(4);
const B_NAT: Natural = Natural::const_from(7);

#[derive(Clone, PartialEq, Eq)]
pub struct Point {
    x: Integer,
    y: Integer,
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
        let public_key_vec = Natural::saturating_from(&point.x).to_power_of_2_digits_asc(8);
        let mut public_key_bytes: [u8; 32] = [0; 32];
        let public_key_slice = &public_key_vec[0..public_key_vec.len().min(32)];
        public_key_bytes[0..public_key_slice.len()].copy_from_slice(public_key_slice);
        PublicKey {
            point: point,
            bytes: public_key_bytes,
        }
    }
    fn calculate_public_key_point(public_key_bytes: &[u8; 32]) -> Result<Point, CryptoError> {
        let p_nat = Natural::from_string_base(16, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap();
        let x = Natural::from_power_of_2_digits_asc(8, public_key_bytes.iter().cloned()).unwrap();
        let y_sq = (&x * &x * &x + B_NAT) % &p_nat;
        let mut y = (&y_sq).mod_pow(&((&p_nat + ONE_NAT) / FOUR_NAT), &p_nat);

        if x >= p_nat {
            //x value in public key is not a valid coordinate because it is not less than the elliptic curve field size
            return Err(CryptoError::InvalidPublicKey);
        }

        y = if &y * &y % &p_nat != y_sq {
            //public key is not a valid x coordinate on the curve
            return Err(CryptoError::InvalidPublicKey);
        } else if (&y % TWO_NAT) == 0 {
            y
        } else {
            &p_nat - &y
        };

        let x_integer = Integer::from(x);
        let y_integer = Integer::from(y);

        Ok(Point { x: x_integer, y: y_integer })
    }
}

pub struct Signature {
    r: Integer,
    s: Integer,
    bytes: [u8; SIGNATURE_SIZE],
}

impl SignatureTrait for Signature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; 64] = bytes[0..64].try_into().map_err(|_| CryptoError::InvalidSignature)?;

        let r = Integer::from(Natural::from_power_of_2_digits_asc(8, signature_bytes[0..32].iter().cloned()).unwrap());
        let s = Integer::from(Natural::from_power_of_2_digits_asc(8, signature_bytes[32..64].iter().cloned()).unwrap());

        Ok(Signature { r, s, bytes: signature_bytes })
    }

    fn serialize(&self) -> &[u8; crate::SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl Signature {
    fn new_from_rs(r: Integer, s: Integer) -> Self {
        let mut sig: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
        let r_bytes = Natural::saturating_from(&r).to_power_of_2_digits_asc(8);
        let s_bytes = Natural::saturating_from(&s).to_power_of_2_digits_asc(8);

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
    r: Integer,
    s: Integer,
    bytes: [u8; MULTI_SIGNATURE_SIZE],
}

impl MultiSignatureTrait for MultiSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; 64] = bytes[0..64].try_into().map_err(|_| CryptoError::InvalidSignature)?;

        let r = Integer::from(Natural::from_power_of_2_digits_asc(8, signature_bytes[0..32].iter().cloned()).unwrap());
        let s = Integer::from(Natural::from_power_of_2_digits_asc(8, signature_bytes[32..64].iter().cloned()).unwrap());

        Ok(MultiSignature { r, s, bytes: signature_bytes })
    }

    fn serialize(&self) -> &[u8; crate::MULTI_SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl MultiSignature {
    fn new_from_rs(r: Integer, s: Integer) -> Self {
        let mut sig: [u8; SIGNATURE_SIZE] = [0; SIGNATURE_SIZE];
        let r_bytes = Natural::saturating_from(&r).to_power_of_2_digits_asc(8);
        let s_bytes = Natural::saturating_from(&s).to_power_of_2_digits_asc(8);

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
    r: Vec<Natural>,
    r_bytes: Vec<[u8; 32]>,
    s: Natural,
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
        let s = Natural::from_power_of_2_digits_asc(8, s_bytes.iter().cloned()).unwrap();

        let mut r = Vec::<Natural>::new();
        let mut r_bytes = Vec::<[u8; 32]>::new();

        for i in 0..count {
            let start = 34 + i as usize * 32;
            let end = start + 32;
            r_bytes.push(bytes[start..end].try_into().map_err(|_| CryptoError::InvalidSignature)?);
            let r_i = Natural::from_power_of_2_digits_asc(8, bytes[start..end].iter().cloned()).unwrap();
            r.push(r_i);
        }

        Ok(AggregatedSignature { r, r_bytes, s })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE * self.r.len());
        result.extend_from_slice(&(self.r.len() as u16).to_le_bytes());
        result.extend_from_slice(&self.s.to_power_of_2_digits_asc(8));
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
    p: Integer,
    p_nat: Natural,
    n: Integer,
    n_nat: Natural,
    g: Point,
    private_key: Integer,
    private_key_bytes: [u8; 32],
    public_key: PublicKey,
}

impl Crypto {
    //Calculate the double of the given point
    fn double(&self, point: &Point) -> Point {
        let nat_py = Natural::saturating_from(&point.y);
        let inverse = Integer::from(&nat_py.mod_shl(1u8, &self.p_nat).mod_inverse(&self.p_nat).unwrap());
        let slope = (THREE * (&point.x).square() * inverse) % &self.p;

        let mut x = ((&slope).square() - &point.x * TWO) % &self.p;
        let mut y = ((&slope) * (&point.x - &x) - &point.y) % &self.p;

        if x < 0 {
            x = x + &self.p;
        }

        if y < 0 {
            y = y + &self.p;
        }

        Point { x, y }
    }

    //Add two points
    fn add(&self, point1: &Point, point2: &Point) -> Point {
        if point1 == point2 {
            return self.double(point1);
        }

        let mut diff = &point1.x - &point2.x;
        if diff < 0 {
            diff = diff + &self.p;
        }

        let nat_diff = Natural::saturating_from(&diff);
        let inverse = Integer::from(&nat_diff.mod_inverse(&self.p_nat).unwrap());

        let slope = ((&point1.y - &point2.y) * inverse) % &self.p;
        let mut x = (&slope * &slope - &point1.x - &point2.x) % &self.p;
        let mut y = (slope * (&point1.x - &x) - &point1.y) % &self.p;
        if y < 0 {
            y = y + &self.p;
        }

        if x < 0 {
            x = x + &self.p;
        }

        Point { x, y }
    }

    // Point multiplication with scalar k
    // k is a scalar and point is a point on the elliptic curve
    // This function uses the double-and-add algorithm to perform scalar multiplication
    fn multiply(&self, k: &Integer, point: &Point) -> Point {
        let mut result = point.clone();
        let bits = k.to_string_base(2);
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

    fn point_from_x(&self, x: &Natural) -> Result<Point, CryptoError> {
        let y_sq = (x * x * x + B_NAT) % &self.p_nat;
        let mut y = (&y_sq).mod_pow(&((&self.p_nat + ONE_NAT) / FOUR_NAT), &self.p_nat);

        if x >= &self.p_nat {
            //x value in public key is not a valid coordinate because it is not less than the elliptic curve field size
            return Err(CryptoError::InvalidSignature);
        }

        y = if &y * &y % &self.p_nat != y_sq {
            //public key is not a valid x coordinate on the curve
            return Err(CryptoError::InvalidSignature);
        } else if (&y % TWO_NAT) == 0 {
            y
        } else {
            &self.p_nat - &y
        };

        let x_integer = Integer::from(x);
        let y_integer = Integer::from(y);

        Ok(Point { x: x_integer, y: y_integer })
    }

    fn sign_common(&self, message: &[u8]) -> (Integer, Integer) {
        //deterministic nonce generation
        let mut k0: Integer;
        let mut counter = 0u32;
        loop {
            let counter_bytes = counter.to_le_bytes();
            k0 = Integer::from(
                Natural::from_power_of_2_digits_asc(8, self.tagged_hash(b"nonce", &self.private_key_bytes, &message, &counter_bytes).iter().cloned()).unwrap()
                    % &self.n_nat,
            );

            if k0 > 0 {
                break;
            }
            counter += 1;
        }

        let random_point = self.multiply(&k0, &self.g);
        let k = if (&random_point.y % TWO) == 0 { k0 } else { &self.n - k0 };

        let random_bytes = Natural::saturating_from(&random_point.x).to_power_of_2_digits_asc(8);

        let e = Natural::from_power_of_2_digits_asc(
            8,
            self.tagged_hash(b"challenge", &random_bytes, &self.public_key.bytes, message).iter().cloned(),
        )
        .unwrap()
            % &self.n_nat;

        let r = random_point.x;

        let mut s = (&k + &Integer::from(e) * &self.private_key) % &self.n;
        if s < 0 {
            s = s + &self.n;
        }
        (r, s)
    }

    fn verify_common(&self, message: &[u8], r: &Integer, s: &Integer, signature_bytes: [u8; 64], public_key: &PublicKey) -> bool {
        if r >= &self.p_nat || s >= &self.n_nat {
            //r value in signature is not less than the elliptic curve field size or s value in signature is not less than the number of points on the elliptic curve
            return false;
        }

        let e = Integer::from(
            Natural::from_power_of_2_digits_asc(
                8,
                self.tagged_hash(b"challenge", &signature_bytes[0..32], &public_key.bytes, message)
                    .iter()
                    .cloned(),
            )
            .unwrap()
                % &self.n_nat,
        );

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
        let p_nat = Natural::from_string_base(16, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F").unwrap();
        let p = Integer::from(&p_nat);
        let n_nat = Natural::from_string_base(16, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap();
        let n = Integer::from(&n_nat);
        let g = Point {
            x: Integer::from_string_base(16, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap(),
            y: Integer::from_string_base(16, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap(),
        };

        let private_key_int_result = Natural::from_power_of_2_digits_asc(8, private_key_bytes.iter().cloned());
        let private_key_nat = match private_key_int_result {
            Some(value) => value,
            None => return Err(CryptoError::InvalidPrivateKey),
        };
        if private_key_nat < 1 || private_key_nat >= n_nat {
            return Err(CryptoError::InvalidPrivateKey);
        }

        let placeholder_point = Point {
            x: Integer::from(0),
            y: Integer::from(0),
        };

        let placeholder_public_key = PublicKey {
            point: placeholder_point,
            bytes: [0; 32],
        };

        let mut new_self = Self {
            p,
            p_nat,
            n,
            n_nat,
            g,
            private_key: Integer::from(private_key_nat),
            private_key_bytes,
            //temporary public key, we calculate the real one some lines below
            public_key: placeholder_public_key,
        };

        let mut public_key_point = new_self.multiply(&new_self.private_key, &new_self.g);
        if &public_key_point.y % TWO != 0 {
            public_key_point.y = &new_self.p - &public_key_point.y;
            new_self.private_key = &new_self.n - &new_self.private_key;
        };

        if public_key_point.x <= 0 {
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
        let mut r = Vec::<Natural>::new();
        let mut r_bytes = Vec::<[u8; 32]>::new();
        let mut s = Natural::from(0u32);

        //calculate the sum of r values to use in the initial seed of the random number generation
        let mut r_sum = Natural::from(0u32);

        if signatures.is_empty() {
            return Err(CryptoError::InvalidSignature);
        };

        for signature in signatures.iter() {
            r_sum = (r_sum + Natural::saturating_from(&signature.r)) % &self.p_nat;
            r.push(Natural::saturating_from(&signature.r));
            r_bytes.push(signature.bytes[0..32].try_into().unwrap());
        }

        let r_sum_bytes = &r_sum.to_power_of_2_digits_asc(8);
        //generate the initial random sedd using the sum of r values and the message
        let initial_random_seed = self.tagged_hash(b"aggregate", &r_sum_bytes, &r_sum_bytes, &message);

        //calculate the sum of s values (multiplid by the generated random number) to use in the aggregated signature
        //the random number should be betwen 1 and n-1
        let mut i: u32 = 0;
        for signature in signatures.iter() {
            let i_bytes = Natural::from(i as u32).to_power_of_2_digits_asc(8);
            //calculate the random number using the initial seed and the sequence number
            let random_number = Natural::from_power_of_2_digits_asc(8, self.tagged_hash(b"rand", &initial_random_seed, &i_bytes, &i_bytes).iter().cloned())
                .unwrap()
                % (&self.n_nat - &ONE_NAT)
                + &ONE_NAT;

            s = (s + &Natural::saturating_from(&signature.s) * &random_number) % &self.n_nat;
            i += 1;
        }
        Ok(AggregatedSignature { r, r_bytes, s })
    }

    fn verify_aggregated_signature(&self, message: &[u8], aggregated_signature: &AggregatedSignature, public_keys: &[&PublicKey]) -> bool {
        //calculate the sum of r values to use in the initial seed of the random number generation
        let mut r_sum = Natural::from(0u32);
        for r in aggregated_signature.r.iter() {
            r_sum = (r_sum + r) % &self.p_nat;
        }
        let r_initrand_sum_bytes = &r_sum.to_power_of_2_digits_asc(8);
        let initial_random_seed = self.tagged_hash(b"aggregate", &r_initrand_sum_bytes, &r_initrand_sum_bytes, &message);

        //calculate the sum of r values (multiplid by the generated random number) and the sum ok public keys multiplied by (n-ex)
        let mut r_point_sum = Point {
            x: Integer::from(0),
            y: Integer::from(0),
        };
        let mut pk_point_sum: Point = Point {
            x: Integer::from(0),
            y: Integer::from(0),
        };
        for i in 0..aggregated_signature.get_count() {
            if &aggregated_signature.r[i] >= &self.p_nat || &aggregated_signature.s >= &self.n_nat {
                //r value in signature is not less than the elliptic curve field size or s value in signature is not less than the number of points on the elliptic curve
                return false;
            }

            //calculate the random number using the initial seed and the sequence number
            let i_bytes = Natural::from(i as u32).to_power_of_2_digits_asc(8);
            let random_number = Natural::from_power_of_2_digits_asc(8, self.tagged_hash(b"rand", &initial_random_seed, &i_bytes, &i_bytes).iter().cloned())
                .unwrap()
                % (&self.n_nat - &ONE_NAT)
                + &ONE_NAT;

            let r_point = if let Ok(r_point) = self.point_from_x(&aggregated_signature.r[i]) {
                r_point
            } else {
                return false;
            };

            let r_point_multiplied = self.multiply(&Integer::from(&random_number), &r_point);

            if i > 0 {
                r_point_sum = self.add(&r_point_sum, &r_point_multiplied);
            } else {
                r_point_sum = r_point_multiplied;
            }

            //calculate the challenge
            let e = Natural::from_power_of_2_digits_asc(
                8,
                self.tagged_hash(b"challenge", &aggregated_signature.r_bytes[i], &public_keys[i].bytes, message)
                    .iter()
                    .cloned(),
            )
            .unwrap()
                % &self.n_nat;

            let pk_point = self.multiply(&Integer::from(&(&self.n_nat - e) * &random_number), &public_keys[i].point);
            if i > 0 {
                pk_point_sum = self.add(&pk_point_sum, &pk_point);
            } else {
                pk_point_sum = pk_point;
            }
        }
        let g_point = self.multiply(&Integer::from(&aggregated_signature.s), &self.g);

        let sum_point = self.add(&pk_point_sum, &g_point);

        if &sum_point.x == &r_point_sum.x {
            return true;
        } else {
            return false;
        }
    }
}
