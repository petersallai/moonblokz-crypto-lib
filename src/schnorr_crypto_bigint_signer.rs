use core::cmp::min;
use crypto_bigint::{Encoding, NonZero, U256};
use sha2::digest::FixedOutput;
use sha2::{Digest, Sha256};

use crate::AGGREGATED_SIGNATURE_CONSTANT_SIZE;
use crate::AGGREGATED_SIGNATURE_VARIABLE_SIZE;
use crate::AggregatedSignatureTrait;
use crate::MAX_AGGREGATED_SIGNATURES;
use crate::MULTI_SIGNATURE_SIZE;
use crate::MultiSignatureTrait;
use crate::PRIVATE_KEY_SIZE;
use crate::PUBLIC_KEY_SIZE;
use crate::PublicKeyTrait;
use crate::SIGNATURE_SIZE;

use crate::CryptoError;
use crate::CryptoTrait;
use crate::SignatureTrait;

const B: U256 = U256::from_u8(7);

#[derive(Clone, PartialEq, Eq)]
pub struct Point {
    x: U256,
    y: U256,
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

        let public_key_bytes: [u8; 32] = bytes[0..32]
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let point = Self::calculate_public_key_point(&public_key_bytes)?;
        Ok(PublicKey {
            point,
            bytes: public_key_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

impl PublicKey {
    fn new_from_point(point: Point) -> Self {
        PublicKey {
            bytes: point.x.to_le_bytes(),
            point,
        }
    }

    fn calculate_public_key_point(public_key_bytes: &[u8; 32]) -> Result<Point, CryptoError> {
        let p = Crypto::p_const();
        let x = U256::from_le_bytes(*public_key_bytes);
        let y_sq = Crypto::mod_add(Crypto::mod_mul(Crypto::mod_mul(x, x, p), x, p), B, p);
        let y = Crypto::pow_mod(y_sq, Crypto::p_sqrt_exp(), p);

        if x >= p {
            return Err(CryptoError::InvalidPublicKey);
        }

        let y = if Crypto::mod_mul(y, y, p) != y_sq {
            return Err(CryptoError::InvalidPublicKey);
        } else if (y.to_le_bytes()[0] & 1) == 0 {
            y
        } else {
            Crypto::mod_sub(p, y, p)
        };

        Ok(Point { x, y })
    }
}

pub struct Signature {
    r: U256,
    s: U256,
    bytes: [u8; SIGNATURE_SIZE],
}

impl SignatureTrait for Signature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; 64] = bytes[0..64]
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let r = U256::from_le_slice(&signature_bytes[0..32]);
        let s = U256::from_le_slice(&signature_bytes[32..64]);

        Ok(Signature {
            r,
            s,
            bytes: signature_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl Signature {
    fn new_from_rs(r: U256, s: U256) -> Self {
        let mut sig = [0u8; SIGNATURE_SIZE];
        let r_bytes = r.to_le_bytes();
        let s_bytes = s.to_le_bytes();
        sig[0..32].copy_from_slice(&r_bytes);
        sig[32..64].copy_from_slice(&s_bytes);
        Signature { r, s, bytes: sig }
    }
}

pub struct MultiSignature {
    r: U256,
    s: U256,
    bytes: [u8; MULTI_SIGNATURE_SIZE],
}

impl MultiSignatureTrait for MultiSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SIGNATURE_SIZE {
            return Err(CryptoError::InvalidSignature);
        }

        let signature_bytes: [u8; 64] = bytes[0..64]
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let r = U256::from_le_slice(&signature_bytes[0..32]);
        let s = U256::from_le_slice(&signature_bytes[32..64]);

        Ok(MultiSignature {
            r,
            s,
            bytes: signature_bytes,
        })
    }

    fn serialize(&self) -> &[u8; crate::MULTI_SIGNATURE_SIZE] {
        &self.bytes
    }
}

impl MultiSignature {
    fn new_from_rs(r: U256, s: U256) -> Self {
        let mut sig = [0u8; SIGNATURE_SIZE];
        let r_bytes = r.to_le_bytes();
        let s_bytes = s.to_le_bytes();
        sig[0..32].copy_from_slice(&r_bytes);
        sig[32..64].copy_from_slice(&s_bytes);
        MultiSignature { r, s, bytes: sig }
    }
}

pub struct AggregatedSignature {
    count: usize,
    r_bytes: [[u8; 32]; MAX_AGGREGATED_SIGNATURES],
    s: U256,
}

impl AggregatedSignatureTrait for AggregatedSignature {
    fn new(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < 2 {
            return Err(CryptoError::InvalidSignature);
        }

        let count_slice: [u8; 2] = bytes[0..2]
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let count = u16::from_le_bytes(count_slice) as usize;
        if count > MAX_AGGREGATED_SIGNATURES {
            return Err(CryptoError::InvalidSignature);
        }

        if bytes.len()
            < AGGREGATED_SIGNATURE_VARIABLE_SIZE * count + AGGREGATED_SIGNATURE_CONSTANT_SIZE
        {
            return Err(CryptoError::InvalidSignature);
        }

        let s_bytes: [u8; 32] = bytes[2..34]
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let s = U256::from_le_bytes(s_bytes);
        let mut r_bytes = [[0u8; 32]; MAX_AGGREGATED_SIGNATURES];

        for i in 0..count {
            let start = 34 + i * 32;
            let end = start + 32;
            r_bytes[i] = bytes[start..end]
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature)?;
        }

        Ok(AggregatedSignature { count, r_bytes, s })
    }

    fn serialize(&self, out: &mut [u8]) -> Result<usize, CryptoError> {
        let total_len =
            AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE * self.count;
        if out.len() < total_len {
            return Err(CryptoError::InvalidSignature);
        }

        out[0..2].copy_from_slice(&(self.count as u16).to_le_bytes());
        let s_bytes = self.s.to_le_bytes();
        let mut s_fixed = [0u8; 32];
        let s_len = min(s_bytes.len(), 32);
        s_fixed[..s_len].copy_from_slice(&s_bytes[..s_len]);
        out[2..34].copy_from_slice(&s_fixed);
        for i in 0..self.count {
            let start = 34 + i * 32;
            let end = start + 32;
            out[start..end].copy_from_slice(&self.r_bytes[i]);
        }
        Ok(total_len)
    }

    fn get_count(&self) -> usize {
        self.count
    }

    fn serialized_len(&self) -> usize {
        AGGREGATED_SIGNATURE_CONSTANT_SIZE + AGGREGATED_SIGNATURE_VARIABLE_SIZE * self.count
    }
}

pub struct Crypto {
    p: U256,
    n: U256,
    g: Point,
    private_key: U256,
    private_key_bytes: [u8; 32],
    public_key: PublicKey,
}

impl Crypto {
    #[inline]
    fn p_const() -> U256 {
        U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    }

    #[inline]
    fn n_const() -> U256 {
        U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    }

    #[inline]
    fn p_sqrt_exp() -> U256 {
        U256::from_be_hex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C")
    }

    #[inline]
    fn g_point() -> Point {
        Point {
            x: U256::from_be_hex(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            ),
            y: U256::from_be_hex(
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            ),
        }
    }

    #[inline]
    fn mod_add(a: U256, b: U256, m: U256) -> U256 {
        a.add_mod(&b, &m)
    }

    #[inline]
    fn mod_sub(a: U256, b: U256, m: U256) -> U256 {
        a.sub_mod(&b, &m)
    }

    #[inline]
    fn mod_mul(a: U256, b: U256, m: U256) -> U256 {
        a.mul_mod(&b, &NonZero::new(m).unwrap())
    }

    fn mod_inv(a: U256, m: U256) -> U256 {
        let m_nz = NonZero::new(m).unwrap();
        let inv = a.inv_mod(&m_nz);
        if bool::from(inv.is_some()) {
            inv.unwrap()
        } else {
            U256::ZERO
        }
    }

    #[inline]
    fn is_identity(point: &Point) -> bool {
        point.x == U256::ZERO && point.y == U256::ZERO
    }

    #[inline]
    fn trim_le_bytes(bytes: &[u8; 32]) -> &[u8] {
        let mut len = bytes.len();
        while len > 0 && bytes[len - 1] == 0 {
            len -= 1;
        }
        &bytes[..len]
    }

    #[inline]
    fn trim_u32_le_bytes(bytes: &[u8; 4]) -> &[u8] {
        let mut len = bytes.len();
        while len > 0 && bytes[len - 1] == 0 {
            len -= 1;
        }
        &bytes[..len]
    }

    fn pow_mod(mut base: U256, exp: U256, m: U256) -> U256 {
        let mut result = U256::ONE;
        let exp_bytes = exp.to_le_bytes();
        for i in 0..256 {
            if ((exp_bytes[i / 8] >> (i % 8)) & 1) == 1 {
                result = Self::mod_mul(result, base, m);
            }
            base = Self::mod_mul(base, base, m);
        }
        result
    }

    fn scalar_msb_first_steps(k: &U256) -> [u8; 256] {
        let mut bits = [0u8; 256];
        let bytes = k.to_be_bytes();
        for i in 0..256 {
            let byte = bytes[i / 8];
            let bit = (byte >> (7 - (i % 8))) & 1;
            bits[i] = bit;
        }
        bits
    }

    fn double(&self, point: &Point) -> Point {
        if Self::is_identity(point) {
            return point.clone();
        }
        let two_y = Self::mod_add(point.y, point.y, self.p);
        let inv = Self::mod_inv(two_y, self.p);
        if inv == U256::ZERO {
            return Point {
                x: U256::ZERO,
                y: U256::ZERO,
            };
        }
        let x_sq = Self::mod_mul(point.x, point.x, self.p);
        let three_x_sq = Self::mod_add(x_sq, Self::mod_add(x_sq, x_sq, self.p), self.p);
        let slope = Self::mod_mul(three_x_sq, inv, self.p);
        let two_x = Self::mod_add(point.x, point.x, self.p);
        let x = Self::mod_sub(Self::mod_mul(slope, slope, self.p), two_x, self.p);
        let y = Self::mod_sub(
            Self::mod_mul(slope, Self::mod_sub(point.x, x, self.p), self.p),
            point.y,
            self.p,
        );
        Point { x, y }
    }

    fn add(&self, point1: &Point, point2: &Point) -> Point {
        if Self::is_identity(point1) {
            return point2.clone();
        }
        if Self::is_identity(point2) {
            return point1.clone();
        }
        if point1 == point2 {
            return self.double(point1);
        }

        let diff = Self::mod_sub(point1.x, point2.x, self.p);
        let inv = Self::mod_inv(diff, self.p);
        if inv == U256::ZERO {
            return Point {
                x: U256::ZERO,
                y: U256::ZERO,
            };
        }
        let slope = Self::mod_mul(Self::mod_sub(point1.y, point2.y, self.p), inv, self.p);
        let x = Self::mod_sub(
            Self::mod_sub(Self::mod_mul(slope, slope, self.p), point1.x, self.p),
            point2.x,
            self.p,
        );
        let y = Self::mod_sub(
            Self::mod_mul(slope, Self::mod_sub(point1.x, x, self.p), self.p),
            point1.y,
            self.p,
        );
        Point { x, y }
    }

    fn multiply(&self, k: &U256, point: &Point) -> Point {
        if *k == U256::ZERO || Self::is_identity(point) {
            return Point {
                x: U256::ZERO,
                y: U256::ZERO,
            };
        }
        let bits = Self::scalar_msb_first_steps(k);
        let mut found = false;
        let mut result = point.clone();

        for bit in bits {
            if !found {
                if bit == 1 {
                    found = true;
                }
                continue;
            }
            result = self.double(&result);
            if bit == 1 {
                result = self.add(&result, point);
            }
        }
        result
    }

    fn tagged_hash(
        &self,
        tag_bytes: &[u8],
        message1: &[u8],
        message2: &[u8],
        message3: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(tag_bytes);
        hasher.update(message1);
        hasher.update(message2);
        hasher.update(message3);
        hasher.finalize_fixed().into()
    }

    fn point_from_x(&self, x: &U256) -> Result<Point, CryptoError> {
        let y_sq = Self::mod_add(
            Self::mod_mul(Self::mod_mul(*x, *x, self.p), *x, self.p),
            B,
            self.p,
        );
        let y0 = Self::pow_mod(y_sq, Self::p_sqrt_exp(), self.p);

        if x >= &self.p {
            return Err(CryptoError::InvalidSignature);
        }

        let y = if Self::mod_mul(y0, y0, self.p) != y_sq {
            return Err(CryptoError::InvalidSignature);
        } else if (y0.to_le_bytes()[0] & 1) == 0 {
            y0
        } else {
            Self::mod_sub(self.p, y0, self.p)
        };

        Ok(Point { x: *x, y })
    }

    fn sign_common(&self, message: &[u8]) -> (U256, U256) {
        let mut k0;
        let mut counter = 0u32;
        loop {
            let counter_bytes = counter.to_le_bytes();
            k0 = U256::from_le_bytes(self.tagged_hash(
                b"nonce",
                &self.private_key_bytes,
                message,
                &counter_bytes,
            ));
            k0 = k0.rem(&NonZero::new(self.n).unwrap());
            if k0 > U256::ZERO {
                break;
            }
            counter += 1;
        }

        let random_point = self.multiply(&k0, &self.g);
        let k = if (random_point.y.to_le_bytes()[0] & 1) == 0 {
            k0
        } else {
            Self::mod_sub(self.n, k0, self.n)
        };

        let random_bytes = random_point.x.to_le_bytes();
        let random_bytes_trim = Self::trim_le_bytes(&random_bytes);
        let e = U256::from_le_bytes(self.tagged_hash(
            b"challenge",
            random_bytes_trim,
            &self.public_key.bytes,
            message,
        ))
        .rem(&NonZero::new(self.n).unwrap());
        let r = random_point.x;
        let s = Self::mod_add(k, Self::mod_mul(e, self.private_key, self.n), self.n);
        (r, s)
    }

    fn verify_common(
        &self,
        message: &[u8],
        r: &U256,
        s: &U256,
        signature_bytes: [u8; 64],
        public_key: &PublicKey,
    ) -> bool {
        if *r >= self.p || *s >= self.n {
            return false;
        }

        let mut r_fixed = [0u8; 32];
        r_fixed.copy_from_slice(&signature_bytes[0..32]);
        let r_trim = Self::trim_le_bytes(&r_fixed);
        let e =
            U256::from_le_bytes(self.tagged_hash(b"challenge", r_trim, &public_key.bytes, message))
                .rem(&NonZero::new(self.n).unwrap());

        let point1 = self.multiply(s, &self.g);
        let n_minus_e = self.n - e;
        let point2 = self.multiply(&n_minus_e, &public_key.point);
        let point3 = self.add(&point1, &point2);
        &point3.x == r
    }
}

impl CryptoTrait for Crypto {
    fn new(private_key_bytes: [u8; PRIVATE_KEY_SIZE]) -> Result<Self, CryptoError> {
        let p = Self::p_const();
        let n = Self::n_const();
        let g = Self::g_point();
        let private_key = U256::from_le_bytes(private_key_bytes);

        if private_key < U256::ONE || private_key >= n {
            return Err(CryptoError::InvalidPrivateKey);
        }

        let placeholder_public_key = PublicKey {
            point: Point {
                x: U256::ZERO,
                y: U256::ZERO,
            },
            bytes: [0; 32],
        };

        let mut new_self = Self {
            p,
            n,
            g,
            private_key,
            private_key_bytes,
            public_key: placeholder_public_key,
        };

        let mut public_key_point = new_self.multiply(&new_self.private_key, &new_self.g);
        if (public_key_point.y.to_le_bytes()[0] & 1) == 1 {
            public_key_point.y = Self::mod_sub(new_self.p, public_key_point.y, new_self.p);
            new_self.private_key = Self::mod_sub(new_self.n, new_self.private_key, new_self.n);
        }

        if public_key_point.x == U256::ZERO || public_key_point.x >= new_self.p {
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
        Signature::new_from_rs(r, s)
    }

    fn multi_sign(&self, message: &[u8]) -> MultiSignature {
        let (r, s) = self.sign_common(message);
        MultiSignature::new_from_rs(r, s)
    }

    fn verify_signature(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> bool {
        self.verify_common(
            message,
            &signature.r,
            &signature.s,
            signature.bytes,
            public_key,
        )
    }

    fn verify_multi_signature(
        &self,
        message: &[u8],
        multi_signature: &MultiSignature,
        public_key: &PublicKey,
    ) -> bool {
        self.verify_common(
            message,
            &multi_signature.r,
            &multi_signature.s,
            multi_signature.bytes,
            public_key,
        )
    }

    fn aggregate_signatures(
        &self,
        signatures: &[&MultiSignature],
        message: &[u8],
    ) -> Result<AggregatedSignature, CryptoError> {
        if signatures.is_empty() || signatures.len() > MAX_AGGREGATED_SIGNATURES {
            return Err(CryptoError::InvalidSignature);
        }

        let mut r_bytes = [[0u8; 32]; MAX_AGGREGATED_SIGNATURES];
        let mut s = U256::ZERO;
        let mut r_sum = U256::ZERO;

        for (index, signature) in signatures.iter().enumerate() {
            r_sum = Self::mod_add(r_sum, signature.r, self.p);
            r_bytes[index] = signature.bytes[0..32].try_into().unwrap();
        }

        let r_sum_bytes = r_sum.to_le_bytes();
        let r_sum_trim = Self::trim_le_bytes(&r_sum_bytes);
        let initial_random_seed = self.tagged_hash(b"aggregate", r_sum_trim, r_sum_trim, message);

        for (i, signature) in signatures.iter().enumerate() {
            let i_bytes = (i as u32).to_le_bytes();
            let i_trim = Self::trim_u32_le_bytes(&i_bytes);
            let random_base = U256::from_le_bytes(self.tagged_hash(
                b"rand",
                &initial_random_seed,
                i_trim,
                i_trim,
            ));
            let random_number = Self::mod_add(
                random_base.rem(&NonZero::new(Self::mod_sub(self.n, U256::ONE, self.n)).unwrap()),
                U256::ONE,
                self.n,
            );
            s = Self::mod_add(s, Self::mod_mul(signature.s, random_number, self.n), self.n);
        }

        Ok(AggregatedSignature {
            count: signatures.len(),
            r_bytes,
            s,
        })
    }

    fn verify_aggregated_signature(
        &self,
        message: &[u8],
        aggregated_signature: &AggregatedSignature,
        public_keys: &[&PublicKey],
    ) -> bool {
        if aggregated_signature.get_count() != public_keys.len() {
            return false;
        }

        let mut r_sum = U256::ZERO;
        for i in 0..aggregated_signature.get_count() {
            let r_value = U256::from_le_bytes(aggregated_signature.r_bytes[i]);
            r_sum = Self::mod_add(r_sum, r_value, self.p);
        }
        let r_sum_bytes = r_sum.to_le_bytes();
        let r_sum_trim = Self::trim_le_bytes(&r_sum_bytes);
        let initial_random_seed = self.tagged_hash(b"aggregate", r_sum_trim, r_sum_trim, message);

        let mut r_point_sum = Point {
            x: U256::ZERO,
            y: U256::ZERO,
        };
        let mut pk_point_sum = Point {
            x: U256::ZERO,
            y: U256::ZERO,
        };

        for i in 0..aggregated_signature.get_count() {
            let r_value = U256::from_le_bytes(aggregated_signature.r_bytes[i]);
            if r_value >= self.p || aggregated_signature.s >= self.n {
                return false;
            }

            let i_u32 = (i as u32).to_le_bytes();
            let i_trim = Self::trim_u32_le_bytes(&i_u32);
            let random_base = U256::from_le_bytes(self.tagged_hash(
                b"rand",
                &initial_random_seed,
                i_trim,
                i_trim,
            ));
            let random_number = Self::mod_add(
                random_base.rem(&NonZero::new(Self::mod_sub(self.n, U256::ONE, self.n)).unwrap()),
                U256::ONE,
                self.n,
            );

            let r_point = if let Ok(point) = self.point_from_x(&r_value) {
                point
            } else {
                return false;
            };
            let r_point_multiplied = self.multiply(&random_number, &r_point);
            if i > 0 {
                r_point_sum = self.add(&r_point_sum, &r_point_multiplied);
            } else {
                r_point_sum = r_point_multiplied;
            }

            let r_trim = Self::trim_le_bytes(&aggregated_signature.r_bytes[i]);
            let e = U256::from_le_bytes(self.tagged_hash(
                b"challenge",
                r_trim,
                &public_keys[i].bytes,
                message,
            ))
            .rem(&NonZero::new(self.n).unwrap());
            let n_minus_e = self.n - e;
            let scalar = Self::mod_mul(n_minus_e, random_number, self.n);
            let pk_point = self.multiply(&scalar, &public_keys[i].point);
            if i > 0 {
                pk_point_sum = self.add(&pk_point_sum, &pk_point);
            } else {
                pk_point_sum = pk_point;
            }
        }

        let g_point = self.multiply(&aggregated_signature.s, &self.g);
        let sum_point = self.add(&pk_point_sum, &g_point);
        sum_point.x == r_point_sum.x
    }
}
