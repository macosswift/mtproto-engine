use base64::Engine;
use num_bigint::BigUint;
use zeroize::Zeroize;

use super::aes_ige::aes_ige_encrypt;
use super::hash::{sha1, sha1_parts, sha256, sha256_parts};
use super::rng::SecureRandom;
use crate::tl::Writer;

const RSA_BYTES: usize = 256;
const RSA_PAD_DATA_LIMIT: usize = 144;
const RSA_PAD_PADDED_LEN: usize = 192;
const LEGACY_DATA_LIMIT: usize = 255 - 20;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RsaError {
    #[error("invalid PEM encoding")]
    InvalidPem,
    #[error("invalid DER structure")]
    InvalidDer,
    #[error("modulus must be 2048 bits")]
    UnsupportedModulus,
    #[error("payload is {0} bytes, too long for RSA padding")]
    PayloadTooLong(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
    fingerprint: i64,
}

impl RsaPublicKey {
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self, RsaError> {
        let n = BigUint::from_bytes_be(n);
        let e = BigUint::from_bytes_be(e);
        if n.bits() != 2048 {
            return Err(RsaError::UnsupportedModulus);
        }
        let mut writer = Writer::new();
        writer.write_bytes(&n.to_bytes_be());
        writer.write_bytes(&e.to_bytes_be());
        let hash = sha1(writer.as_slice());
        let fingerprint = i64::from_le_bytes(hash[12..20].try_into().expect("8 bytes"));
        Ok(Self { n, e, fingerprint })
    }

    pub fn from_pem(pem: &str) -> Result<Self, RsaError> {
        let body: String =
            pem.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with("-----")).collect();
        let der =
            base64::engine::general_purpose::STANDARD.decode(body.as_bytes()).map_err(|_| RsaError::InvalidPem)?;
        let (n, e) = if pem.contains("BEGIN RSA PUBLIC KEY") {
            parse_pkcs1(&der)?
        } else if pem.contains("BEGIN PUBLIC KEY") {
            parse_spki(&der)?
        } else {
            return Err(RsaError::InvalidPem);
        };
        Self::from_components(&n, &e)
    }

    pub fn fingerprint(&self) -> i64 {
        self.fingerprint
    }

    pub fn modulus_be(&self) -> Vec<u8> {
        self.n.to_bytes_be()
    }

    fn raw_encrypt(&self, block: &[u8; RSA_BYTES]) -> Option<[u8; RSA_BYTES]> {
        let m = BigUint::from_bytes_be(block);
        if m >= self.n {
            return None;
        }
        super::dh::to_fixed_be::<RSA_BYTES>(&m.modpow(&self.e, &self.n))
    }

    pub fn encrypt_pad(&self, data: &[u8], rng: &mut impl SecureRandom) -> Result<[u8; RSA_BYTES], RsaError> {
        if data.len() > RSA_PAD_DATA_LIMIT {
            return Err(RsaError::PayloadTooLong(data.len()));
        }
        let mut data_with_padding = [0u8; RSA_PAD_PADDED_LEN];
        data_with_padding[..data.len()].copy_from_slice(data);
        rng.fill(&mut data_with_padding[data.len()..]);
        let mut reversed = data_with_padding;
        reversed.reverse();
        loop {
            let mut temp_key = [0u8; 32];
            rng.fill(&mut temp_key);
            let mut data_with_hash = [0u8; RSA_PAD_PADDED_LEN + 32];
            data_with_hash[..RSA_PAD_PADDED_LEN].copy_from_slice(&reversed);
            data_with_hash[RSA_PAD_PADDED_LEN..].copy_from_slice(&sha256_parts(&[&temp_key, &data_with_padding]));
            aes_ige_encrypt(&temp_key, &[0u8; 32], &mut data_with_hash).expect("224 is a multiple of 16");
            let aes_hash = sha256(&data_with_hash);
            let mut block = [0u8; RSA_BYTES];
            for (index, byte) in block[..32].iter_mut().enumerate() {
                *byte = temp_key[index] ^ aes_hash[index];
            }
            block[32..].copy_from_slice(&data_with_hash);
            temp_key.zeroize();
            let encrypted = self.raw_encrypt(&block);
            block.zeroize();
            if let Some(encrypted) = encrypted {
                data_with_padding.zeroize();
                reversed.zeroize();
                return Ok(encrypted);
            }
        }
    }

    pub fn encrypt_legacy(&self, data: &[u8], rng: &mut impl SecureRandom) -> Result<[u8; RSA_BYTES], RsaError> {
        if data.len() > LEGACY_DATA_LIMIT {
            return Err(RsaError::PayloadTooLong(data.len()));
        }
        let mut block = [0u8; RSA_BYTES];
        block[1..21].copy_from_slice(&sha1_parts(&[data]));
        block[21..21 + data.len()].copy_from_slice(data);
        rng.fill(&mut block[21 + data.len()..]);
        let encrypted = self.raw_encrypt(&block).ok_or(RsaError::PayloadTooLong(data.len()));
        block.zeroize();
        encrypted
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn decrypt_with_private_exponent(&self, d: &BigUint, data: &[u8]) -> Vec<u8> {
        BigUint::from_bytes_be(data).modpow(d, &self.n).to_bytes_be()
    }

    pub fn public_exponent_raw(&self, data: &[u8]) -> Vec<u8> {
        BigUint::from_bytes_be(data).modpow(&self.e, &self.n).to_bytes_be()
    }
}

struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn read(&mut self, expected_tag: u8) -> Result<&'a [u8], RsaError> {
        let (&tag, rest) = self.data.split_first().ok_or(RsaError::InvalidDer)?;
        if tag != expected_tag {
            return Err(RsaError::InvalidDer);
        }
        let (&first, mut rest) = rest.split_first().ok_or(RsaError::InvalidDer)?;
        let length = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 || rest.len() < count {
                return Err(RsaError::InvalidDer);
            }
            let length = rest[..count].iter().fold(0usize, |acc, &b| (acc << 8) | b as usize);
            rest = &rest[count..];
            length
        };
        if rest.len() < length {
            return Err(RsaError::InvalidDer);
        }
        let (value, remaining) = rest.split_at(length);
        self.data = remaining;
        Ok(value)
    }
}

fn strip_integer(value: &[u8]) -> &[u8] {
    let mut value = value;
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    value
}

fn parse_pkcs1(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RsaError> {
    let mut outer = Der { data: der };
    let mut sequence = Der { data: outer.read(0x30)? };
    let n = strip_integer(sequence.read(0x02)?).to_vec();
    let e = strip_integer(sequence.read(0x02)?).to_vec();
    Ok((n, e))
}

fn parse_spki(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), RsaError> {
    let mut outer = Der { data: der };
    let mut sequence = Der { data: outer.read(0x30)? };
    sequence.read(0x30)?;
    let bit_string = sequence.read(0x03)?;
    let (&unused_bits, key) = bit_string.split_first().ok_or(RsaError::InvalidDer)?;
    if unused_bits != 0 {
        return Err(RsaError::InvalidDer);
    }
    parse_pkcs1(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;

    pub const PRODUCTION_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\n\
MIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n\
5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n\
62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n\
+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\n\
t6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n\
5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n\
-----END RSA PUBLIC KEY-----";

    #[test]
    fn production_key_parses_with_expected_fingerprint() {
        let key = RsaPublicKey::from_pem(PRODUCTION_KEY).unwrap();
        assert_eq!(key.fingerprint() as u64, 0xd09d1d85de64fd85);
    }

    #[test]
    fn spki_and_pkcs1_agree() {
        let pkcs1 = RsaPublicKey::from_pem(PRODUCTION_KEY).unwrap();
        let body: String = PRODUCTION_KEY.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
        let mut spki = vec![
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
        ];
        spki.extend_from_slice(&der);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            base64::engine::general_purpose::STANDARD.encode(&spki)
        );
        assert_eq!(RsaPublicKey::from_pem(&pem).unwrap(), pkcs1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(RsaPublicKey::from_pem("-----BEGIN RSA PUBLIC KEY-----\n!!!\n-----END RSA PUBLIC KEY-----").is_err());
        assert!(RsaPublicKey::from_pem("-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----").is_err());
        assert!(RsaPublicKey::from_components(&[0xff; 128], &[1, 0, 1]).is_err());
    }

    #[test]
    fn rsa_pad_payload_limits() {
        let key = RsaPublicKey::from_pem(PRODUCTION_KEY).unwrap();
        let mut rng = XorShiftRandom::new(9);
        assert!(key.encrypt_pad(&[0u8; 145], &mut rng).is_err());
        let encrypted = key.encrypt_pad(&[1u8; 144], &mut rng).unwrap();
        assert_eq!(encrypted.len(), 256);
        assert!(key.encrypt_legacy(&[0u8; 236], &mut rng).is_err());
        assert!(key.encrypt_legacy(&[0u8; 100], &mut rng).is_ok());
    }
}

#[cfg(test)]
mod pad_tests {
    use super::*;
    use crate::crypto::{XorShiftRandom, aes_ige_decrypt};
    use crate::test_support::test_rsa_key_pair;
    use proptest::prelude::*;

    fn rsa_pad_decrypt(encrypted: &[u8; 256]) -> Option<Vec<u8>> {
        let pair = test_rsa_key_pair();
        let block = pair.decrypt(encrypted);
        let aes_hash = sha256(&block[32..]);
        let mut temp_key = [0u8; 32];
        for i in 0..32 {
            temp_key[i] = block[i] ^ aes_hash[i];
        }
        let mut data_with_hash = block[32..].to_vec();
        aes_ige_decrypt(&temp_key, &[0u8; 32], &mut data_with_hash).ok()?;
        let mut data_with_padding = data_with_hash[..192].to_vec();
        data_with_padding.reverse();
        if sha256_parts(&[&temp_key, &data_with_padding]) != data_with_hash[192..] {
            return None;
        }
        Some(data_with_padding)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn rsa_pad_roundtrips_through_private_key(data in proptest::collection::vec(any::<u8>(), 0..=144), seed in any::<u64>()) {
            let pair = test_rsa_key_pair();
            let mut rng = XorShiftRandom::new(seed);
            let encrypted = pair.public.encrypt_pad(&data, &mut rng).unwrap();
            let decrypted = rsa_pad_decrypt(&encrypted).expect("hash must verify");
            prop_assert_eq!(&decrypted[..data.len()], &data[..]);
        }
    }

    #[test]
    fn legacy_roundtrip() {
        let pair = test_rsa_key_pair();
        let mut rng = XorShiftRandom::new(5);
        let data = b"p_q_inner_data payload";
        let encrypted = pair.public.encrypt_legacy(data, &mut rng).unwrap();
        let block = pair.decrypt(&encrypted);
        assert_eq!(block[0], 0);
        assert_eq!(&block[1..21], &sha1(data));
        assert_eq!(&block[21..21 + data.len()], data);
    }
}
