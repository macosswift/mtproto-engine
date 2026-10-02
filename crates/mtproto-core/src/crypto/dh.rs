use num_bigint::BigUint;
use num_traits::One;

use super::prime::is_probable_prime;
use super::rng::SecureRandom;

pub const DH_PRIME_BYTES: usize = 256;

pub const KNOWN_DH_PRIME: [u8; DH_PRIME_BYTES] = [
    0xc7, 0x1c, 0xae, 0xb9, 0xc6, 0xb1, 0xc9, 0x04, 0x8e, 0x6c, 0x52, 0x2f, 0x70, 0xf1, 0x3f, 0x73, 0x98, 0x0d, 0x40,
    0x23, 0x8e, 0x3e, 0x21, 0xc1, 0x49, 0x34, 0xd0, 0x37, 0x56, 0x3d, 0x93, 0x0f, 0x48, 0x19, 0x8a, 0x0a, 0xa7, 0xc1,
    0x40, 0x58, 0x22, 0x94, 0x93, 0xd2, 0x25, 0x30, 0xf4, 0xdb, 0xfa, 0x33, 0x6f, 0x6e, 0x0a, 0xc9, 0x25, 0x13, 0x95,
    0x43, 0xae, 0xd4, 0x4c, 0xce, 0x7c, 0x37, 0x20, 0xfd, 0x51, 0xf6, 0x94, 0x58, 0x70, 0x5a, 0xc6, 0x8c, 0xd4, 0xfe,
    0x6b, 0x6b, 0x13, 0xab, 0xdc, 0x97, 0x46, 0x51, 0x29, 0x69, 0x32, 0x84, 0x54, 0xf1, 0x8f, 0xaf, 0x8c, 0x59, 0x5f,
    0x64, 0x24, 0x77, 0xfe, 0x96, 0xbb, 0x2a, 0x94, 0x1d, 0x5b, 0xcd, 0x1d, 0x4a, 0xc8, 0xcc, 0x49, 0x88, 0x07, 0x08,
    0xfa, 0x9b, 0x37, 0x8e, 0x3c, 0x4f, 0x3a, 0x90, 0x60, 0xbe, 0xe6, 0x7c, 0xf9, 0xa4, 0xa4, 0xa6, 0x95, 0x81, 0x10,
    0x51, 0x90, 0x7e, 0x16, 0x27, 0x53, 0xb5, 0x6b, 0x0f, 0x6b, 0x41, 0x0d, 0xba, 0x74, 0xd8, 0xa8, 0x4b, 0x2a, 0x14,
    0xb3, 0x14, 0x4e, 0x0e, 0xf1, 0x28, 0x47, 0x54, 0xfd, 0x17, 0xed, 0x95, 0x0d, 0x59, 0x65, 0xb4, 0xb9, 0xdd, 0x46,
    0x58, 0x2d, 0xb1, 0x17, 0x8d, 0x16, 0x9c, 0x6b, 0xc4, 0x65, 0xb0, 0xd6, 0xff, 0x9c, 0xa3, 0x92, 0x8f, 0xef, 0x5b,
    0x9a, 0xe4, 0xe4, 0x18, 0xfc, 0x15, 0xe8, 0x3e, 0xbe, 0xa0, 0xf8, 0x7f, 0xa9, 0xff, 0x5e, 0xed, 0x70, 0x05, 0x0d,
    0xed, 0x28, 0x49, 0xf4, 0x7b, 0xf9, 0x59, 0xd9, 0x56, 0x85, 0x0c, 0xe9, 0x29, 0x85, 0x1f, 0x0d, 0x81, 0x15, 0xf6,
    0x35, 0xb1, 0x05, 0xee, 0x2e, 0x4e, 0x15, 0xd0, 0x4b, 0x24, 0x54, 0xbf, 0x6f, 0x4f, 0xad, 0xf0, 0x34, 0xb1, 0x04,
    0x03, 0x11, 0x9c, 0xd8, 0xe3, 0xb9, 0x2f, 0xcc, 0x5b,
];

const PRIMALITY_ROUNDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DhError {
    #[error("dh_prime must be exactly 2048 bits")]
    BadPrimeLength,
    #[error("dh_prime is not a safe prime")]
    PrimeNotSafe,
    #[error("generator {0} is not supported")]
    BadGenerator(i32),
    #[error("generator {0} does not generate the required subgroup")]
    GeneratorCondition(i32),
    #[error("g_a or g_b is outside the safe range")]
    ValueOutOfRange,
}

pub trait DhPrimeCache {
    fn is_known_safe(&self, prime: &[u8]) -> Option<bool>;
    fn remember(&mut self, prime: &[u8], safe: bool);
}

pub fn check_dh_params(
    prime: &[u8],
    g: i32,
    cache: Option<&mut dyn DhPrimeCache>,
    rng: &mut impl SecureRandom,
) -> Result<BigUint, DhError> {
    if prime.len() != DH_PRIME_BYTES || prime[0] & 0x80 == 0 {
        return Err(DhError::BadPrimeLength);
    }
    let p = BigUint::from_bytes_be(prime);
    check_generator(&p, g)?;
    if prime == KNOWN_DH_PRIME {
        return Ok(p);
    }
    let cached = cache.as_ref().and_then(|cache| cache.is_known_safe(prime));
    let safe = match cached {
        Some(safe) => safe,
        None => {
            let safe = is_probable_prime(&p, PRIMALITY_ROUNDS, rng)
                && is_probable_prime(&((&p - BigUint::one()) >> 1), PRIMALITY_ROUNDS, rng);
            if let Some(cache) = cache {
                cache.remember(prime, safe);
            }
            safe
        }
    };
    if safe { Ok(p) } else { Err(DhError::PrimeNotSafe) }
}

fn check_generator(p: &BigUint, g: i32) -> Result<(), DhError> {
    let rem = |m: u32| -> u32 {
        let r = p % BigUint::from(m);
        r.iter_u32_digits().next().unwrap_or(0)
    };
    let ok = match g {
        2 => rem(8) == 7,
        3 => rem(3) == 2,
        4 => true,
        5 => matches!(rem(5), 1 | 4),
        6 => matches!(rem(24), 19 | 23),
        7 => matches!(rem(7), 3 | 5 | 6),
        _ => return Err(DhError::BadGenerator(g)),
    };
    if ok { Ok(()) } else { Err(DhError::GeneratorCondition(g)) }
}

pub fn check_g_a_or_b(value: &BigUint, prime: &BigUint) -> Result<(), DhError> {
    let one = BigUint::one();
    if value <= &one || value >= &(prime - &one) {
        return Err(DhError::ValueOutOfRange);
    }
    let bound = one << (2048 - 64);
    if value < &bound || value > &(prime - &bound) {
        return Err(DhError::ValueOutOfRange);
    }
    Ok(())
}

pub fn to_fixed_be<const N: usize>(value: &BigUint) -> Option<[u8; N]> {
    let bytes = value.to_bytes_be();
    if bytes.len() > N {
        return None;
    }
    let mut out = [0u8; N];
    out[N - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MapCache(HashMap<Vec<u8>, bool>, usize);

    impl DhPrimeCache for MapCache {
        fn is_known_safe(&self, prime: &[u8]) -> Option<bool> {
            self.0.get(prime).copied()
        }
        fn remember(&mut self, prime: &[u8], safe: bool) {
            self.1 += 1;
            self.0.insert(prime.to_vec(), safe);
        }
    }

    #[test]
    fn known_prime_with_g3_is_accepted() {
        let mut rng = XorShiftRandom::new(1);
        let p = check_dh_params(&KNOWN_DH_PRIME, 3, None, &mut rng).unwrap();
        assert_eq!(p.to_bytes_be(), KNOWN_DH_PRIME);
    }

    #[test]
    fn known_prime_is_actually_a_safe_prime() {
        let mut rng = XorShiftRandom::new(2);
        let p = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
        assert!(is_probable_prime(&p, 8, &mut rng));
        assert!(is_probable_prime(&((&p - BigUint::one()) >> 1), 8, &mut rng));
    }

    #[test]
    fn generator_conditions_follow_documentation() {
        let p = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
        let accepted: Vec<i32> = (0..10).filter(|&g| check_generator(&p, g).is_ok()).collect();
        let expected: Vec<i32> = (2..=7)
            .filter(|&g| {
                let r = |m: u32| (&p % BigUint::from(m)).iter_u32_digits().next().unwrap_or(0);
                match g {
                    2 => r(8) == 7,
                    3 => r(3) == 2,
                    4 => true,
                    5 => [1, 4].contains(&r(5)),
                    6 => [19, 23].contains(&r(24)),
                    7 => [3, 5, 6].contains(&r(7)),
                    _ => false,
                }
            })
            .collect();
        assert_eq!(accepted, expected);
        assert!(accepted.contains(&3));
        assert_eq!(check_generator(&p, 1), Err(DhError::BadGenerator(1)));
        assert_eq!(check_generator(&p, 8), Err(DhError::BadGenerator(8)));
    }

    #[test]
    fn rejects_wrong_prime_shapes() {
        let mut rng = XorShiftRandom::new(3);
        assert_eq!(check_dh_params(&KNOWN_DH_PRIME[1..], 3, None, &mut rng), Err(DhError::BadPrimeLength));
        let mut small = KNOWN_DH_PRIME;
        small[0] = 0x47;
        assert_eq!(check_dh_params(&small, 3, None, &mut rng), Err(DhError::BadPrimeLength));
    }

    #[test]
    fn unknown_composite_is_rejected_and_cached() {
        let mut rng = XorShiftRandom::new(4);
        let mut composite = KNOWN_DH_PRIME;
        composite[255] = 0xff;
        let mut cache = MapCache::default();
        let p = BigUint::from_bytes_be(&composite);
        let g = (2..=7).find(|&g| check_generator(&p, g).is_ok()).unwrap();
        assert_eq!(check_dh_params(&composite, g, Some(&mut cache), &mut rng), Err(DhError::PrimeNotSafe));
        assert_eq!(cache.1, 1);
        assert_eq!(check_dh_params(&composite, g, Some(&mut cache), &mut rng), Err(DhError::PrimeNotSafe));
        assert_eq!(cache.1, 1);
    }

    #[test]
    fn g_a_range_checks() {
        let p = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
        let one = BigUint::one();
        let bound = &one << (2048 - 64);
        assert!(check_g_a_or_b(&one, &p).is_err());
        assert!(check_g_a_or_b(&(&bound - &one), &p).is_err());
        assert!(check_g_a_or_b(&bound, &p).is_ok());
        assert!(check_g_a_or_b(&(&p - &bound), &p).is_ok());
        assert!(check_g_a_or_b(&(&p - &bound + &one), &p).is_err());
        assert!(check_g_a_or_b(&(&p - &one), &p).is_err());
        assert!(check_g_a_or_b(&p, &p).is_err());
    }

    #[test]
    fn fixed_be_padding() {
        assert_eq!(to_fixed_be::<4>(&BigUint::from(0x0102u32)), Some([0, 0, 1, 2]));
        assert_eq!(to_fixed_be::<1>(&BigUint::from(0x0102u32)), None);
    }
}
