use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};

use super::rng::SecureRandom;

const SMALL_PRIMES: [u32; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
    113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239,
    241, 251,
];

pub fn is_probable_prime(n: &BigUint, rounds: usize, rng: &mut impl SecureRandom) -> bool {
    let two = BigUint::from(2u32);
    if n < &two {
        return false;
    }
    for &small in SMALL_PRIMES.iter() {
        let small = BigUint::from(small);
        if n == &small {
            return true;
        }
        if (n % &small).is_zero() {
            return false;
        }
    }

    let one = BigUint::one();
    let n_minus_one = n - &one;
    let mut d = n_minus_one.clone();
    let mut s = 0u32;
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    let byte_len = n.bits().div_ceil(8) as usize + 8;
    let range = n - BigUint::from(3u32);
    let mut buffer = vec![0u8; byte_len];
    'witness: for _ in 0..rounds {
        rng.fill(&mut buffer);
        let a = BigUint::from_bytes_be(&buffer) % &range + &two;
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_one {
            continue;
        }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue 'witness;
            }
            if x == one {
                return false;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;

    #[test]
    fn small_numbers() {
        let mut rng = XorShiftRandom::new(1);
        let primes: Vec<u32> = (0..300u32).filter(|&n| is_probable_prime(&BigUint::from(n), 16, &mut rng)).collect();
        let expected: Vec<u32> =
            (0..300u32).filter(|&n| n >= 2 && (2..n).take_while(|d| d * d <= n).all(|d| n % d != 0)).collect();
        assert_eq!(primes, expected);
    }

    #[test]
    fn carmichael_numbers_are_composite() {
        let mut rng = XorShiftRandom::new(2);
        for n in [561u64, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185] {
            assert!(!is_probable_prime(&BigUint::from(n), 32, &mut rng), "{n}");
        }
    }

    #[test]
    fn large_known_values() {
        let mut rng = XorShiftRandom::new(3);
        let mersenne_127 = (BigUint::one() << 127) - BigUint::one();
        assert!(is_probable_prime(&mersenne_127, 32, &mut rng));
        let composite = &mersenne_127 * BigUint::from(1_000_003u64);
        assert!(!is_probable_prime(&composite, 32, &mut rng));
    }
}
