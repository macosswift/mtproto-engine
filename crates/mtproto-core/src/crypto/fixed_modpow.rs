use zeroize::Zeroize;

const LIMBS: usize = 32;
const WINDOW: usize = 4;

type Limbs = [u64; LIMBS];

fn from_be(bytes: &[u8; 256]) -> Limbs {
    core::array::from_fn(|index| {
        let end = 256 - 8 * index;
        u64::from_be_bytes(bytes[end - 8..end].try_into().expect("8 bytes"))
    })
}

fn to_be(limbs: &Limbs) -> [u8; 256] {
    let mut out = [0u8; 256];
    for (index, limb) in limbs.iter().enumerate() {
        let end = 256 - 8 * index;
        out[end - 8..end].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// `value - modulus` when `extra` is set or `value >= modulus`, without branching on the value.
fn reduce_once(value: &mut Limbs, extra: u64, modulus: &Limbs) {
    let mut difference = [0u64; LIMBS];
    let mut borrow = 0u64;
    for index in 0..LIMBS {
        let (step, first) = value[index].overflowing_sub(modulus[index]);
        let (step, second) = step.overflowing_sub(borrow);
        difference[index] = step;
        borrow = u64::from(first | second);
    }
    let keep_difference = core::hint::black_box((u64::from(extra != 0) | (borrow ^ 1)).wrapping_neg());
    for index in 0..LIMBS {
        value[index] = (difference[index] & keep_difference) | (value[index] & !keep_difference);
    }
    difference.zeroize();
}

fn montgomery_multiply(a: &Limbs, b: &Limbs, modulus: &Limbs, inverse: u64) -> Limbs {
    let mut t = [0u64; LIMBS + 2];
    for &digit in b.iter() {
        let mut carry = 0u128;
        for index in 0..LIMBS {
            let sum = u128::from(t[index]) + u128::from(a[index]) * u128::from(digit) + carry;
            t[index] = sum as u64;
            carry = sum >> 64;
        }
        let sum = u128::from(t[LIMBS]) + carry;
        t[LIMBS] = sum as u64;
        t[LIMBS + 1] = (sum >> 64) as u64;
        let factor = t[0].wrapping_mul(inverse);
        let mut carry = (u128::from(t[0]) + u128::from(factor) * u128::from(modulus[0])) >> 64;
        for index in 1..LIMBS {
            let sum = u128::from(t[index]) + u128::from(factor) * u128::from(modulus[index]) + carry;
            t[index - 1] = sum as u64;
            carry = sum >> 64;
        }
        let sum = u128::from(t[LIMBS]) + carry;
        t[LIMBS - 1] = sum as u64;
        t[LIMBS] = t[LIMBS + 1] + (sum >> 64) as u64;
        t[LIMBS + 1] = 0;
    }
    let mut result: Limbs = t[..LIMBS].try_into().expect("limbs");
    reduce_once(&mut result, t[LIMBS], modulus);
    t.zeroize();
    result
}

fn select(table: &[Limbs; 1 << WINDOW], wanted: usize) -> Limbs {
    let mut out = [0u64; LIMBS];
    for (index, entry) in table.iter().enumerate() {
        let difference = (index ^ wanted) as u64;
        let mask = core::hint::black_box(((difference | difference.wrapping_neg()) >> 63).wrapping_sub(1));
        for limb in 0..LIMBS {
            out[limb] |= entry[limb] & mask;
        }
    }
    out
}

/// `base^exponent mod modulus` for a 2048-bit odd modulus with fixed-size, wiped temporaries and a
/// fixed sequence of multiplications. None for an even modulus or a base not below it.
pub fn secret_modpow(base: &[u8; 256], exponent: &[u8; 256], modulus: &[u8; 256]) -> Option<[u8; 256]> {
    let modulus = from_be(modulus);
    if modulus[0] & 1 == 0 || modulus[LIMBS - 1] >> 63 == 0 {
        return None;
    }
    let mut base = from_be(base);
    let mut check = base;
    reduce_once(&mut check, 0, &modulus);
    if check != base {
        base.zeroize();
        return None;
    }
    let mut inverse = 1u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(modulus[0].wrapping_mul(inverse)));
    }
    let inverse = inverse.wrapping_neg();
    let mut doubled = [0u64; LIMBS];
    doubled[0] = 1;
    let mut one_montgomery = [0u64; LIMBS];
    for step in 0..2 * 64 * LIMBS {
        let carry = doubled[LIMBS - 1] >> 63;
        for index in (1..LIMBS).rev() {
            doubled[index] = (doubled[index] << 1) | (doubled[index - 1] >> 63);
        }
        doubled[0] <<= 1;
        reduce_once(&mut doubled, carry, &modulus);
        if step + 1 == 64 * LIMBS {
            one_montgomery = doubled;
        }
    }
    let r_squared = doubled;
    let mut table = [[0u64; LIMBS]; 1 << WINDOW];
    table[0] = one_montgomery;
    table[1] = montgomery_multiply(&base, &r_squared, &modulus, inverse);
    for index in 2..table.len() {
        table[index] = montgomery_multiply(&table[index - 1], &table[1], &modulus, inverse);
    }
    let mut accumulator = one_montgomery;
    for byte in exponent.iter() {
        for nibble in [byte >> 4, byte & 0x0f] {
            for _ in 0..WINDOW {
                accumulator = montgomery_multiply(&accumulator, &accumulator, &modulus, inverse);
            }
            let mut factor = select(&table, usize::from(nibble));
            accumulator = montgomery_multiply(&accumulator, &factor, &modulus, inverse);
            factor.zeroize();
        }
    }
    let mut one = [0u64; LIMBS];
    one[0] = 1;
    let mut result = montgomery_multiply(&accumulator, &one, &modulus, inverse);
    let out = to_be(&result);
    result.zeroize();
    accumulator.zeroize();
    table.zeroize();
    base.zeroize();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KNOWN_DH_PRIME, SecureRandom, XorShiftRandom};
    use num_bigint::BigUint;

    fn fixed(value: &BigUint) -> [u8; 256] {
        crate::crypto::to_fixed_be::<256>(value).expect("2048 bits")
    }

    #[test]
    fn agrees_with_num_bigint() {
        let mut rng = XorShiftRandom::new(7);
        let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
        let mut moduli = vec![prime.clone()];
        for _ in 0..3 {
            let mut bytes = [0u8; 256];
            rng.fill(&mut bytes);
            bytes[0] |= 0x80;
            bytes[255] |= 1;
            moduli.push(BigUint::from_bytes_be(&bytes));
        }
        for modulus in &moduli {
            for _ in 0..4 {
                let mut base = [0u8; 256];
                rng.fill(&mut base);
                let base = BigUint::from_bytes_be(&base) % modulus;
                let mut exponent = [0u8; 256];
                rng.fill(&mut exponent);
                let expected = base.modpow(&BigUint::from_bytes_be(&exponent), modulus);
                assert_eq!(secret_modpow(&fixed(&base), &exponent, &fixed(modulus)), Some(fixed(&expected)));
            }
            for small in [0u32, 1, 2, 3, 7] {
                let exponent = fixed(&BigUint::from(small));
                let base = fixed(&BigUint::from(3u32));
                let expected = BigUint::from(3u32).modpow(&BigUint::from(small), modulus);
                assert_eq!(secret_modpow(&base, &exponent, &fixed(modulus)), Some(fixed(&expected)));
            }
        }
        let mut even = KNOWN_DH_PRIME;
        even[255] &= !1;
        assert_eq!(secret_modpow(&fixed(&BigUint::from(2u32)), &[1u8; 256], &even), None);
        assert_eq!(secret_modpow(&KNOWN_DH_PRIME, &[1u8; 256], &KNOWN_DH_PRIME), None);
    }
}
