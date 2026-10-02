const FACTOR_STEP_BUDGET: u64 = 1 << 24;

pub fn factorize_pq(pq: u64) -> Option<(u64, u64)> {
    if pq < 4 {
        return None;
    }
    if pq.is_multiple_of(2) {
        return Some((2, pq / 2));
    }
    if is_prime_u64(pq) {
        return None;
    }
    let mut budget = FACTOR_STEP_BUDGET;
    for seed in 1..64u64 {
        if budget == 0 {
            return None;
        }
        if let Some(divisor) = brent(pq, seed, &mut budget) {
            let other = pq / divisor;
            let (p, q) = if divisor < other { (divisor, other) } else { (other, divisor) };
            if p > 1 && p.checked_mul(q) == Some(pq) {
                return Some((p, q));
            }
        }
    }
    None
}

#[inline]
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64, m: u64) -> u64 {
    let mut result = 1u64;
    base %= m;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base, m);
        }
        base = mul_mod(base, base, m);
        exponent >>= 1;
    }
    result
}

pub fn is_prime_u64(n: u64) -> bool {
    const BASES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    if n < 2 {
        return false;
    }
    for base in BASES {
        if n == base {
            return true;
        }
        if n.is_multiple_of(base) {
            return false;
        }
    }
    let shift = (n - 1).trailing_zeros();
    let d = (n - 1) >> shift;
    'witness: for base in BASES {
        let mut x = pow_mod(base, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..shift {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn brent(n: u64, c: u64, budget: &mut u64) -> Option<u64> {
    let step = |x: u64| ((mul_mod(x, x, n) as u128 + c as u128) % n as u128) as u64;
    let mut y = (c.wrapping_mul(0x9e37_79b9) + 2) % n;
    let batch = 128u64;
    let mut g = 1u64;
    let mut r = 1u64;
    let mut q = 1u64;
    let mut x = y;
    let mut ys = y;
    let limit = 1u64 << 26;
    while g == 1 {
        x = y;
        if *budget < r {
            *budget = 0;
            return None;
        }
        *budget -= r;
        for _ in 0..r {
            y = step(y);
        }
        let mut k = 0u64;
        while k < r && g == 1 {
            ys = y;
            let steps = batch.min(r - k);
            if *budget < steps {
                *budget = 0;
                return None;
            }
            *budget -= steps;
            for _ in 0..steps {
                y = step(y);
                q = mul_mod(q, x.abs_diff(y), n);
            }
            g = gcd(q, n);
            k += batch;
        }
        r *= 2;
        if r > limit {
            return None;
        }
    }
    if g == n {
        loop {
            ys = step(ys);
            g = gcd(x.abs_diff(ys), n);
            if g > 1 {
                break;
            }
        }
    }
    if g == n || g == 1 { None } else { Some(g) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_documentation_sample() {
        assert_eq!(factorize_pq(0x17ED48941A08F981), Some((0x494C553B, 0x53911073)));
    }

    #[test]
    fn small_and_degenerate_inputs() {
        assert_eq!(factorize_pq(0), None);
        assert_eq!(factorize_pq(3), None);
        assert_eq!(factorize_pq(15), Some((3, 5)));
        assert_eq!(factorize_pq(4), Some((2, 2)));
        assert_eq!(factorize_pq(10), Some((2, 5)));
    }

    #[test]
    fn products_of_large_32_bit_primes() {
        let primes: [u64; 8] =
            [4294967291, 4294967279, 4294967231, 4294967197, 2147483647, 1000000007, 1000000009, 998244353];
        for (i, &p) in primes.iter().enumerate() {
            for &q in &primes[i + 1..] {
                let (a, b) = if p < q { (p, q) } else { (q, p) };
                assert_eq!(factorize_pq(p * q), Some((a, b)), "{p} * {q}");
            }
        }
    }

    #[test]
    fn primes_and_hostile_values_are_rejected_quickly() {
        let started = std::time::Instant::now();
        for value in [0xFFFF_FFFF_FFFF_FFC5u64, 0x7FFF_FFFF_FFFF_FFE7, 4294967291, 1_000_000_007, u64::MAX] {
            let result = factorize_pq(value);
            if let Some((p, q)) = result {
                assert_eq!(p as u128 * q as u128, value as u128);
            }
        }
        assert_eq!(factorize_pq(0xFFFF_FFFF_FFFF_FFC5), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn deterministic_primality_matches_trial_division() {
        let trial = |n: u64| n >= 2 && (2..).take_while(|d| d * d <= n).all(|d| !n.is_multiple_of(d));
        for n in 0..20_000u64 {
            assert_eq!(is_prime_u64(n), trial(n), "{n}");
        }
        assert!(is_prime_u64(0xFFFF_FFFF_FFFF_FFC5));
        assert!(!is_prime_u64(4294967291 * 4294967279));
        assert!(!is_prime_u64(3_215_031_751));
    }

    #[test]
    fn square_of_prime() {
        assert_eq!(factorize_pq(4294967291 * 4294967291), Some((4294967291, 4294967291)));
    }
}
