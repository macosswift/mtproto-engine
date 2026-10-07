use mtproto_core::crypto::{KNOWN_DH_PRIME, SecureRandom, XorShiftRandom, secret_modpow, to_fixed_be};
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn fixed(value: &BigUint) -> [u8; 256] {
    to_fixed_be::<256>(value).expect("2048 bits")
}

fn check(base: &BigUint, exponent: &BigUint, modulus: &BigUint) {
    let expected = base.modpow(exponent, modulus);
    let got = secret_modpow(&fixed(base), &fixed(exponent), &fixed(modulus));
    assert_eq!(got, Some(fixed(&expected)), "base {base:x}\nexponent {exponent:x}\nmodulus {modulus:x}");
}

fn random_modulus(rng: &mut XorShiftRandom) -> BigUint {
    let mut bytes = [0u8; 256];
    rng.fill(&mut bytes);
    bytes[0] |= 0x80;
    bytes[255] |= 1;
    BigUint::from_bytes_be(&bytes)
}

fn random_below(rng: &mut XorShiftRandom, modulus: &BigUint) -> BigUint {
    let mut bytes = [0u8; 256];
    rng.fill(&mut bytes);
    BigUint::from_bytes_be(&bytes) % modulus
}

fn cases() -> usize {
    std::env::var("MODPOW_CASES").ok().and_then(|value| value.parse().ok()).unwrap_or(3000)
}

#[test]
fn random_inputs_agree_with_num_bigint() {
    let mut rng = XorShiftRandom::new(0x5eed_2026_1007);
    let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
    for case in 0..cases() {
        let modulus = if case % 4 == 0 { prime.clone() } else { random_modulus(&mut rng) };
        let base = random_below(&mut rng, &modulus);
        let mut exponent = [0u8; 256];
        rng.fill(&mut exponent);
        match case % 5 {
            0 => exponent[..128].fill(0),
            1 => exponent[0] |= 0x80,
            _ => {}
        }
        check(&base, &BigUint::from_bytes_be(&exponent), &modulus);
    }
}

#[test]
fn edge_inputs_agree_with_num_bigint() {
    let mut rng = XorShiftRandom::new(99);
    let smallest = (BigUint::one() << 2047usize) + BigUint::one();
    let largest = (BigUint::one() << 2048usize) - BigUint::one();
    let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
    let mut moduli = vec![smallest, largest, prime];
    for _ in 0..4 {
        moduli.push(random_modulus(&mut rng));
    }
    for modulus in &moduli {
        let one = BigUint::one();
        let bases = [
            BigUint::zero(),
            one.clone(),
            BigUint::from(2u32),
            BigUint::from(7u32),
            modulus - &one,
            modulus - BigUint::from(2u32),
            (BigUint::one() << 2047usize) % modulus,
            ((BigUint::one() << 2048usize) - BigUint::one()) % modulus,
            random_below(&mut rng, modulus),
        ];
        let exponents = [
            BigUint::zero(),
            one.clone(),
            BigUint::from(2u32),
            BigUint::from(15u32),
            BigUint::from(16u32),
            BigUint::from(0xffff_ffffu32),
            BigUint::one() << 2047usize,
            (BigUint::one() << 2048usize) - BigUint::one(),
            modulus - &one,
            modulus.clone(),
            random_below(&mut rng, modulus),
        ];
        for base in &bases {
            for exponent in &exponents {
                check(base, exponent, modulus);
            }
        }
    }
}

#[test]
fn refuses_what_it_cannot_compute() {
    let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
    let two = fixed(&BigUint::from(2u32));
    let exponent = [0x5au8; 256];
    let mut even = KNOWN_DH_PRIME;
    even[255] &= !1;
    assert_eq!(secret_modpow(&two, &exponent, &even), None, "even modulus");
    let mut short = KNOWN_DH_PRIME;
    short[0] = 0x7f;
    assert_eq!(secret_modpow(&two, &exponent, &short), None, "2047-bit modulus");
    assert_eq!(secret_modpow(&two, &exponent, &[0u8; 256]), None, "zero modulus");
    assert_eq!(secret_modpow(&KNOWN_DH_PRIME, &exponent, &KNOWN_DH_PRIME), None, "base == modulus");
    let above = fixed(&(&prime + BigUint::one()));
    assert_eq!(secret_modpow(&above, &exponent, &KNOWN_DH_PRIME), None, "base > modulus");
    assert_eq!(secret_modpow(&[0xff; 256], &exponent, &KNOWN_DH_PRIME), None, "base 2^2048-1");
}

#[test]
#[ignore = "timing probe, run with --release --ignored --nocapture"]
fn timing_does_not_depend_on_the_exponent() {
    let prime = KNOWN_DH_PRIME;
    let base = fixed(&BigUint::from(3u32));
    let mut rng = XorShiftRandom::new(5);
    let mut random = [0u8; 256];
    rng.fill(&mut random);
    let exponents: [(&str, [u8; 256]); 4] = [
        ("zeros", [0u8; 256]),
        ("ones", [0xffu8; 256]),
        ("random", random),
        ("top bit", {
            let mut e = [0u8; 256];
            e[0] = 0x80;
            e
        }),
    ];
    for _ in 0..3 {
        for (name, exponent) in &exponents {
            let mut samples = Vec::new();
            for _ in 0..40 {
                let start = std::time::Instant::now();
                std::hint::black_box(secret_modpow(std::hint::black_box(&base), exponent, &prime));
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            samples.sort_by(f64::total_cmp);
            println!("{name:8} median {:.3} ms  min {:.3} ms", samples[20], samples[0]);
        }
    }
    let generator = BigUint::from(3u32);
    let exponent = BigUint::from_bytes_be(&random);
    let modulus = BigUint::from_bytes_be(&prime);
    let mut samples = Vec::new();
    for _ in 0..40 {
        let start = std::time::Instant::now();
        std::hint::black_box(generator.modpow(&exponent, &modulus));
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    println!("num-bigint median {:.3} ms", samples[20]);
}
