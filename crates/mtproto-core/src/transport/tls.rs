use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::One;
use sha2::Sha256;

use super::buffer::InputBuffer;
use super::proxy_secret::MAX_DOMAIN_LENGTH;
use crate::crypto::SecureRandom;

pub const MAX_TLS_PACKET_LENGTH: usize = 2878;
pub const MIN_CLIENT_HELLO_LEN: usize = 513;
const GREASE_SIZE: usize = 8;
const ML_KEM_POLYNOMIAL_LEN: usize = 1152;
const ML_KEM_PUBLIC_KEY_LEN: usize = ML_KEM_POLYNOMIAL_LEN + 32;
const ML_KEM_Q: u32 = 3329;
const CHANGE_CIPHER_SPEC: &[u8] = b"\x14\x03\x03\x00\x01\x01";
const APPLICATION_DATA: &[u8] = b"\x17\x03\x03";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsHelloError {
    #[error("first part of response to hello is invalid")]
    InvalidPrefix,
    #[error("response hash mismatch")]
    HashMismatch,
    #[error("hello template overflow")]
    Template,
}

enum Op {
    Str(&'static [u8]),
    Random(usize),
    Zero(usize),
    Domain,
    Grease(usize),
    Key,
    MlKemKey,
    BeginScope,
    EndScope,
    Choice(&'static [&'static [Op]]),
}

const CIPHERS_SHORT: &[Op] = &[
    Op::Str(b"\x00\x1c"),
    Op::Grease(0),
    Op::Str(
        b"\x13\x02\x13\x01\x13\x03\xc0\x2c\xc0\x30\xc0\x2b\xcc\xa9\xc0\x2f\xcc\xa8\xc0\x0a\xc0\x09\xc0\x14\xc0\x13",
    ),
];

const CIPHERS_LONG: &[Op] = &[
    Op::Str(b"\x00\x2a"),
    Op::Grease(0),
    Op::Str(
        b"\x13\x02\x13\x03\x13\x01\xc0\x2c\xc0\x2b\xcc\xa9\xc0\x30\xc0\x2f\xcc\xa8\xc0\x0a\xc0\x09\xc0\x14\xc0\x13\x00\x9d\x00\x9c\x00\x35\x00\x2f\xc0\x08\xc0\x12\x00\x0a",
    ),
];

const ALPN_HTTP1: &[Op] = &[Op::Str(b"\x00\x10\x00\x0b\x00\x09\x08\x68\x74\x74\x70\x2f\x31\x2e\x31")];

const ALPN_H2_HTTP1: &[Op] = &[Op::Str(b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31")];

const SAFARI_HELLO: &[Op] = &[
    Op::Str(b"\x16\x03\x01"),
    Op::BeginScope,
    Op::Str(b"\x01\x00"),
    Op::BeginScope,
    Op::Str(b"\x03\x03"),
    Op::Zero(32),
    Op::Str(b"\x20"),
    Op::Random(32),
    Op::Choice(&[CIPHERS_SHORT, CIPHERS_LONG]),
    Op::Str(b"\x01\x00"),
    Op::BeginScope,
    Op::Grease(2),
    Op::Str(b"\x00\x00\x00\x00"),
    Op::BeginScope,
    Op::BeginScope,
    Op::Str(b"\x00"),
    Op::BeginScope,
    Op::Domain,
    Op::EndScope,
    Op::EndScope,
    Op::EndScope,
    Op::Str(b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c"),
    Op::Grease(4),
    Op::Str(b"\x11\xec\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00"),
    Op::Choice(&[ALPN_HTTP1, ALPN_H2_HTTP1]),
    Op::Str(
        b"\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x16\x00\x14\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x00\x12\x00\x00\x00\x33\x04\xef\x04\xed",
    ),
    Op::Grease(4),
    Op::Str(b"\x00\x01\x00\x11\xec\x04\xc0"),
    Op::MlKemKey,
    Op::Key,
    Op::Str(b"\x00\x1d\x00\x20"),
    Op::Key,
    Op::Str(b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x07\x06"),
    Op::Grease(6),
    Op::Str(b"\x03\x04\x03\x03\x00\x1b\x00\x03\x02\x00\x01"),
    Op::Grease(3),
    Op::Str(b"\x00\x01\x00"),
    Op::EndScope,
    Op::EndScope,
    Op::EndScope,
];

fn grease(rng: &mut impl SecureRandom) -> [u8; GREASE_SIZE] {
    let mut values = [0u8; GREASE_SIZE];
    rng.fill(&mut values);
    for value in values.iter_mut() {
        *value = (*value & 0xf0) | 0x0a;
    }
    for i in (0..GREASE_SIZE).step_by(2) {
        if values[i] == values[i + 1] {
            values[i + 1] ^= 0x10;
        }
    }
    values
}

fn curve_modulus() -> BigUint {
    (BigUint::one() << 255u32) - BigUint::from(19u32)
}

fn y2(x: &BigUint, p: &BigUint) -> BigUint {
    let coef = BigUint::from(486662u32);
    let mut y = (x + coef) % p;
    y = (y * x) % p;
    y = (y + BigUint::one()) % p;
    (y * x) % p
}

fn double_x(x: &BigUint, p: &BigUint) -> BigUint {
    let denominator = (y2(x, p) * BigUint::from(4u32)) % p;
    let x_squared = (x * x) % p;
    let numerator = (x_squared + p - BigUint::one()) % p;
    let numerator = (&numerator * &numerator) % p;
    let inverse = denominator.modpow(&(p - BigUint::from(2u32)), p);
    (numerator * inverse) % p
}

fn is_quadratic_residue(value: &BigUint, p: &BigUint) -> bool {
    let exponent = (p - BigUint::one()) >> 1;
    value.modpow(&exponent, p).is_one()
}

fn fake_x25519_key(rng: &mut impl SecureRandom) -> [u8; 32] {
    let p = curve_modulus();
    loop {
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        key[31] &= 127;
        let x = BigUint::from_bytes_be(&key);
        let mut x = (&x * &x) % &p;
        if !is_quadratic_residue(&y2(&x, &p), &p) {
            continue;
        }
        for _ in 0..3 {
            x = double_x(&x, &p);
        }
        let le = x.to_bytes_le();
        let mut out = [0u8; 32];
        out[..le.len()].copy_from_slice(&le);
        return out;
    }
}

fn fake_ml_kem_key(rng: &mut impl SecureRandom, out: &mut Vec<u8>) {
    let mut entropy = [0u8; ML_KEM_POLYNOMIAL_LEN / 3 * 8];
    rng.fill(&mut entropy);
    for chunk in entropy.chunks_exact(8) {
        let a = u32::from_le_bytes(chunk[..4].try_into().expect("4")) % ML_KEM_Q;
        let b = u32::from_le_bytes(chunk[4..].try_into().expect("4")) % ML_KEM_Q;
        out.extend_from_slice(&[a as u8, ((a >> 8) | ((b & 0x0f) << 4)) as u8, (b >> 4) as u8]);
    }
    let start = out.len();
    out.resize(start + ML_KEM_PUBLIC_KEY_LEN - ML_KEM_POLYNOMIAL_LEN, 0);
    rng.fill(&mut out[start..]);
}

struct HelloBuilder<'a, R: SecureRandom> {
    data: Vec<u8>,
    scopes: Vec<usize>,
    greases: [u8; GREASE_SIZE],
    domain: &'a [u8],
    rng: &'a mut R,
}

impl<R: SecureRandom> HelloBuilder<'_, R> {
    fn execute(&mut self, ops: &[Op]) {
        for op in ops {
            match op {
                Op::Str(bytes) => self.data.extend_from_slice(bytes),
                Op::Random(length) => {
                    let start = self.data.len();
                    self.data.resize(start + length, 0);
                    self.rng.fill(&mut self.data[start..]);
                }
                Op::Zero(length) => self.data.resize(self.data.len() + length, 0),
                Op::Domain => self.data.extend_from_slice(self.domain),
                Op::Grease(index) => self.data.extend_from_slice(&[self.greases[*index], self.greases[*index]]),
                Op::Key => {
                    let key = fake_x25519_key(self.rng);
                    self.data.extend_from_slice(&key);
                }
                Op::MlKemKey => fake_ml_kem_key(self.rng, &mut self.data),
                Op::BeginScope => {
                    self.scopes.push(self.data.len());
                    self.data.extend_from_slice(&[0, 0]);
                }
                Op::EndScope => close_scope(&mut self.data, &mut self.scopes),
                Op::Choice(alternatives) => {
                    let index = (self.rng.next_u64() % alternatives.len() as u64) as usize;
                    let depth = self.scopes.len();
                    self.execute(alternatives[index]);
                    debug_assert_eq!(self.scopes.len(), depth);
                }
            }
        }
    }
}

pub fn client_hello(domain: &[u8], secret: &[u8; 16], unix_time: i32, rng: &mut impl SecureRandom) -> Vec<u8> {
    let domain = &domain[..domain.len().min(MAX_DOMAIN_LENGTH)];
    let greases = grease(rng);
    let mut builder =
        HelloBuilder { data: Vec::with_capacity(1600 + domain.len()), scopes: Vec::new(), greases, domain, rng };
    builder.execute(SAFARI_HELLO);
    debug_assert!(builder.scopes.is_empty());
    let mut data = builder.data;
    debug_assert!(data.len() >= MIN_CLIENT_HELLO_LEN);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(&data);
    let mut hash: [u8; 32] = mac.finalize().into_bytes().into();
    let tail = i32::from_le_bytes(hash[28..32].try_into().expect("4")) ^ unix_time;
    hash[28..32].copy_from_slice(&tail.to_le_bytes());
    data[11..43].copy_from_slice(&hash);
    data
}

fn close_scope(data: &mut [u8], scopes: &mut Vec<usize>) {
    let begin = scopes.pop().expect("balanced scopes");
    let size = data.len() - begin - 2;
    assert!(size < (1 << 14), "scope too large");
    data[begin] = (size >> 8) as u8;
    data[begin + 1] = size as u8;
}

pub fn verify_server_hello(
    buffer: &mut InputBuffer,
    client_random: &[u8; 32],
    secret: &[u8; 16],
) -> Result<bool, TlsHelloError> {
    let data = buffer.as_slice();
    let mut position = 0usize;
    for prefix in [&b"\x16\x03\x03"[..], &b"\x14\x03\x03\x00\x01\x01\x17\x03\x03"[..]] {
        if data.len() < position + prefix.len() + 2 {
            return Ok(false);
        }
        if &data[position..position + prefix.len()] != prefix {
            return Err(TlsHelloError::InvalidPrefix);
        }
        position += prefix.len();
        let skip = ((data[position] as usize) << 8) | data[position + 1] as usize;
        position += 2;
        if data.len() < position + skip {
            return Ok(false);
        }
        position += skip;
    }
    if position < 43 {
        return Err(TlsHelloError::InvalidPrefix);
    }
    let mut response = data[..position].to_vec();
    let received: [u8; 32] = response[11..43].try_into().expect("32");
    response[11..43].fill(0);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(client_random);
    mac.update(&response);
    mac.verify_slice(&received).map_err(|_| TlsHelloError::HashMismatch)?;
    buffer.consume(position);
    Ok(true)
}

#[derive(Debug, Default)]
pub struct TlsRecordWriter {
    sent_first: bool,
}

impl TlsRecordWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        if !self.sent_first {
            self.sent_first = true;
            out.extend_from_slice(CHANGE_CIPHER_SPEC);
        }
        for chunk in payload.chunks(MAX_TLS_PACKET_LENGTH) {
            out.extend_from_slice(APPLICATION_DATA);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
    }
}

#[derive(Debug, Default)]
pub struct TlsRecordReader;

impl TlsRecordReader {
    pub fn new() -> Self {
        Self
    }

    pub fn read(&mut self, input: &mut InputBuffer, output: &mut Vec<u8>) -> Result<bool, super::TransportError> {
        let data = input.as_slice();
        if data.len() < 5 {
            return Ok(false);
        }
        if &data[..3] != APPLICATION_DATA {
            return Err(super::TransportError::InvalidTlsRecord);
        }
        let length = ((data[3] as usize) << 8) | data[4] as usize;
        if data.len() < 5 + length {
            return Ok(false);
        }
        output.extend_from_slice(&data[5..5 + length]);
        input.consume(5 + length);
        Ok(true)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn server_hello_for_tests(client_hello: &[u8], secret: &[u8; 16], rng: &mut impl SecureRandom) -> Vec<u8> {
    let mut body = vec![0u8; 80];
    rng.fill(&mut body);
    let mut response = Vec::new();
    response.extend_from_slice(b"\x16\x03\x03");
    response.extend_from_slice(&(body.len() as u16).to_be_bytes());
    response.extend_from_slice(&body);
    response[11..43].fill(0);
    response.extend_from_slice(b"\x14\x03\x03\x00\x01\x01\x17\x03\x03");
    let app = vec![0x55u8; 40];
    response.extend_from_slice(&(app.len() as u16).to_be_bytes());
    response.extend_from_slice(&app);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(&client_hello[11..43]);
    mac.update(&response);
    let hash = mac.finalize().into_bytes();
    response[11..43].copy_from_slice(&hash);
    response
}

#[cfg(any(test, feature = "test-support"))]
pub fn verify_client_hello_for_tests(hello: &[u8], secret: &[u8; 16]) -> Option<i32> {
    if hello.len() < 43 || hello.len() > 16 * 1024 {
        return None;
    }
    let mut zeroed = hello.to_vec();
    zeroed[11..43].fill(0);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
    mac.update(&zeroed);
    let expected = mac.finalize().into_bytes();
    if hello[11..39] != expected[..28] {
        return None;
    }
    let received = i32::from_le_bytes(hello[39..43].try_into().expect("4"));
    let computed = i32::from_le_bytes(expected[28..32].try_into().expect("4"));
    Some(received ^ computed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;

    struct ParsedHello {
        ciphers: Vec<u16>,
        extensions: Vec<(u16, Vec<u8>)>,
    }

    fn read_u16(data: &[u8], at: &mut usize) -> u16 {
        let value = u16::from_be_bytes([data[*at], data[*at + 1]]);
        *at += 2;
        value
    }

    fn read_block<'a>(data: &'a [u8], at: &mut usize) -> &'a [u8] {
        let length = read_u16(data, at) as usize;
        let block = &data[*at..*at + length];
        *at += length;
        block
    }

    fn parse_hello(hello: &[u8]) -> ParsedHello {
        assert_eq!(&hello[..3], b"\x16\x03\x01");
        let mut at = 3;
        let record = read_block(hello, &mut at);
        assert_eq!(at, hello.len(), "record length covers the whole hello");
        assert_eq!(&record[..2], b"\x01\x00");
        let mut at = 2;
        let handshake = read_block(record, &mut at);
        assert_eq!(at, record.len(), "handshake length covers the whole record");
        assert_eq!(&handshake[..2], b"\x03\x03");
        assert_eq!(handshake[34], 0x20);
        let mut at = 35 + 32;
        let ciphers = read_block(handshake, &mut at).chunks(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        assert_eq!(&handshake[at..at + 2], b"\x01\x00");
        at += 2;
        let extension_block = read_block(handshake, &mut at);
        assert_eq!(at, handshake.len());
        let mut extensions = Vec::new();
        let mut at = 0;
        while at < extension_block.len() {
            let kind = read_u16(extension_block, &mut at);
            extensions.push((kind, read_block(extension_block, &mut at).to_vec()));
        }
        assert_eq!(at, extension_block.len());
        ParsedHello { ciphers, extensions }
    }

    fn is_grease(value: u16) -> bool {
        let [high, low] = value.to_be_bytes();
        high == low && low & 0x0f == 0x0a
    }

    #[test]
    fn hello_is_well_formed_and_chrome_shaped() {
        for seed in 0..64 {
            let mut rng = XorShiftRandom::new(seed);
            let hello = client_hello(b"www.google.com", &[3u8; 16], 1_700_000_000, &mut rng);
            assert!(hello.len() >= MIN_CLIENT_HELLO_LEN);
            let parsed = parse_hello(&hello);
            assert!(parsed.ciphers.len() == 14 || parsed.ciphers.len() == 21);
            assert!(is_grease(parsed.ciphers[0]));
            assert_eq!(parsed.ciphers[1], 0x1302);

            let kinds: Vec<u16> = parsed.extensions.iter().map(|(kind, _)| *kind).collect();
            assert!(is_grease(kinds[0]) && is_grease(*kinds.last().unwrap()));
            assert_ne!(kinds[0], *kinds.last().unwrap());
            assert_eq!(
                &kinds[1..kinds.len() - 1],
                &[
                    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b,
                    0x001b
                ]
            );
            let extension = |kind: u16| &parsed.extensions.iter().find(|(k, _)| *k == kind).unwrap().1;

            let sni = extension(0x0000);
            assert_eq!(&sni[..5], &[0, 17, 0, 0, 14]);
            assert_eq!(&sni[5..], b"www.google.com");

            let groups = extension(0x000a);
            assert_eq!(groups[..2], [0, 12]);
            assert!(is_grease(u16::from_be_bytes([groups[2], groups[3]])));
            assert_eq!(&groups[4..], b"\x11\xec\x00\x1d\x00\x17\x00\x18\x00\x19");

            let alpn = extension(0x0010);
            assert!(alpn == b"\x00\x09\x08http/1.1" || alpn == b"\x00\x0c\x02h2\x08http/1.1");

            let shares = extension(0x0033);
            let mut at = 0;
            let list = read_block(shares, &mut at);
            assert_eq!(at, shares.len());
            let mut at = 0;
            let mut found = Vec::new();
            while at < list.len() {
                let group = read_u16(list, &mut at);
                found.push((group, read_block(list, &mut at).to_vec()));
            }
            assert_eq!(found.len(), 3);
            assert!(is_grease(found[0].0));
            assert_eq!(found[0].1, [0]);
            assert_eq!(found[0].0, u16::from_be_bytes([groups[2], groups[3]]));
            assert_eq!(found[1].0, 0x11ec);
            assert_eq!(found[1].1.len(), ML_KEM_PUBLIC_KEY_LEN + 32);
            for triple in found[1].1[..ML_KEM_POLYNOMIAL_LEN].chunks(3) {
                let a = u32::from(triple[0]) | (u32::from(triple[1] & 0x0f) << 8);
                let b = u32::from(triple[1] >> 4) | (u32::from(triple[2]) << 4);
                assert!(a < ML_KEM_Q && b < ML_KEM_Q);
            }
            assert_eq!(found[2].0, 0x001d);
            assert_eq!(found[2].1.len(), 32);
            assert_ne!(found[1].1[ML_KEM_PUBLIC_KEY_LEN..], found[2].1[..]);

            let versions = extension(0x002b);
            assert_eq!(versions.len(), 7);
            assert!(is_grease(u16::from_be_bytes([versions[1], versions[2]])));
            assert_eq!(&versions[3..], b"\x03\x04\x03\x03");
            assert_eq!(extension(*kinds.last().unwrap()), &[0]);
        }
    }

    #[test]
    fn hello_choices_cover_every_alternative() {
        let mut cipher_lengths = std::collections::HashSet::new();
        let mut alpn_lengths = std::collections::HashSet::new();
        for seed in 0..64 {
            let mut rng = XorShiftRandom::new(1000 + seed);
            let parsed = parse_hello(&client_hello(b"a.b", &[1u8; 16], 0, &mut rng));
            cipher_lengths.insert(parsed.ciphers.len());
            alpn_lengths.insert(parsed.extensions.iter().find(|(k, _)| *k == 0x0010).unwrap().1.len());
        }
        assert_eq!(cipher_lengths.len(), 2);
        assert_eq!(alpn_lengths.len(), 2);
    }

    #[test]
    fn hello_hmac_encodes_time() {
        let mut rng = XorShiftRandom::new(2);
        let secret = [9u8; 16];
        let hello = client_hello(b"example.org", &secret, 1_234_567, &mut rng);
        assert_eq!(verify_client_hello_for_tests(&hello, &secret), Some(1_234_567));
        assert_eq!(verify_client_hello_for_tests(&hello, &[8u8; 16]), None);
        let mut tampered = hello.clone();
        tampered[200] ^= 1;
        assert_eq!(verify_client_hello_for_tests(&tampered, &secret), None);
    }

    #[test]
    fn long_and_empty_domains_stay_well_formed() {
        let mut rng = XorShiftRandom::new(3);
        let domain = vec![b'a'; 400];
        let parsed = parse_hello(&client_hello(&domain, &[1u8; 16], 0, &mut rng));
        let sni = &parsed.extensions.iter().find(|(k, _)| *k == 0).unwrap().1;
        assert_eq!(sni.len(), 5 + MAX_DOMAIN_LENGTH);
        let hello = client_hello(b"", &[1u8; 16], 0, &mut rng);
        assert!(hello.len() >= MIN_CLIENT_HELLO_LEN);
        parse_hello(&hello);
    }

    #[test]
    fn grease_pairs_differ() {
        let mut rng = XorShiftRandom::new(4);
        for _ in 0..1000 {
            let g = grease(&mut rng);
            for value in g {
                assert_eq!(value & 0x0f, 0x0a);
            }
            for i in (0..GREASE_SIZE).step_by(2) {
                assert_ne!(g[i], g[i + 1]);
            }
        }
    }

    #[test]
    fn fake_key_is_on_curve() {
        let mut rng = XorShiftRandom::new(5);
        let p = curve_modulus();
        for _ in 0..5 {
            let key = fake_x25519_key(&mut rng);
            let x = BigUint::from_bytes_le(&key);
            assert!(x < p);
            assert!(is_quadratic_residue(&y2(&x, &p), &p));
        }
    }

    #[test]
    fn server_hello_roundtrip() {
        let mut rng = XorShiftRandom::new(6);
        let secret = [5u8; 16];
        let hello = client_hello(b"cdn.example", &secret, 99, &mut rng);
        let response = server_hello_for_tests(&hello, &secret, &mut rng);
        let random: [u8; 32] = hello[11..43].try_into().unwrap();
        let mut buffer = InputBuffer::new();
        for (index, byte) in response.iter().enumerate() {
            buffer.extend(&[*byte]);
            let done = verify_server_hello(&mut buffer, &random, &secret).unwrap();
            assert_eq!(done, index == response.len() - 1);
        }
        assert!(buffer.is_empty());

        let mut tampered = response.clone();
        tampered[60] ^= 1;
        let mut buffer = InputBuffer::new();
        buffer.extend(&tampered);
        assert_eq!(verify_server_hello(&mut buffer, &random, &secret), Err(TlsHelloError::HashMismatch));

        let mut buffer = InputBuffer::new();
        buffer.extend(b"\x15\x03\x03\x00\x02ab");
        assert_eq!(verify_server_hello(&mut buffer, &random, &secret), Err(TlsHelloError::InvalidPrefix));
    }

    #[test]
    fn zero_length_and_split_records_do_not_stall() {
        let mut input = InputBuffer::new();
        let mut reader = TlsRecordReader::new();
        let mut collected = Vec::new();
        input.extend(b"\x17\x03\x03\x00\x00");
        input.extend(b"\x17\x03\x03\x00\x03ab");
        assert!(reader.read(&mut input, &mut collected).unwrap());
        assert!(collected.is_empty());
        assert!(!reader.read(&mut input, &mut collected).unwrap());
        input.extend(b"c");
        assert!(reader.read(&mut input, &mut collected).unwrap());
        assert_eq!(collected, b"abc");
        assert!(input.is_empty());
    }

    #[test]
    fn record_writer_and_reader() {
        let mut writer = TlsRecordWriter::new();
        let mut out = Vec::new();
        let payload = vec![7u8; MAX_TLS_PACKET_LENGTH * 2 + 10];
        writer.write(&payload, &mut out);
        writer.write(&[1, 2, 3], &mut out);
        assert_eq!(&out[..6], CHANGE_CIPHER_SPEC);
        let mut input = InputBuffer::new();
        input.extend(&out[6..]);
        let mut reader = TlsRecordReader::new();
        let mut collected = Vec::new();
        while reader.read(&mut input, &mut collected).unwrap() {}
        assert!(input.is_empty());
        assert_eq!(collected.len(), payload.len() + 3);
        let mut bad = InputBuffer::new();
        bad.extend(b"\x16\x03\x03\x00\x01x");
        assert!(reader.read(&mut bad, &mut collected).is_err());
    }
}
