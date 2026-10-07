#![no_main]

//! The auth key exchange against a hostile server, in three stages so the fuzzer gets past the
//! nonces and the RSA layer: (0) res_pq from the fuzzer; (1) a valid res_pq, then server_DH_params
//! whose encrypted inner data is the fuzzer's plaintext, sealed with the real temporary AES key;
//! (2) valid answers up to set_client_DH_params, then dh_gen answers from the fuzzer, hashed with the
//! key the server side computes.

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::Cursor;
use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{
    KNOWN_DH_PRIME, XorShiftRandom, aes_ige_decrypt, aes_ige_encrypt, handshake_tmp_aes, sha1, sha1_parts, sha256,
    sha256_parts, to_fixed_be,
};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeError, HandshakeStep};
use mtproto_core::message::{decode_plain_message, encode_plain_message};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::test_support::test_rsa_key_pair;
use mtproto_core::tl::mtproto::{
    ClientDhInnerData, DhGenKind, PqInnerData, ResPq, ServerDhInnerData, ServerDhParams, SetClientDhParamsAnswer,
};
use mtproto_core::tl::{Reader, TlRead, TlWrite};
use num_bigint::BigUint;

const NOW: f64 = 1_727_000_000.0;
const PQ: u64 = 0x17ED48941A08F981;
const SERVER_NONCE: [u8; 16] = [0x5a; 16];
const SEED: u64 = 0xfeed;

struct Fixture {
    nonce: [u8; 16],
    new_nonce: [u8; 32],
    req_dh_params: Vec<u8>,
    a: BigUint,
    inner: Vec<u8>,
}

fn config() -> HandshakeConfig {
    HandshakeConfig { dc_id: 2, temp_key_expires_in: None, public_keys: vec![test_rsa_key_pair().public] }
}

fn reply(msg_id_step: u8, body: &[u8]) -> Vec<u8> {
    encode_plain_message(msg_id_for_time(NOW) + i64::from(msg_id_step) * 4 + 1, body)
}

fn res_pq(nonce: [u8; 16]) -> Vec<u8> {
    let fingerprint = test_rsa_key_pair().public.fingerprint();
    ResPq { nonce, server_nonce: SERVER_NONCE, pq: PQ.to_be_bytes().to_vec(), fingerprints: vec![7, fingerprint] }
        .to_bytes()
}

fn started() -> (Handshake, XorShiftRandom, [u8; 16]) {
    let mut rng = XorShiftRandom::new(SEED);
    let (handshake, packet) = Handshake::start(config(), NOW, &mut rng);
    let body = decode_plain_message(&packet).expect("plain").body;
    let nonce: [u8; 16] = body[4..20].try_into().expect("nonce");
    (handshake, rng, nonce)
}

fn after_res_pq() -> (Handshake, XorShiftRandom, Vec<u8>) {
    let (mut handshake, mut rng, nonce) = started();
    let HandshakeStep::Send(packet) =
        handshake.on_packet(&reply(1, &res_pq(nonce)), NOW, None, &mut rng).expect("valid res_pq")
    else {
        panic!("res_pq finishes nothing");
    };
    (handshake, rng, packet)
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let (_, _, nonce) = started();
        let (_, _, packet) = after_res_pq();
        let body = decode_plain_message(&packet).expect("plain").body;
        let mut reader = Reader::new(body);
        reader.read_u32().expect("constructor");
        reader.read_int128().expect("nonce");
        reader.read_int128().expect("server nonce");
        reader.read_bytes().expect("p");
        reader.read_bytes().expect("q");
        reader.read_i64().expect("fingerprint");
        let encrypted = reader.read_bytes().expect("encrypted").to_vec();
        let block = test_rsa_key_pair().decrypt(&encrypted);
        let aes_hash = sha256(&block[32..]);
        let temp_key: [u8; 32] = core::array::from_fn(|i| block[i] ^ aes_hash[i]);
        let mut data_with_hash = block[32..].to_vec();
        aes_ige_decrypt(&temp_key, &[0u8; 32], &mut data_with_hash).expect("aligned");
        let mut data_with_padding = data_with_hash[..192].to_vec();
        data_with_padding.reverse();
        assert_eq!(sha256_parts(&[&temp_key, &data_with_padding])[..], data_with_hash[192..], "RSA_PAD hash");
        let inner = PqInnerData::read_from(&mut Reader::new(&data_with_padding)).expect("p_q_inner_data");
        assert_eq!(inner.nonce, nonce);
        assert_eq!(inner.server_nonce, SERVER_NONCE);
        assert_eq!(inner.pq, PQ.to_be_bytes());
        let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
        let a = BigUint::from_bytes_be(&[0x3c; 256]);
        let g_a = BigUint::from(3u32).modpow(&a, &prime);
        let server_inner = ServerDhInnerData {
            nonce,
            server_nonce: SERVER_NONCE,
            g: 3,
            dh_prime: KNOWN_DH_PRIME.to_vec(),
            g_a: g_a.to_bytes_be(),
            server_time: NOW as i32 + 100,
        }
        .to_bytes();
        Fixture { nonce, new_nonce: inner.new_nonce, req_dh_params: packet, a, inner: server_inner }
    })
}

fn seal_inner(fixture: &Fixture, inner: &[u8], cursor: &mut Cursor<'_>) -> Vec<u8> {
    let control = cursor.u8();
    let mut answer = sha1(inner).to_vec();
    if control & 1 != 0 {
        answer[usize::from(control >> 3) % 20] ^= 1;
    }
    answer.extend_from_slice(inner);
    let padding = if control & 2 != 0 { usize::from(cursor.u8() % 48) } else { 0 };
    let aligned = (answer.len() + padding).div_ceil(16) * 16;
    answer.resize(aligned, 0);
    let tmp = handshake_tmp_aes(&fixture.new_nonce, &SERVER_NONCE);
    aes_ige_encrypt(&tmp.key, &tmp.iv, &mut answer).expect("aligned");
    if control & 4 != 0 {
        answer.truncate(answer.len().saturating_sub(usize::from(cursor.u8() % 16)));
    }
    let mut nonce = fixture.nonce;
    let mut server_nonce = SERVER_NONCE;
    if control & 0x40 != 0 {
        nonce[usize::from(cursor.u8() % 16)] ^= 1;
    }
    if control & 0x80 != 0 {
        server_nonce[usize::from(cursor.u8() % 16)] ^= 1;
    }
    ServerDhParams::Ok { nonce, server_nonce, encrypted_answer: answer }.to_bytes()
}

fn stage_zero(cursor: &mut Cursor<'_>) {
    let (mut handshake, mut rng, nonce) = started();
    let patch = cursor.u8();
    let mut body = cursor.rest().to_vec();
    if patch & 1 != 0 && body.len() >= 20 {
        body[4..20].copy_from_slice(&nonce);
    }
    let packet = if patch & 2 != 0 { body } else { reply(patch >> 2, &body) };
    if let Ok(HandshakeStep::Send(next)) = handshake.on_packet(&packet, NOW, None, &mut rng) {
        let request = decode_plain_message(&next).expect("client packets are plain messages");
        assert!(request.body.len() > 300, "req_DH_params carries the RSA block");
    }
}

fn stage_one(cursor: &mut Cursor<'_>) {
    let fixture = fixture();
    let (mut handshake, mut rng, packet) = after_res_pq();
    assert_eq!(packet, fixture.req_dh_params, "the client's randomness is deterministic");
    let mode = cursor.u8();
    let body = match mode % 4 {
        0 => cursor.rest().to_vec(),
        1 => {
            let mut body = cursor.rest().to_vec();
            if body.len() >= 36 {
                body[4..20].copy_from_slice(&fixture.nonce);
                body[20..36].copy_from_slice(&SERVER_NONCE);
            }
            body
        }
        _ => {
            let inner = if mode & 4 != 0 {
                let mut inner = fixture.inner.clone();
                let edits = cursor.u8() % 8;
                for _ in 0..edits {
                    let at = cursor.below(inner.len());
                    inner[at] = cursor.u8();
                }
                inner
            } else {
                cursor.chunk().to_vec()
            };
            seal_inner(fixture, &inner, cursor)
        }
    };
    match handshake.on_packet(&reply(2, &body), NOW, None, &mut rng) {
        Ok(HandshakeStep::Send(next)) => {
            let request = decode_plain_message(&next).expect("plain");
            let mut reader = Reader::new(request.body);
            reader.read_u32().expect("constructor");
            assert_eq!(reader.read_int128().expect("nonce"), fixture.nonce);
            assert_eq!(reader.read_int128().expect("server nonce"), SERVER_NONCE);
            let mut data = reader.read_bytes().expect("encrypted").to_vec();
            let tmp = handshake_tmp_aes(&fixture.new_nonce, &SERVER_NONCE);
            aes_ige_decrypt(&tmp.key, &tmp.iv, &mut data).expect("client data is aligned");
            let mut inner_reader = Reader::new(&data[20..]);
            let inner = ClientDhInnerData::read_from(&mut inner_reader).expect("client_DH_inner_data");
            let consumed = inner_reader.position();
            assert_eq!(sha1(&data[20..20 + consumed])[..], data[..20], "client data hash");
            assert!(data.len() - 20 - consumed < 16, "client padding");
            assert_eq!(inner.retry_id, 0);
        }
        Ok(HandshakeStep::Done(_)) => panic!("server_DH_params cannot finish the exchange"),
        Err(_) => {}
    }
}

fn stage_two(cursor: &mut Cursor<'_>) {
    let fixture = fixture();
    let (mut handshake, mut rng, _) = after_res_pq();
    let mut empty = Cursor::new(&[]);
    let params = seal_inner(fixture, &fixture.inner, &mut empty);
    let Ok(HandshakeStep::Send(mut request)) = handshake.on_packet(&reply(2, &params), NOW, None, &mut rng) else {
        panic!("the fixture's server_DH_params is valid");
    };
    let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
    let tmp = handshake_tmp_aes(&fixture.new_nonce, &SERVER_NONCE);
    for round in 0..8u8 {
        let body = decode_plain_message(&request).expect("plain").body;
        let mut reader = Reader::new(body);
        reader.read_u32().expect("constructor");
        reader.read_int128().expect("nonce");
        reader.read_int128().expect("server nonce");
        let mut data = reader.read_bytes().expect("encrypted").to_vec();
        aes_ige_decrypt(&tmp.key, &tmp.iv, &mut data).expect("aligned");
        let inner = ClientDhInnerData::read_from(&mut Reader::new(&data[20..])).expect("inner");
        let g_b = BigUint::from_bytes_be(&inner.g_b);
        let key = AuthKey::new(to_fixed_be::<256>(&g_b.modpow(&fixture.a, &prime)).expect("fits"));
        let control = cursor.u8();
        let kind = match control % 3 {
            0 => DhGenKind::Ok,
            1 => DhGenKind::Retry,
            _ => DhGenKind::Fail,
        };
        let number = match kind {
            DhGenKind::Ok => 1u8,
            DhGenKind::Retry => 2,
            DhGenKind::Fail => 3,
        };
        let mut hash = sha1_parts(&[&fixture.new_nonce, &[number], &key.aux_hash().to_le_bytes()]);
        let tampered = control & 0x10 != 0;
        if tampered {
            hash[4 + usize::from(cursor.u8() % 16)] ^= 1;
        }
        let mut nonce = fixture.nonce;
        let wrong_nonce = control & 0x20 != 0;
        if wrong_nonce {
            nonce[usize::from(cursor.u8() % 16)] ^= 0x80;
        }
        let answer = SetClientDhParamsAnswer {
            kind,
            nonce,
            server_nonce: SERVER_NONCE,
            new_nonce_hash: hash[4..20].try_into().expect("16"),
        }
        .to_bytes();
        match handshake.on_packet(&reply(3 + round, &answer), NOW, None, &mut rng) {
            Ok(HandshakeStep::Done(result)) => {
                assert!(kind == DhGenKind::Ok && !tampered && !wrong_nonce, "accepted a bad dh_gen answer");
                assert_eq!(result.auth_key, key);
                let salt: [u8; 8] = core::array::from_fn(|i| fixture.new_nonce[i] ^ SERVER_NONCE[i]);
                assert_eq!(result.server_salt, i64::from_le_bytes(salt));
                assert_eq!(result.server_time, NOW as i32 + 100);
                return;
            }
            Ok(HandshakeStep::Send(next)) => {
                assert!(kind == DhGenKind::Retry && !tampered && !wrong_nonce, "a bad answer moved the exchange on");
                assert!(round + 1 < 5, "more retries than MAX_DH_RETRIES");
                let body = decode_plain_message(&next).expect("plain").body;
                let mut data = Reader::new(&body[36..]).read_bytes().expect("encrypted").to_vec();
                aes_ige_decrypt(&tmp.key, &tmp.iv, &mut data).expect("aligned");
                let retried = ClientDhInnerData::read_from(&mut Reader::new(&data[20..])).expect("inner");
                assert_eq!(retried.retry_id, key.aux_hash() as i64, "retry_id is the previous key's aux hash");
                request = next;
            }
            Err(error) => {
                if kind == DhGenKind::Ok && !tampered && !wrong_nonce {
                    panic!("a valid dh_gen_ok was refused: {error}");
                }
                if kind == DhGenKind::Retry && !tampered && !wrong_nonce {
                    assert_eq!(error, HandshakeError::TooManyRetries);
                }
                return;
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    match cursor.u8() % 3 {
        0 => stage_zero(&mut cursor),
        1 => stage_one(&mut cursor),
        _ => stage_two(&mut cursor),
    }
});
