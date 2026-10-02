use num_bigint::BigUint;

use super::{TestRsaKeyPair, test_rsa_key_pair};
use crate::auth_key::AuthKey;
use crate::crypto::{
    KNOWN_DH_PRIME, SecureRandom, aes_ige_decrypt, aes_ige_encrypt, handshake_tmp_aes, sha1, sha1_parts, sha256,
    sha256_parts, to_fixed_be,
};
use crate::message::{decode_plain_message, encode_plain_message};
use crate::msg_id::MsgIdGenerator;
use crate::tl::mtproto::{
    ClientDhInnerData, DhGenKind, PqInnerData, ResPq, ServerDhInnerData, ServerDhParams, SetClientDhParamsAnswer,
};
use crate::tl::{Reader, TlRead, TlWrite, ids};

#[derive(Debug, Clone, Default)]
pub struct ServerHandshakeBehavior {
    pub retries_before_ok: u32,
    pub fail_dh_gen: bool,
    pub fail_dh_params: bool,
    pub corrupt_answer_hash: bool,
    pub wrong_nonce_in_res_pq: bool,
    pub foreign_fingerprint: bool,
    pub bad_g: Option<i32>,
    pub small_g_a: bool,
    pub server_time: i32,
    pub pq_override: Option<Vec<u8>>,
    pub wrong_server_nonce_in_dh_params: bool,
    pub wrong_nonce_in_inner_data: bool,
    pub wrong_nonce_in_dh_gen: bool,
    pub corrupt_new_nonce_hash: bool,
    pub corrupt_fail_hash: bool,
    pub unaligned_encrypted_answer: bool,
    pub excess_answer_padding: bool,
    pub dh_prime_override: Option<Vec<u8>>,
    pub trailing_bytes: bool,
    pub repeat_res_pq: bool,
}

#[derive(Debug, Clone)]
pub struct ServerHandshakeOutcome {
    pub auth_key: AuthKey,
    pub server_salt: i64,
    pub dc: i32,
    pub expires_in: Option<i32>,
}

pub struct ServerHandshake {
    keys: TestRsaKeyPair,
    behavior: ServerHandshakeBehavior,
    msg_ids: MsgIdGenerator,
    nonce: [u8; 16],
    server_nonce: [u8; 16],
    new_nonce: [u8; 32],
    a: BigUint,
    dc: i32,
    expires_in: Option<i32>,
    retries_sent: u32,
    pub outcome: Option<ServerHandshakeOutcome>,
}

const PQ: u64 = 0x17ED48941A08F981;

impl ServerHandshake {
    pub fn new(behavior: ServerHandshakeBehavior) -> Self {
        Self {
            keys: test_rsa_key_pair(),
            behavior,
            msg_ids: MsgIdGenerator::new(),
            nonce: [0; 16],
            server_nonce: [0; 16],
            new_nonce: [0; 32],
            a: BigUint::default(),
            dc: 0,
            expires_in: None,
            retries_sent: 0,
            outcome: None,
        }
    }

    pub fn public_key(&self) -> crate::crypto::RsaPublicKey {
        self.keys.public.clone()
    }

    fn reply(&mut self, mut body: Vec<u8>) -> Vec<u8> {
        let id = self.msg_ids.next(self.behavior.server_time as f64) | 1;
        let mut packet = encode_plain_message(id, &body);
        if self.behavior.trailing_bytes {
            body.clear();
            body.extend_from_slice(&[0x5au8; 12]);
            packet.extend_from_slice(&body);
            let declared = u32::from_le_bytes(packet[16..20].try_into().unwrap()) + 12;
            packet[16..20].copy_from_slice(&declared.to_le_bytes());
        }
        packet
    }

    fn res_pq(&mut self, rng: &mut impl SecureRandom) -> Vec<u8> {
        let mut nonce = self.nonce;
        if self.behavior.wrong_nonce_in_res_pq {
            nonce[0] ^= 1;
        }
        let fingerprint = if self.behavior.foreign_fingerprint { 0x1234 } else { self.keys.public.fingerprint() };
        let _ = rng;
        let body = ResPq {
            nonce,
            server_nonce: self.server_nonce,
            pq: self.behavior.pq_override.clone().unwrap_or_else(|| PQ.to_be_bytes().to_vec()),
            fingerprints: vec![0x7777, fingerprint],
        }
        .to_bytes();
        self.reply(body)
    }

    pub fn handle(&mut self, packet: &[u8], rng: &mut impl SecureRandom) -> Option<Vec<u8>> {
        let message = decode_plain_message(packet).ok()?;
        let mut reader = Reader::new(message.body);
        let constructor = reader.read_u32().ok()?;
        match constructor {
            ids::REQ_PQ_MULTI => {
                self.nonce = reader.read_int128().ok()?;
                self.server_nonce = rng.array();
                Some(self.res_pq(rng))
            }
            ids::REQ_DH_PARAMS => {
                let nonce = reader.read_int128().ok()?;
                let server_nonce = reader.read_int128().ok()?;
                let p = reader.read_bytes().ok()?.to_vec();
                let q = reader.read_bytes().ok()?.to_vec();
                let fingerprint = reader.read_i64().ok()?;
                let encrypted = reader.read_bytes().ok()?.to_vec();
                assert_eq!(nonce, self.nonce);
                assert_eq!(server_nonce, self.server_nonce);
                assert_eq!(p, vec![0x49, 0x4C, 0x55, 0x3B]);
                assert_eq!(q, vec![0x53, 0x91, 0x10, 0x73]);
                assert_eq!(fingerprint, self.keys.public.fingerprint());
                let block = self.keys.decrypt(&encrypted);
                let aes_hash = sha256(&block[32..]);
                let mut temp_key = [0u8; 32];
                for i in 0..32 {
                    temp_key[i] = block[i] ^ aes_hash[i];
                }
                let mut data_with_hash = block[32..].to_vec();
                aes_ige_decrypt(&temp_key, &[0u8; 32], &mut data_with_hash).ok()?;
                let mut data_with_padding = data_with_hash[..192].to_vec();
                data_with_padding.reverse();
                assert_eq!(sha256_parts(&[&temp_key, &data_with_padding])[..], data_with_hash[192..]);
                let mut inner_reader = Reader::new(&data_with_padding);
                let inner = PqInnerData::read_from(&mut inner_reader).ok()?;
                assert_eq!(inner.nonce, self.nonce);
                self.new_nonce = inner.new_nonce;
                self.dc = inner.dc;
                self.expires_in = inner.expires_in;

                if self.behavior.repeat_res_pq {
                    return Some(self.res_pq(rng));
                }
                let mut server_nonce = self.server_nonce;
                if self.behavior.wrong_server_nonce_in_dh_params {
                    server_nonce[3] ^= 0x40;
                }
                if self.behavior.fail_dh_params {
                    let mut hash = sha1(&self.new_nonce);
                    if self.behavior.corrupt_fail_hash {
                        hash[7] ^= 1;
                    }
                    let body = ServerDhParams::Fail {
                        nonce: self.nonce,
                        server_nonce,
                        new_nonce_hash: hash[4..20].try_into().unwrap(),
                    }
                    .to_bytes();
                    return Some(self.reply(body));
                }

                let prime_bytes = self.behavior.dh_prime_override.clone().unwrap_or_else(|| KNOWN_DH_PRIME.to_vec());
                let prime = BigUint::from_bytes_be(&prime_bytes);
                let g = self.behavior.bad_g.unwrap_or(3);
                let mut a_bytes = [0u8; 256];
                rng.fill(&mut a_bytes);
                self.a = BigUint::from_bytes_be(&a_bytes);
                let g_a = if self.behavior.small_g_a {
                    BigUint::from(2u32)
                } else {
                    BigUint::from(3u32).modpow(&self.a, &prime)
                };
                let mut inner_nonce = self.nonce;
                if self.behavior.wrong_nonce_in_inner_data {
                    inner_nonce[9] ^= 0x10;
                }
                let inner = ServerDhInnerData {
                    nonce: inner_nonce,
                    server_nonce: self.server_nonce,
                    g,
                    dh_prime: prime_bytes,
                    g_a: g_a.to_bytes_be(),
                    server_time: self.behavior.server_time,
                }
                .to_bytes();
                let mut answer = sha1(&inner).to_vec();
                if self.behavior.corrupt_answer_hash {
                    answer[0] ^= 1;
                }
                answer.extend_from_slice(&inner);
                let unpadded = answer.len();
                answer.resize(unpadded.div_ceil(16) * 16, 0);
                if self.behavior.excess_answer_padding {
                    answer.resize(answer.len() + 16, 0);
                }
                rng.fill(&mut answer[unpadded..]);
                let tmp = handshake_tmp_aes(&self.new_nonce, &self.server_nonce);
                aes_ige_encrypt(&tmp.key, &tmp.iv, &mut answer).ok()?;
                if self.behavior.unaligned_encrypted_answer {
                    answer.truncate(answer.len() - 4);
                }
                let body = ServerDhParams::Ok { nonce: self.nonce, server_nonce, encrypted_answer: answer }.to_bytes();
                Some(self.reply(body))
            }
            ids::SET_CLIENT_DH_PARAMS => {
                let _nonce = reader.read_int128().ok()?;
                let _server_nonce = reader.read_int128().ok()?;
                let mut data = reader.read_bytes().ok()?.to_vec();
                let tmp = handshake_tmp_aes(&self.new_nonce, &self.server_nonce);
                aes_ige_decrypt(&tmp.key, &tmp.iv, &mut data).ok()?;
                let mut inner_reader = Reader::new(&data[20..]);
                let inner = ClientDhInnerData::read_from(&mut inner_reader).ok()?;
                let consumed = inner_reader.position();
                assert_eq!(sha1(&data[20..20 + consumed])[..], data[..20]);
                let prime = BigUint::from_bytes_be(&KNOWN_DH_PRIME);
                let g_b = BigUint::from_bytes_be(&inner.g_b);
                let key = to_fixed_be::<256>(&g_b.modpow(&self.a, &prime)).unwrap();
                let auth_key = AuthKey::new(key);
                let (kind, number) = if self.behavior.fail_dh_gen {
                    (DhGenKind::Fail, 3u8)
                } else if self.retries_sent < self.behavior.retries_before_ok {
                    self.retries_sent += 1;
                    (DhGenKind::Retry, 2u8)
                } else {
                    (DhGenKind::Ok, 1u8)
                };
                if kind == DhGenKind::Ok {
                    let mut salt = [0u8; 8];
                    for (byte, (a, b)) in salt.iter_mut().zip(self.new_nonce.iter().zip(self.server_nonce.iter())) {
                        *byte = a ^ b;
                    }
                    self.outcome = Some(ServerHandshakeOutcome {
                        auth_key: auth_key.clone(),
                        server_salt: i64::from_le_bytes(salt),
                        dc: self.dc,
                        expires_in: self.expires_in,
                    });
                }
                if self.retries_sent > 0 && kind != DhGenKind::Retry {
                    assert_ne!(inner.retry_id, 0);
                }
                let mut hash = sha1_parts(&[&self.new_nonce, &[number], &auth_key.aux_hash().to_le_bytes()]);
                if self.behavior.corrupt_new_nonce_hash {
                    hash[10] ^= 2;
                }
                let mut nonce = self.nonce;
                if self.behavior.wrong_nonce_in_dh_gen {
                    nonce[15] ^= 0x80;
                }
                let body = SetClientDhParamsAnswer {
                    kind,
                    nonce,
                    server_nonce: self.server_nonce,
                    new_nonce_hash: hash[4..20].try_into().unwrap(),
                }
                .to_bytes();
                Some(self.reply(body))
            }
            _ => None,
        }
    }
}

impl core::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerHandshake").field("dc", &self.dc).finish()
    }
}
