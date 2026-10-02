use num_bigint::BigUint;
use zeroize::Zeroize;

use crate::auth_key::AuthKey;
use crate::crypto::{
    DhError, DhPrimeCache, RsaPublicKey, SecureRandom, aes_ige_decrypt, aes_ige_encrypt, check_dh_params,
    check_g_a_or_b, factorize_pq, handshake_tmp_aes, is_probable_prime, sha1, sha1_parts, to_fixed_be,
};
use crate::message::{MessageError, constant_time_eq, decode_plain_message, encode_plain_message};
use crate::msg_id::MsgIdGenerator;
use crate::tl::mtproto::{
    ClientDhInnerData, DhGenKind, PqInnerData, ReqDhParams, ReqPqMulti, ResPq, ServerDhInnerData, ServerDhParams,
    SetClientDhParams, SetClientDhParamsAnswer,
};
use crate::tl::{Reader, TlError, TlRead, TlWrite};

pub const MAX_DH_RETRIES: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandshakeError {
    #[error("message: {0}")]
    Message(#[from] MessageError),
    #[error("tl: {0}")]
    Tl(#[from] TlError),
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("server nonce mismatch")]
    ServerNonceMismatch,
    #[error("no known RSA key among {0} server fingerprints")]
    UnknownFingerprints(usize),
    #[error("pq has an invalid length {0}")]
    BadPq(usize),
    #[error("failed to factorize pq")]
    FactorizationFailed,
    #[error("server_DH_params_fail")]
    ServerDhParamsFail,
    #[error("encrypted answer is malformed")]
    BadEncryptedAnswer,
    #[error("dh: {0}")]
    Dh(#[from] DhError),
    #[error("new_nonce_hash mismatch")]
    NewNonceHashMismatch,
    #[error("dh_gen_fail")]
    DhGenFail,
    #[error("too many dh_gen_retry answers")]
    TooManyRetries,
    #[error("unexpected message in state {0}")]
    UnexpectedMessage(&'static str),
    #[error("rsa: {0}")]
    Rsa(#[from] crate::crypto::RsaError),
}

#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    pub dc_id: i32,
    pub temp_key_expires_in: Option<i32>,
    pub public_keys: Vec<RsaPublicKey>,
}

#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub auth_key: AuthKey,
    pub server_salt: i64,
    pub server_time: i32,
    pub time_difference: f64,
    pub expires_at: Option<i32>,
}

enum State {
    WaitResPq {
        nonce: [u8; 16],
    },
    WaitDhParams {
        nonce: [u8; 16],
        server_nonce: [u8; 16],
        new_nonce: [u8; 32],
    },
    WaitDhGen {
        nonce: [u8; 16],
        server_nonce: [u8; 16],
        new_nonce: [u8; 32],
        auth_key: AuthKey,
        prime: BigUint,
        g: u32,
        g_a: BigUint,
        server_time: i32,
        time_difference: f64,
        retries: u32,
    },
    Done,
}

pub struct Handshake {
    config: HandshakeConfig,
    state: State,
    msg_ids: MsgIdGenerator,
}

pub enum HandshakeStep {
    Send(Vec<u8>),
    Done(HandshakeResult),
}

impl Handshake {
    pub fn start(config: HandshakeConfig, server_now: f64, rng: &mut impl SecureRandom) -> (Self, Vec<u8>) {
        let nonce: [u8; 16] = rng.array();
        let mut handshake = Self { config, state: State::WaitResPq { nonce }, msg_ids: MsgIdGenerator::new() };
        let packet = handshake.plain(server_now, &ReqPqMulti { nonce });
        (handshake, packet)
    }

    pub fn last_msg_id(&self) -> i64 {
        self.msg_ids.last()
    }

    pub fn is_temporary(&self) -> bool {
        self.config.temp_key_expires_in.is_some()
    }

    fn plain(&mut self, server_now: f64, body: &impl TlWrite) -> Vec<u8> {
        let msg_id = self.msg_ids.next(server_now);
        encode_plain_message(msg_id, &body.to_bytes())
    }

    pub fn on_packet(
        &mut self,
        packet: &[u8],
        local_unix_now: f64,
        prime_cache: Option<&mut dyn DhPrimeCache>,
        rng: &mut impl SecureRandom,
    ) -> Result<HandshakeStep, HandshakeError> {
        let message = decode_plain_message(packet)?;
        let state = core::mem::replace(&mut self.state, State::Done);
        match state {
            State::WaitResPq { nonce } => {
                let res_pq = ResPq::read_from(&mut Reader::new(message.body))?;
                if res_pq.nonce != nonce {
                    return Err(HandshakeError::NonceMismatch);
                }
                let key = res_pq
                    .fingerprints
                    .iter()
                    .find_map(|fingerprint| {
                        self.config.public_keys.iter().find(|key| key.fingerprint() == *fingerprint)
                    })
                    .cloned()
                    .ok_or(HandshakeError::UnknownFingerprints(res_pq.fingerprints.len()))?;
                if res_pq.pq.is_empty() || res_pq.pq.len() > 8 {
                    return Err(HandshakeError::BadPq(res_pq.pq.len()));
                }
                let pq = res_pq.pq.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
                if pq < 4 || is_probable_prime(&BigUint::from(pq), 32, rng) {
                    return Err(HandshakeError::FactorizationFailed);
                }
                let (p, q) = factorize_pq(pq).ok_or(HandshakeError::FactorizationFailed)?;
                let p_bytes = minimal_be(p);
                let q_bytes = minimal_be(q);
                let new_nonce: [u8; 32] = rng.array();
                let inner = PqInnerData {
                    pq: res_pq.pq.clone(),
                    p: p_bytes.clone(),
                    q: q_bytes.clone(),
                    nonce,
                    server_nonce: res_pq.server_nonce,
                    new_nonce,
                    dc: self.config.dc_id,
                    expires_in: self.config.temp_key_expires_in,
                };
                let mut inner_bytes = inner.to_bytes();
                let encrypted = key.encrypt_pad(&inner_bytes, rng)?;
                inner_bytes.zeroize();
                let request = ReqDhParams {
                    nonce,
                    server_nonce: res_pq.server_nonce,
                    p: &p_bytes,
                    q: &q_bytes,
                    public_key_fingerprint: key.fingerprint(),
                    encrypted_data: &encrypted,
                };
                let packet = self.plain(local_unix_now, &request);
                self.state = State::WaitDhParams { nonce, server_nonce: res_pq.server_nonce, new_nonce };
                Ok(HandshakeStep::Send(packet))
            }
            State::WaitDhParams { nonce, server_nonce, new_nonce } => {
                let params = ServerDhParams::read_from(&mut Reader::new(message.body))?;
                let encrypted_answer = match params {
                    ServerDhParams::Ok {
                        nonce: received_nonce,
                        server_nonce: received_server_nonce,
                        encrypted_answer,
                    } => {
                        check_nonces(&nonce, &received_nonce, &server_nonce, &received_server_nonce)?;
                        encrypted_answer
                    }
                    ServerDhParams::Fail {
                        nonce: received_nonce,
                        server_nonce: received_server_nonce,
                        new_nonce_hash,
                    } => {
                        check_nonces(&nonce, &received_nonce, &server_nonce, &received_server_nonce)?;
                        let expected = sha1(&new_nonce);
                        if !constant_time_eq(&new_nonce_hash, &expected[4..20]) {
                            return Err(HandshakeError::NewNonceHashMismatch);
                        }
                        return Err(HandshakeError::ServerDhParamsFail);
                    }
                };
                if encrypted_answer.is_empty() || encrypted_answer.len() % 16 != 0 {
                    return Err(HandshakeError::BadEncryptedAnswer);
                }
                let tmp = handshake_tmp_aes(&new_nonce, &server_nonce);
                let mut answer = encrypted_answer;
                aes_ige_decrypt(&tmp.key, &tmp.iv, &mut answer).map_err(|_| HandshakeError::BadEncryptedAnswer)?;
                if answer.len() < 20 {
                    return Err(HandshakeError::BadEncryptedAnswer);
                }
                let mut reader = Reader::new(&answer[20..]);
                let inner = ServerDhInnerData::read_from(&mut reader)?;
                let consumed = reader.position();
                let padding = answer.len() - 20 - consumed;
                if padding >= 16 || !constant_time_eq(&sha1(&answer[20..20 + consumed]), &answer[..20]) {
                    return Err(HandshakeError::BadEncryptedAnswer);
                }
                check_nonces(&nonce, &inner.nonce, &server_nonce, &inner.server_nonce)?;
                let prime = check_dh_params(&inner.dh_prime, inner.g, prime_cache, rng)?;
                let g_a = BigUint::from_bytes_be(&inner.g_a);
                check_g_a_or_b(&g_a, &prime)?;
                let time_difference = inner.server_time as f64 - local_unix_now;
                let g = inner.g as u32;
                self.finish_dh(
                    nonce,
                    server_nonce,
                    new_nonce,
                    prime,
                    g,
                    g_a,
                    inner.server_time,
                    time_difference,
                    local_unix_now + time_difference,
                    0,
                    0,
                    rng,
                )
            }
            State::WaitDhGen {
                nonce,
                server_nonce,
                new_nonce,
                auth_key,
                prime,
                g,
                g_a,
                server_time,
                time_difference,
                retries,
            } => {
                let answer = SetClientDhParamsAnswer::read_from(&mut Reader::new(message.body))?;
                check_nonces(&nonce, &answer.nonce, &server_nonce, &answer.server_nonce)?;
                let number = match answer.kind {
                    DhGenKind::Ok => 1u8,
                    DhGenKind::Retry => 2,
                    DhGenKind::Fail => 3,
                };
                let aux = auth_key.aux_hash().to_le_bytes();
                let expected = sha1_parts(&[&new_nonce, &[number], &aux]);
                if !constant_time_eq(&answer.new_nonce_hash, &expected[4..20]) {
                    return Err(HandshakeError::NewNonceHashMismatch);
                }
                match answer.kind {
                    DhGenKind::Ok => {
                        let mut salt_bytes = [0u8; 8];
                        for i in 0..8 {
                            salt_bytes[i] = new_nonce[i] ^ server_nonce[i];
                        }
                        let expires_at =
                            self.config.temp_key_expires_in.map(|expires_in| server_time.saturating_add(expires_in));
                        self.state = State::Done;
                        Ok(HandshakeStep::Done(HandshakeResult {
                            auth_key,
                            server_salt: i64::from_le_bytes(salt_bytes),
                            server_time,
                            time_difference,
                            expires_at,
                        }))
                    }
                    DhGenKind::Retry => {
                        if retries + 1 >= MAX_DH_RETRIES {
                            return Err(HandshakeError::TooManyRetries);
                        }
                        let retry_id = auth_key.aux_hash() as i64;
                        drop(auth_key);
                        self.finish_dh(
                            nonce,
                            server_nonce,
                            new_nonce,
                            prime,
                            g,
                            g_a,
                            server_time,
                            time_difference,
                            local_unix_now + time_difference,
                            retry_id,
                            retries + 1,
                            rng,
                        )
                    }
                    DhGenKind::Fail => Err(HandshakeError::DhGenFail),
                }
            }
            State::Done => Err(HandshakeError::UnexpectedMessage("done")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_dh(
        &mut self,
        nonce: [u8; 16],
        server_nonce: [u8; 16],
        new_nonce: [u8; 32],
        prime: BigUint,
        g: u32,
        g_a: BigUint,
        server_time: i32,
        time_difference: f64,
        server_now: f64,
        retry_id: i64,
        retries: u32,
        rng: &mut impl SecureRandom,
    ) -> Result<HandshakeStep, HandshakeError> {
        let generator = BigUint::from(g);
        let (b, g_b) = loop {
            let mut b_bytes = [0u8; 256];
            rng.fill(&mut b_bytes);
            let b = BigUint::from_bytes_be(&b_bytes);
            b_bytes.zeroize();
            let g_b = generator.modpow(&b, &prime);
            if check_g_a_or_b(&g_b, &prime).is_ok() {
                break (b, g_b);
            }
        };
        let key_number = g_a.modpow(&b, &prime);
        drop(b);
        let key_bytes = to_fixed_be::<256>(&key_number).expect("key fits 2048 bits");
        let auth_key = AuthKey::new(key_bytes);

        let inner = ClientDhInnerData { nonce, server_nonce, retry_id, g_b: g_b.to_bytes_be() };
        let inner_bytes = inner.to_bytes();
        let mut data = Vec::with_capacity(20 + inner_bytes.len() + 16);
        data.extend_from_slice(&sha1(&inner_bytes));
        data.extend_from_slice(&inner_bytes);
        let unpadded = data.len();
        data.resize(unpadded.div_ceil(16) * 16, 0);
        rng.fill(&mut data[unpadded..]);
        let tmp = handshake_tmp_aes(&new_nonce, &server_nonce);
        aes_ige_encrypt(&tmp.key, &tmp.iv, &mut data).expect("aligned");
        let request = SetClientDhParams { nonce, server_nonce, encrypted_data: &data };
        let packet = self.plain(server_now, &request);
        self.state = State::WaitDhGen {
            nonce,
            server_nonce,
            new_nonce,
            auth_key,
            prime,
            g,
            g_a,
            server_time,
            time_difference,
            retries,
        };
        Ok(HandshakeStep::Send(packet))
    }
}

fn check_nonces(
    nonce: &[u8; 16],
    received_nonce: &[u8; 16],
    server_nonce: &[u8; 16],
    received_server_nonce: &[u8; 16],
) -> Result<(), HandshakeError> {
    if nonce != received_nonce {
        return Err(HandshakeError::NonceMismatch);
    }
    if server_nonce != received_server_nonce {
        return Err(HandshakeError::ServerNonceMismatch);
    }
    Ok(())
}

fn minimal_be(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::minimal_be;

    #[test]
    fn minimal_big_endian() {
        assert_eq!(minimal_be(0x494C553B), vec![0x49, 0x4C, 0x55, 0x3B]);
        assert_eq!(minimal_be(1), vec![1]);
        assert_eq!(minimal_be(0), vec![0]);
    }
}
