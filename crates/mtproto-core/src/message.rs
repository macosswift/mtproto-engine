use crate::auth_key::AuthKey;
use crate::crypto::{
    SecureRandom, Side, aes_ige_decrypt, aes_ige_encrypt, message_key_v1, message_key_v2, msg_key_v1, sha256_parts,
};

pub const ENCRYPTED_HEADER_LEN: usize = 24;
pub const INNER_HEADER_LEN: usize = 32;
pub const MIN_PADDING: usize = 12;
pub const MAX_PADDING: usize = 1024;
pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    #[error("packet is too short ({0} bytes)")]
    TooShort(usize),
    #[error("encrypted payload length {0} is not a multiple of 16")]
    Unaligned(usize),
    #[error("auth_key_id mismatch: expected {expected:#018x}, found {found:#018x}")]
    AuthKeyMismatch { expected: u64, found: u64 },
    #[error("msg_key mismatch")]
    MsgKeyMismatch,
    #[error("invalid message length {length} for payload of {available} bytes")]
    InvalidLength { length: i64, available: usize },
    #[error("invalid padding length {0}")]
    InvalidPadding(usize),
    #[error("session_id mismatch")]
    SessionMismatch,
    #[error("server msg_id {0:#x} is not odd")]
    EvenServerMsgId(i64),
    #[error("plain message has non-zero auth_key_id")]
    NotPlain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub salt: i64,
    pub session_id: i64,
    pub msg_id: i64,
    pub seq_no: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedMessage {
    pub header: MessageHeader,
    pub plaintext: Vec<u8>,
    pub body_range: core::ops::Range<usize>,
}

impl DecryptedMessage {
    pub fn body(&self) -> &[u8] {
        &self.plaintext[self.body_range.clone()]
    }

    pub fn into_body(mut self) -> Vec<u8> {
        self.plaintext.truncate(self.body_range.end);
        self.plaintext.drain(..self.body_range.start);
        self.plaintext
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PaddingPolicy {
    pub extra_random_blocks: usize,
}

impl PaddingPolicy {
    pub fn padding_len(&self, unpadded: usize, rng: &mut impl SecureRandom) -> usize {
        let mut padding = MIN_PADDING + (16 - (unpadded + MIN_PADDING) % 16) % 16;
        if self.extra_random_blocks > 0 {
            let extra = (rng.next_u32() as usize % (self.extra_random_blocks + 1)) * 16;
            padding += extra;
            while padding > MAX_PADDING {
                padding -= 16;
            }
        }
        padding
    }
}

pub struct EncryptedPacket {
    pub data: Vec<u8>,
    pub quick_ack_token: u32,
}

pub fn encrypt_message(
    auth_key: &AuthKey,
    header: &MessageHeader,
    body: &[u8],
    side: Side,
    padding: PaddingPolicy,
    rng: &mut impl SecureRandom,
) -> EncryptedPacket {
    let unpadded = INNER_HEADER_LEN + body.len();
    let padding_len = padding.padding_len(unpadded, rng);
    let total = ENCRYPTED_HEADER_LEN + unpadded + padding_len;
    let mut data = Vec::with_capacity(total);
    data.extend_from_slice(&auth_key.id().to_le_bytes());
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&header.salt.to_le_bytes());
    data.extend_from_slice(&header.session_id.to_le_bytes());
    data.extend_from_slice(&header.msg_id.to_le_bytes());
    data.extend_from_slice(&header.seq_no.to_le_bytes());
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(body);
    let padding_start = data.len();
    data.resize(total, 0);
    rng.fill(&mut data[padding_start..]);

    let x = match side {
        Side::Client => 0,
        Side::Server => 8,
    };
    let key = auth_key.bytes();
    let msg_key_large = sha256_parts(&[&key[88 + x..120 + x], &data[ENCRYPTED_HEADER_LEN..]]);
    let msg_key: [u8; 16] = msg_key_large[8..24].try_into().expect("16 bytes");
    let quick_ack_token = u32::from_le_bytes(msg_key_large[..4].try_into().expect("4 bytes")) | 0x8000_0000;
    data[8..24].copy_from_slice(&msg_key);
    let material = message_key_v2(key, &msg_key, side);
    aes_ige_encrypt(&material.key, &material.iv, &mut data[ENCRYPTED_HEADER_LEN..]).expect("aligned by construction");
    EncryptedPacket { data, quick_ack_token }
}

pub fn read_auth_key_id(packet: &[u8]) -> Option<u64> {
    packet.get(..8).map(|bytes| u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}

pub fn decrypt_message(auth_key: &AuthKey, packet: &[u8], side: Side) -> Result<DecryptedMessage, MessageError> {
    if packet.len() < ENCRYPTED_HEADER_LEN + INNER_HEADER_LEN + MIN_PADDING {
        return Err(MessageError::TooShort(packet.len()));
    }
    let encrypted_len = (packet.len() - ENCRYPTED_HEADER_LEN) / 16 * 16;
    if encrypted_len < INNER_HEADER_LEN + MIN_PADDING {
        return Err(MessageError::TooShort(packet.len()));
    }
    let found = read_auth_key_id(packet).expect("length checked");
    if found != auth_key.id() {
        return Err(MessageError::AuthKeyMismatch { expected: auth_key.id(), found });
    }
    let msg_key: [u8; 16] = packet[8..24].try_into().expect("16 bytes");
    let material = message_key_v2(auth_key.bytes(), &msg_key, side);
    let mut plaintext = packet[ENCRYPTED_HEADER_LEN..ENCRYPTED_HEADER_LEN + encrypted_len].to_vec();
    aes_ige_decrypt(&material.key, &material.iv, &mut plaintext).expect("aligned");

    let x = match side {
        Side::Client => 0,
        Side::Server => 8,
    };
    let key = auth_key.bytes();
    let computed = sha256_parts(&[&key[88 + x..120 + x], &plaintext]);
    let length = i32::from_le_bytes(plaintext[28..32].try_into().expect("4 bytes")) as i64;
    let max_body = plaintext.len() - INNER_HEADER_LEN;
    let length_ok = length >= 0 && length % 4 == 0 && (length as usize) <= max_body;
    let padding = if length_ok { max_body - length as usize } else { 0 };
    let padding_ok = (MIN_PADDING..=MAX_PADDING).contains(&padding);
    let key_ok = constant_time_eq(&computed[8..24], &msg_key);
    if !key_ok {
        return Err(MessageError::MsgKeyMismatch);
    }
    if !length_ok {
        return Err(MessageError::InvalidLength { length, available: max_body });
    }
    if !padding_ok {
        return Err(MessageError::InvalidPadding(padding));
    }
    let header = MessageHeader {
        salt: i64::from_le_bytes(plaintext[0..8].try_into().expect("8")),
        session_id: i64::from_le_bytes(plaintext[8..16].try_into().expect("8")),
        msg_id: i64::from_le_bytes(plaintext[16..24].try_into().expect("8")),
        seq_no: i32::from_le_bytes(plaintext[24..28].try_into().expect("4")),
    };
    let body_range = INNER_HEADER_LEN..INNER_HEADER_LEN + length as usize;
    Ok(DecryptedMessage { header, plaintext, body_range })
}

pub fn encrypt_message_v1(
    auth_key: &AuthKey,
    header: &MessageHeader,
    body: &[u8],
    rng: &mut impl SecureRandom,
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(INNER_HEADER_LEN + body.len() + 16);
    plaintext.extend_from_slice(&header.salt.to_le_bytes());
    plaintext.extend_from_slice(&header.session_id.to_le_bytes());
    plaintext.extend_from_slice(&header.msg_id.to_le_bytes());
    plaintext.extend_from_slice(&header.seq_no.to_le_bytes());
    plaintext.extend_from_slice(&(body.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(body);
    let msg_key = msg_key_v1(&plaintext);
    let unpadded = plaintext.len();
    plaintext.resize(unpadded.div_ceil(16) * 16, 0);
    rng.fill(&mut plaintext[unpadded..]);
    let material = message_key_v1(auth_key.bytes(), &msg_key, Side::Client);
    aes_ige_encrypt(&material.key, &material.iv, &mut plaintext).expect("aligned");
    let mut packet = Vec::with_capacity(ENCRYPTED_HEADER_LEN + plaintext.len());
    packet.extend_from_slice(&auth_key.id().to_le_bytes());
    packet.extend_from_slice(&msg_key);
    packet.extend_from_slice(&plaintext);
    packet
}

pub fn decrypt_message_v1(auth_key: &AuthKey, packet: &[u8], side: Side) -> Result<DecryptedMessage, MessageError> {
    if packet.len() < ENCRYPTED_HEADER_LEN + INNER_HEADER_LEN {
        return Err(MessageError::TooShort(packet.len()));
    }
    let encrypted_len = packet.len() - ENCRYPTED_HEADER_LEN;
    if !encrypted_len.is_multiple_of(16) {
        return Err(MessageError::Unaligned(encrypted_len));
    }
    let found = read_auth_key_id(packet).expect("length checked");
    if found != auth_key.id() {
        return Err(MessageError::AuthKeyMismatch { expected: auth_key.id(), found });
    }
    let msg_key: [u8; 16] = packet[8..24].try_into().expect("16 bytes");
    let material = message_key_v1(auth_key.bytes(), &msg_key, side);
    let mut plaintext = packet[ENCRYPTED_HEADER_LEN..].to_vec();
    aes_ige_decrypt(&material.key, &material.iv, &mut plaintext).expect("aligned");
    let length = i32::from_le_bytes(plaintext[28..32].try_into().expect("4 bytes")) as i64;
    let max_body = plaintext.len() - INNER_HEADER_LEN;
    if length < 0 || length as usize > max_body || max_body - length as usize > 15 {
        return Err(MessageError::InvalidLength { length, available: max_body });
    }
    let end = INNER_HEADER_LEN + length as usize;
    if !constant_time_eq(&msg_key_v1(&plaintext[..end]), &msg_key) {
        return Err(MessageError::MsgKeyMismatch);
    }
    let header = MessageHeader {
        salt: i64::from_le_bytes(plaintext[0..8].try_into().expect("8")),
        session_id: i64::from_le_bytes(plaintext[8..16].try_into().expect("8")),
        msg_id: i64::from_le_bytes(plaintext[16..24].try_into().expect("8")),
        seq_no: i32::from_le_bytes(plaintext[24..28].try_into().expect("4")),
    };
    Ok(DecryptedMessage { header, plaintext, body_range: INNER_HEADER_LEN..end })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainMessage<'a> {
    pub msg_id: i64,
    pub body: &'a [u8],
}

pub fn encode_plain_message(msg_id: i64, body: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(20 + body.len());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&msg_id.to_le_bytes());
    data.extend_from_slice(&(body.len() as u32).to_le_bytes());
    data.extend_from_slice(body);
    data
}

pub fn decode_plain_message(packet: &[u8]) -> Result<PlainMessage<'_>, MessageError> {
    if packet.len() < 20 {
        return Err(MessageError::TooShort(packet.len()));
    }
    if read_auth_key_id(packet) != Some(0) {
        return Err(MessageError::NotPlain);
    }
    let msg_id = i64::from_le_bytes(packet[8..16].try_into().expect("8"));
    let length = i32::from_le_bytes(packet[16..20].try_into().expect("4")) as i64;
    if length < 0 || length as usize > packet.len() - 20 {
        return Err(MessageError::InvalidLength { length, available: packet.len() - 20 });
    }
    Ok(PlainMessage { msg_id, body: &packet[20..20 + length as usize] })
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::XorShiftRandom;
    use proptest::prelude::*;

    fn key(seed: u8) -> AuthKey {
        AuthKey::new(core::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)))
    }

    fn header() -> MessageHeader {
        MessageHeader { salt: 0x1122334455667788, session_id: -42, msg_id: 0x51e57ac42770964a, seq_no: 7 }
    }

    #[test]
    fn client_to_server_roundtrip() {
        let mut rng = XorShiftRandom::new(1);
        let body = b"0123456789abcdef0123".to_vec();
        let packet = encrypt_message(&key(1), &header(), &body, Side::Client, PaddingPolicy::default(), &mut rng);
        assert_eq!((packet.data.len() - 24) % 16, 0);
        assert!(packet.quick_ack_token & 0x8000_0000 != 0);
        let decrypted = decrypt_message(&key(1), &packet.data, Side::Client).unwrap();
        assert_eq!(decrypted.header, header());
        assert_eq!(decrypted.body(), &body[..]);
        assert_eq!(decrypted.into_body(), body);
    }

    #[test]
    fn wrong_side_or_key_is_rejected() {
        let mut rng = XorShiftRandom::new(2);
        let packet = encrypt_message(&key(1), &header(), &[0u8; 16], Side::Server, PaddingPolicy::default(), &mut rng);
        assert_eq!(decrypt_message(&key(1), &packet.data, Side::Client), Err(MessageError::MsgKeyMismatch));
        assert!(matches!(
            decrypt_message(&key(2), &packet.data, Side::Server),
            Err(MessageError::AuthKeyMismatch { .. })
        ));
        assert!(decrypt_message(&key(1), &packet.data, Side::Server).is_ok());
    }

    #[test]
    fn tampering_is_detected_everywhere() {
        let mut rng = XorShiftRandom::new(3);
        let packet = encrypt_message(&key(1), &header(), &[5u8; 64], Side::Server, PaddingPolicy::default(), &mut rng);
        for index in 8..packet.data.len() {
            let mut tampered = packet.data.clone();
            tampered[index] ^= 0x01;
            assert!(decrypt_message(&key(1), &tampered, Side::Server).is_err(), "byte {index}");
        }
    }

    #[test]
    fn rejects_bad_shapes() {
        assert_eq!(decrypt_message(&key(1), &[0u8; 10], Side::Server), Err(MessageError::TooShort(10)));
        assert_eq!(decrypt_message(&key(1), &[0u8; 67], Side::Server), Err(MessageError::TooShort(67)));
        assert!(matches!(
            decrypt_message(&key(1), &[0u8; 24 + 50 + 1], Side::Server),
            Err(MessageError::AuthKeyMismatch { .. })
        ));
    }

    #[test]
    fn trailing_transport_junk_is_ignored_like_tdlib() {
        let mut rng = XorShiftRandom::new(11);
        let body = [7u8; 40];
        let mut packet =
            encrypt_message(&key(1), &header(), &body, Side::Server, PaddingPolicy::default(), &mut rng).data;
        for junk in 1..16 {
            let mut padded = packet.clone();
            padded.extend(std::iter::repeat_n(0xa5u8, junk));
            let decrypted = decrypt_message(&key(1), &padded, Side::Server).unwrap();
            assert_eq!(decrypted.body(), &body[..]);
        }
        packet.truncate(packet.len() - 1);
        assert_eq!(decrypt_message(&key(1), &packet, Side::Server), Err(MessageError::MsgKeyMismatch));
    }

    fn forge(auth_key: &AuthKey, declared_length: i32, payload_len: usize, rng: &mut XorShiftRandom) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&header().salt.to_le_bytes());
        plaintext.extend_from_slice(&header().session_id.to_le_bytes());
        plaintext.extend_from_slice(&header().msg_id.to_le_bytes());
        plaintext.extend_from_slice(&header().seq_no.to_le_bytes());
        plaintext.extend_from_slice(&declared_length.to_le_bytes());
        plaintext.resize(32 + payload_len, 0);
        rng.fill(&mut plaintext[32..]);
        let large = sha256_parts(&[&auth_key.bytes()[96..128], &plaintext]);
        let msg_key: [u8; 16] = large[8..24].try_into().unwrap();
        let material = message_key_v2(auth_key.bytes(), &msg_key, Side::Server);
        aes_ige_encrypt(&material.key, &material.iv, &mut plaintext).unwrap();
        let mut packet = auth_key.id().to_le_bytes().to_vec();
        packet.extend_from_slice(&msg_key);
        packet.extend_from_slice(&plaintext);
        packet
    }

    #[test]
    fn padding_bounds_are_enforced_after_authentication() {
        let auth_key = key(5);
        let mut rng = XorShiftRandom::new(12);
        assert_eq!(
            decrypt_message(&auth_key, &forge(&auth_key, 24, 32, &mut rng), Side::Server),
            Err(MessageError::InvalidPadding(8))
        );
        assert!(decrypt_message(&auth_key, &forge(&auth_key, 20, 32, &mut rng), Side::Server).is_ok());
        assert_eq!(
            decrypt_message(&auth_key, &forge(&auth_key, 4, 1056, &mut rng), Side::Server),
            Err(MessageError::InvalidPadding(1052))
        );
        assert!(decrypt_message(&auth_key, &forge(&auth_key, 16, 1040, &mut rng), Side::Server).is_ok());
        assert_eq!(
            decrypt_message(&auth_key, &forge(&auth_key, 12, 1040, &mut rng), Side::Server),
            Err(MessageError::InvalidPadding(1028))
        );
        assert!(matches!(
            decrypt_message(&auth_key, &forge(&auth_key, -16, 64, &mut rng), Side::Server),
            Err(MessageError::InvalidLength { .. })
        ));
        assert!(matches!(
            decrypt_message(&auth_key, &forge(&auth_key, 18, 64, &mut rng), Side::Server),
            Err(MessageError::InvalidLength { .. })
        ));
        assert!(matches!(
            decrypt_message(&auth_key, &forge(&auth_key, 68, 64, &mut rng), Side::Server),
            Err(MessageError::InvalidLength { .. })
        ));
    }

    #[test]
    fn rejects_forged_length_with_valid_msg_key() {
        let auth_key = key(9);
        let mut rng = XorShiftRandom::new(4);
        for forged_length in [-4i32, 3, 1 << 20, 0] {
            let mut plaintext = Vec::new();
            plaintext.extend_from_slice(&header().salt.to_le_bytes());
            plaintext.extend_from_slice(&header().session_id.to_le_bytes());
            plaintext.extend_from_slice(&header().msg_id.to_le_bytes());
            plaintext.extend_from_slice(&header().seq_no.to_le_bytes());
            plaintext.extend_from_slice(&forged_length.to_le_bytes());
            plaintext.extend_from_slice(&[0u8; 16]);
            plaintext.resize(48 + 16, 0);
            rng.fill(&mut plaintext[48..]);
            let large = sha256_parts(&[&auth_key.bytes()[96..128], &plaintext]);
            let msg_key: [u8; 16] = large[8..24].try_into().unwrap();
            let material = message_key_v2(auth_key.bytes(), &msg_key, Side::Server);
            aes_ige_encrypt(&material.key, &material.iv, &mut plaintext).unwrap();
            let mut packet = auth_key.id().to_le_bytes().to_vec();
            packet.extend_from_slice(&msg_key);
            packet.extend_from_slice(&plaintext);
            let result = decrypt_message(&auth_key, &packet, Side::Server);
            if forged_length == 0 {
                assert_eq!(result, Err(MessageError::InvalidPadding(32)).or(result.clone()));
            } else {
                assert!(matches!(result, Err(MessageError::InvalidLength { .. })), "{forged_length}: {result:?}");
            }
        }
    }

    #[test]
    fn padding_policy_bounds() {
        let mut rng = XorShiftRandom::new(5);
        for unpadded in 0..200 {
            let padding = PaddingPolicy::default().padding_len(unpadded, &mut rng);
            assert!((12..28).contains(&padding));
            assert_eq!((unpadded + padding) % 16, 0);
            let padding = PaddingPolicy { extra_random_blocks: 200 }.padding_len(unpadded, &mut rng);
            assert!((12..=1024).contains(&padding));
            assert_eq!((unpadded + padding) % 16, 0);
        }
    }

    #[test]
    fn v1_roundtrip_and_tamper() {
        let mut rng = XorShiftRandom::new(6);
        let body = b"bind_auth_key_inner-payload-0000".to_vec();
        let packet = encrypt_message_v1(&key(4), &header(), &body, &mut rng);
        let decrypted = decrypt_message_v1(&key(4), &packet, Side::Client).unwrap();
        assert_eq!(decrypted.body(), &body[..]);
        assert_eq!(decrypted.header, header());
        let mut tampered = packet.clone();
        tampered[40] ^= 1;
        assert!(decrypt_message_v1(&key(4), &tampered, Side::Client).is_err());
    }

    #[test]
    fn plain_message_roundtrip() {
        let encoded = encode_plain_message(0x51e57ac42770964a, b"abcd");
        let decoded = decode_plain_message(&encoded).unwrap();
        assert_eq!(decoded.msg_id, 0x51e57ac42770964a);
        assert_eq!(decoded.body, b"abcd");
        let mut wrong_len = encoded.clone();
        wrong_len[16] = 5;
        assert!(decode_plain_message(&wrong_len).is_err());
        let mut keyed = encoded.clone();
        keyed[0] = 1;
        assert_eq!(decode_plain_message(&keyed), Err(MessageError::NotPlain));
        let mut trailing = encoded;
        trailing.extend_from_slice(&[9u8; 7]);
        assert_eq!(decode_plain_message(&trailing).unwrap().body, b"abcd");
        let mut negative = trailing.clone();
        negative[16..20].copy_from_slice(&(-4i32).to_le_bytes());
        assert!(matches!(decode_plain_message(&negative), Err(MessageError::InvalidLength { .. })));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn roundtrip_any_body(words in proptest::collection::vec(any::<u32>(), 0..300), seed in any::<u64>(), extra in 0usize..64) {
            let body: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            let mut rng = XorShiftRandom::new(seed);
            let packet = encrypt_message(&key(7), &header(), &body, Side::Server, PaddingPolicy { extra_random_blocks: extra }, &mut rng);
            let decrypted = decrypt_message(&key(7), &packet.data, Side::Server).unwrap();
            prop_assert_eq!(decrypted.body(), &body[..]);
        }

        #[test]
        fn decrypt_never_panics(data in proptest::collection::vec(any::<u8>(), 0..200)) {
            let auth_key = key(3);
            let mut packet = auth_key.id().to_le_bytes().to_vec();
            packet.extend_from_slice(&data);
            let _ = decrypt_message(&auth_key, &packet, Side::Server);
            let _ = decrypt_message_v1(&auth_key, &packet, Side::Server);
            let _ = decode_plain_message(&data);
        }
    }
}
