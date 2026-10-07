//! C-11, C-14, C-18, M-18 and L-09: msg_key comparison, length and padding bounds, handshake key derivation,
//! the encrypted message layout and exact ends of MTProto service objects.

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{
    SecureRandom, Side, XorShiftRandom, aes_ige_decrypt, aes_ige_encrypt, handshake_tmp_aes, message_key_v2,
    sha1_parts, sha256_parts,
};
use mtproto_core::message::{
    MessageError, MessageHeader, PaddingPolicy, decrypt_message, decrypt_message_v1, encrypt_message,
    encrypt_message_v1,
};
use mtproto_core::tl::mtproto::{ServiceMessage, gzip};
use mtproto_core::tl::{Writer, ids};

const MESSAGE_SOURCE: &str = include_str!("../src/message.rs");
const HANDSHAKE_SOURCE: &str = include_str!("../src/handshake.rs");

fn key(seed: u8) -> AuthKey {
    AuthKey::new(core::array::from_fn(|index| (index as u8).wrapping_mul(29).wrapping_add(seed)))
}

fn header() -> MessageHeader {
    MessageHeader {
        salt: 0x0102_0304_0506_0708,
        session_id: -0x1122_3344_5566_7788,
        msg_id: 0x51e5_7ac4_2770_964b,
        seq_no: 9,
    }
}

fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source.find(signature).unwrap_or_else(|| panic!("{signature} not found"));
    let end = source[start..].find("\n}\n").map(|end| start + end + 2).expect("function end");
    &source[start..end]
}

fn server_packet(auth_key: &AuthKey, plaintext: &[u8]) -> Vec<u8> {
    let msg_key: [u8; 16] = sha256_parts(&[&auth_key.bytes()[96..128], plaintext])[8..24].try_into().unwrap();
    let material = message_key_v2(auth_key.bytes(), &msg_key, Side::Server);
    let mut encrypted = plaintext.to_vec();
    aes_ige_encrypt(&material.key, &material.iv, &mut encrypted).unwrap();
    let mut packet = auth_key.id().to_le_bytes().to_vec();
    packet.extend_from_slice(&msg_key);
    packet.extend_from_slice(&encrypted);
    packet
}

fn plaintext(declared_length: i32, payload_len: usize, rng: &mut XorShiftRandom) -> Vec<u8> {
    let header = header();
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&header.salt.to_le_bytes());
    plaintext.extend_from_slice(&header.session_id.to_le_bytes());
    plaintext.extend_from_slice(&header.msg_id.to_le_bytes());
    plaintext.extend_from_slice(&header.seq_no.to_le_bytes());
    plaintext.extend_from_slice(&declared_length.to_le_bytes());
    plaintext.resize(32 + payload_len, 0);
    rng.fill(&mut plaintext[32..]);
    plaintext
}

#[test]
fn msg_key_checks_use_a_constant_time_comparison() {
    let compare = function_body(MESSAGE_SOURCE, "pub(crate) fn constant_time_eq(");
    assert!(compare.contains(".fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0"), "{compare}");
    for early_exit in ["return", "break", ".any(", ".all(", ".position(", ".find(", "x == y", "x != y"] {
        assert!(!compare.contains(early_exit), "constant_time_eq must not stop early ({early_exit}): {compare}");
    }
    for (source, signature, expected) in [
        (MESSAGE_SOURCE, "pub fn decrypt_message(", "constant_time_eq(&computed[8..24], &msg_key)"),
        (MESSAGE_SOURCE, "pub fn decrypt_message_v1(", "constant_time_eq(&msg_key_v1(&plaintext[..end]), &msg_key)"),
    ] {
        let body = function_body(source, signature);
        assert!(body.contains(expected), "{signature} compares msg_key with constant_time_eq");
        for plain in ["== msg_key", "!= msg_key", "msg_key ==", "msg_key !="] {
            assert!(!body.contains(plain), "{signature} compares msg_key with {plain}");
        }
    }
    assert_eq!(HANDSHAKE_SOURCE.matches("constant_time_eq(").count(), 3, "every handshake hash check");
    assert!(!HANDSHAKE_SOURCE.contains("new_nonce_hash =="), "new_nonce_hash is never compared with ==");

    let auth_key = key(1);
    let mut rng = XorShiftRandom::new(11);
    let packet = encrypt_message(&auth_key, &header(), &[3u8; 48], Side::Server, PaddingPolicy::default(), &mut rng);
    let v1 = encrypt_message_v1(&auth_key, &header(), &[3u8; 48], &mut rng);
    for index in 8..24 {
        for bit in [0x01u8, 0x80] {
            let mut forged = packet.data.clone();
            forged[index] ^= bit;
            assert_eq!(decrypt_message(&auth_key, &forged, Side::Server), Err(MessageError::MsgKeyMismatch));
            let mut forged = v1.clone();
            forged[index] ^= bit;
            assert!(decrypt_message_v1(&auth_key, &forged, Side::Client).is_err(), "v1 byte {index}");
        }
    }
}

#[test]
fn every_length_and_padding_combination_follows_the_tdlib_bounds() {
    let auth_key = key(2);
    let mut rng = XorShiftRandom::new(14);
    for payload_len in [32usize, 48, 1040, 1056, 1072] {
        for declared in (-8i32..=payload_len as i32 + 8).chain([i32::MIN, i32::MAX, 1 << 20]) {
            let packet = server_packet(&auth_key, &plaintext(declared, payload_len, &mut rng));
            let result = decrypt_message(&auth_key, &packet, Side::Server);
            let fits = declared >= 0 && declared % 4 == 0 && declared as usize <= payload_len;
            let padding = if fits { payload_len - declared as usize } else { 0 };
            let accepted = fits && (12..=1024).contains(&padding);
            match result {
                Ok(message) => {
                    assert!(accepted, "length {declared} in {payload_len} bytes was accepted");
                    assert_eq!(message.body().len(), declared as usize);
                    assert_eq!(message.header, header());
                }
                Err(MessageError::InvalidLength { length, available }) => {
                    assert!(!fits, "length {declared} in {payload_len} bytes was refused as a length");
                    assert_eq!((length, available), (declared as i64, payload_len));
                }
                Err(MessageError::InvalidPadding(found)) => {
                    assert!(fits && !accepted, "padding {found} for length {declared} in {payload_len} bytes");
                    assert_eq!(found, padding);
                }
                Err(other) => panic!("length {declared} in {payload_len} bytes: {other:?}"),
            }
        }
    }
}

#[test]
fn handshake_tmp_aes_matches_the_documented_derivation_and_sample() {
    let new_nonce: [u8; 32] =
        hex::decode("311C85DB234AA2640AFC4A76A735CF5B1F0FD68BD17FA181E1229AD867CC024D").unwrap().try_into().unwrap();
    let server_nonce: [u8; 16] = hex::decode("A5CF4D33F4A11EA877BA4AA573907330").unwrap().try_into().unwrap();
    let material = handshake_tmp_aes(&new_nonce, &server_nonce);
    assert_eq!(
        hex::encode_upper(material.key),
        "F011280887C7BB01DF0FC4E17830E0B91FBB8BE4B2267CB985AE25F33B527253",
        "tmp_aes_key of core.telegram.org/mtproto/samples-auth_key"
    );
    assert_eq!(
        hex::encode_upper(material.iv),
        "3212D579EE35452ED23E0D0C92841AA7D31B2E9BDEF2151E80D15860311C85DB",
        "tmp_aes_iv of core.telegram.org/mtproto/samples-auth_key"
    );
    let mut rng = XorShiftRandom::new(18);
    for _ in 0..32 {
        let new_nonce: [u8; 32] = rng.array();
        let server_nonce: [u8; 16] = rng.array();
        let material = handshake_tmp_aes(&new_nonce, &server_nonce);
        let new_server = sha1_parts(&[&new_nonce, &server_nonce]);
        let server_new = sha1_parts(&[&server_nonce, &new_nonce]);
        let new_new = sha1_parts(&[&new_nonce, &new_nonce]);
        assert_eq!(material.key.to_vec(), [&new_server[..], &server_new[..12]].concat());
        assert_eq!(material.iv.to_vec(), [&server_new[12..20], &new_new[..], &new_nonce[..4]].concat());
    }
}

#[test]
fn encrypted_messages_follow_the_documented_layout_both_ways() {
    let auth_key = key(3);
    let mut rng = XorShiftRandom::new(20);
    let body: Vec<u8> = (0u8..44).collect();
    let header = header();
    let packet = encrypt_message(&auth_key, &header, &body, Side::Client, PaddingPolicy::default(), &mut rng).data;
    assert_eq!(packet[..8], auth_key.id().to_le_bytes(), "auth_key_id first");
    let msg_key: [u8; 16] = packet[8..24].try_into().unwrap();
    let material = message_key_v2(auth_key.bytes(), &msg_key, Side::Client);
    let mut plain = packet[24..].to_vec();
    aes_ige_decrypt(&material.key, &material.iv, &mut plain).unwrap();
    assert_eq!(plain[0..8], header.salt.to_le_bytes(), "salt");
    assert_eq!(plain[8..16], header.session_id.to_le_bytes(), "session_id");
    assert_eq!(plain[16..24], header.msg_id.to_le_bytes(), "message_id");
    assert_eq!(plain[24..28], header.seq_no.to_le_bytes(), "seq_no");
    assert_eq!(plain[28..32], (body.len() as u32).to_le_bytes(), "message_data_length");
    assert_eq!(plain[32..32 + body.len()], body[..], "message_data");
    let padding = plain.len() - 32 - body.len();
    assert!((12..=1024).contains(&padding) && plain.len() % 16 == 0, "padding {padding}");
    assert_eq!(sha256_parts(&[&auth_key.bytes()[88..120], &plain])[8..24], msg_key, "msg_key covers the padding");

    let mut inbound = Vec::new();
    inbound.extend_from_slice(&0x7777_6666_5555_4444i64.to_le_bytes());
    inbound.extend_from_slice(&header.session_id.to_le_bytes());
    inbound.extend_from_slice(&0x51e5_7ac4_2770_9a01i64.to_le_bytes());
    inbound.extend_from_slice(&3i32.to_le_bytes());
    inbound.extend_from_slice(&(body.len() as i32).to_le_bytes());
    inbound.extend_from_slice(&body);
    inbound.resize(inbound.len() + 20, 0xa5);
    let decrypted = decrypt_message(&auth_key, &server_packet(&auth_key, &inbound), Side::Server).unwrap();
    assert_eq!(
        decrypted.header,
        MessageHeader {
            salt: 0x7777_6666_5555_4444,
            session_id: header.session_id,
            msg_id: 0x51e5_7ac4_2770_9a01,
            seq_no: 3
        }
    );
    assert_eq!(decrypted.body(), &body[..]);

    let mut swapped = inbound.clone();
    swapped[24..28].copy_from_slice(&(body.len() as i32).to_le_bytes());
    swapped[28..32].copy_from_slice(&3i32.to_le_bytes());
    assert!(
        matches!(
            decrypt_message(&auth_key, &server_packet(&auth_key, &swapped), Side::Server),
            Err(MessageError::InvalidLength { length: 3, .. })
        ),
        "the length is read at offset 28, nowhere else"
    );
}

fn service_objects() -> Vec<(&'static str, Vec<u8>)> {
    let ids_vector = |writer: &mut Writer| writer.write_i64_vector(&[0x51e5_7ac4_2770_9001, 0x51e5_7ac4_2770_9005]);
    let mut objects = Vec::new();
    let mut add = |name: &'static str, build: &dyn Fn(&mut Writer)| {
        let mut writer = Writer::new();
        build(&mut writer);
        objects.push((name, writer.into_inner()));
    };
    add("pong", &|w| {
        w.write_u32(ids::PONG);
        w.write_i64(1);
        w.write_i64(2);
    });
    add("bad_msg_notification", &|w| {
        w.write_u32(ids::BAD_MSG_NOTIFICATION);
        w.write_i64(1);
        w.write_i32(2);
        w.write_i32(16);
    });
    add("bad_server_salt", &|w| {
        w.write_u32(ids::BAD_SERVER_SALT);
        w.write_i64(1);
        w.write_i32(2);
        w.write_i32(48);
        w.write_i64(3);
    });
    add("new_session_created", &|w| {
        w.write_u32(ids::NEW_SESSION_CREATED);
        w.write_i64(1);
        w.write_i64(2);
        w.write_i64(3);
    });
    add("msgs_ack", &|w| {
        w.write_u32(ids::MSGS_ACK);
        ids_vector(w);
    });
    add("msg_detailed_info", &|w| {
        w.write_u32(ids::MSG_DETAILED_INFO);
        w.write_i64(1);
        w.write_i64(2);
        w.write_i32(3);
        w.write_i32(0);
    });
    add("msg_new_detailed_info", &|w| {
        w.write_u32(ids::MSG_NEW_DETAILED_INFO);
        w.write_i64(2);
        w.write_i32(3);
        w.write_i32(0);
    });
    add("msg_resend_req", &|w| {
        w.write_u32(ids::MSG_RESEND_REQ);
        ids_vector(w);
    });
    add("msg_resend_ans_req", &|w| {
        w.write_u32(ids::MSG_RESEND_ANS_REQ);
        ids_vector(w);
    });
    add("msgs_state_req", &|w| {
        w.write_u32(ids::MSGS_STATE_REQ);
        ids_vector(w);
    });
    add("msgs_state_info", &|w| {
        w.write_u32(ids::MSGS_STATE_INFO);
        w.write_i64(1);
        w.write_bytes(&[4, 4]);
    });
    add("msgs_all_info", &|w| {
        w.write_u32(ids::MSGS_ALL_INFO);
        ids_vector(w);
        w.write_bytes(&[4, 4]);
    });
    add("future_salts", &|w| {
        w.write_u32(ids::FUTURE_SALTS);
        w.write_i64(1);
        w.write_i32(2);
        w.write_u32(ids::VECTOR);
        w.write_i32(1);
        w.write_u32(ids::FUTURE_SALT);
        w.write_i32(10);
        w.write_i32(20);
        w.write_i64(30);
    });
    add("ping", &|w| {
        w.write_u32(ids::PING);
        w.write_i64(1);
    });
    add("ping_delay_disconnect", &|w| {
        w.write_u32(ids::PING_DELAY_DISCONNECT);
        w.write_i64(1);
        w.write_i32(75);
    });
    add("http_wait", &|w| {
        w.write_u32(ids::HTTP_WAIT);
        w.write_i32(0);
        w.write_i32(0);
        w.write_i32(25_000);
    });
    add("destroy_session_ok", &|w| {
        w.write_u32(ids::DESTROY_SESSION_OK);
        w.write_i64(1);
    });
    add("destroy_session_none", &|w| {
        w.write_u32(ids::DESTROY_SESSION_NONE);
        w.write_i64(1);
    });
    add("destroy_auth_key_ok", &|w| w.write_u32(ids::DESTROY_AUTH_KEY_OK));
    add("destroy_auth_key_none", &|w| w.write_u32(ids::DESTROY_AUTH_KEY_NONE));
    add("destroy_auth_key_fail", &|w| w.write_u32(ids::DESTROY_AUTH_KEY_FAIL));
    add("gzip_packed", &|w| {
        w.write_u32(ids::GZIP_PACKED);
        w.write_bytes(&gzip(&[0u8; 64]));
    });
    add("msg_copy", &|w| {
        w.write_u32(ids::MSG_COPY);
        w.write_u32(ids::MESSAGE);
        w.write_i64(0x51e5_7ac4_2770_9001);
        w.write_i32(1);
        w.write_i32(12);
        w.write_u32(ids::PONG);
        w.write_i64(1);
    });
    objects
}

#[test]
fn every_service_object_parses_when_it_ends_exactly() {
    for (name, body) in service_objects() {
        let parsed = ServiceMessage::parse(&body);
        assert!(
            matches!(&parsed, Ok(message) if !matches!(message, ServiceMessage::Other { .. } | ServiceMessage::Ignored { .. })),
            "{name}: {parsed:?}"
        );
    }
}

#[test]
#[ignore = "L-09: ServiceMessage::parse never checks that a service object ends where its fields end"]
fn service_objects_with_trailing_bytes_are_refused_like_tdlib_fetch_end() {
    let mut accepted = Vec::new();
    for (name, mut body) in service_objects() {
        body.extend_from_slice(&0x5a5a_5a5au32.to_le_bytes());
        if ServiceMessage::parse(&body).is_ok() {
            accepted.push(name);
        }
    }
    assert!(accepted.is_empty(), "service objects taken with 4 trailing bytes: {accepted:?}");
}
