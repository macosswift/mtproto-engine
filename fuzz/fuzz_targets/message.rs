#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, test_key};
use mtproto_core::crypto::{Side, XorShiftRandom};
use mtproto_core::message::{
    MessageHeader, PaddingPolicy, decode_plain_message, decrypt_message, decrypt_message_v1, encrypt_message,
};

fuzz_target!(|data: &[u8]| {
    let key = test_key();
    let mut cursor = Cursor::new(data);
    match cursor.u8() % 3 {
        0 => {
            let packet = cursor.rest();
            for side in [Side::Client, Side::Server] {
                assert!(decrypt_message(&key, packet, side).is_err(), "unsealed bytes decrypted");
                assert!(decrypt_message_v1(&key, packet, side).is_err(), "unsealed bytes decrypted (v1)");
            }
            if let Ok(plain) = decode_plain_message(packet) {
                assert!(plain.body.len() + 20 <= packet.len());
            }
        }
        1 => {
            let header = MessageHeader {
                salt: cursor.u64() as i64,
                session_id: cursor.u64() as i64,
                msg_id: cursor.u64() as i64,
                seq_no: cursor.u32() as i32,
            };
            let side = if cursor.bool() { Side::Client } else { Side::Server };
            let length = usize::from(cursor.u16()) / 4 * 4;
            let body = cursor.bytes(length).to_vec();
            let body = &body[..body.len() / 4 * 4];
            let mut rng = XorShiftRandom::new(u64::from(cursor.u32()) | 1);
            let packet = encrypt_message(&key, &header, body, side, PaddingPolicy::default(), &mut rng);
            let decrypted = decrypt_message(&key, &packet.data, side).expect("own packet decrypts");
            assert_eq!(decrypted.header, header);
            assert_eq!(decrypted.body(), body);
            let other = if side == Side::Client { Side::Server } else { Side::Client };
            assert!(decrypt_message(&key, &packet.data, other).is_err(), "the other direction's keys");
            let mut tampered = packet.data.clone();
            let at = cursor.below(tampered.len());
            tampered[at] ^= cursor.u8() | 1;
            assert!(decrypt_message(&key, &tampered, side).is_err(), "a flipped byte at {at} went unnoticed");
            if tampered.len() > 24 {
                let cut = 24 + cursor.below(tampered.len() - 24);
                assert!(decrypt_message(&key, &packet.data[..cut], side).is_err(), "truncated at {cut}");
            }
        }
        _ => {
            let header = MessageHeader { salt: 1, session_id: 2, msg_id: 3, seq_no: 4 };
            let body = vec![0u8; 16];
            let mut rng = XorShiftRandom::new(7);
            let packet = encrypt_message(&key, &header, &body, Side::Server, PaddingPolicy::default(), &mut rng);
            let mut forged = packet.data.clone();
            let tail = cursor.rest();
            let span = tail.len().min(forged.len() - 24);
            forged[24..24 + span].copy_from_slice(&tail[..span]);
            if forged != packet.data {
                assert!(decrypt_message(&key, &forged, Side::Server).is_err(), "forged ciphertext accepted");
            }
        }
    }
});
