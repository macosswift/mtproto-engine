use std::time::Instant;

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{OsRandom, Side, aes_ige_decrypt, sha256};
use mtproto_core::message::{MessageHeader, PaddingPolicy, decrypt_message, encrypt_message};

fn main() {
    let size = 64 * 1024 * 1024;
    let mut data = vec![7u8; size];
    let key = [1u8; 32];
    let iv = [2u8; 32];
    let started = Instant::now();
    aes_ige_decrypt(&key, &iv, &mut data).unwrap();
    let aes = size as f64 / started.elapsed().as_secs_f64() / 1e6;
    let started = Instant::now();
    let digest = sha256(&data);
    let sha = size as f64 / started.elapsed().as_secs_f64() / 1e6;
    let auth_key = AuthKey::new([3u8; 256]);
    let header = MessageHeader { salt: 1, session_id: 2, msg_id: 4, seq_no: 1 };
    let body = vec![9u8; 512 * 1024];
    let packet =
        encrypt_message(&auth_key, &header, &body, Side::Server, PaddingPolicy::default(), &mut OsRandom::new());
    let rounds = 128;
    let started = Instant::now();
    for _ in 0..rounds {
        let message = decrypt_message(&auth_key, &packet.data, Side::Server).unwrap();
        assert_eq!(message.body().len(), body.len());
    }
    let message_rate = (rounds * body.len()) as f64 / started.elapsed().as_secs_f64() / 1e6;
    println!(
        "aes-ige {aes:.0} MB/s, sha256 {sha:.0} MB/s, decrypt_message(512KB) {message_rate:.0} MB/s [{:x}]",
        digest[0]
    );
}
