use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mtproto_core::crypto::{OsRandom, RsaPublicKey, Side};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeStep};
use mtproto_core::message::{MessageHeader, PaddingPolicy, decrypt_message, encrypt_message};
use mtproto_core::msg_id::{MsgIdGenerator, SeqNoGenerator};
use mtproto_core::tl::Writer;
use mtproto_core::tl::mtproto::{ServiceMessage, write_ping};
use mtproto_core::transport::{Framing, Incoming, TransportConfig, TransportStream};

const TEST_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAyMEdY1aR+sCR3ZSJrtztKTKqigvO/vBfqACJLZtS7QMgCGXJ6XIR\nyy7mx66W0/sOFa7/1mAZtEoIokDP3ShoqF4fVNb6XeqgQfaUHd8wJpDWHcR2OFwv\nplUUI1PLTktZ9uW2WE23b+ixNwJjJGwBDJPQEQFBE+vfmH0JP503wr5INS1poWg/\nj25sIWeYPHYeOrFp/eXaqhISP6G+q2IeTaWTXpwZj4LzXq5YOpk4bYEQ6mvRq7D1\naHWfYmlEGepfaYR8Q0YqvvhYtMte3ITnuSJs171+GDqpdKcSwHnd6FudwGO4pcCO\nj4WcDuXc2CTHgH8gFTNhp/Y8/SpDOhvn9QIDAQAB\n-----END RSA PUBLIC KEY-----";
const PROD_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----";

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

fn read_packet(socket: &mut TcpStream, stream: &mut TransportStream) -> Vec<u8> {
    let mut buffer = [0u8; 65536];
    loop {
        match stream.next_incoming().expect("frame") {
            Some(Incoming::Packet(packet)) => return packet,
            Some(Incoming::TransportError(code)) => panic!("transport error {code}"),
            Some(other) => println!("  incoming {other:?}"),
            None => {
                let read = socket.read(&mut buffer).expect("read");
                assert!(read > 0, "connection closed");
                stream.receive(&buffer[..read]).expect("receive");
            }
        }
    }
}

fn probe(
    label: &str,
    address: &str,
    dc_id: i32,
    obfuscation_dc: i16,
    key_pem: &str,
    temp: Option<i32>,
    framing: Framing,
) {
    println!("== {label} ({address}, dc {dc_id}, temp={temp:?}, {framing:?})");
    let started = Instant::now();
    let mut rng = OsRandom::new();
    let mut socket = TcpStream::connect(address).expect("connect");
    socket.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    socket.set_nodelay(true).unwrap();
    let mut stream = TransportStream::new(
        &TransportConfig { framing, dc_id: obfuscation_dc, secret: None, unix_time: unix_now() as i32 },
        &mut rng,
    );
    let config = HandshakeConfig {
        dc_id,
        temp_key_expires_in: temp,
        public_keys: vec![RsaPublicKey::from_pem(key_pem).unwrap()],
    };
    let (mut handshake, mut packet) = Handshake::start(config, unix_now(), &mut rng);
    let result = loop {
        stream.send_packet(&packet, false, &mut rng);
        socket.write_all(&stream.take_outgoing()).unwrap();
        let reply = read_packet(&mut socket, &mut stream);
        match handshake.on_packet(&reply, unix_now(), None, &mut rng).expect("handshake step") {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(result) => break result,
        }
    };
    println!(
        "  auth key {:?} in {:?}, salt {:#x}, time difference {:.3}s, expires_at {:?}",
        result.auth_key,
        started.elapsed(),
        result.server_salt,
        result.time_difference,
        result.expires_at
    );

    let session_id: i64 = rand_i64();
    let mut msg_ids = MsgIdGenerator::new();
    msg_ids.reset_floor(handshake.last_msg_id());
    let mut seq = SeqNoGenerator::new();
    let ping_id = rand_i64();
    let mut body = Writer::new();
    write_ping(&mut body, ping_id);
    let msg_id = msg_ids.next(unix_now() + result.time_difference);
    let header = MessageHeader { salt: result.server_salt, session_id, msg_id, seq_no: seq.next(true) };
    let encrypted =
        encrypt_message(&result.auth_key, &header, body.as_slice(), Side::Client, PaddingPolicy::default(), &mut rng);
    let ping_started = Instant::now();
    stream.send_packet(&encrypted.data, true, &mut rng);
    socket.write_all(&stream.take_outgoing()).unwrap();
    for _ in 0..4 {
        let reply = read_packet(&mut socket, &mut stream);
        let decrypted = decrypt_message(&result.auth_key, &reply, Side::Server).expect("decrypt server message");
        assert_eq!(decrypted.header.session_id, session_id);
        assert_eq!(decrypted.header.msg_id & 1, 1, "server msg_id must be odd");
        let messages = match ServiceMessage::parse(decrypted.body()).expect("parse") {
            ServiceMessage::Container(items) => {
                items.iter().map(|m| ServiceMessage::parse(m.body).unwrap().clone_shape()).collect()
            }
            other => vec![other.clone_shape()],
        };
        for message in &messages {
            println!("  <- {message}");
        }
        if messages.iter().any(|m| m.starts_with("Pong") && m.contains(&format!("ping_id: {ping_id}"))) {
            println!("  pong verified in {:?} (msg_id {:#x})", ping_started.elapsed(), msg_id);
            return;
        }
    }
    panic!("no pong");
}

trait Shape {
    fn clone_shape(&self) -> String;
}

impl Shape for ServiceMessage<'_> {
    fn clone_shape(&self) -> String {
        match self {
            ServiceMessage::Other { constructor, body } => format!("Other({constructor:#010x}, {} bytes)", body.len()),
            other => format!("{other:?}"),
        }
    }
}

fn rand_i64() -> i64 {
    use mtproto_core::crypto::SecureRandom;
    OsRandom::new().next_u64() as i64
}

fn main() {
    probe("test DC2", "149.154.167.40:443", 10002, 10002, TEST_KEY, None, Framing::Abridged);
    probe("test DC2 temp key", "149.154.167.40:443", 10002, 10002, TEST_KEY, Some(3600), Framing::Intermediate);
    probe("production DC2", "149.154.167.51:443", 2, 2, PROD_KEY, None, Framing::PaddedIntermediate);
    probe("production DC4 temp key", "149.154.167.91:443", 4, 4, PROD_KEY, Some(86400), Framing::Abridged);
}
