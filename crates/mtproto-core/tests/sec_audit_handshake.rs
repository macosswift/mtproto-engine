use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeError, HandshakeStep};
use mtproto_core::message::{MessageError, encode_plain_message};
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};

const NOW: f64 = 1_727_000_000.0;

fn behavior() -> ServerHandshakeBehavior {
    ServerHandshakeBehavior { server_time: NOW as i32 + 10, ..Default::default() }
}

fn config(server: &ServerHandshake) -> HandshakeConfig {
    HandshakeConfig { dc_id: 2, temp_key_expires_in: None, public_keys: vec![server.public_key()] }
}

/// Every server answer of one complete key exchange, in order.
fn recorded_answers(seed: u64) -> Vec<Vec<u8>> {
    let mut rng = XorShiftRandom::new(seed);
    let mut server = ServerHandshake::new(behavior());
    let (mut client, mut packet) = Handshake::start(config(&server), NOW, &mut rng);
    let mut answers = Vec::new();
    loop {
        let reply = server.handle(&packet, &mut rng).expect("server reply");
        answers.push(reply.clone());
        match client.on_packet(&reply, NOW, None, &mut rng).expect("handshake step") {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(_) => return answers,
        }
    }
}

#[test]
fn answers_recorded_from_an_earlier_exchange_are_refused_at_every_step() {
    let old = recorded_answers(1);
    assert_eq!(old.len(), 3);
    for (step, recorded) in old.iter().enumerate() {
        let mut rng = XorShiftRandom::new(1000 + step as u64);
        let mut server = ServerHandshake::new(behavior());
        let (mut client, mut packet) = Handshake::start(config(&server), NOW, &mut rng);
        for _ in 0..step {
            let reply = server.handle(&packet, &mut rng).expect("server reply");
            match client.on_packet(&reply, NOW, None, &mut rng).expect("genuine step") {
                HandshakeStep::Send(next) => packet = next,
                HandshakeStep::Done(_) => panic!("finished early"),
            }
        }
        let error = match client.on_packet(recorded, NOW, None, &mut rng) {
            Err(error) => error,
            Ok(_) => panic!("step {step}: a recorded answer was accepted"),
        };
        assert!(
            matches!(error, HandshakeError::NonceMismatch | HandshakeError::ServerNonceMismatch),
            "step {step}: {error:?}"
        );
    }
}

#[test]
fn a_failed_exchange_cannot_be_resumed_by_a_later_genuine_answer() {
    let mut rng = XorShiftRandom::new(7);
    let mut server = ServerHandshake::new(behavior());
    let (mut client, packet) = Handshake::start(config(&server), NOW, &mut rng);
    let genuine = server.handle(&packet, &mut rng).expect("res_pq");
    assert!(client.on_packet(&encode_plain_message(5, &[0u8; 64]), NOW, None, &mut rng).is_err());
    assert_eq!(
        client.on_packet(&genuine, NOW, None, &mut rng).err(),
        Some(HandshakeError::UnexpectedMessage("done")),
        "an exchange ends at its first bad message"
    );
}

#[test]
fn handshake_messages_must_be_plain() {
    let mut rng = XorShiftRandom::new(8);
    let mut server = ServerHandshake::new(behavior());
    let (mut client, packet) = Handshake::start(config(&server), NOW, &mut rng);
    let mut reply = server.handle(&packet, &mut rng).expect("res_pq");
    reply[0] ^= 1;
    assert_eq!(
        client.on_packet(&reply, NOW, None, &mut rng).err(),
        Some(HandshakeError::Message(MessageError::NotPlain))
    );
}

#[test]
fn every_exchange_draws_fresh_nonces_and_keys() {
    let mut keys = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    for seed in 0..8u64 {
        let mut rng = XorShiftRandom::new(50 + seed);
        let mut server = ServerHandshake::new(behavior());
        let (mut client, mut packet) = Handshake::start(config(&server), NOW, &mut rng);
        assert!(nonces.insert(packet[20 + 4..20 + 4 + 16].to_vec()), "req_pq_multi nonce repeated");
        loop {
            let reply = server.handle(&packet, &mut rng).expect("server reply");
            match client.on_packet(&reply, NOW, None, &mut rng).expect("step") {
                HandshakeStep::Send(next) => packet = next,
                HandshakeStep::Done(result) => {
                    assert!(keys.insert(result.auth_key.id()), "auth key repeated");
                    break;
                }
            }
        }
    }
}
