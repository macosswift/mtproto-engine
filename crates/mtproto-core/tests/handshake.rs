use mtproto_core::crypto::{RsaPublicKey, XorShiftRandom};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeError, HandshakeStep};
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};

const NOW: f64 = 1_727_000_000.0;

fn run(
    behavior: ServerHandshakeBehavior,
    temp: Option<i32>,
    keys: Option<Vec<RsaPublicKey>>,
) -> Result<(mtproto_core::handshake::HandshakeResult, ServerHandshake), HandshakeError> {
    let mut rng = XorShiftRandom::new(99);
    let mut server = ServerHandshake::new(behavior);
    let config = HandshakeConfig {
        dc_id: 10002,
        temp_key_expires_in: temp,
        public_keys: keys.unwrap_or_else(|| vec![server.public_key()]),
    };
    let (mut client, mut packet) = Handshake::start(config, NOW, &mut rng);
    for _ in 0..20 {
        let reply = server.handle(&packet, &mut rng).expect("server reply");
        match client.on_packet(&reply, NOW, None, &mut rng)? {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(result) => return Ok((result, server)),
        }
    }
    panic!("handshake did not finish");
}

fn behavior() -> ServerHandshakeBehavior {
    ServerHandshakeBehavior { server_time: NOW as i32 + 1000, ..Default::default() }
}

#[test]
fn permanent_key_agreement() {
    let (result, server) = run(behavior(), None, None).unwrap();
    let outcome = server.outcome.unwrap();
    assert_eq!(result.auth_key, outcome.auth_key);
    assert_eq!(result.server_salt, outcome.server_salt);
    assert_eq!(outcome.dc, 10002);
    assert_eq!(outcome.expires_in, None);
    assert_eq!(result.expires_at, None);
    assert!((result.time_difference - 1000.0).abs() < 1e-9);
}

#[test]
fn temporary_key_agreement() {
    let (result, server) = run(behavior(), Some(86400), None).unwrap();
    let outcome = server.outcome.unwrap();
    assert_eq!(outcome.expires_in, Some(86400));
    assert_eq!(result.expires_at, Some(NOW as i32 + 1000 + 86400));
    assert_eq!(result.auth_key, outcome.auth_key);
}

#[test]
fn dh_gen_retry_is_followed() {
    let (result, server) = run(ServerHandshakeBehavior { retries_before_ok: 2, ..behavior() }, None, None).unwrap();
    assert_eq!(result.auth_key, server.outcome.unwrap().auth_key);
}

#[test]
fn too_many_retries_fail() {
    let error = run(ServerHandshakeBehavior { retries_before_ok: 10, ..behavior() }, None, None).unwrap_err();
    assert_eq!(error, HandshakeError::TooManyRetries);
}

#[test]
fn server_failures_are_reported() {
    assert_eq!(
        run(ServerHandshakeBehavior { fail_dh_gen: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::DhGenFail
    );
    assert_eq!(
        run(ServerHandshakeBehavior { fail_dh_params: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::ServerDhParamsFail
    );
}

#[test]
fn tampering_is_rejected() {
    assert_eq!(
        run(ServerHandshakeBehavior { wrong_nonce_in_res_pq: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::NonceMismatch
    );
    assert_eq!(
        run(ServerHandshakeBehavior { corrupt_answer_hash: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::BadEncryptedAnswer
    );
    assert!(matches!(
        run(ServerHandshakeBehavior { foreign_fingerprint: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::UnknownFingerprints(_)
    ));
    assert!(matches!(
        run(ServerHandshakeBehavior { bad_g: Some(9), ..behavior() }, None, None).unwrap_err(),
        HandshakeError::Dh(_)
    ));
    assert!(matches!(
        run(ServerHandshakeBehavior { small_g_a: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::Dh(_)
    ));
}

#[test]
fn unknown_server_key_is_rejected() {
    let production = RsaPublicKey::from_pem(
        "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----",
    )
    .unwrap();
    assert!(matches!(
        run(behavior(), None, Some(vec![production])).unwrap_err(),
        HandshakeError::UnknownFingerprints(_)
    ));
}

#[test]
fn server_dh_params_fail_with_bad_hash_is_reported_as_hash_mismatch() {
    assert_eq!(
        run(ServerHandshakeBehavior { fail_dh_params: true, corrupt_fail_hash: true, ..behavior() }, None, None)
            .unwrap_err(),
        HandshakeError::NewNonceHashMismatch
    );
}

#[test]
fn nonce_checks_cover_every_message() {
    assert_eq!(
        run(ServerHandshakeBehavior { wrong_server_nonce_in_dh_params: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::ServerNonceMismatch
    );
    assert_eq!(
        run(ServerHandshakeBehavior { wrong_nonce_in_inner_data: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::NonceMismatch
    );
    assert_eq!(
        run(ServerHandshakeBehavior { wrong_nonce_in_dh_gen: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::NonceMismatch
    );
}

#[test]
fn dh_gen_hash_mismatch_is_rejected() {
    assert_eq!(
        run(ServerHandshakeBehavior { corrupt_new_nonce_hash: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::NewNonceHashMismatch
    );
}

#[test]
fn encrypted_answer_shape_is_validated() {
    assert_eq!(
        run(ServerHandshakeBehavior { unaligned_encrypted_answer: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::BadEncryptedAnswer
    );
    assert_eq!(
        run(ServerHandshakeBehavior { excess_answer_padding: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::BadEncryptedAnswer
    );
}

#[test]
fn hostile_pq_values_fail_fast_without_hanging() {
    let started = std::time::Instant::now();
    for pq in [
        vec![],
        vec![0],
        vec![1],
        vec![3],
        vec![0x7f; 9],
        0xffff_ffff_ffff_ffc5u64.to_be_bytes().to_vec(),
        2_305_843_009_213_693_951u64.to_be_bytes().to_vec(),
    ] {
        let error =
            run(ServerHandshakeBehavior { pq_override: Some(pq.clone()), ..behavior() }, None, None).unwrap_err();
        assert!(matches!(error, HandshakeError::BadPq(_) | HandshakeError::FactorizationFailed), "{pq:?}: {error:?}");
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn non_safe_or_short_primes_are_rejected() {
    let mut composite = mtproto_core::crypto::KNOWN_DH_PRIME;
    composite[255] = 0xff;
    let g = (2..=7)
        .find(|&g| {
            let p = num_bigint_dig(&composite);
            match g {
                2 => p % 8 == 7,
                3 => p % 3 == 2,
                4 => true,
                5 => [1, 4].contains(&(p % 5)),
                6 => [19, 23].contains(&(p % 24)),
                _ => [3, 5, 6].contains(&(p % 7)),
            }
        })
        .unwrap();
    let error = run(
        ServerHandshakeBehavior { dh_prime_override: Some(composite.to_vec()), bad_g: Some(g), ..behavior() },
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(error, HandshakeError::Dh(_)), "{error:?}");
    let error =
        run(ServerHandshakeBehavior { dh_prime_override: Some(composite[1..].to_vec()), ..behavior() }, None, None)
            .unwrap_err();
    assert!(matches!(error, HandshakeError::Dh(_)), "{error:?}");
}

fn num_bigint_dig(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &byte| (acc * 256 + byte as u64) % 840)
}

#[test]
fn trailing_bytes_after_handshake_answers_are_tolerated_like_tdlib() {
    let (result, server) = run(ServerHandshakeBehavior { trailing_bytes: true, ..behavior() }, None, None).unwrap();
    assert_eq!(result.auth_key, server.outcome.unwrap().auth_key);
}

#[test]
fn unexpected_constructor_in_state_fails() {
    assert!(matches!(
        run(ServerHandshakeBehavior { repeat_res_pq: true, ..behavior() }, None, None).unwrap_err(),
        HandshakeError::Tl(_)
    ));
}

#[test]
fn handshake_never_panics_on_garbage() {
    use mtproto_core::message::encode_plain_message;
    let mut rng = XorShiftRandom::new(5);
    let server = ServerHandshake::new(behavior());
    for seed in 0..300u64 {
        let config = HandshakeConfig { dc_id: 2, temp_key_expires_in: None, public_keys: vec![server.public_key()] };
        let (mut client, _) = Handshake::start(config, NOW, &mut rng);
        let mut garbage = XorShiftRandom::new(seed);
        let length = (seed as usize * 7) % 700;
        let mut body = vec![0u8; length];
        mtproto_core::crypto::SecureRandom::fill(&mut garbage, &mut body);
        if seed % 3 == 0 && body.len() >= 4 {
            body[..4].copy_from_slice(&0x05162463u32.to_le_bytes());
        }
        let _ = client.on_packet(&encode_plain_message(5, &body), NOW, None, &mut rng);
        let _ = client.on_packet(&body, NOW, None, &mut rng);
    }
}
