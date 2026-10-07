//! H-03 and K-16: secrets are wiped before their memory goes back to the allocator. The scanning allocator in
//! support/freed_memory.rs looks for each watched secret in every heap block as it is freed or moved.

#[path = "support/freed_memory.rs"]
mod freed_memory;

use base64::Engine as _;
use mtproto_core::Zeroize;
use mtproto_core::crypto::{AesCtr, SecureRandom, XorShiftRandom, handshake_tmp_aes, sha256_parts};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeError, HandshakeResult, HandshakeStep};
use mtproto_core::message::decode_plain_message;
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_core::tl::mtproto::ResPq;
use mtproto_core::tl::{Reader, TlRead};
use mtproto_core::transport::{
    Framing, HttpCredentials, HttpRoute, InputBuffer, ProxySecret, Socks5Auth, Socks5Handshake, Socks5Progress,
    Socks5Target, TransportConfig, TransportStream, obfuscated_init, server_hello_for_tests, write_post_head,
};

const NOW: f64 = 1_727_000_000.0;

fn pattern<const N: usize>(seed: u8) -> [u8; N] {
    core::array::from_fn(|index| seed.wrapping_add((index as u8).wrapping_mul(29)) ^ 0x5c)
}

#[test]
fn the_freed_memory_scanner_finds_secrets_freed_without_wiping() {
    let secret: [u8; 32] = pattern(1);
    let key: [u8; 32] = pattern(2);
    let mut watch = freed_memory::watch();
    watch.secret("secret", &secret);
    watch.secret("cipher key", &key);
    let mut wiped = secret.to_vec();
    let unwiped = secret.to_vec();
    let mut grown = Vec::with_capacity(32);
    grown.extend_from_slice(&secret);
    let cipher = AesCtr::new(&key, &[0u8; 16]);
    watch.arm();

    wiped.zeroize();
    drop(wiped);
    drop(cipher);
    assert!(watch.found().is_empty(), "wiped buffers and ciphers are clean: {:?}", watch.found());

    drop(unwiped);
    assert_eq!(watch.found(), ["secret"], "a buffer freed without wiping is found");
    watch.clear_hits();

    grown.reserve(64 * 1024);
    assert_eq!(watch.found(), ["secret"], "a buffer moved by a reallocation is found");
    watch.clear_hits();
    grown.zeroize();
    drop(grown);

    let live = AesCtr::new(&key, &[0u8; 16]);
    freed_memory::free_unwiped_copy(&live);
    assert_eq!(watch.found(), ["cipher key"], "an unwiped copy of a cipher reveals its key");
    watch.stop();
    drop(live);
}

fn proxy_key_leaks(forms: &[(&'static str, String)], key: &[u8; 16]) -> Vec<&'static str> {
    let mut leaks = Vec::new();
    for (form, text) in forms {
        let mut watch = freed_memory::watch();
        watch.secret("proxy key", key);
        watch.arm();
        let secret = ProxySecret::from_link(text, false).expect("valid secret");
        let copy = secret.clone();
        let binary = ProxySecret::from_binary(secret.raw(), false).expect("valid secret");
        drop(copy);
        drop(binary);
        drop(secret);
        watch.stop();
        if !watch.found().is_empty() {
            leaks.push(*form);
        }
    }
    leaks
}

fn link_key() -> [u8; 16] {
    core::array::from_fn(|index| 0x10u8.wrapping_add(index as u8 * 7))
}

#[test]
fn proxy_secrets_leave_no_copy_in_freed_memory() {
    let key = link_key();
    let padded = [&[0xddu8][..], &key].concat();
    let fake_tls = [&[0xeeu8][..], &key, b"www.example.com"].concat();
    let forms = [
        ("hex", fake_tls.iter().map(|byte| format!("{byte:02x}")).collect()),
        ("padded hex", padded.iter().map(|byte| format!("{byte:02x}")).collect()),
        ("base64url", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&padded)),
        ("base64url fake-TLS", base64::engine::general_purpose::URL_SAFE.encode(&fake_tls)),
    ];
    let leaks = proxy_key_leaks(&forms, &key);
    assert!(leaks.is_empty(), "a proxy key parsed from these link forms is left in freed memory: {leaks:?}");
}

#[test]
#[ignore = "H-03: ProxySecret::from_link tries URL-safe base64 first; a standard-base64 secret fails it late and the partly decoded key is freed unwiped"]
fn a_standard_base64_proxy_secret_leaves_no_partial_decoding_in_freed_memory() {
    let key = link_key();
    let fake_tls = [&[0xeeu8][..], &key, b"telegram.com>"].concat();
    let standard = base64::engine::general_purpose::STANDARD.encode(&fake_tls);
    assert!(standard.trim_end_matches('=').ends_with('+'), "{standard}: only the URL-safe decoding fails, late");
    let leaks = proxy_key_leaks(&[("base64", standard)], &key);
    assert!(leaks.is_empty(), "a proxy key parsed from these link forms is left in freed memory: {leaks:?}");
}

#[test]
fn obfuscation_keys_and_keystreams_leave_no_copy_in_freed_memory() {
    let secret: [u8; 16] = pattern(3);
    let mut rng = XorShiftRandom::new(3);
    let mut watch = freed_memory::watch();
    let init = Box::new(obfuscated_init(Framing::PaddedIntermediate, 2, Some(&secret), false, &mut rng));
    let mut reversed = init.header;
    reversed.reverse();
    let encrypt_key = sha256_parts(&[&init.header[8..40], &secret]);
    let decrypt_key = sha256_parts(&[&reversed[8..40], &secret]);
    let mut keystream = [0u8; 128];
    AesCtr::new(&encrypt_key, &init.header[40..56].try_into().unwrap()).apply(&mut keystream);
    watch.secret("encrypt key", &encrypt_key);
    watch.secret("decrypt key", &decrypt_key);
    watch.secret("unused keystream", &keystream[64..]);
    watch.arm();
    drop(init);
    watch.stop();
    assert!(watch.found().is_empty(), "obfuscation state left in freed memory: {:?}", watch.found());
}

#[test]
fn a_transport_stream_leaves_no_proxy_secret_or_obfuscation_key_in_freed_memory() {
    let secret: [u8; 16] = pattern(5);
    let mut rng = XorShiftRandom::new(5);
    let config = TransportConfig {
        framing: Framing::Intermediate,
        dc_id: 2,
        secret: Some(ProxySecret::from_binary(&[&[0xddu8][..], &secret].concat(), false).unwrap()),
        unix_time: NOW as i32,
    };
    let mut stream = Box::new(TransportStream::new(&config, &mut rng));
    stream.send_packet(&[7u8; 64], false, &mut rng);
    let header: [u8; 64] = stream.outgoing()[..64].try_into().unwrap();
    let mut reversed = header;
    reversed.reverse();
    let mut watch = freed_memory::watch();
    watch.secret("proxy secret", &secret);
    watch.secret("stream encrypt key", &sha256_parts(&[&header[8..40], &secret]));
    watch.secret("stream decrypt key", &sha256_parts(&[&reversed[8..40], &secret]));
    watch.arm();
    stream.receive(&[0x33u8; 40]).unwrap();
    drop(stream.take_outgoing());
    drop(stream);
    drop(config);
    watch.stop();
    assert!(watch.found().is_empty(), "transport stream secrets left in freed memory: {:?}", watch.found());
}

#[test]
#[ignore = "H-03: a fake-TLS TransportStream keeps a copy of the proxy key in TlsState and frees it unwiped"]
fn a_fake_tls_stream_leaves_no_proxy_key_in_freed_memory() {
    let key: [u8; 16] = pattern(4);
    let mut raw = vec![0xeeu8];
    raw.extend_from_slice(&key);
    raw.extend_from_slice(b"www.example.com");
    let config = TransportConfig {
        framing: Framing::Intermediate,
        dc_id: 2,
        secret: Some(ProxySecret::from_binary(&raw, false).unwrap()),
        unix_time: NOW as i32,
    };
    let mut leaks = Vec::new();
    for established in [false, true] {
        let mut rng = XorShiftRandom::new(4);
        let mut stream = Box::new(TransportStream::new(&config, &mut rng));
        let hello = stream.take_outgoing();
        let answer = server_hello_for_tests(&hello, &key, &mut rng);
        let mut watch = freed_memory::watch();
        watch.secret("proxy key", &key);
        watch.arm();
        if established {
            stream.receive(&answer).unwrap();
            assert!(stream.is_ready());
        }
        drop(stream);
        watch.stop();
        if !watch.found().is_empty() {
            leaks.push(if established { "after the server hello" } else { "waiting for the server hello" });
        }
        drop(hello);
        drop(answer);
    }
    assert!(leaks.is_empty(), "proxy key left in freed memory by a stream dropped {leaks:?}");
}

#[test]
#[ignore = "H-03: Socks5Auth has no Drop, so the SOCKS5 password the handshake keeps is freed unwiped"]
fn socks5_credentials_leave_no_copy_in_freed_memory() {
    let password = "correct-horse-battery-staple".to_string();
    let mut watch = freed_memory::watch();
    watch.secret("socks5 password", password.as_bytes());
    let target = Socks5Target::Ipv4([149, 154, 167, 51], 443);
    let auth = Socks5Auth { username: "user".into(), password };
    watch.arm();
    let (mut handshake, greeting) = Socks5Handshake::new(target, Some(auth)).unwrap();
    drop(greeting);
    let mut input = InputBuffer::new();
    input.extend(&[5, 2]);
    let Socks5Progress::Send(mut request) = handshake.feed(&mut input).unwrap() else {
        panic!("the proxy asked for credentials");
    };
    request.zeroize();
    drop(request);
    drop(handshake);
    watch.stop();
    assert!(watch.found().is_empty(), "SOCKS5 password left in freed memory");
}

#[test]
#[ignore = "H-03: HttpCredentials::header_value builds `user:password` and its Basic encoding in Strings freed unwiped"]
fn http_proxy_credentials_leave_no_copy_in_freed_memory() {
    let password = "correct-horse-battery-staple".to_string();
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("user:{password}"));
    let mut watch = freed_memory::watch();
    watch.secret("http proxy password", password.as_bytes());
    watch.secret("basic credentials", basic.as_bytes());
    let route = HttpRoute::Forwarded {
        authority: "149.154.167.51:80".into(),
        credentials: Some(HttpCredentials { username: "user".into(), password }),
    };
    watch.arm();
    let mut head = Vec::new();
    write_post_head(&route, 64, &mut head);
    assert!(head.windows(basic.len()).any(|window| window == basic.as_bytes()), "the header is written");
    head.zeroize();
    drop(head);
    drop(route);
    watch.stop();
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

struct RecordingRandom {
    inner: XorShiftRandom,
    draws32: [[u8; 32]; 8],
    count32: usize,
    draws256: [[u8; 256]; 4],
    count256: usize,
}

impl RecordingRandom {
    fn new(seed: u64) -> Self {
        Self {
            inner: XorShiftRandom::new(seed),
            draws32: [[0; 32]; 8],
            count32: 0,
            draws256: [[0; 256]; 4],
            count256: 0,
        }
    }
}

impl SecureRandom for RecordingRandom {
    fn fill(&mut self, buffer: &mut [u8]) {
        self.inner.fill(buffer);
        if buffer.len() == 32 && self.count32 < self.draws32.len() {
            self.draws32[self.count32].copy_from_slice(buffer);
            self.count32 += 1;
        }
        if buffer.len() == 256 && self.count256 < self.draws256.len() {
            self.draws256[self.count256].copy_from_slice(buffer);
            self.count256 += 1;
        }
    }
}

struct Exchange {
    result: HandshakeResult,
    server_nonce: [u8; 16],
    rng: RecordingRandom,
}

fn exchange(seed: u64, watch: Option<&freed_memory::Watch>) -> Exchange {
    let arm = || {
        if let Some(watch) = watch {
            watch.arm();
        }
    };
    let stop = || {
        if let Some(watch) = watch {
            watch.stop();
        }
    };
    let mut rng = RecordingRandom::new(seed);
    let mut server_rng = XorShiftRandom::new(seed ^ 0x5555);
    let mut server = ServerHandshake::new(ServerHandshakeBehavior { server_time: NOW as i32, ..Default::default() });
    let config = HandshakeConfig { dc_id: 2, temp_key_expires_in: None, public_keys: vec![server.public_key()] };
    arm();
    let (client, mut packet) = Handshake::start(config, NOW, &mut rng);
    let mut client = Box::new(client);
    stop();
    let mut server_nonce = None;
    for _ in 0..8 {
        let reply = server.handle(&packet, &mut server_rng).expect("server reply");
        if server_nonce.is_none() {
            let body = decode_plain_message(&reply).unwrap().body;
            server_nonce = Some(ResPq::read_from(&mut Reader::new(body)).unwrap().server_nonce);
        }
        arm();
        let step = client.on_packet(&reply, NOW, None, &mut rng).expect("handshake step");
        stop();
        match step {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(result) => {
                arm();
                drop(client);
                drop(packet);
                stop();
                return Exchange { result, server_nonce: server_nonce.unwrap(), rng };
            }
        }
    }
    panic!("the handshake did not finish");
}

fn new_nonce(exchange: &Exchange) -> [u8; 32] {
    let salt = exchange.result.server_salt.to_le_bytes();
    *exchange.rng.draws32[..exchange.rng.count32]
        .iter()
        .find(|draw| (0..8).all(|index| draw[index] ^ exchange.server_nonce[index] == salt[index]))
        .expect("new_nonce is one of the 32-byte draws")
}

#[test]
#[ignore = "K-16: new_nonce stays behind in the handshake's memory when the state moves (mem::replace) and is freed unwiped"]
fn after_dh_gen_ok_no_new_nonce_or_tmp_aes_is_left_in_freed_memory() {
    let first = exchange(16, None);
    let new_nonce = new_nonce(&first);
    let tmp = handshake_tmp_aes(&new_nonce, &first.server_nonce);
    let mut watch = freed_memory::watch();
    watch.secret("new_nonce", &new_nonce);
    watch.secret("tmp_aes_key", &tmp.key);
    watch.secret("tmp_aes_iv", &tmp.iv);
    watch.secret("auth_key", first.result.auth_key.bytes());
    let second = exchange(16, Some(&watch));
    assert_eq!(second.result.auth_key, first.result.auth_key, "the two runs agree");
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

#[test]
#[ignore = "K-16: the DH exponent b and the shared key g_a^b are num-bigint values, freed unwiped"]
fn after_dh_gen_ok_no_dh_exponent_or_shared_key_number_is_left_in_freed_memory() {
    let first = exchange(17, None);
    assert!(first.rng.count256 >= 1, "b was drawn");
    let mut watch = freed_memory::watch();
    for draw in &first.rng.draws256[..first.rng.count256] {
        watch.big_number("b", draw);
    }
    watch.big_number("g_a^b", first.result.auth_key.bytes());
    let second = exchange(17, Some(&watch));
    assert_eq!(second.result.auth_key, first.result.auth_key, "the two runs agree");
    assert!(watch.found().is_empty(), "left in freed memory: {:?}", watch.found());
}

#[test]
fn a_finished_handshake_acts_on_nothing_more() {
    let mut rng = XorShiftRandom::new(18);
    let mut server = ServerHandshake::new(ServerHandshakeBehavior { server_time: NOW as i32, ..Default::default() });
    let config = HandshakeConfig { dc_id: 2, temp_key_expires_in: None, public_keys: vec![server.public_key()] };
    let (mut client, mut packet) = Handshake::start(config, NOW, &mut rng);
    let mut replies = Vec::new();
    loop {
        let reply = server.handle(&packet, &mut rng).expect("server reply");
        replies.push(reply.clone());
        match client.on_packet(&reply, NOW, None, &mut rng).unwrap() {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(_) => break,
        }
    }
    for reply in &replies {
        assert_eq!(
            client.on_packet(reply, NOW, None, &mut rng).err(),
            Some(HandshakeError::UnexpectedMessage("done")),
            "a finished handshake keeps no state to act on"
        );
    }
}
