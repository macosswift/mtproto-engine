use std::panic::{AssertUnwindSafe, catch_unwind};

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{SecureRandom, Side, XorShiftRandom, factorize_pq};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeStep};
use mtproto_core::message::{
    MessageHeader, PaddingPolicy, decode_plain_message, decrypt_message, decrypt_message_v1, encode_plain_message,
    encrypt_message,
};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::rpc::{
    ApiEnvironment, RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole, Verification,
};
use mtproto_core::session::{Now, QueryId, QueryOptions, ServerSalt, Session, SessionConfig};
use mtproto_core::test_support::server_peer::ServerPeer;
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_core::tl::mtproto::{ServiceMessage, gunzip, gzip, parse_rpc_result_limited};
use mtproto_core::transport::InputBuffer;
use mtproto_core::transport::ProxySecret;
use mtproto_core::transport::accept_obfuscated_header;
use mtproto_core::transport::{FrameDecoder, Framing, Incoming, encode_frame};
use mtproto_core::transport::{Socks5Auth, Socks5Handshake, Socks5Progress, Socks5Target};
use mtproto_core::transport::{TlsRecordReader, server_hello_for_tests, verify_server_hello};
use mtproto_core::transport::{TransportConfig, TransportStream};

use crate::generate::{Gen, TlContext, amplification_body, gzip_small_bomb, service_body};

pub type CaseResult = Result<(), String>;

pub struct Target {
    pub name: &'static str,
    pub about: &'static str,
    pub run: fn(u64) -> CaseResult,
}

pub const TARGETS: &[Target] = &[
    Target { name: "tl", about: "service-message and rpc_result parsers, recursively", run: tl_case },
    Target { name: "gunzip", about: "gzip_packed inflation limits and bombs", run: gunzip_case },
    Target { name: "plain", about: "unencrypted handshake message envelope", run: plain_case },
    Target {
        name: "decrypt",
        about: "MTProto 2.0 decryption; every tampered packet must be rejected",
        run: decrypt_case,
    },
    Target { name: "frames", about: "abridged / intermediate / padded framing, chunked", run: frames_case },
    Target {
        name: "stream",
        about: "obfuscated2 and fake-TLS transport streams from a hostile peer",
        run: stream_case,
    },
    Target { name: "tls", about: "fake-TLS ServerHello verification and record reader", run: tls_case },
    Target { name: "socks5", about: "SOCKS5 handshake against a hostile proxy", run: socks5_case },
    Target { name: "secret", about: "MTProxy secrets from links and binary", run: secret_case },
    Target { name: "pq", about: "pq factorisation of attacker-chosen values", run: pq_case },
    Target { name: "handshake", about: "auth key exchange against a hostile server and a MITM", run: handshake_case },
    Target {
        name: "session",
        about: "session state machine fed hostile, validly encrypted packets",
        run: session_case,
    },
    Target {
        name: "rpc",
        about: "RPC layer (wrapping, errors, flood waits, migrations) under a hostile server",
        run: rpc_case,
    },
    Target {
        name: "soak",
        about: "30-90 simulated days: sleep, clock changes, salt rotation, drops; exactly-once, no growth",
        run: crate::soak::soak_case,
    },
];

pub fn find(name: &str) -> Option<&'static Target> {
    TARGETS.iter().find(|target| target.name == name)
}

const START: f64 = 1_727_000_000.0;
const MAX_FOOTPRINT: usize = 96 * 1024 * 1024;
const MAX_PACKET_TIME: std::time::Duration = std::time::Duration::from_millis(400);

fn ensure(condition: bool, message: impl FnOnce() -> String) -> CaseResult {
    if condition { Ok(()) } else { Err(message()) }
}

fn walk_service(body: &[u8], depth: usize) -> CaseResult {
    if depth > 24 {
        return Ok(());
    }
    match ServiceMessage::parse(body) {
        Ok(ServiceMessage::Container(children)) => {
            ensure(children.len() <= 1024, || format!("container with {} children", children.len()))?;
            for child in children {
                walk_service(child.body, depth + 1)?;
            }
        }
        Ok(ServiceMessage::GzipPacked(packed)) => {
            if let Ok(unpacked) = gunzip(packed, 1 << 20) {
                ensure(unpacked.len() <= 1 << 20, || "gunzip exceeded its limit".into())?;
                walk_service(&unpacked, depth + 1)?;
            }
        }
        Ok(ServiceMessage::MsgCopy(inner)) => walk_service(inner.body, depth + 1)?,
        Ok(ServiceMessage::RpcResult { result, .. }) => {
            let _ = parse_rpc_result_limited(result, 1 << 20);
            walk_service(result, depth + 1)?;
        }
        Ok(ServiceMessage::FutureSalts { salts, .. }) => {
            ensure(salts.len() <= 1 << 16, || format!("{} future salts", salts.len()))?;
        }
        _ => {}
    }
    Ok(())
}

fn tl_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let cx = TlContext { client_msg_ids: vec![msg_id_for_time(START)], server_time: START, session_id: 1 };
    let mut body = if g.one_in(5) {
        {
            let len = g.small_len();
            g.bytes(len)
        }
    } else {
        service_body(&mut g, &cx, 0)
    };
    if g.one_in(2) {
        g.mutate(&mut body);
    }
    walk_service(&body, 0)?;
    let _ = parse_rpc_result_limited(&body, 1 << 20);
    Ok(())
}

fn gunzip_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let mut data = match g.below(5) {
        0 => {
            let len = g.small_len();
            g.bytes(len)
        }
        1 => gzip_small_bomb().to_vec(),
        _ => {
            let len = g.small_len();
            gzip(&g.bytes(len))
        }
    };
    if g.one_in(2) {
        g.mutate(&mut data);
    }
    let limit = *g.pick(&[0usize, 1, 16, 1024, 1 << 20]);
    if let Ok(output) = gunzip(&data, limit) {
        ensure(output.len() <= limit, || format!("gunzip returned {} bytes over a {limit} limit", output.len()))?;
    }
    Ok(())
}

fn plain_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let len = g.small_len();
    let mut packet = encode_plain_message(g.i64(), &g.bytes(len));
    g.mutate(&mut packet);
    if let Ok(message) = decode_plain_message(&packet) {
        ensure(message.body.len() <= packet.len(), || "plain body longer than its packet".into())?;
    }
    Ok(())
}

fn random_key(g: &mut Gen) -> AuthKey {
    let mut key = [0u8; 256];
    g.rng().fill(&mut key);
    AuthKey::new(key)
}

fn decrypt_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let key = random_key(&mut g);
    let header = MessageHeader { salt: g.i64(), session_id: g.i64(), msg_id: g.i64(), seq_no: g.i32() };
    let len = g.small_len() & !3;
    let body = g.bytes(len);
    let mut rng = XorShiftRandom::new(seed);
    let original = encrypt_message(&key, &header, &body, Side::Server, PaddingPolicy::default(), &mut rng).data;
    let decrypted = decrypt_message(&key, &original, Side::Server).map_err(|error| format!("roundtrip: {error}"))?;
    ensure(decrypted.body() == body.as_slice(), || "roundtrip body mismatch".into())?;
    let mut tampered = original.clone();
    g.mutate(&mut tampered);
    let _ = decrypt_message_v1(&key, &tampered, Side::Server);
    if let Ok(accepted) = decrypt_message(&key, &tampered, Side::Server) {
        ensure(accepted.header == header && accepted.body() == body.as_slice(), || {
            format!("tampered packet decrypted to different content ({} -> {} bytes)", original.len(), tampered.len())
        })?;
        ensure(tampered.len() - original.len().min(tampered.len()) < 16 && tampered.starts_with(&original), || {
            "tampered ciphertext accepted".into()
        })?;
    }
    let mut wrong_side = original;
    if !g.one_in(4) {
        g.mutate(&mut wrong_side);
    }
    ensure(decrypt_message(&key, &wrong_side, Side::Client).is_err(), || "reflected packet accepted".into())?;
    Ok(())
}

fn framing(g: &mut Gen) -> Framing {
    *g.pick(&[Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate])
}

fn hostile_frames(g: &mut Gen, framing: Framing) -> Vec<u8> {
    let mut stream = Vec::new();
    for _ in 0..g.range(1, 8) {
        match g.below(8) {
            0 => {
                let token = g.u32() | 0x8000_0000;
                match framing {
                    Framing::Abridged => stream.extend_from_slice(&token.to_be_bytes()),
                    _ => stream.extend_from_slice(&token.to_le_bytes()),
                }
            }
            1 => {
                let code = *g.pick(&[-404i32, -429, -444, -1, 0]);
                encode_frame(framing, &code.to_le_bytes(), false, g.rng(), &mut stream);
            }
            2 => {
                let garbage = {
                    let len = g.small_len();
                    g.bytes(len)
                };
                stream.extend_from_slice(&garbage);
            }
            _ => {
                let len = (g.small_len() + 4) & !3;
                let payload = g.bytes(len);
                encode_frame(framing, &payload, false, g.rng(), &mut stream);
            }
        }
    }
    if g.one_in(3) {
        g.mutate(&mut stream);
    }
    stream
}

fn drain_frames(
    decoder: &FrameDecoder,
    buffer: &mut InputBuffer,
    received: usize,
    max_len: usize,
) -> Result<bool, String> {
    for _ in 0..100_000 {
        match decoder.decode(buffer) {
            Ok(Some(Incoming::Packet(packet))) => {
                ensure(packet.len() <= max_len, || format!("frame of {} over max {max_len}", packet.len()))?;
                ensure(packet.len() <= received, || "frame longer than the input".into())?;
            }
            Ok(Some(_)) => {}
            Ok(None) => return Ok(true),
            Err(_) => return Ok(false),
        }
    }
    Err("frame decoder made no progress".into())
}

fn frames_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let framing = framing(&mut g);
    let max_len = if g.one_in(3) { g.range(4, 4096) } else { mtproto_core::transport::MAX_FRAME_LEN };
    let decoder = FrameDecoder::with_max_len(framing, max_len);
    let stream = hostile_frames(&mut g, framing);
    let mut buffer = InputBuffer::new();
    let mut received = 0;
    for chunk in g.split(&stream) {
        buffer.extend(chunk);
        received += chunk.len();
        let _ = decoder.pending_frame_len(&buffer);
        let _ = decoder.pending_frame(&buffer);
        if !drain_frames(&decoder, &mut buffer, received, max_len)? {
            break;
        }
        ensure(buffer.len() <= received, || "decoder buffer grew beyond its input".into())?;
    }
    Ok(())
}

fn hostile_secret(g: &mut Gen) -> Option<ProxySecret> {
    match g.below(4) {
        0 => None,
        1 => ProxySecret::from_binary(&g.bytes(16), false).ok(),
        2 => {
            let mut raw = vec![0xdd];
            raw.extend_from_slice(&g.bytes(16));
            ProxySecret::from_binary(&raw, false).ok()
        }
        _ => {
            let mut raw = vec![0xee];
            raw.extend_from_slice(&g.bytes(16));
            let domain_len = g.range(1, 182);
            raw.extend(std::iter::repeat_n(b'a', domain_len));
            ProxySecret::from_binary(&raw, false).ok()
        }
    }
}

fn split_tls_records(data: &[u8]) -> Vec<u8> {
    let mut input = InputBuffer::new();
    let mut rest = data;
    if rest.starts_with(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]) {
        rest = &rest[6..];
    }
    input.extend(rest);
    let mut output = Vec::new();
    let mut reader = TlsRecordReader::new();
    while let Ok(true) = reader.read(&mut input, &mut output) {}
    output
}

fn tls_records(g: &mut Gen, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let take = g.range(1, 2878).min(rest.len());
        let (head, tail) = rest.split_at(take);
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(head.len() as u16).to_be_bytes());
        out.extend_from_slice(head);
        rest = tail;
    }
    out
}

fn stream_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let framing = framing(&mut g);
    let secret = hostile_secret(&mut g);
    let emulate_tls = secret.as_ref().is_some_and(ProxySecret::emulate_tls);
    let proxy_key = secret.as_ref().map(ProxySecret::proxy_key);
    let config = TransportConfig { framing, dc_id: g.i32() as i16, secret, unix_time: START as i32 };
    let mut rng = XorShiftRandom::new(seed ^ 0x55);
    let mut client = TransportStream::new(&config, &mut rng);
    let effective = client.framing();
    client.send_packet(&g.bytes(32), g.one_in(2), &mut rng);
    let mut from_server = Vec::new();
    let mut received = 0;
    let header_stream = if emulate_tls {
        let hello = client.take_outgoing();
        let server_hello = server_hello_for_tests(&hello, proxy_key.as_ref().expect("key"), &mut rng);
        let mut prefix = server_hello.clone();
        if g.one_in(5) {
            g.mutate(&mut prefix);
        }
        received += prefix.len();
        if client.receive(&prefix).is_err() || !client.is_ready() {
            return Ok(());
        }
        from_server.extend_from_slice(&server_hello);
        split_tls_records(&client.take_outgoing())
    } else {
        client.take_outgoing()
    };
    ensure(header_stream.len() >= 64, || "client sent no obfuscation header".into())?;
    let header: [u8; 64] = header_stream[..64].try_into().expect("64");
    let Some(mut server) = accept_obfuscated_header(&header, proxy_key.as_ref()) else {
        return Err("server cannot accept the client's obfuscation header".into());
    };
    ensure(server.framing == effective, || "obfuscation header announces another framing".into())?;
    let mut plain = hostile_frames(&mut g, effective);
    server.encryptor.apply(&mut plain);
    let mut wire = if emulate_tls { tls_records(&mut g, &plain) } else { plain };
    if g.one_in(4) {
        g.mutate(&mut wire);
    }
    for chunk in g.split(&wire) {
        received += chunk.len();
        if client.receive(chunk).is_err() {
            return Ok(());
        }
        ensure(client.buffered_input_len() <= received, || "transport buffered more than it received".into())?;
        let _ = client.pending_frame_head();
        for _ in 0..100_000 {
            match client.next_incoming() {
                Ok(Some(Incoming::Packet(packet))) => {
                    ensure(packet.len() <= received, || "packet longer than the input".into())?;
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return Ok(()),
            }
        }
    }
    Ok(())
}

fn tls_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let secret: [u8; 16] = g.rng().array();
    let mut client_random = [0u8; 32];
    g.rng().fill(&mut client_random);
    let mut fake_hello = vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03];
    fake_hello.extend_from_slice(&client_random);
    fake_hello.extend_from_slice(&g.bytes(470));
    let mut rng = XorShiftRandom::new(seed);
    let mut response = server_hello_for_tests(&fake_hello, &secret, &mut rng);
    let untouched = response.clone();
    if !g.one_in(4) {
        g.mutate(&mut response);
    }
    let mut buffer = InputBuffer::new();
    let mut fed = 0;
    for chunk in g.split(&response) {
        buffer.extend(chunk);
        fed += chunk.len();
        match verify_server_hello(&mut buffer, &client_random, &secret) {
            Ok(true) => {
                let consumed = fed - buffer.len();
                ensure(consumed <= untouched.len() && response[..consumed] == untouched[..consumed], || {
                    "a forged ServerHello passed verification".into()
                })?;
                break;
            }
            Ok(false) => {}
            Err(_) => break,
        }
    }
    let mut records = InputBuffer::new();
    let mut output = Vec::new();
    let mut reader = TlsRecordReader::new();
    let len = g.small_len() + 1;
    let payload = g.bytes(len);
    let mut raw = tls_records(&mut g, &payload);
    g.mutate(&mut raw);
    for chunk in g.split(&raw) {
        records.extend(chunk);
        while let Ok(true) = reader.read(&mut records, &mut output) {}
    }
    ensure(output.len() <= raw.len(), || "tls reader produced more than it read".into())
}

fn text(g: &mut Gen, max: usize) -> String {
    let len = g.below(max + 1);
    (0..len).map(|_| (b'a' + (g.below(26) as u8)) as char).collect()
}

fn socks5_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let target = match g.below(3) {
        0 => Socks5Target::Ipv4(g.rng().array(), g.u32() as u16),
        1 => Socks5Target::Ipv6(g.rng().array(), g.u32() as u16),
        _ => Socks5Target::Domain(text(&mut g, 300), g.u32() as u16),
    };
    let auth = g.one_in(2).then(|| Socks5Auth { username: text(&mut g, 300), password: text(&mut g, 300) });
    let with_auth = auth.is_some();
    let Ok((mut handshake, _greeting)) = Socks5Handshake::new(target, auth) else {
        return Ok(());
    };
    let mut replies = Vec::new();
    replies.extend_from_slice(&[0x05, if with_auth { 0x02 } else { 0x00 }]);
    if with_auth {
        replies.extend_from_slice(&[0x01, 0x00]);
    }
    replies.extend_from_slice(&[0x05, 0x00, 0x00]);
    match g.below(4) {
        0 => {
            replies.push(0x01);
            replies.extend_from_slice(&g.bytes(6));
        }
        1 => {
            replies.push(0x04);
            replies.extend_from_slice(&g.bytes(18));
        }
        2 => {
            let len = g.below(256);
            replies.push(0x03);
            replies.push(len as u8);
            replies.extend_from_slice(&g.bytes(len + 2));
        }
        _ => replies.push(g.u32() as u8),
    }
    if g.one_in(2) {
        g.mutate(&mut replies);
    }
    let mut input = InputBuffer::new();
    let mut steps = 0;
    for chunk in g.split(&replies) {
        input.extend(chunk);
        loop {
            steps += 1;
            ensure(steps < 10_000, || "socks5 handshake does not progress".into())?;
            match handshake.feed(&mut input) {
                Ok(Socks5Progress::NeedMore) => break,
                Ok(Socks5Progress::Send(_)) => {}
                Ok(Socks5Progress::Connected) | Err(_) => return Ok(()),
            }
        }
    }
    Ok(())
}

fn secret_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let link = match g.below(4) {
        0 => {
            let alphabet = b"0123456789abcdefABCDEF";
            let len = g.below(500);
            (0..len).map(|_| *g.pick(alphabet) as char).collect::<String>()
        }
        1 => {
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/=";
            let len = g.below(500);
            (0..len).map(|_| *g.pick(alphabet) as char).collect::<String>()
        }
        2 => {
            let mut raw = vec![0xee];
            raw.extend_from_slice(&g.bytes(16));
            raw.extend_from_slice(&{
                let len = g.below(400);
                g.bytes(len)
            });
            raw.iter().map(|byte| format!("{byte:02x}")).collect()
        }
        _ => String::from_utf8_lossy(&{
            let len = g.small_len();
            g.bytes(len)
        })
        .into_owned(),
    };
    let truncate = g.one_in(2);
    let parsed = ProxySecret::from_link(&link, truncate).ok().or_else(|| {
        ProxySecret::from_binary(
            &{
                let len = g.below(400);
                g.bytes(len)
            },
            truncate,
        )
        .ok()
    });
    if let Some(secret) = parsed {
        let _ = secret.domain();
        let _ = secret.proxy_key();
        let config = TransportConfig { framing: Framing::Intermediate, dc_id: 2, secret: Some(secret), unix_time: 0 };
        let mut rng = XorShiftRandom::new(seed);
        let mut stream = TransportStream::new(&config, &mut rng);
        stream.send_packet(&[0; 16], false, &mut rng);
        let _ = stream.take_outgoing();
    }
    Ok(())
}

fn pq_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let pq = match g.below(6) {
        0 => g.u64(),
        1 => *g.pick(&[0u64, 1, 2, 3, 4, u64::MAX, u64::MAX - 58, 0xFFFF_FFFB * 0xFFFF_FFFB, 1 << 63]),
        2 => {
            let small = *g.pick(&[2u64, 3, 5, 7, 11, 13]);
            small.wrapping_mul(g.u64() >> 4)
        }
        3 => (g.u64() >> 32 | 1).wrapping_mul(g.u64() >> 32 | 1),
        4 => 0xFFFF_FFFF_FFFF_FFC5,
        _ => g.u64() >> g.below(64),
    };
    if let Some((p, q)) = factorize_pq(pq) {
        ensure(p as u128 * q as u128 == pq as u128, || format!("factorisation of {pq} returned {p} x {q}"))?;
        ensure(p > 1 && q > 1, || format!("trivial factorisation of {pq}"))?;
    }
    Ok(())
}

#[derive(Default)]
struct PrimeCache(Vec<(Vec<u8>, bool)>);

impl mtproto_core::crypto::DhPrimeCache for PrimeCache {
    fn is_known_safe(&self, prime: &[u8]) -> Option<bool> {
        self.0.iter().find(|(known, _)| known == prime).map(|(_, safe)| *safe)
    }

    fn remember(&mut self, prime: &[u8], safe: bool) {
        self.0.push((prime.to_vec(), safe));
    }
}

fn handshake_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let mut behavior = ServerHandshakeBehavior {
        server_time: if g.one_in(4) { g.i32() } else { START as i32 + g.below(1000) as i32 - 500 },
        retries_before_ok: if g.one_in(4) { g.below(8) as u32 } else { 0 },
        ..Default::default()
    };
    match g.below(24) {
        0 => behavior.fail_dh_gen = true,
        1 => behavior.fail_dh_params = true,
        2 => behavior.corrupt_answer_hash = true,
        3 => behavior.wrong_nonce_in_res_pq = true,
        4 => behavior.foreign_fingerprint = true,
        5 => behavior.bad_g = Some(*g.pick(&[0, 1, 2, 3, 4, 5, 6, 7, 8, -2, i32::MAX])),
        6 => behavior.small_g_a = true,
        7 => {
            behavior.pq_override = Some(match g.below(5) {
                0 => Vec::new(),
                1 => {
                    let len = g.range(1, 9);
                    g.bytes(len)
                }
                2 => {
                    let len = g.range(9, 300);
                    g.bytes(len)
                }
                3 => 0xFFFF_FFFF_FFFF_FFC5u64.to_be_bytes().to_vec(),
                _ => (g.u64() | 1).to_be_bytes().to_vec(),
            })
        }
        8 => behavior.wrong_server_nonce_in_dh_params = true,
        9 => behavior.wrong_nonce_in_inner_data = true,
        10 => behavior.wrong_nonce_in_dh_gen = true,
        11 => behavior.corrupt_new_nonce_hash = true,
        12 => behavior.corrupt_fail_hash = true,
        13 => behavior.unaligned_encrypted_answer = true,
        14 => behavior.excess_answer_padding = true,
        15 => {
            behavior.dh_prime_override = Some(match g.below(4) {
                0 => g.bytes(256),
                1 => {
                    let len = g.below(600);
                    g.bytes(len)
                }
                2 => {
                    let mut prime = mtproto_core::crypto::KNOWN_DH_PRIME.to_vec();
                    let last = prime.len() - 1;
                    prime[last] ^= 2;
                    prime
                }
                _ => vec![0xff; 256],
            })
        }
        16 => behavior.trailing_bytes = true,
        17 => behavior.repeat_res_pq = true,
        _ => {}
    }
    let mut server = ServerHandshake::new(behavior);
    let temporary = g.one_in(2);
    let config = HandshakeConfig {
        dc_id: 2,
        temp_key_expires_in: temporary.then_some(86_400),
        public_keys: vec![server.public_key()],
    };
    let mut rng = XorShiftRandom::new(seed ^ 0xabc);
    let (mut client, mut packet) = Handshake::start(config, START, &mut rng);
    let mut cache = PrimeCache::default();
    let use_cache = g.one_in(2);
    for _ in 0..24 {
        let reply = catch_unwind(AssertUnwindSafe(|| server.handle(&packet, &mut rng)));
        let Ok(Some(mut reply)) = reply else {
            return Ok(());
        };
        if g.one_in(3) {
            g.mutate(&mut reply);
        }
        let cache: Option<&mut dyn mtproto_core::crypto::DhPrimeCache> =
            if use_cache { Some(&mut cache) } else { None };
        match client.on_packet(&reply, START, cache, &mut rng) {
            Ok(HandshakeStep::Send(next)) => packet = next,
            Ok(HandshakeStep::Done(result)) => {
                let agreed = server.outcome.as_ref().is_some_and(|outcome| outcome.auth_key == result.auth_key);
                return ensure(agreed, || "client accepted an auth key the server never agreed to".into());
            }
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

struct Peer {
    server: ServerPeer,
    client_msg_ids: Vec<i64>,
}

impl Peer {
    fn absorb(&mut self, data: &[u8]) {
        let packet = self.server.decode(data);
        self.client_msg_ids.push(packet.header.msg_id);
        for message in packet.messages {
            self.client_msg_ids.push(message.msg_id);
        }
        let excess = self.client_msg_ids.len().saturating_sub(256);
        self.client_msg_ids.drain(..excess);
    }

    fn hostile_packet(&mut self, g: &mut Gen, session_id: i64, salt: i64) -> Vec<u8> {
        let cx =
            TlContext { client_msg_ids: self.client_msg_ids.clone(), server_time: self.server.server_time, session_id };
        match g.below(16) {
            0 => {
                let len = g.small_len() + 8;
                g.bytes(len)
            }
            2 if g.one_in(4) => {
                self.server.session_id = session_id;
                self.server.salt = salt;
                let body = amplification_body(g, &cx);
                self.server.seal(cx.server_msg_id(g), 0, &body)
            }
            1 => {
                let body = service_body(g, &cx, 0);
                let mut packet = self.server.seal(cx.server_msg_id(g), g.i32(), &body);
                g.mutate(&mut packet);
                packet
            }
            _ => {
                self.server.session_id = if g.one_in(12) { g.i64() } else { session_id };
                self.server.salt = if g.one_in(3) { g.i64() } else { salt };
                let body = service_body(g, &cx, 0);
                let seq_no = if g.one_in(2) { 2 * g.below(1 << 20) as i32 + 1 } else { g.i32() };
                self.server.seal(cx.server_msg_id(g), seq_no, &body)
            }
        }
    }
}

fn advance(g: &mut Gen, now: &mut Now, server: &mut ServerPeer) {
    let step = match g.below(6) {
        0 => 0.001,
        1 => 0.5,
        2 => 5.0,
        3 => 30.0,
        4 => 130.0,
        _ => 400.0 * (g.below(100) as f64 / 100.0),
    };
    now.mono += step;
    now.unix += step;
    server.server_time += step;
    if g.one_in(40) {
        now.unix += if g.one_in(2) { 86_400.0 } else { -86_400.0 };
    }
}

fn session_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let key = random_key(&mut g);
    let mut now = Now { mono: 100.0, unix: START };
    let salts = [ServerSalt { salt: 101, valid_since: START - 100.0, valid_until: START + 1800.0 }];
    let mut rng = XorShiftRandom::new(seed ^ 0x77);
    let mut session = Session::new(SessionConfig::default(), key.clone(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let mut peer = Peer { server: ServerPeer::new(key, START), client_msg_ids: Vec::new() };
    peer.server.salt = 101;
    let mut next_query = 0u64;
    let send = |g: &mut Gen, session: &mut Session, now: Now, next_query: &mut u64| {
        for _ in 0..g.range(1, 12) {
            *next_query += 1;
            let next_query = *next_query;
            let len = g.small_len();
            let mut body = vec![0x44, 0x33, 0x22, 0x11];
            body.extend_from_slice(&g.bytes(len & !3));
            let invoke_after = g.one_in(4).then(|| QueryId(g.below(next_query as usize) as u64));
            session.send(QueryId(next_query), body, QueryOptions { quick_ack: g.one_in(3), invoke_after }, now);
        }
    };
    send(&mut g, &mut session, now, &mut next_query);
    let mut events = 0usize;
    for _ in 0..g.range(1, 48) {
        flush_session(&mut session, &mut peer, now, &mut rng)?;
        let packet = peer.hostile_packet(&mut g, session.session_id(), 101);
        let started = std::time::Instant::now();
        let _ = session.handle_packet(&packet, now, &mut rng);
        if std::env::var_os("MTPROTO_FUZZ_TRACE").is_some() {
            eprintln!("packet {} bytes: {:?}", packet.len(), started.elapsed());
        }
        ensure(started.elapsed() < MAX_PACKET_TIME, || {
            format!("one {}-byte packet took {:?}", packet.len(), started.elapsed())
        })?;
        if g.one_in(8) {
            session.handle_quick_ack(g.u32());
        }
        events += session.drain_events().len();
        ensure(events < 1_000_000, || "event storm".into())?;
        if g.one_in(3) {
            advance(&mut g, &mut now, &mut peer.server);
            let _ = session.handle_timeout(now);
            let _ = session.poll_timeout(now);
        }
        if g.one_in(10) {
            let started = std::time::Instant::now();
            session.connection_closed();
            session.connection_opened(now);
            ensure(started.elapsed() < MAX_PACKET_TIME, || format!("reconnect took {:?}", started.elapsed()))?;
        }
        if g.one_in(6) {
            send(&mut g, &mut session, now, &mut next_query);
        }
        if g.one_in(8) {
            let _ = session.cancel(QueryId(g.below(next_query as usize + 1) as u64));
        }
        if g.one_in(8) {
            session.note_outbound_backlog(Some(g.below(1 << 20)), now);
        }
        let footprint = session.footprint();
        ensure(footprint < MAX_FOOTPRINT, || format!("session footprint {footprint} bytes"))?;
    }
    flush_session(&mut session, &mut peer, now, &mut rng)
}

fn flush_session(session: &mut Session, peer: &mut Peer, now: Now, rng: &mut XorShiftRandom) -> CaseResult {
    let started = std::time::Instant::now();
    let result = flush_session_inner(session, peer, now, rng);
    if std::env::var_os("MTPROTO_FUZZ_TRACE").is_some() {
        eprintln!("flush: {:?}", started.elapsed());
    }
    result
}

fn flush_session_inner(session: &mut Session, peer: &mut Peer, now: Now, rng: &mut XorShiftRandom) -> CaseResult {
    let mut bytes = 0usize;
    for _ in 0..512 {
        let Some(transmit) = session.poll_transmit(now, rng) else {
            return Ok(());
        };
        bytes += transmit.data.len();
        ensure(bytes < 256 * 1024 * 1024, || "session transmitted over 256 MB in one flush".into())?;
        peer.absorb(&transmit.data);
    }
    Err("session keeps transmitting without new input".into())
}

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "Mac".into(),
        system_version: "26".into(),
        app_version: "1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: "h".into(),
        disable_updates: false,
    }
}

fn rpc_case(seed: u64) -> CaseResult {
    let mut g = Gen::new(seed);
    let key = random_key(&mut g);
    let mut now = Now { mono: 100.0, unix: START };
    let salts = [ServerSalt { salt: 5, valid_since: START - 10.0, valid_until: START + 100_000.0 }];
    let mut rng = XorShiftRandom::new(seed ^ 0x99);
    let mut session = Session::new(SessionConfig::default(), key.clone(), &salts, 0.0, now, &mut rng);
    session.connection_opened(now);
    let role = match g.below(4) {
        0 => SessionRole::Main,
        1 => SessionRole::Cdn,
        _ => SessionRole::Worker { requires_auth_token: g.one_in(2) },
    };
    let mut client = RpcClient::new(session, role, Some(environment()), g.one_in(2).then(|| "h".to_string()));
    let mut peer = Peer { server: ServerPeer::new(key, START), client_msg_ids: Vec::new() };
    peer.server.salt = 5;
    let mut next = 0u64;
    let send = |g: &mut Gen, client: &mut RpcClient, now: Now, next: &mut u64| {
        for _ in 0..g.range(1, 10) {
            *next += 1;
            let next = *next;
            let flags = RequestFlags {
                automatic_flood_wait: g.one_in(2),
                report_flood_wait: g.one_in(2),
                retry_server_errors: g.one_in(2),
                quick_ack: g.one_in(3),
                progress: g.one_in(3),
                timeout_timer: g.one_in(3),
                expected_response_size: g.u32() % (1 << 20),
                without_updates: g.one_in(3),
                delegate_retry_decisions: g.one_in(3),
            };
            let invoke_after = g.one_in(5).then(|| RequestId(g.below(next as usize) as u64));
            let body = vec![0x88, 0x77, 0x66, 0x55, (next & 0xff) as u8, 0, 0, 0];
            client.send(RpcRequest { id: RequestId(next), body, flags, invoke_after }, now);
        }
    };
    send(&mut g, &mut client, now, &mut next);
    let mut events = 0usize;
    for _ in 0..g.range(1, 48) {
        flush_rpc(&mut client, &mut peer, now, &mut rng)?;
        let packet = peer.hostile_packet(&mut g, client.session().session_id(), 5);
        let started = std::time::Instant::now();
        let _ = client.handle_packet(&packet, now, &mut rng);
        ensure(started.elapsed() < MAX_PACKET_TIME, || {
            format!("one {}-byte packet took {:?}", packet.len(), started.elapsed())
        })?;
        for event in client.drain_events() {
            events += 1;
            match event {
                RpcEvent::RetryDecisionRequired { id, .. } => client.decide_retry(id, g.one_in(2), now),
                RpcEvent::VerificationRequired { id, .. } => {
                    let verification = if g.one_in(2) {
                        Verification::Recaptcha { token: text(&mut g, 64) }
                    } else {
                        Verification::Apns { nonce: text(&mut g, 64), secret: text(&mut g, 64) }
                    };
                    client.resolve_verification(id, verification, now);
                }
                RpcEvent::AuthTokenRequired => client.set_auth_token_ready(g.one_in(2), now),
                RpcEvent::ConnectionShouldReset => {
                    client.connection_closed(now);
                    client.connection_opened(now);
                }
                _ => {}
            }
        }
        ensure(events < 1_000_000, || "rpc event storm".into())?;
        if g.one_in(3) {
            advance(&mut g, &mut now, &mut peer.server);
            let _ = client.handle_timeout(now);
            let _ = client.poll_timeout(now);
        }
        if g.one_in(10) {
            client.connection_closed(now);
            client.connection_opened(now);
        }
        if g.one_in(6) {
            send(&mut g, &mut client, now, &mut next);
        }
        if g.one_in(8) {
            let _ = client.cancel(RequestId(g.below(next as usize + 1) as u64), now);
        }
        if g.one_in(12) {
            client.fail_request(RequestId(g.below(next as usize + 1) as u64), g.i32(), "FUZZ", now);
        }
        if g.one_in(16) {
            client.invalidate_initialization();
        }
        if g.one_in(16) {
            client.reset_session(now, &mut rng);
        }
        let footprint = client.session().footprint();
        ensure(footprint < MAX_FOOTPRINT, || format!("rpc session footprint {footprint} bytes"))?;
        ensure(client.request_count() <= next as usize, || "rpc client tracks more requests than sent".into())?;
    }
    flush_rpc(&mut client, &mut peer, now, &mut rng)
}

fn flush_rpc(client: &mut RpcClient, peer: &mut Peer, now: Now, rng: &mut XorShiftRandom) -> CaseResult {
    for _ in 0..512 {
        let Some(transmit) = client.poll_transmit(now, rng) else {
            return Ok(());
        };
        peer.absorb(&transmit.data);
    }
    Err("rpc client keeps transmitting without new input".into())
}
