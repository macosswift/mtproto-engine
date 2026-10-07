//! Public-API paths no other test reached (found with `cargo llvm-cov`): error branches of the
//! parsers that face the network, secrets kept out of `Debug`, and small accessors the runtime relies
//! on. Every test pins behaviour, not just execution.

use std::io::Write;

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{
    AesIge, DhError, DhPrimeCache, KNOWN_DH_PRIME, OsRandom, RsaError, RsaPublicKey, SecureRandom, XorShiftRandom,
    aes_ige_decrypt, aes_ige_encrypt, check_dh_params, factorize_pq, handshake_tmp_aes, is_probable_prime, to_fixed_be,
};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeError, HandshakeStep};
use mtproto_core::message::{decode_plain_message, encode_plain_message};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior, test_rsa_key_pair};
use mtproto_core::tl::mtproto::{
    PqInnerData, ResPq, ServerDhParams, ServiceMessage, SetClientDhParamsAnswer, gunzip, write_destroy_session,
    write_rpc_result,
};
use mtproto_core::tl::{Reader, TlError, TlRead, TlWrite, Writer, ids};
use mtproto_core::transport::{
    FrameDecoder, Framing, HttpConnectError, HttpConnectHandshake, HttpCredentials, HttpError, HttpResponseReader,
    InputBuffer, MAX_HEAD_LEN, ProxySecret, Socks5Auth, Socks5Handshake, Socks5Progress, Socks5Target, TlsHelloError,
    TransportConfig, TransportError, TransportStream, WsError, WsHandshake, trim_padded_payload,
    verify_client_hello_for_tests, verify_server_hello,
};

const NOW: f64 = 1_727_000_000.0;

#[test]
fn writer_reserve_patch_and_raw_words() {
    let mut writer = Writer::from_vec(vec![0xaa]);
    assert!(!writer.is_empty());
    assert!(Writer::new().is_empty());
    let slot = writer.reserve_i32();
    writer.write_u64(0x0102_0304_0506_0708);
    writer.patch_i32(slot, -2);
    assert_eq!(
        writer.into_inner(),
        vec![0xaa, 0xfe, 0xff, 0xff, 0xff, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        "the patched word lands where it was reserved, little-endian"
    );
}

#[test]
fn reader_tracks_what_is_left() {
    let data = [1u8, 0, 0, 0, 2, 0, 0, 0];
    let mut reader = Reader::new(&data);
    assert!(!reader.is_empty());
    assert_eq!(reader.read_u32().unwrap(), 1);
    assert_eq!(reader.rest(), &[2, 0, 0, 0]);
    assert_eq!(reader.finish(), Err(TlError::TrailingData(4)));
    reader.read_u32().unwrap();
    assert!(reader.is_empty());
    assert_eq!(reader.finish(), Ok(()));
}

#[test]
fn service_writers_parse_back() {
    let mut writer = Writer::new();
    write_destroy_session(&mut writer, -77);
    let body = writer.into_inner();
    assert_eq!(&body[..4], &ids::DESTROY_SESSION.to_le_bytes());
    assert_eq!(i64::from_le_bytes(body[4..12].try_into().unwrap()), -77);
    assert_eq!(ServiceMessage::parse(&body).unwrap(), ServiceMessage::Ignored { constructor: ids::DESTROY_SESSION });

    let mut writer = Writer::new();
    write_rpc_result(&mut writer, 0x1234_5678_9abc, &[9, 9, 9, 9]);
    assert_eq!(
        ServiceMessage::parse(&writer.into_inner()).unwrap(),
        ServiceMessage::RpcResult { req_msg_id: 0x1234_5678_9abc, result: &[9, 9, 9, 9] }
    );
}

#[test]
fn handshake_types_refuse_foreign_constructors() {
    let mut body = 0xdead_beefu32.to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 64]);
    assert_eq!(PqInnerData::from_bytes(&body), Err(TlError::UnexpectedConstructor { offset: 0, found: 0xdead_beef }));
    assert_eq!(
        SetClientDhParamsAnswer::from_bytes(&body),
        Err(TlError::UnexpectedConstructor { offset: 0, found: 0xdead_beef })
    );
    let inner = PqInnerData {
        pq: vec![1],
        p: vec![2],
        q: vec![3],
        nonce: [4; 16],
        server_nonce: [5; 16],
        new_nonce: [6; 32],
        dc: -2,
        expires_in: Some(3600),
    };
    let temp = inner.to_bytes();
    assert_eq!(&temp[..4], &ids::P_Q_INNER_DATA_TEMP_DC.to_le_bytes(), "a temporary key says so");
    assert_eq!(PqInnerData::from_bytes(&temp).unwrap(), inner);
}

#[test]
fn zlib_payloads_grow_their_buffer_and_respect_the_limit() {
    let original: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&original).unwrap();
    let packed = encoder.finish().unwrap();
    assert!(packed.len() * 4 < original.len(), "the output outgrows the first capacity guess");
    assert_eq!(gunzip(&packed, 1 << 20).unwrap(), original);
    assert!(matches!(gunzip(&packed, 100_000), Err(TlError::Gzip(_))), "a bomb is cut at the limit");
}

#[test]
fn framing_prefixes_and_decoder_identity() {
    assert_eq!(Framing::Abridged.plain_prefix(), &[0xef]);
    assert_eq!(Framing::Intermediate.plain_prefix(), &[0xee; 4]);
    assert_eq!(Framing::PaddedIntermediate.plain_prefix(), &[0xdd; 4]);
    for framing in [Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate] {
        assert_eq!(FrameDecoder::new(framing).framing(), framing);
        assert_eq!(framing.plain_prefix()[0] as u32, framing.tag() & 0xff);
    }
}

#[test]
fn client_frames_with_no_payload_are_refused() {
    let decoder = FrameDecoder::new(Framing::Abridged);
    let mut input = InputBuffer::new();
    input.extend(&[0x80]);
    assert_eq!(decoder.decode_client_frame(&mut input), Err(TransportError::InvalidLength(0)));
    for framing in [Framing::Intermediate, Framing::PaddedIntermediate] {
        let decoder = FrameDecoder::new(framing);
        let mut input = InputBuffer::new();
        input.extend(&3u32.to_le_bytes());
        input.extend(&[1, 2, 3]);
        assert_eq!(decoder.decode_client_frame(&mut input), Err(TransportError::InvalidLength(3)));
        let mut input = InputBuffer::new();
        input.extend(&(0x8000_0000u32 | 2).to_le_bytes());
        assert_eq!(
            decoder.decode_client_frame(&mut input),
            Err(TransportError::InvalidLength(2)),
            "a quick-ack flag does not excuse a short frame"
        );
    }
}

#[test]
fn padded_payload_trimming_edges() {
    assert_eq!(trim_padded_payload(&[1, 2, 3, 4, 5, 6, 7]), 4, "too short for a key id: whole words");
    let mut plain = vec![0u8; 19];
    assert_eq!(trim_padded_payload(&plain), 16, "a plain message too short for its length field");
    plain.resize(40, 0);
    plain[16..20].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(trim_padded_payload(&plain), 40, "a length past the end is ignored");
    plain[16..20].copy_from_slice(&8u32.to_le_bytes());
    assert_eq!(trim_padded_payload(&plain), 28, "a plain message keeps exactly its declared body");
    let mut encrypted = vec![7u8; 22];
    assert_eq!(trim_padded_payload(&encrypted), 20, "shorter than the encrypted header");
    encrypted.resize(24 + 16 + 5, 7);
    assert_eq!(trim_padded_payload(&encrypted), 40, "encrypted data keeps whole AES blocks");
}

#[test]
fn http_credentials_and_socks_auth_never_print_their_secrets() {
    let credentials = HttpCredentials { username: "user".into(), password: "hunter2".into() };
    let printed = format!("{credentials:?}");
    assert!(!printed.contains("hunter2") && !printed.contains("user"), "{printed}");
    let auth = Socks5Auth { username: "user".into(), password: "hunter2".into() };
    let printed = format!("{auth:?}");
    assert!(!printed.contains("hunter2"), "{printed}");
    let key = AuthKey::new([0x5a; 256]);
    let printed = format!("{key:?}");
    assert!(printed.starts_with("AuthKey(0x") && !printed.contains("5a5a5a"), "{printed}");
    assert_eq!(printed, format!("AuthKey({:#018x})", key.id()));
}

#[test]
fn proxy_secret_kinds_and_raw_bytes() {
    let simple = ProxySecret::from_link("00112233445566778899aabbccddeeff", false).unwrap();
    assert_eq!(format!("{simple:?}"), "ProxySecret(simple)");
    assert_eq!(simple.raw().len(), 16);
    let padded = ProxySecret::from_link("dd00112233445566778899aabbccddeeff", false).unwrap();
    assert_eq!(format!("{padded:?}"), "ProxySecret(padded)");
    assert_eq!(padded.raw()[0], 0xdd);
    assert_eq!(padded.proxy_key(), simple.proxy_key(), "the key is the 16 bytes after the tag");
    let mut raw = vec![0xee];
    raw.extend_from_slice(&[1; 16]);
    raw.extend_from_slice(b"example.com");
    let tls = ProxySecret::from_binary(&raw, false).unwrap();
    assert_eq!(format!("{tls:?}"), "ProxySecret(fake-tls)");
    assert_eq!(tls.raw(), &raw[..]);
    assert_eq!(tls.domain(), Some(&b"example.com"[..]));
}

#[test]
fn http_reader_defaults_and_body_head() {
    let mut reader = HttpResponseReader::default();
    let mut input = InputBuffer::new();
    input.extend(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcd");
    assert_eq!(reader.read(&mut input), Ok(None));
    assert_eq!(reader.body_head(), b"abcd", "the start of a body still arriving can be inspected");
    assert_eq!(reader.body_progress(), Some((Some(10), 4)));
    input.extend(b"efghij");
    let response = reader.read(&mut input).unwrap().unwrap();
    assert_eq!(response.body, b"abcdefghij");
    assert!(reader.body_head().is_empty());
}

#[test]
fn http_reader_refuses_oversized_heads_bodies_and_statuses() {
    let mut head = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    head.extend(vec![b'a'; MAX_HEAD_LEN]);
    head.extend_from_slice(b"\r\n\r\n");
    let mut input = InputBuffer::new();
    input.extend(&head);
    assert_eq!(HttpResponseReader::new().read(&mut input), Err(HttpError::HeadTooLarge), "complete but too long");

    let mut reader = HttpResponseReader::with_max_body(8);
    let mut input = InputBuffer::new();
    input.extend(b"HTTP/1.1 200 OK\r\n\r\n0123456789");
    assert_eq!(reader.read(&mut input), Err(HttpError::BodyTooLarge(10)), "a body running until close is capped");

    let mut input = InputBuffer::new();
    input.extend(b"HTTP/1.1 600 Beyond\r\n\r\n");
    assert_eq!(HttpResponseReader::new().read(&mut input), Err(HttpError::StatusLine));
    let mut input = InputBuffer::new();
    input.extend(b"HTTP/1.1 099 Below\r\n\r\n");
    assert_eq!(HttpResponseReader::new().read(&mut input), Err(HttpError::StatusLine));

    let mut input = InputBuffer::new();
    input.extend(b"HTTP/1.1 200 OK\r\nContent-Length:\t  \t3 \t\r\n\r\nabc");
    let response = HttpResponseReader::new().read(&mut input).unwrap().unwrap();
    assert_eq!(response.body, b"abc", "whitespace around a header value is trimmed");

    let (mut connect, _) = HttpConnectHandshake::new("h:1", None);
    let mut input = InputBuffer::new();
    input.extend(&vec![b'x'; MAX_HEAD_LEN + 1]);
    assert_eq!(connect.feed(&mut input), Err(HttpConnectError::Malformed(HttpError::HeadTooLarge)));
}

#[test]
fn socks5_stays_connected_and_leaves_tunnel_bytes() {
    let (mut handshake, _) = Socks5Handshake::new(Socks5Target::Ipv4([1, 2, 3, 4], 443), None).unwrap();
    let mut input = InputBuffer::new();
    input.extend(&[5, 0]);
    assert!(matches!(handshake.feed(&mut input).unwrap(), Socks5Progress::Send(_)));
    input.extend(&[5, 0, 0, 1, 9, 9, 9, 9, 0, 80, 0xef, 0x01]);
    assert_eq!(handshake.feed(&mut input).unwrap(), Socks5Progress::Connected);
    assert_eq!(input.as_slice(), &[0xef, 0x01], "bytes after the reply belong to the tunnel");
    assert_eq!(handshake.feed(&mut input).unwrap(), Socks5Progress::Connected, "done stays done");
    assert_eq!(input.as_slice(), &[0xef, 0x01], "and consumes nothing more");
}

#[test]
fn websocket_upgrade_responses_that_are_not_http() {
    for (response, expected) in [
        (&b"HTTP/1.1 101 OK\r\n\xff\xfe: x\r\n\r\n"[..], WsError::Malformed),
        (b"SPDY/3 101 Switching\r\n\r\n", WsError::Malformed),
        (b"HTTP/1.1 101 Switching Protocols\r\nno colon here\r\n\r\n", WsError::Malformed),
        (b"HTTP/1.1 abc Switching Protocols\r\n\r\n", WsError::Malformed),
    ] {
        let (mut handshake, _) = WsHandshake::new("h", "/apiws", [3; 16]);
        let mut input = InputBuffer::new();
        input.extend(response);
        assert_eq!(handshake.feed(&mut input), Err(expected), "{}", String::from_utf8_lossy(response));
    }
    let (mut handshake, _) = WsHandshake::new("h", "/apiws", [3; 16]);
    let mut input = InputBuffer::new();
    input.extend(&vec![b'a'; MAX_HEAD_LEN + 1]);
    assert_eq!(handshake.feed(&mut input), Err(WsError::Malformed), "a head that never ends");
}

#[test]
fn server_hello_shorter_than_its_random_is_refused() {
    let mut input = InputBuffer::new();
    input.extend(b"\x16\x03\x03\x00\x02ab\x14\x03\x03\x00\x01\x01\x17\x03\x03\x00\x02cd");
    assert_eq!(verify_server_hello(&mut input, &[0; 32], &[0; 16]), Err(TlsHelloError::InvalidPrefix));
    assert_eq!(verify_client_hello_for_tests(&[0x16; 42], &[0; 16]), None, "too short to carry a random");
    assert_eq!(verify_client_hello_for_tests(&vec![0x16; 16 * 1024 + 1], &[0; 16]), None, "too long");
}

#[test]
fn transport_stream_outgoing_can_be_taken_in_parts_and_buffers_shrink() {
    let mut rng = XorShiftRandom::new(3);
    let config = TransportConfig { framing: Framing::Intermediate, dc_id: 2, secret: None, unix_time: 0 };
    let mut stream = TransportStream::new(&config, &mut rng);
    stream.send_packet(&vec![1u8; 4096], false, &mut rng);
    let all = stream.outgoing().to_vec();
    assert_eq!(all.len(), 64 + 4 + 4096);
    stream.consume_outgoing(100);
    assert_eq!(stream.outgoing(), &all[100..], "the socket took 100 bytes; the rest waits");
    stream.consume_outgoing(all.len() - 100);
    assert!(!stream.has_outgoing());
    assert_eq!(stream.pending_frame_len(), None);
    assert_eq!(stream.pending_frame_head(), None, "no frame header has arrived");
    stream.receive(&[0x11, 0x22]).unwrap();
    assert_eq!(stream.pending_frame_head(), None, "half a length word is not a frame head");
    stream.send_packet(&vec![2u8; 96 * 1024], false, &mut rng);
    let length = stream.outgoing().len();
    stream.consume_outgoing(length);
    stream.receive(&vec![0u8; 96 * 1024]).unwrap();
    stream.shrink_buffers();
    stream.send_packet(&[3u8; 32], false, &mut rng);
    assert_eq!(stream.take_outgoing().len(), 4 + 32, "the stream works after giving its buffers back");
}

#[test]
fn handshake_reports_its_kind_and_refuses_anything_after_done() {
    let mut rng = XorShiftRandom::new(17);
    let mut server = ServerHandshake::new(ServerHandshakeBehavior { server_time: NOW as i32, ..Default::default() });
    let config = HandshakeConfig { dc_id: 2, temp_key_expires_in: Some(3600), public_keys: vec![server.public_key()] };
    let (mut client, mut packet) = Handshake::start(config, NOW, &mut rng);
    assert!(client.is_temporary());
    let first_id = client.last_msg_id();
    assert_eq!(decode_plain_message(&packet).unwrap().msg_id, first_id);
    let reply = loop {
        let reply = server.handle(&packet, &mut rng).expect("server reply");
        match client.on_packet(&reply, NOW, None, &mut rng).unwrap() {
            HandshakeStep::Send(next) => {
                assert!(client.last_msg_id() > first_id, "each request gets a newer msg_id");
                packet = next;
            }
            HandshakeStep::Done(_) => break reply,
        }
    };
    assert_eq!(client.on_packet(&reply, NOW, None, &mut rng).err(), Some(HandshakeError::UnexpectedMessage("done")));
}

#[test]
fn an_encrypted_answer_of_one_block_is_refused_before_parsing() {
    let mut rng = XorShiftRandom::new(23);
    let key = test_rsa_key_pair().public;
    let config = HandshakeConfig { dc_id: 2, temp_key_expires_in: None, public_keys: vec![key.clone()] };
    let (mut client, packet) = Handshake::start(config, NOW, &mut rng);
    assert!(!client.is_temporary());
    let nonce: [u8; 16] = decode_plain_message(&packet).unwrap().body[4..20].try_into().unwrap();
    let server_nonce = [9u8; 16];
    let res_pq = ResPq {
        nonce,
        server_nonce,
        pq: 0x17ED48941A08F981u64.to_be_bytes().to_vec(),
        fingerprints: vec![key.fingerprint()],
    };
    let reply = encode_plain_message(msg_id_for_time(NOW) | 1, &res_pq.to_bytes());
    assert!(matches!(client.on_packet(&reply, NOW, None, &mut rng), Ok(HandshakeStep::Send(_))));
    let params = ServerDhParams::Ok { nonce, server_nonce, encrypted_answer: vec![0x42; 16] };
    let reply = encode_plain_message(msg_id_for_time(NOW) + 5, &params.to_bytes());
    assert_eq!(client.on_packet(&reply, NOW, None, &mut rng).err(), Some(HandshakeError::BadEncryptedAnswer));
}

#[test]
fn rsa_public_exponent_inverts_the_private_one() {
    let pair = test_rsa_key_pair();
    let message = b"the quick brown fox";
    let signed = pair.public.decrypt_with_private_exponent(&pair.d, message);
    assert_eq!(pair.public.public_exponent_raw(&signed), message.to_vec());
}

#[test]
fn malformed_rsa_keys_are_refused() {
    let wrap = |label: &str, der: &[u8]| {
        use base64::Engine;
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    };
    assert_eq!(
        RsaPublicKey::from_pem(&wrap("RSA PUBLIC KEY", &[0x30, 0x80])),
        Err(RsaError::InvalidDer),
        "indefinite length"
    );
    assert_eq!(
        RsaPublicKey::from_pem(&wrap("RSA PUBLIC KEY", &[0x30, 0x85, 1, 1, 1, 1, 1])),
        Err(RsaError::InvalidDer),
        "a five-byte length"
    );
    assert_eq!(RsaPublicKey::from_pem(&wrap("RSA PUBLIC KEY", &[0x30, 0x82, 0x01])), Err(RsaError::InvalidDer));
    let spki = [0x30, 0x08, 0x30, 0x00, 0x03, 0x04, 0x01, 0x30, 0x00, 0x00];
    assert_eq!(RsaPublicKey::from_pem(&wrap("PUBLIC KEY", &spki)), Err(RsaError::InvalidDer), "unused bits in the key");
    assert_eq!(RsaPublicKey::from_pem(&wrap("PRIVATE KEY", &spki)), Err(RsaError::InvalidPem));
    assert_eq!(
        RsaPublicKey::from_pem("-----BEGIN RSA PUBLIC KEY-----\n!!!\n-----END RSA PUBLIC KEY-----"),
        Err(RsaError::InvalidPem)
    );
}

#[test]
fn streaming_aes_ige_matches_one_shot_in_both_directions() {
    let key = [7u8; 32];
    let iv = [9u8; 32];
    let plain: Vec<u8> = (0..96u8).collect();
    let mut expected = plain.clone();
    aes_ige_encrypt(&key, &iv, &mut expected).unwrap();
    let mut streaming = AesIge::new(&key, &iv);
    assert_eq!(streaming.iv(), &iv);
    let mut data = plain.clone();
    let (head, tail) = data.split_at_mut(32);
    streaming.encrypt(head).unwrap();
    streaming.encrypt(tail).unwrap();
    assert_eq!(data, expected);
    assert_ne!(streaming.iv(), &iv, "the chaining state moved on");
    let mut decrypting = AesIge::new(&key, &iv);
    let (head, tail) = data.split_at_mut(48);
    decrypting.decrypt(head).unwrap();
    decrypting.decrypt(tail).unwrap();
    assert_eq!(data, plain);
    assert!(decrypting.decrypt(&mut [0u8; 15]).is_err());
    let mut again = expected.clone();
    aes_ige_decrypt(&key, &iv, &mut again).unwrap();
    assert_eq!(again, plain);
}

#[test]
fn os_random_serves_small_and_large_requests() {
    let mut rng = OsRandom::default();
    assert_eq!(format!("{rng:?}"), "OsRandom { .. }");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        assert!(seen.insert(rng.next_u64()), "a repeated 64-bit value");
    }
    let mut large = vec![0u8; 4096];
    rng.fill(&mut large);
    assert!(large.iter().filter(|byte| **byte == 0).count() < 100, "a large buffer is filled");
    fn draw(mut source: impl SecureRandom) -> [u64; 2] {
        [source.next_u64(), source.next_u64()]
    }
    let through_reference = draw(&mut rng);
    let through_box = draw(Box::new(OsRandom::new()) as Box<dyn SecureRandom>);
    assert_ne!(through_reference[0], through_reference[1]);
    assert_ne!(through_box[0], through_box[1]);
    assert_ne!(through_reference, through_box);
    rng.fill(&mut []);
}

struct Remembered(Option<bool>, Vec<(Vec<u8>, bool)>);

impl DhPrimeCache for Remembered {
    fn is_known_safe(&self, _prime: &[u8]) -> Option<bool> {
        self.0
    }
    fn remember(&mut self, prime: &[u8], safe: bool) {
        self.1.push((prime.to_vec(), safe));
    }
}

#[test]
fn a_cached_verdict_replaces_the_primality_test() {
    let mut prime = KNOWN_DH_PRIME;
    prime[255] ^= 0x10;
    let mut rng = XorShiftRandom::new(1);
    let mut cache = Remembered(Some(false), Vec::new());
    assert_eq!(check_dh_params(&prime, 4, Some(&mut cache), &mut rng), Err(DhError::PrimeNotSafe));
    let mut cache = Remembered(Some(true), Vec::new());
    assert!(check_dh_params(&prime, 4, Some(&mut cache), &mut rng).is_ok(), "the cache is trusted");
    assert!(cache.1.is_empty(), "a cached verdict is not stored again");
    let mut cache = Remembered(None, Vec::new());
    assert_eq!(check_dh_params(&prime, 4, Some(&mut cache), &mut rng), Err(DhError::PrimeNotSafe));
    assert_eq!(cache.1, vec![(prime.to_vec(), false)], "a fresh verdict is remembered");
}

#[test]
fn fixed_width_encoding_refuses_values_that_do_not_fit() {
    let big = num_bigint::BigUint::from_bytes_be(&[1; 9]);
    assert_eq!(to_fixed_be::<8>(&big), None);
    assert_eq!(to_fixed_be::<9>(&big), Some([1; 9]));
    assert_eq!(to_fixed_be::<4>(&num_bigint::BigUint::from(258u32)), Some([0, 0, 1, 2]));
}

#[test]
fn pq_factorisation_edges() {
    assert_eq!(factorize_pq(0x7fff_ffff_ffff_ffe7), None, "a prime has no factors");
    assert_eq!(factorize_pq(3), None);
    assert_eq!(factorize_pq(1 << 40), Some((2, 1 << 39)));
    let p = 4_294_967_291u64;
    let q = 4_294_967_279u64;
    assert_eq!(factorize_pq(p * q), Some((q, p)), "two 32-bit primes, the hardest case pq can be");
    let square = 65_521u64 * 65_521;
    assert_eq!(factorize_pq(square), Some((65_521, 65_521)));
    let mut rng = XorShiftRandom::new(4);
    assert!(is_probable_prime(&num_bigint::BigUint::from(p), 16, &mut rng));
    assert!(!is_probable_prime(&num_bigint::BigUint::from(561u32), 16, &mut rng), "a Carmichael number");
    assert!(!is_probable_prime(&num_bigint::BigUint::from(p * q), 16, &mut rng));
}

#[test]
fn temporary_aes_material_depends_on_both_nonces() {
    let a = handshake_tmp_aes(&[1; 32], &[2; 16]);
    let b = handshake_tmp_aes(&[1; 32], &[3; 16]);
    let c = handshake_tmp_aes(&[4; 32], &[2; 16]);
    assert_ne!(a.key, b.key);
    assert_ne!(a.key, c.key);
    assert_eq!(&a.iv[28..], &[1, 1, 1, 1], "the iv ends with new_nonce[0..4]");
}
