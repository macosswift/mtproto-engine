//! Property tests over the public API: sequence numbers, salt rotation, and the stream parsers that
//! must give the same result however the network splits their input.

use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::msg_id::SeqNoGenerator;
use mtproto_core::session::{SALT_SAFETY_MARGIN, SaltState, ServerSalt};
use mtproto_core::transport::{
    Framing, HttpResponseReader, Incoming, InputBuffer, ProxySecret, TransportConfig, TransportStream, WsDeframer,
    accept_obfuscated_header, encode_frame,
};
use proptest::prelude::*;

fn split(data: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
    let mut points: Vec<usize> = cuts.iter().map(|cut| cut % (data.len() + 1)).collect();
    points.push(data.len());
    points.sort_unstable();
    let mut start = 0;
    let mut chunks = Vec::new();
    for point in points {
        chunks.push(data[start..point].to_vec());
        start = point;
    }
    chunks
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Content-related messages get odd numbers that rise by two; service messages repeat the even
    /// number of the content count so far.
    #[test]
    fn seqno_counts_content_messages(kinds in proptest::collection::vec(any::<bool>(), 0..200)) {
        let mut generator = SeqNoGenerator::new();
        let mut content = 0;
        for content_related in kinds {
            let seq_no = generator.next(content_related);
            prop_assert_eq!(seq_no, content * 2 + i32::from(content_related));
            prop_assert_eq!(seq_no & 1 == 1, content_related);
            if content_related {
                content += 1;
            }
            prop_assert_eq!(generator.content_messages(), content);
        }
        generator.reset();
        prop_assert_eq!(generator.next(false), 0);
    }

    /// Whatever salts the server hands out, the salt in use at any time is the latest one that has
    /// started, a salt never comes back once replaced, and the next change is always ahead.
    #[test]
    fn salts_rotate_forward_only(
        starts in proptest::collection::vec(0i32..20_000, 1..30),
        lengths in proptest::collection::vec(1i32..4_000, 30),
        probes in proptest::collection::vec(0.0f64..30_000.0, 1..40),
    ) {
        let salts: Vec<ServerSalt> = starts
            .iter()
            .zip(&lengths)
            .enumerate()
            .map(|(index, (start, length))| ServerSalt {
                salt: index as i64 + 1,
                valid_since: f64::from(*start),
                valid_until: f64::from(start + length),
            })
            .collect();
        let mut probes = probes;
        probes.sort_by(f64::total_cmp);
        let mut state = SaltState::empty();
        state.set_future(salts.clone(), -1.0);
        let mut previous_since = f64::NEG_INFINITY;
        for at in probes {
            let current = state.current_salt(at);
            let latest_started = salts
                .iter()
                .filter(|salt| salt.valid_since <= at)
                .max_by(|a, b| a.valid_since.total_cmp(&b.valid_since).then(b.salt.cmp(&a.salt)));
            if let Some(expected) = latest_started {
                let in_use = salts.iter().find(|salt| salt.salt == current).expect("a salt from the list");
                prop_assert_eq!(in_use.valid_since, expected.valid_since);
                prop_assert!(in_use.valid_since >= previous_since, "a replaced salt came back");
                previous_since = in_use.valid_since;
            }
            if let Some(next) = state.next_change_time(at) {
                prop_assert!(next > at);
            }
            let valid = state.has_valid_salt(at);
            prop_assert!(valid || state.needs_future_salts(at));
            if valid {
                let in_use = salts.iter().find(|salt| salt.salt == current).expect("a salt from the list");
                prop_assert!(in_use.valid_until > at + SALT_SAFETY_MARGIN);
            }
            let all = state.all();
            prop_assert!(all.windows(2).all(|pair| pair[0].valid_since <= pair[1].valid_since));
        }
    }

    /// A 200 response with a Content-Length or chunked body parses to the same body under any split.
    #[test]
    fn http_bodies_survive_any_split(
        body in proptest::collection::vec(any::<u8>(), 0..3000),
        chunked in any::<bool>(),
        chunk in 1usize..700,
        cuts in proptest::collection::vec(any::<usize>(), 0..40),
    ) {
        let mut wire = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n".to_vec();
        if chunked {
            wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
            for piece in body.chunks(chunk) {
                wire.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                wire.extend_from_slice(piece);
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
        } else {
            wire.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
            wire.extend_from_slice(&body);
        }
        let mut reader = HttpResponseReader::new();
        let mut input = InputBuffer::new();
        let mut responses = Vec::new();
        for piece in split(&wire, &cuts) {
            input.extend(&piece);
            while let Some(response) = reader.read(&mut input).expect("well formed") {
                responses.push(response);
            }
        }
        prop_assert_eq!(responses.len(), 1);
        prop_assert_eq!(&responses[0].body, &body);
        prop_assert!(responses[0].keep_alive);
        prop_assert!(input.is_empty());
    }

    /// Binary frames of any sizes, with pings between them, deframe to the same stream under any split.
    #[test]
    fn websocket_stream_survives_any_split(
        frames in proptest::collection::vec((proptest::collection::vec(any::<u8>(), 0..400), any::<bool>()), 0..12),
        cuts in proptest::collection::vec(any::<usize>(), 0..40),
    ) {
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (payload, ping_after) in &frames {
            wire.push(0x82);
            if payload.len() < 126 {
                wire.push(payload.len() as u8);
            } else {
                wire.push(126);
                wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            wire.extend_from_slice(payload);
            expected.extend_from_slice(payload);
            if *ping_after {
                wire.extend_from_slice(&[0x89, 2, 7, 7]);
            }
        }
        let mut deframer = WsDeframer::new();
        let mut input = InputBuffer::new();
        let mut out = Vec::new();
        for piece in split(&wire, &cuts) {
            input.extend(&piece);
            deframer.feed(&mut input, &mut out).expect("valid frames");
        }
        prop_assert_eq!(out, expected);
        prop_assert!(input.is_empty());
    }

    /// Server frames through obfuscated2 (with and without an MTProxy secret) reach the client intact
    /// under any split of the encrypted stream.
    #[test]
    fn obfuscated_server_frames_survive_any_split(
        framing in prop::sample::select(vec![Framing::Abridged, Framing::Intermediate, Framing::PaddedIntermediate]),
        secret in prop::option::of(any::<[u8; 16]>()),
        blocks in proptest::collection::vec(0usize..40, 1..6),
        seed in any::<u64>(),
        cuts in proptest::collection::vec(any::<usize>(), 0..30),
    ) {
        let mut rng = XorShiftRandom::new(seed | 1);
        let secret = secret.map(|key| ProxySecret::from_binary(&key, false).expect("16-byte secret"));
        let key = secret.as_ref().map(ProxySecret::proxy_key);
        let config = TransportConfig { framing, dc_id: 2, secret, unix_time: 0 };
        let mut client = TransportStream::new(&config, &mut rng);
        client.send_packet(&[1u8; 24], false, &mut rng);
        let header: [u8; 64] = client.take_outgoing()[..64].try_into().expect("header");
        let mut server = accept_obfuscated_header(&header, key.as_ref()).expect("own header");
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        for (index, extra) in blocks.iter().enumerate() {
            let mut packet = vec![index as u8 + 1; 24 + extra * 16];
            packet[..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
            encode_frame(server.framing, &packet, false, &mut rng, &mut wire);
            expected.push(Incoming::Packet(packet));
        }
        server.encryptor.apply(&mut wire);
        let mut received = Vec::new();
        for piece in split(&wire, &cuts) {
            client.receive(&piece).expect("server bytes");
            while let Some(incoming) = client.next_incoming().expect("server frames") {
                received.push(incoming);
            }
        }
        prop_assert_eq!(received, expected);
    }
}
