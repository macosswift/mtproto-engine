#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, split_points};
use mtproto_core::transport::{
    HttpConnectHandshake, HttpResponseReader, InputBuffer, MAX_ERROR_BODY_LEN, MAX_HEAD_LEN, MAX_INBOUND_FRAME_LEN,
};

/// Hostile bytes: whatever arrives, the reader stays bounded and only completes well-formed responses.
fn hostile(cursor: &mut Cursor<'_>) {
    let max_body = if cursor.bool() { 4096 } else { MAX_INBOUND_FRAME_LEN };
    let connect = cursor.bool();
    let wire = cursor.chunk().to_vec();
    let points = split_points(cursor, wire.len());
    if connect {
        let (mut handshake, _) = HttpConnectHandshake::new("149.154.167.51:443", None);
        let mut input = InputBuffer::new();
        let mut start = 0;
        for end in points {
            input.extend(&wire[start..end]);
            start = end;
            match handshake.feed(&mut input) {
                Ok(true) => {
                    assert!(handshake.is_done());
                    return;
                }
                Ok(false) => assert!(input.len() <= MAX_HEAD_LEN, "unbounded head {}", input.len()),
                Err(_) => return,
            }
        }
        return;
    }
    let mut reader = HttpResponseReader::with_max_body(max_body);
    let mut input = InputBuffer::new();
    let mut start = 0;
    for end in points {
        input.extend(&wire[start..end]);
        start = end;
        loop {
            match reader.read(&mut input) {
                Ok(Some(response)) => {
                    assert!((200..600).contains(&response.status), "status {}", response.status);
                    if (200..300).contains(&response.status) {
                        assert!(response.body.len() <= max_body);
                    } else {
                        assert!(response.body.is_empty(), "error bodies are dropped");
                        assert!(response.transport_error().is_some());
                    }
                    assert!(!reader.in_response());
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
        if let Some((expected, received)) = reader.body_progress() {
            assert!(received <= max_body);
            if let Some(expected) = expected {
                assert!(received <= expected);
            }
        }
        assert!(reader.body_head().len() <= max_body.max(MAX_ERROR_BODY_LEN));
    }
    let _ = reader.finish();
}

/// A response built from the fuzzer's choices parses back exactly, however it is split.
fn well_formed(cursor: &mut Cursor<'_>) {
    let status = [200u16, 204, 404, 429, 500, 502][cursor.below(6)];
    let chunked = cursor.bool();
    let close = cursor.bool();
    let http10 = cursor.bool();
    let continues = cursor.u8() % 3;
    let body = cursor.chunk().to_vec();
    let mut wire = Vec::new();
    for _ in 0..continues {
        wire.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    wire.extend_from_slice(if http10 { b"HTTP/1.0 " } else { b"HTTP/1.1 " });
    wire.extend_from_slice(format!("{status} Reason\r\nServer: x\r\n").as_bytes());
    if close {
        wire.extend_from_slice(b"Connection: close\r\n");
    } else if http10 {
        wire.extend_from_slice(b"Connection: keep-alive\r\n");
    }
    let body = if status == 204 { Vec::new() } else { body };
    if chunked && status != 204 {
        wire.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        let mut rest = &body[..];
        while !rest.is_empty() {
            let take = (usize::from(cursor.u8()) + 1).min(rest.len());
            wire.extend_from_slice(format!("{take:x}\r\n").as_bytes());
            wire.extend_from_slice(&rest[..take]);
            wire.extend_from_slice(b"\r\n");
            rest = &rest[take..];
        }
        wire.extend_from_slice(b"0\r\n\r\n");
    } else {
        wire.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
        wire.extend_from_slice(&body);
    }
    let points = split_points(cursor, wire.len());
    let mut reader = HttpResponseReader::new();
    let mut input = InputBuffer::new();
    let mut responses = Vec::new();
    let mut start = 0;
    for end in points {
        input.extend(&wire[start..end]);
        start = end;
        while let Some(response) = reader.read(&mut input).expect("a well-formed response parses") {
            responses.push(response);
        }
    }
    assert_eq!(responses.len(), 1, "{}", String::from_utf8_lossy(&wire));
    let response = &responses[0];
    assert_eq!(response.status, status);
    assert_eq!(response.keep_alive, !close);
    if (200..300).contains(&status) {
        assert_eq!(response.body, body);
    } else {
        assert!(response.body.is_empty());
    }
    assert!(input.is_empty());
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    if cursor.u8() & 1 == 0 {
        hostile(&mut cursor);
    } else {
        well_formed(&mut cursor);
    }
});
