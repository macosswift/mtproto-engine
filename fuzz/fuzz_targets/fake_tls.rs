#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, split_points};
use mtproto_core::crypto::XorShiftRandom;
use mtproto_core::transport::{
    InputBuffer, MIN_CLIENT_HELLO_LEN, TlsRecordReader, TlsRecordWriter, client_hello, server_hello_for_tests,
    verify_client_hello_for_tests, verify_server_hello,
};

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let mode = cursor.u8();
    let secret: [u8; 16] = core::array::from_fn(|_| cursor.u8());
    let domain_len = usize::from(cursor.u8());
    let domain = cursor.bytes(domain_len).to_vec();
    let unix_time = cursor.u32() as i32;
    let mut rng = XorShiftRandom::new(u64::from(cursor.u32()) | 1);
    let hello = client_hello(&domain, &secret, unix_time, &mut rng);
    assert!(hello.len() >= MIN_CLIENT_HELLO_LEN);
    assert_eq!(usize::from(u16::from_be_bytes([hello[3], hello[4]])) + 5, hello.len(), "record covers the hello");
    assert_eq!(verify_client_hello_for_tests(&hello, &secret), Some(unix_time));
    let client_random: [u8; 32] = hello[11..43].try_into().expect("32");
    match mode % 3 {
        0 => {
            let mut response = server_hello_for_tests(&hello, &secret, &mut rng);
            let flips = cursor.u8() % 4;
            for _ in 0..flips {
                let at = cursor.below(response.len());
                response[at] ^= cursor.u8() | 1;
            }
            let tail = cursor.chunk();
            response.extend_from_slice(tail);
            let mut input = InputBuffer::new();
            let mut start = 0;
            let mut verified = None;
            for end in split_points(&mut cursor, response.len()) {
                input.extend(&response[start..end]);
                start = end;
                match verify_server_hello(&mut input, &client_random, &secret) {
                    Ok(true) => {
                        verified = Some(input.len());
                        break;
                    }
                    Ok(false) => {}
                    Err(_) => {
                        verified = None;
                        break;
                    }
                }
            }
            if flips == 0
                && let Some(left) = verified
            {
                assert!(left <= tail.len());
            }
        }
        1 => {
            let wire = cursor.chunk().to_vec();
            let mut input = InputBuffer::new();
            let mut start = 0;
            for end in split_points(&mut cursor, wire.len()) {
                input.extend(&wire[start..end]);
                start = end;
                if verify_server_hello(&mut input, &client_random, &secret).is_err() {
                    return;
                }
            }
        }
        _ => {
            let payload = cursor.chunk().to_vec();
            let mut wire = Vec::new();
            TlsRecordWriter::new().write(&payload, &mut wire);
            let garbage = cursor.bool();
            if garbage {
                wire.extend_from_slice(cursor.rest());
            }
            let mut input = InputBuffer::new();
            input.extend(&wire[6..]);
            let mut reader = TlsRecordReader::new();
            let mut out = Vec::new();
            loop {
                match reader.read(&mut input, &mut out) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => {
                        assert!(garbage, "own records never fail");
                        break;
                    }
                }
            }
            assert!(out.len() >= payload.len());
            assert_eq!(&out[..payload.len()], &payload[..]);
        }
    }
});
