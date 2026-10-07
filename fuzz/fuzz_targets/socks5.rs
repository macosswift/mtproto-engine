#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_cargo_fuzz::{Cursor, split_points};
use mtproto_core::transport::{InputBuffer, Socks5Auth, Socks5Handshake, Socks5Progress, Socks5Target};

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let target = match cursor.u8() % 3 {
        0 => Socks5Target::Ipv4(core::array::from_fn(|_| cursor.u8()), cursor.u16()),
        1 => Socks5Target::Ipv6(core::array::from_fn(|_| cursor.u8()), cursor.u16()),
        _ => {
            let length = usize::from(cursor.u16() % 300);
            Socks5Target::Domain(String::from_utf8_lossy(cursor.bytes(length)).into_owned(), cursor.u16())
        }
    };
    let auth = cursor.bool().then(|| {
        let user = usize::from(cursor.u16() % 300);
        let username = String::from_utf8_lossy(cursor.bytes(user)).into_owned();
        let pass = usize::from(cursor.u16() % 300);
        Socks5Auth { username, password: String::from_utf8_lossy(cursor.bytes(pass)).into_owned() }
    });
    let with_auth = auth.is_some();
    let Ok((mut handshake, greeting)) = Socks5Handshake::new(target.clone(), auth.clone()) else {
        return;
    };
    assert_eq!(greeting, if with_auth { vec![5, 2, 0, 2] } else { vec![5, 1, 0] });
    let wire = cursor.chunk().to_vec();
    let mut input = InputBuffer::new();
    let mut start = 0;
    let mut sent = Vec::new();
    for end in split_points(&mut cursor, wire.len()) {
        input.extend(&wire[start..end]);
        start = end;
        loop {
            let before = input.len();
            match handshake.feed(&mut input) {
                Ok(Socks5Progress::NeedMore) => {
                    assert_eq!(input.len(), before, "NeedMore consumes nothing");
                    break;
                }
                Ok(Socks5Progress::Send(request)) => {
                    assert!(before - input.len() == 2, "replies to greeting/auth are two bytes");
                    sent.push(request);
                }
                Ok(Socks5Progress::Connected) => {
                    assert!(handshake.is_done());
                    let connect = sent.last().expect("a connect request went out first");
                    assert_eq!(&connect[..3], &[5, 1, 0]);
                    match &target {
                        Socks5Target::Ipv4(address, port) => {
                            assert_eq!(connect[3], 1);
                            assert_eq!(&connect[4..8], address);
                            assert_eq!(&connect[8..], port.to_be_bytes());
                        }
                        Socks5Target::Ipv6(address, port) => {
                            assert_eq!(connect[3], 4);
                            assert_eq!(&connect[4..20], address);
                            assert_eq!(&connect[20..], port.to_be_bytes());
                        }
                        Socks5Target::Domain(domain, port) => {
                            assert_eq!(connect[3], 3);
                            assert_eq!(usize::from(connect[4]), domain.len());
                            assert_eq!(&connect[5..5 + domain.len()], domain.as_bytes());
                            assert_eq!(&connect[5 + domain.len()..], port.to_be_bytes());
                        }
                    }
                    if sent.len() == 2 {
                        let auth = auth.as_ref().expect("an auth request needs credentials");
                        let request = &sent[0];
                        assert_eq!(request[0], 1);
                        assert_eq!(usize::from(request[1]), auth.username.len());
                    } else {
                        assert_eq!(sent.len(), 1);
                    }
                    return;
                }
                Err(_) => return,
            }
        }
    }
});
