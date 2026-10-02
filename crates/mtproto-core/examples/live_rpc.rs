use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mtproto_core::crypto::{OsRandom, RsaPublicKey};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeStep};
use mtproto_core::rpc::{ApiEnvironment, RequestFlags, RequestId, RpcClient, RpcEvent, RpcRequest, SessionRole};
use mtproto_core::session::{Now, ServerSalt, Session, SessionConfig};
use mtproto_core::tl::{Reader, Writer};
use mtproto_core::transport::{Framing, Incoming, TransportConfig, TransportStream};

const PROD_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----";

fn now(start: Instant) -> Now {
    Now {
        mono: start.elapsed().as_secs_f64(),
        unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
    }
}

fn read_into(socket: &mut TcpStream, stream: &mut TransportStream) -> bool {
    let mut buffer = [0u8; 65536];
    match socket.read(&mut buffer) {
        Ok(0) => panic!("connection closed"),
        Ok(read) => {
            stream.receive(&buffer[..read]).expect("receive");
            true
        }
        Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => false,
        Err(error) => panic!("read: {error}"),
    }
}

fn main() {
    let start = Instant::now();
    let mut rng = OsRandom::new();
    let address = std::env::args().nth(1).unwrap_or_else(|| "149.154.167.51:443".into());
    let dc_id: i32 = std::env::args().nth(2).map(|v| v.parse().unwrap()).unwrap_or(2);
    let mut socket = TcpStream::connect(&address).expect("connect");
    socket.set_nodelay(true).unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut stream = TransportStream::new(
        &TransportConfig {
            framing: Framing::PaddedIntermediate,
            dc_id: dc_id as i16,
            secret: None,
            unix_time: now(start).unix as i32,
        },
        &mut rng,
    );

    let (mut handshake, mut packet) = Handshake::start(
        HandshakeConfig {
            dc_id,
            temp_key_expires_in: None,
            public_keys: vec![RsaPublicKey::from_pem(PROD_KEY).unwrap()],
        },
        now(start).unix,
        &mut rng,
    );
    let result = loop {
        stream.send_packet(&packet, false, &mut rng);
        socket.write_all(&stream.take_outgoing()).unwrap();
        let reply = loop {
            match stream.next_incoming().unwrap() {
                Some(Incoming::Packet(reply)) => break reply,
                Some(other) => panic!("unexpected {other:?}"),
                None => {
                    read_into(&mut socket, &mut stream);
                }
            }
        };
        match handshake.on_packet(&reply, now(start).unix, None, &mut rng).unwrap() {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(result) => break result,
        }
    };
    println!("auth key {:?} after {:?}", result.auth_key, start.elapsed());
    let current = now(start);
    let server_time = current.unix + result.time_difference;
    let salts =
        [ServerSalt { salt: result.server_salt, valid_since: server_time - 10.0, valid_until: server_time + 600.0 }];
    let mut session = Session::new(
        SessionConfig::default(),
        result.auth_key.clone(),
        &salts,
        result.time_difference,
        current,
        &mut rng,
    );
    session.connection_opened(current);
    let environment = ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "Rust MTProto engine probe".into(),
        system_version: "macOS".into(),
        app_version: "0.1".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: "probe".into(),
        disable_updates: true,
    };
    let mut client = RpcClient::new(session, SessionRole::Main, Some(environment), None);
    let requests = [(1u64, 0x1fb33026u32, "help.getNearestDc"), (2, 0xc4f9186b, "help.getConfig")];
    let sent_at = Instant::now();
    for (id, constructor, _) in requests {
        let mut writer = Writer::new();
        writer.write_u32(constructor);
        client.send(
            RpcRequest {
                id: RequestId(id),
                body: writer.into_inner(),
                flags: RequestFlags { quick_ack: true, ..Default::default() },
                invoke_after: None,
            },
            now(start),
        );
    }
    let mut done = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while done < requests.len() && Instant::now() < deadline {
        while let Some(transmit) = client.poll_transmit(now(start), &mut rng) {
            stream.send_packet(&transmit.data, transmit.quick_ack_token.is_some(), &mut rng);
        }
        if stream.has_outgoing() {
            socket.write_all(&stream.take_outgoing()).unwrap();
        }
        read_into(&mut socket, &mut stream);
        while let Some(incoming) = stream.next_incoming().unwrap() {
            match incoming {
                Incoming::Packet(data) => client.handle_packet(&data, now(start), &mut rng).expect("packet"),
                Incoming::QuickAck(token) => client.handle_quick_ack(token, now(start)),
                other => println!("transport {other:?}"),
            }
        }
        client.handle_timeout(now(start)).expect("timeout");
        while let Some(event) = client.poll_event() {
            match event {
                RpcEvent::Completed { id, body, response_time, .. } => {
                    done += 1;
                    let name = requests.iter().find(|r| r.0 == id.0).unwrap().2;
                    let constructor = u32::from_le_bytes(body[..4].try_into().unwrap());
                    print!("  {name}: constructor {constructor:#010x}, {} bytes, {:?}", body.len(), sent_at.elapsed());
                    if constructor == 0x8e1a1775 {
                        let mut reader = Reader::new(&body[4..]);
                        let country = String::from_utf8_lossy(reader.read_bytes().unwrap()).to_string();
                        let this_dc = reader.read_i32().unwrap();
                        let nearest = reader.read_i32().unwrap();
                        print!(" country={country} this_dc={this_dc} nearest_dc={nearest}");
                    }
                    println!(" server_time={response_time:.0}");
                }
                RpcEvent::Failed { id, code, message, .. } => {
                    done += 1;
                    println!("  request {} failed: {code} {message}", id.0);
                }
                other => println!("  event {other:?}"),
            }
        }
    }
    assert_eq!(done, requests.len(), "all requests answered");
}
