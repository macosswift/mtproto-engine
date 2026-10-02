use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mtproto_core::auth_key::AuthKey;
use mtproto_core::crypto::{OsRandom, RsaPublicKey, Side};
use mtproto_core::handshake::{Handshake, HandshakeConfig, HandshakeStep};
use mtproto_core::message::{MessageHeader, PaddingPolicy, decrypt_message, encrypt_message};
use mtproto_core::msg_id::msg_id_for_time;
use mtproto_core::rpc::{ApiEnvironment, wrap_request};
use mtproto_core::tl::Writer;
use mtproto_core::tl::mtproto::{ServiceMessage, write_msgs_ack, write_ping};
use mtproto_core::transport::{Framing, Incoming, TransportConfig, TransportStream};

const PROD_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----";

struct Probe {
    address: String,
    dc_id: i32,
    auth_key: AuthKey,
    salt: i64,
    session_id: i64,
    time_difference: f64,
    last_msg_id: i64,
    seq_no: i32,
    rng: OsRandom,
}

struct Connection {
    socket: TcpStream,
    stream: TransportStream,
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

fn connect(address: &str, dc_id: i32, rng: &mut OsRandom) -> Connection {
    let socket = TcpStream::connect(address).expect("connect");
    socket.set_nodelay(true).unwrap();
    socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let stream = TransportStream::new(
        &TransportConfig {
            framing: Framing::PaddedIntermediate,
            dc_id: dc_id as i16,
            secret: None,
            unix_time: unix_now() as i32,
        },
        rng,
    );
    Connection { socket, stream }
}

impl Connection {
    fn send(&mut self, packet: &[u8], rng: &mut OsRandom) {
        self.stream.send_packet(packet, false, rng);
        self.socket.write_all(&self.stream.take_outgoing()).unwrap();
    }

    fn collect(&mut self, duration: Duration) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + duration;
        let mut packets = Vec::new();
        let mut buffer = [0u8; 65536];
        while Instant::now() < deadline {
            match self.socket.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => self.stream.receive(&buffer[..read]).expect("receive"),
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                Err(error) => panic!("read: {error}"),
            }
            while let Some(incoming) = self.stream.next_incoming().unwrap() {
                match incoming {
                    Incoming::Packet(data) => packets.push(data),
                    other => println!("    transport {other:?}"),
                }
            }
        }
        packets
    }
}

impl Probe {
    fn next_msg_id(&mut self) -> i64 {
        let candidate = msg_id_for_time(unix_now() + self.time_difference);
        self.last_msg_id = candidate.max(self.last_msg_id + 4);
        self.last_msg_id
    }

    fn next_seq_no(&mut self, content_related: bool) -> i32 {
        if content_related {
            self.seq_no += 1;
            self.seq_no * 2 - 1
        } else {
            self.seq_no * 2
        }
    }

    fn encrypt(&mut self, msg_id: i64, seq_no: i32, body: &[u8]) -> Vec<u8> {
        let header = MessageHeader { salt: self.salt, session_id: self.session_id, msg_id, seq_no };
        encrypt_message(&self.auth_key, &header, body, Side::Client, PaddingPolicy::default(), &mut self.rng).data
    }

    fn describe(&mut self, label: &str, packets: Vec<Vec<u8>>, connection: &mut Connection) {
        println!("  {label}:");
        if packets.is_empty() {
            println!("    (nothing)");
        }
        let mut to_ack = Vec::new();
        for packet in packets {
            let message = decrypt_message(&self.auth_key, &packet, Side::Server).expect("decrypt");
            let header = message.header;
            if header.seq_no & 1 == 1 {
                to_ack.push(header.msg_id);
            }
            print_message(header.msg_id, message.body(), "    ", &mut to_ack, &mut self.salt);
        }
        if !to_ack.is_empty() {
            let mut writer = Writer::new();
            write_msgs_ack(&mut writer, &to_ack);
            let msg_id = self.next_msg_id();
            let seq_no = self.next_seq_no(false);
            let packet = self.encrypt(msg_id, seq_no, &writer.into_inner());
            connection.send(&packet, &mut self.rng);
        }
    }

    fn container(&mut self, messages: &[(i64, i32, &[u8])]) -> (i64, i32, Vec<u8>) {
        let mut writer = Writer::new();
        writer.write_u32(0x73f1f8dc);
        writer.write_i32(messages.len() as i32);
        for (msg_id, seq_no, body) in messages {
            writer.write_i64(*msg_id);
            writer.write_i32(*seq_no);
            writer.write_i32(body.len() as i32);
            writer.write_raw(body);
        }
        let msg_id = self.next_msg_id();
        let seq_no = self.next_seq_no(false);
        (msg_id, seq_no, writer.into_inner())
    }

    fn ping_body(ping_id: i64) -> Vec<u8> {
        let mut writer = Writer::new();
        write_ping(&mut writer, ping_id);
        writer.into_inner()
    }

    fn request(&mut self) -> Vec<u8> {
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
        wrap_request(&0x1fb33026u32.to_le_bytes(), Some(&environment), true, None)
    }
}

fn print_message(msg_id: i64, body: &[u8], indent: &str, to_ack: &mut Vec<i64>, salt: &mut i64) {
    match ServiceMessage::parse(body) {
        Ok(ServiceMessage::Container(messages)) => {
            println!("{indent}container {msg_id}");
            for inner in messages {
                if inner.seqno & 1 == 1 {
                    to_ack.push(inner.msg_id);
                }
                print_message(inner.msg_id, inner.body, &format!("{indent}  "), to_ack, salt);
            }
        }
        Ok(ServiceMessage::RpcResult { req_msg_id, result }) => {
            let constructor = u32::from_le_bytes(result[..4].try_into().unwrap());
            println!("{indent}rpc_result answer_msg_id={msg_id} req_msg_id={req_msg_id} result={constructor:#010x}");
        }
        Ok(ServiceMessage::BadServerSalt { bad_msg_id, new_server_salt, .. }) => {
            println!("{indent}bad_server_salt bad_msg_id={bad_msg_id}");
            *salt = new_server_salt;
        }
        Ok(ServiceMessage::MsgsStateInfo { req_msg_id, info }) => {
            println!("{indent}msgs_state_info req_msg_id={req_msg_id} info={info:?}");
        }
        Ok(other) => println!("{indent}{msg_id}: {other:?}"),
        Err(error) => println!("{indent}{msg_id}: unparsed ({error:?})"),
    }
}

fn handshake(address: &str, dc_id: i32) -> Probe {
    let mut rng = OsRandom::new();
    let mut connection = connect(address, dc_id, &mut rng);
    let (mut handshake, mut packet) = Handshake::start(
        HandshakeConfig {
            dc_id,
            temp_key_expires_in: None,
            public_keys: vec![RsaPublicKey::from_pem(PROD_KEY).unwrap()],
        },
        unix_now(),
        &mut rng,
    );
    let result = loop {
        connection.send(&packet, &mut rng);
        let reply = loop {
            if let Some(reply) = connection.collect(Duration::from_millis(100)).into_iter().next() {
                break reply;
            }
        };
        match handshake.on_packet(&reply, unix_now(), None, &mut rng).unwrap() {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(result) => break result,
        }
    };
    let session_id = rand_i64();
    Probe {
        address: address.to_string(),
        dc_id,
        auth_key: result.auth_key,
        salt: result.server_salt,
        session_id,
        time_difference: result.time_difference,
        last_msg_id: 0,
        seq_no: 0,
        rng,
    }
}

fn rand_i64() -> i64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).unwrap();
    i64::from_le_bytes(bytes)
}

fn main() {
    let address = std::env::args().nth(1).unwrap_or_else(|| "149.154.167.51:443".into());
    let dc_id: i32 = std::env::args().nth(2).map(|v| v.parse().unwrap()).unwrap_or(2);
    let mut probe = handshake(&address, dc_id);
    let settle = Duration::from_millis(1500);

    println!("A. send query X on connection 1, ack the answer, close");
    let mut first = connect(&probe.address, probe.dc_id, &mut probe.rng);
    let body = probe.request();
    let x = probe.next_msg_id();
    let x_seq = probe.next_seq_no(true);
    let x_packet = probe.encrypt(x, x_seq, &body);
    first.send(&x_packet, &mut probe.rng);
    let packets = first.collect(settle);
    probe.describe("connection 1", packets, &mut first);
    drop(first);
    println!("  X = {x}");

    println!("B. re-send the identical packet for X on connection 2");
    let mut second = connect(&probe.address, probe.dc_id, &mut probe.rng);
    second.send(&x_packet, &mut probe.rng);
    let packets = second.collect(settle);
    probe.describe("connection 2", packets, &mut second);

    println!("C. re-encrypt X (same msg_id and seqno, new padding) on connection 2");
    let reencrypted = probe.encrypt(x, x_seq, &body);
    second.send(&reencrypted, &mut probe.rng);
    let packets = second.collect(settle);
    probe.describe("connection 2", packets, &mut second);
    drop(second);

    println!("D. send query Y on connection 3 but do not read; drop the connection immediately after a later ping");
    let y_body = probe.request();
    let y = probe.next_msg_id();
    let y_seq = probe.next_seq_no(true);
    let y_packet = probe.encrypt(y, y_seq, &y_body);
    let mut third = connect(&probe.address, probe.dc_id, &mut probe.rng);
    third.send(&y_packet, &mut probe.rng);
    drop(third);
    std::thread::sleep(Duration::from_millis(300));
    let mut fourth = connect(&probe.address, probe.dc_id, &mut probe.rng);
    println!("  Y = {y}; on connection 4 send ping (higher msg_id) then Y again");
    let mut ping = Writer::new();
    write_ping(&mut ping, 42);
    let ping_id = probe.next_msg_id();
    let ping_seq = probe.next_seq_no(false);
    let ping_packet = probe.encrypt(ping_id, ping_seq, &ping.into_inner());
    fourth.send(&ping_packet, &mut probe.rng);
    fourth.send(&y_packet, &mut probe.rng);
    let packets = fourth.collect(settle);
    probe.describe("connection 4", packets, &mut fourth);

    println!("E. Z never sent before; send ping first, then Z with a LOWER msg_id than the ping");
    let z_body = probe.request();
    let z = probe.next_msg_id();
    let z_seq = probe.next_seq_no(true);
    let mut ping = Writer::new();
    write_ping(&mut ping, 43);
    let ping_id = probe.next_msg_id();
    let ping_seq = probe.next_seq_no(false);
    let ping_packet = probe.encrypt(ping_id, ping_seq, &ping.into_inner());
    fourth.send(&ping_packet, &mut probe.rng);
    let _ = fourth.collect(Duration::from_millis(400));
    let z_packet = probe.encrypt(z, z_seq, &z_body);
    fourth.send(&z_packet, &mut probe.rng);
    println!("  Z = {z} (ping {ping_id})");
    let packets = fourth.collect(settle);
    probe.describe("connection 4", packets, &mut fourth);

    println!("F. W sent and answered but the answer is NOT acked; reconnect and re-send W");
    let w_body = probe.request();
    let w = probe.next_msg_id();
    let w_seq = probe.next_seq_no(true);
    let w_packet = probe.encrypt(w, w_seq, &w_body);
    fourth.send(&w_packet, &mut probe.rng);
    let packets = fourth.collect(settle);
    for packet in &packets {
        let message = decrypt_message(&probe.auth_key, packet, Side::Server).expect("decrypt");
        let mut ignored = Vec::new();
        print_message(message.header.msg_id, message.body(), "    (unacked) ", &mut ignored, &mut probe.salt);
    }
    drop(fourth);
    let mut fifth = connect(&probe.address, probe.dc_id, &mut probe.rng);
    println!("  W = {w}; re-send on connection 5");
    fifth.send(&w_packet, &mut probe.rng);
    let packets = fifth.collect(Duration::from_millis(2500));
    probe.describe("connection 5", packets, &mut fifth);

    println!("G. X2 inside container [ping, X2] answered and acked; re-send X2 inside a NEW container [X2, ping]");
    let x2_body = probe.request();
    let ping_a = Probe::ping_body(50);
    let ping_a_id = probe.next_msg_id();
    let ping_a_seq = probe.next_seq_no(false);
    let x2 = probe.next_msg_id();
    let x2_seq = probe.next_seq_no(true);
    let (c1, c1_seq, c1_body) = probe.container(&[(ping_a_id, ping_a_seq, &ping_a), (x2, x2_seq, &x2_body)]);
    let c1_packet = probe.encrypt(c1, c1_seq, &c1_body);
    fifth.send(&c1_packet, &mut probe.rng);
    let packets = fifth.collect(settle);
    probe.describe("connection 5", packets, &mut fifth);
    drop(fifth);
    let mut sixth = connect(&probe.address, probe.dc_id, &mut probe.rng);
    let ping_b = Probe::ping_body(51);
    let ping_b_id = probe.next_msg_id();
    let ping_b_seq = probe.next_seq_no(false);
    let (c2, c2_seq, c2_body) = probe.container(&[(x2, x2_seq, &x2_body), (ping_b_id, ping_b_seq, &ping_b)]);
    let c2_packet = probe.encrypt(c2, c2_seq, &c2_body);
    println!("  X2 = {x2}");
    sixth.send(&c2_packet, &mut probe.rng);
    let packets = sixth.collect(settle);
    probe.describe("connection 6", packets, &mut sixth);

    println!("H. X3 inside a container written then dropped at once; re-send X3 inside a new container");
    let x3_body = probe.request();
    let x3 = probe.next_msg_id();
    let x3_seq = probe.next_seq_no(true);
    let ping_c = Probe::ping_body(52);
    let ping_c_id = probe.next_msg_id();
    let ping_c_seq = probe.next_seq_no(false);
    let (c3, c3_seq, c3_body) = probe.container(&[(x3, x3_seq, &x3_body), (ping_c_id, ping_c_seq, &ping_c)]);
    let c3_packet = probe.encrypt(c3, c3_seq, &c3_body);
    let mut seventh = connect(&probe.address, probe.dc_id, &mut probe.rng);
    seventh.send(&c3_packet, &mut probe.rng);
    drop(seventh);
    std::thread::sleep(Duration::from_millis(300));
    let ping_d = Probe::ping_body(53);
    let ping_d_id = probe.next_msg_id();
    let ping_d_seq = probe.next_seq_no(false);
    let (c4, c4_seq, c4_body) = probe.container(&[(x3, x3_seq, &x3_body), (ping_d_id, ping_d_seq, &ping_d)]);
    let c4_packet = probe.encrypt(c4, c4_seq, &c4_body);
    println!("  X3 = {x3}");
    sixth.send(&c4_packet, &mut probe.rng);
    let packets = sixth.collect(settle);
    probe.describe("connection 6", packets, &mut sixth);

    println!("I. re-send already-answered X with a WRONG salt");
    let good_salt = probe.salt;
    probe.salt = good_salt ^ 0x5a5a;
    let wrong = probe.encrypt(x, x_seq, &body);
    probe.salt = good_salt;
    sixth.send(&wrong, &mut probe.rng);
    let packets = sixth.collect(settle);
    probe.describe("connection 6", packets, &mut sixth);

    println!("J. NEW query V sent only with a WRONG salt, then re-sent with the right salt and the same msg_id");
    let v_body = probe.request();
    let v = probe.next_msg_id();
    let v_seq = probe.next_seq_no(true);
    probe.salt = good_salt ^ 0x5a5a;
    let v_wrong = probe.encrypt(v, v_seq, &v_body);
    probe.salt = good_salt;
    sixth.send(&v_wrong, &mut probe.rng);
    let packets = sixth.collect(settle);
    probe.describe("connection 6 (wrong salt)", packets, &mut sixth);
    let v_right = probe.encrypt(v, v_seq, &v_body);
    sixth.send(&v_right, &mut probe.rng);
    let packets = sixth.collect(settle);
    println!("  V = {v}");
    probe.describe("connection 6 (right salt)", packets, &mut sixth);
}
