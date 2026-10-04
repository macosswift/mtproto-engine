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

const PROD_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----";

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64()
}

struct Http {
    socket: TcpStream,
    input: Vec<u8>,
    name: &'static str,
}

struct Response {
    status: u32,
    head: String,
    body: Vec<u8>,
}

impl Http {
    fn open(address: &str, name: &'static str) -> Self {
        let socket = TcpStream::connect(address).expect("connect");
        socket.set_nodelay(true).unwrap();
        Self { socket, input: Vec::new(), name }
    }

    fn post(&mut self, body: &[u8]) {
        let mut request =
            format!("POST /api HTTP/1.1\r\nHost: \r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n", body.len())
                .into_bytes();
        request.extend_from_slice(body);
        self.socket.write_all(&request).unwrap();
    }

    fn try_parse(&mut self) -> Option<Response> {
        let end = self.input.windows(4).position(|window| window == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&self.input[..end]).to_string();
        let status = head.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
        let length = head
            .lines()
            .find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        if self.input.len() < end + 4 + length {
            return None;
        }
        let body = self.input[end + 4..end + 4 + length].to_vec();
        self.input.drain(..end + 4 + length);
        Some(Response { status, head, body })
    }

    fn wait(&mut self, timeout: Duration) -> Option<Response> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(response) = self.try_parse() {
                return Some(response);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            self.socket.set_read_timeout(Some(left.min(Duration::from_millis(100)))).unwrap();
            let mut buffer = [0u8; 65536];
            match self.socket.read(&mut buffer) {
                Ok(0) => {
                    println!("    [{}] EOF", self.name);
                    return None;
                }
                Ok(read) => self.input.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                Err(error) => {
                    println!("    [{}] read error {error}", self.name);
                    return None;
                }
            }
        }
    }

    fn idle_until_closed(&mut self, limit: Duration) -> Option<Duration> {
        let started = Instant::now();
        let mut buffer = [0u8; 1024];
        self.socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        while started.elapsed() < limit {
            match self.socket.read(&mut buffer) {
                Ok(0) => return Some(started.elapsed()),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::WouldBlock || error.kind() == ErrorKind::TimedOut => {}
                Err(_) => return Some(started.elapsed()),
            }
        }
        None
    }
}

struct Probe {
    auth_key: AuthKey,
    salt: i64,
    session_id: i64,
    time_difference: f64,
    last_msg_id: i64,
    seq_no: i32,
    rng: OsRandom,
    started: Instant,
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

    fn packet(&mut self, messages: &[(Vec<u8>, bool)]) -> (Vec<u8>, Vec<i64>) {
        let mut ids = Vec::new();
        let mut entries = Vec::new();
        for (body, content) in messages {
            let msg_id = self.next_msg_id();
            let seq_no = self.next_seq_no(*content);
            ids.push(msg_id);
            entries.push((msg_id, seq_no, body.clone()));
        }
        let (msg_id, seq_no, body) = if entries.len() == 1 {
            entries.pop().unwrap()
        } else {
            let mut writer = Writer::new();
            writer.write_u32(0x73f1f8dc);
            writer.write_i32(entries.len() as i32);
            for (msg_id, seq_no, body) in &entries {
                writer.write_i64(*msg_id);
                writer.write_i32(*seq_no);
                writer.write_i32(body.len() as i32);
                writer.write_raw(body);
            }
            (self.next_msg_id(), self.next_seq_no(false), writer.into_inner())
        };
        let header = MessageHeader { salt: self.salt, session_id: self.session_id, msg_id, seq_no };
        let data =
            encrypt_message(&self.auth_key, &header, &body, Side::Client, PaddingPolicy::default(), &mut self.rng).data;
        (data, ids)
    }

    fn describe(&mut self, label: &str, response: Option<Response>, sent_at: Instant) -> Vec<i64> {
        let elapsed = sent_at.elapsed().as_secs_f64();
        let mut to_ack = Vec::new();
        match response {
            None => println!("  {label}: no response after {elapsed:.3}s"),
            Some(response) => {
                println!(
                    "  {label}: HTTP {} after {elapsed:.3}s (t={:.3}), body {} bytes",
                    response.status,
                    self.started.elapsed().as_secs_f64(),
                    response.body.len()
                );
                if response.status != 200 {
                    println!("    head: {}", response.head.replace("\r\n", " | "));
                    return to_ack;
                }
                if response.body.is_empty() {
                    return to_ack;
                }
                match decrypt_message(&self.auth_key, &response.body, Side::Server) {
                    Ok(message) => {
                        if message.header.seq_no & 1 == 1 {
                            to_ack.push(message.header.msg_id);
                        }
                        print_message(message.header.msg_id, message.body(), "    ", &mut to_ack, &mut self.salt);
                    }
                    Err(error) => {
                        println!("    undecryptable: {error:?} {:02x?}", &response.body[..response.body.len().min(16)])
                    }
                }
            }
        }
        to_ack
    }
}

fn http_wait(max_delay: i32, wait_after: i32, max_wait: i32) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_u32(0x9299359f);
    writer.write_i32(max_delay);
    writer.write_i32(wait_after);
    writer.write_i32(max_wait);
    writer.into_inner()
}

fn ping(id: i64) -> Vec<u8> {
    let mut writer = Writer::new();
    write_ping(&mut writer, id);
    writer.into_inner()
}

fn acks(ids: &[i64]) -> Vec<u8> {
    let mut writer = Writer::new();
    write_msgs_ack(&mut writer, ids);
    writer.into_inner()
}

fn query() -> Vec<u8> {
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

fn langpack() -> Vec<u8> {
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
    let mut writer = Writer::new();
    writer.write_u32(0xf2f2330a);
    writer.write_bytes(b"macos");
    writer.write_bytes(b"en");
    wrap_request(&writer.into_inner(), Some(&environment), true, None)
}

fn wrapped(inner: Vec<u8>) -> Vec<u8> {
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
    wrap_request(&inner, Some(&environment), true, None)
}

fn strings_query(count: usize) -> Vec<u8> {
    let keys = [
        "lng_menu_settings",
        "lng_settings_save",
        "lng_cancel",
        "lng_box_ok",
        "lng_close",
        "lng_contacts_header",
        "lng_chats",
        "lng_search",
        "lng_settings_general",
        "lng_about_text",
        "lng_settings_notifications",
        "lng_privacy",
        "lng_language",
        "lng_theme",
        "lng_ok",
        "lng_open",
    ];
    let mut writer = Writer::new();
    writer.write_u32(0xefea3803);
    writer.write_bytes(b"macos");
    writer.write_bytes(b"en");
    writer.write_u32(0x1cb5c415);
    writer.write_i32(count as i32);
    for key in keys.iter().cycle().take(count) {
        writer.write_bytes(key.as_bytes());
    }
    wrapped(writer.into_inner())
}

fn print_message(msg_id: i64, body: &[u8], indent: &str, to_ack: &mut Vec<i64>, salt: &mut i64) {
    match ServiceMessage::parse(body) {
        Ok(ServiceMessage::Container(messages)) => {
            println!("{indent}container {msg_id} with {} messages", messages.len());
            for inner in messages {
                if inner.seqno & 1 == 1 {
                    to_ack.push(inner.msg_id);
                }
                print_message(inner.msg_id, inner.body, &format!("{indent}  "), to_ack, salt);
            }
        }
        Ok(ServiceMessage::RpcResult { req_msg_id, result }) => {
            let constructor = u32::from_le_bytes(result[..4].try_into().unwrap());
            println!("{indent}rpc_result req_msg_id={req_msg_id} result={constructor:#010x}");
        }
        Ok(ServiceMessage::BadServerSalt { bad_msg_id, new_server_salt, .. }) => {
            println!("{indent}bad_server_salt bad_msg_id={bad_msg_id}");
            *salt = new_server_salt;
        }
        Ok(other) => println!("{indent}{other:?}"),
        Err(error) => println!("{indent}unparsed ({error:?}) {:02x?}", &body[..body.len().min(8)]),
    }
}

fn handshake(address: &str, dc_id: i32) -> Probe {
    let mut rng = OsRandom::new();
    let mut http = Http::open(address, "handshake");
    let started = Instant::now();
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
        http.post(&packet);
        let reply = http.wait(Duration::from_secs(10)).expect("handshake reply");
        assert_eq!(reply.status, 200, "{}", reply.head);
        match handshake.on_packet(&reply.body, unix_now(), None, &mut rng).unwrap() {
            HandshakeStep::Send(next) => packet = next,
            HandshakeStep::Done(result) => break result,
        }
    };
    println!("auth key over HTTP in {:.3}s (one keep-alive connection)", started.elapsed().as_secs_f64());
    let mut session_bytes = [0u8; 8];
    getrandom::fill(&mut session_bytes).unwrap();
    Probe {
        auth_key: result.auth_key,
        salt: result.server_salt,
        session_id: i64::from_le_bytes(session_bytes),
        time_difference: result.time_difference,
        last_msg_id: 0,
        seq_no: 0,
        rng,
        started,
    }
}

fn main() {
    let address = std::env::args().nth(1).unwrap_or_else(|| "149.154.167.51:80".into());
    let dc_id: i32 = std::env::args().nth(2).map(|v| v.parse().unwrap()).unwrap_or(2);
    let only: Option<String> = std::env::args().nth(3);
    let run = |name: &str| only.as_deref().is_none_or(|only| only.split(',').any(|item| item == name));
    let mut probe = handshake(&address, dc_id);
    let mut a = Http::open(&address, "A");
    let mut b = Http::open(&address, "B");

    let (packet, _) = probe.packet(&[(ping(1), false)]);
    let sent = Instant::now();
    a.post(&packet);
    let ack = probe.describe("P0 ping, no http_wait (salt check)", a.wait(Duration::from_secs(30)), sent);
    let _ = ack;

    if run("p1") {
        let (packet, _) = probe.packet(&[(ping(2), false)]);
        let sent = Instant::now();
        a.post(&packet);
        probe.describe("P1 ping, no http_wait", a.wait(Duration::from_secs(30)), sent);
    }
    if run("p2") {
        let (packet, _) = probe.packet(&[(http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        a.post(&packet);
        probe.describe("P2 http_wait(0,0,0) alone, nothing pending", a.wait(Duration::from_secs(30)), sent);
    }
    if run("p3") {
        let (packet, _) = probe.packet(&[(http_wait(0, 0, 3000), false)]);
        let sent = Instant::now();
        a.post(&packet);
        probe.describe("P3 http_wait(0,0,3000) alone, nothing pending", a.wait(Duration::from_secs(30)), sent);
    }
    if run("p4") {
        let (packet, _) = probe.packet(&[(acks(&[probe.last_msg_id - 4]), false)]);
        let sent = Instant::now();
        a.post(&packet);
        probe.describe(
            "P4 msgs_ack alone, no http_wait (default max_wait 25s?)",
            a.wait(Duration::from_secs(40)),
            sent,
        );
    }
    if run("p5") {
        let (packet, _) = probe.packet(&[(http_wait(0, 0, 10000), false)]);
        let sent_a = Instant::now();
        a.post(&packet);
        std::thread::sleep(Duration::from_millis(300));
        let (packet, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 0), false)]);
        let sent_b = Instant::now();
        b.post(&packet);
        let rb = b.wait(Duration::from_secs(12));
        let ack_b = probe.describe("P5 B: query + http_wait(max_wait=0) while A long-polls", rb, sent_b);
        let ra = a.wait(Duration::from_secs(12));
        let ack_a = probe.describe("P5 A: long poll(10s)", ra, sent_a);
        let mut all = ack_a;
        all.extend(ack_b);
        if !all.is_empty() {
            let (packet, _) = probe.packet(&[(acks(&all), false), (http_wait(0, 0, 0), false)]);
            let sent = Instant::now();
            a.post(&packet);
            probe.describe("    ack", a.wait(Duration::from_secs(5)), sent);
        }
    }
    if run("p6") {
        let (packet, _) = probe.packet(&[(http_wait(0, 0, 10000), false)]);
        let sent_a = Instant::now();
        a.post(&packet);
        std::thread::sleep(Duration::from_millis(300));
        let (packet, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 10000), false)]);
        let sent_b = Instant::now();
        b.post(&packet);
        let rb = b.wait(Duration::from_secs(12));
        let ack_b = probe.describe("P6 B: query + http_wait(max_wait=10s) while A long-polls", rb, sent_b);
        let ra = a.wait(Duration::from_secs(12));
        let ack_a = probe.describe("P6 A: long poll(10s)", ra, sent_a);
        let mut all = ack_a;
        all.extend(ack_b);
        if !all.is_empty() {
            let (packet, _) = probe.packet(&[(acks(&all), false), (http_wait(0, 0, 0), false)]);
            let sent = Instant::now();
            a.post(&packet);
            probe.describe("    ack", a.wait(Duration::from_secs(5)), sent);
        }
    }
    if run("p7") {
        let (packet, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        a.post(&packet);
        let ra = a.wait(Duration::from_secs(12));
        let ack = probe.describe("P7 A alone: query + http_wait(max_wait=10s)", ra, sent);
        if !ack.is_empty() {
            let (packet, _) = probe.packet(&[(acks(&ack), false), (http_wait(0, 0, 0), false)]);
            let sent = Instant::now();
            a.post(&packet);
            probe.describe("    ack", a.wait(Duration::from_secs(5)), sent);
        }
    }
    if run("p8") {
        let (first, _) = probe.packet(&[(http_wait(0, 0, 5000), false)]);
        let (second, _) = probe.packet(&[(ping(8), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        a.post(&first);
        a.post(&second);
        let r1 = a.wait(Duration::from_secs(8));
        probe.describe("P8 pipelined #1 long poll(5s)", r1, sent);
        let r2 = a.wait(Duration::from_secs(8));
        probe.describe("P8 pipelined #2 ping + http_wait(0)", r2, sent);
    }
    if run("p9") {
        let (first, _) = probe.packet(&[(http_wait(0, 0, 8000), false)]);
        let sent = Instant::now();
        a.post(&first);
        std::thread::sleep(Duration::from_millis(300));
        let (second, _) = probe.packet(&[(http_wait(0, 0, 8000), false)]);
        b.post(&second);
        std::thread::sleep(Duration::from_millis(300));
        let mut c = Http::open(&address, "C");
        let (third, _) = probe.packet(&[(ping(9), false), (http_wait(0, 0, 0), false)]);
        let sent_c = Instant::now();
        c.post(&third);
        probe.describe("P9 C: ping + http_wait(0) while A and B long-poll", c.wait(Duration::from_secs(10)), sent_c);
        probe.describe("P9 B: second long poll(8s)", b.wait(Duration::from_secs(10)), sent);
        probe.describe("P9 A: first long poll(8s)", a.wait(Duration::from_secs(10)), sent);
    }
    if run("p10") {
        let (first, _) = probe.packet(&[(http_wait(0, 0, 8000), false)]);
        let sent = Instant::now();
        a.post(&first);
        std::thread::sleep(Duration::from_millis(300));
        let (second, _) = probe.packet(&[(ping(10), false)]);
        b.post(&second);
        probe.describe("P10 B: ping, no http_wait, while A long-polls", b.wait(Duration::from_secs(30)), sent);
        probe.describe("P10 A: long poll(8s)", a.wait(Duration::from_secs(10)), sent);
    }
    if run("p11") {
        let (first, _) = probe.packet(&[(http_wait(200, 100, 5000), false), (ping(11), false)]);
        let sent = Instant::now();
        a.post(&first);
        probe.describe("P11 ping + http_wait(max_delay=200, wait_after=100)", a.wait(Duration::from_secs(10)), sent);
    }

    if run("p12") {
        let (packet, ids) = probe.packet(&[(query(), true), (http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        a.post(&packet);
        let ack = probe.describe("P12 A: query1 + wait(10s), answer not acked", a.wait(Duration::from_secs(12)), sent);
        let _ = ids;
        let (packet, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        b.post(&packet);
        let ack2 = probe.describe(
            "P12 B: query2 + wait(10s), query1 answer still unacked",
            b.wait(Duration::from_secs(12)),
            sent,
        );
        let mut all = ack;
        all.extend(ack2);
        let (packet, _) = probe.packet(&[(acks(&all), false), (query(), true), (http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        a.post(&packet);
        let ack3 = probe.describe("P12 A: acks + query3 + wait(10s)", a.wait(Duration::from_secs(12)), sent);
        let (packet, _) = probe.packet(&[(acks(&ack3), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        a.post(&packet);
        probe.describe("    ack", a.wait(Duration::from_secs(5)), sent);
    }
    if run("p13") {
        let (pa, _) = probe.packet(&[(http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        a.post(&pa);
        std::thread::sleep(Duration::from_millis(200));
        let (pb, _) = probe.packet(&[(http_wait(0, 0, 10000), false)]);
        b.post(&pb);
        std::thread::sleep(Duration::from_millis(200));
        let mut c = Http::open(&address, "C");
        let (pc, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 0), false)]);
        let sent_c = Instant::now();
        c.post(&pc);
        let _ = probe.describe("P13 C: query1 + wait(0) while A, B parked", c.wait(Duration::from_secs(5)), sent_c);
        std::thread::sleep(Duration::from_millis(150));
        let (pc, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 0), false)]);
        let sent_c2 = Instant::now();
        c.post(&pc);
        let _ = probe.describe("P13 C: query2 + wait(0)", c.wait(Duration::from_secs(5)), sent_c2);
        let rb = b.wait(Duration::from_secs(12));
        let mut all = probe.describe("P13 B (newer slot)", rb, sent);
        let ra = a.wait(Duration::from_secs(12));
        all.extend(probe.describe("P13 A (older slot)", ra, sent));
        let (packet, _) = probe.packet(&[(acks(&all), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        c.post(&packet);
        probe.describe("    ack", c.wait(Duration::from_secs(5)), sent);
    }
    if run("lat") {
        let mut own = Vec::new();
        let mut split = Vec::new();
        let mut c = Http::open(&address, "C");
        for round in 0..8 {
            let (packet, _) = probe.packet(&[(query(), true), (http_wait(0, 0, 10000), false)]);
            let sent = Instant::now();
            a.post(&packet);
            let response = a.wait(Duration::from_secs(12));
            own.push(sent.elapsed().as_secs_f64() * 1000.0);
            let mut ack = Vec::new();
            if let Some(r) = response
                && let Ok(m) = decrypt_message(&probe.auth_key, &r.body, Side::Server)
            {
                if m.header.seq_no & 1 == 1 {
                    ack.push(m.header.msg_id);
                }
                let mut salt = probe.salt;
                print_message(m.header.msg_id, m.body(), "      ", &mut ack, &mut salt);
            }
            let (packet, _) = probe.packet(&[(acks(&ack), false), (http_wait(0, 0, 10000), false)]);
            let sent_slot = Instant::now();
            b.post(&packet);
            std::thread::sleep(Duration::from_millis(100));
            let (packet, _) = probe.packet(&[(query(), true), (http_wait(30, 10, 0), false)]);
            let sent = Instant::now();
            c.post(&packet);
            let rc = c.wait(Duration::from_secs(5));
            let rb = b.wait(Duration::from_secs(12));
            let t = sent.elapsed().as_secs_f64() * 1000.0;
            split.push(t);
            let mut ack = Vec::new();
            for r in [rc, rb].into_iter().flatten() {
                if let Ok(m) = decrypt_message(&probe.auth_key, &r.body, Side::Server) {
                    if m.header.seq_no & 1 == 1 {
                        ack.push(m.header.msg_id);
                    }
                    let mut salt = probe.salt;
                    print_message(m.header.msg_id, m.body(), "      ", &mut ack, &mut salt);
                }
            }
            let _ = sent_slot;
            let (packet, _) = probe.packet(&[(acks(&ack), false), (http_wait(0, 0, 0), false)]);
            c.post(&packet);
            let _ = c.wait(Duration::from_secs(5));
            println!("  lat round {round}: own-slot {:.1} ms, tdlib-style {:.1} ms", own[round], split[round]);
        }
        own.sort_by(f64::total_cmp);
        split.sort_by(f64::total_cmp);
        println!("  lat median: own-slot {:.1} ms, tdlib-style {:.1} ms", own[4], split[4]);
    }

    if run("big") {
        let (packet, _) = probe.packet(&[(langpack(), true), (http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        a.post(&packet);
        let ack = probe.describe("L1 A: langpack + wait(10s), not acked", a.wait(Duration::from_secs(12)), sent);
        let (packet, _) = probe.packet(&[(ping(20), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        b.post(&packet);
        let ack_b =
            probe.describe("L1 B: ping + wait(0) with the big answer unacked", b.wait(Duration::from_secs(12)), sent);
        let (packet, _) = probe.packet(&[(ping(21), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        b.post(&packet);
        probe.describe("L1 B again: ping + wait(0), still unacked", b.wait(Duration::from_secs(12)), sent);
        let mut all = ack;
        all.extend(ack_b);
        let (packet, _) = probe.packet(&[(acks(&all), false), (ping(22), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        b.post(&packet);
        probe.describe("L1 B: acks + ping", b.wait(Duration::from_secs(12)), sent);
    }
    if run("inflight") {
        let mut slow = Http::open(&address, "S");
        let (packet, _) = probe.packet(&[(langpack(), true), (http_wait(0, 0, 10000), false)]);
        let sent = Instant::now();
        slow.post(&packet);
        std::thread::sleep(Duration::from_millis(1500));
        let (packet, _) = probe.packet(&[(ping(30), false), (http_wait(0, 0, 0), false)]);
        let sent_b = Instant::now();
        b.post(&packet);
        let ack_b = probe.describe(
            "L2 B: ping + wait(0) while S's big response is unread",
            b.wait(Duration::from_secs(12)),
            sent_b,
        );
        let ack_s = probe.describe("L2 S: langpack response (read late)", slow.wait(Duration::from_secs(12)), sent);
        let mut all = ack_s;
        all.extend(ack_b);
        let (packet, _) = probe.packet(&[(acks(&all), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        b.post(&packet);
        probe.describe("L2 B: acks", b.wait(Duration::from_secs(12)), sent);
    }

    if run("thresh") {
        let mut candidates: Vec<(&str, Vec<u8>)> = vec![
            ("getConfig", wrapped(0xc4f9186bu32.to_le_bytes().to_vec())),
            (
                "getAppConfig",
                wrapped({
                    let mut w = Writer::new();
                    w.write_u32(0x61e3f854);
                    w.write_i32(0);
                    w.into_inner()
                }),
            ),
        ];
        for count in [1usize, 4, 16] {
            candidates.push(("getStrings", strings_query(count)));
        }
        for (name, body) in candidates {
            let (packet, _) = probe.packet(&[(body, true), (http_wait(0, 0, 10000), false)]);
            let sent = Instant::now();
            a.post(&packet);
            let response = a.wait(Duration::from_secs(12));
            let size = response.as_ref().map_or(0, |r| r.body.len());
            let ack = probe.describe(&format!("{name}: answer ({size} bytes response), not acked"), response, sent);
            let (packet, _) = probe.packet(&[(ping(40), false), (http_wait(0, 0, 0), false)]);
            let sent = Instant::now();
            b.post(&packet);
            let ack_b = probe.describe(
                &format!("{name}: next response re-carries it how?"),
                b.wait(Duration::from_secs(12)),
                sent,
            );
            let mut all = ack;
            all.extend(ack_b);
            let (packet, _) = probe.packet(&[(acks(&all), false), (http_wait(0, 0, 0), false)]);
            b.post(&packet);
            let _ = b.wait(Duration::from_secs(5));
        }
    }
    if run("idle") {
        let mut d = Http::open(&address, "D");
        let (packet, _) = probe.packet(&[(ping(12), false), (http_wait(0, 0, 0), false)]);
        let sent = Instant::now();
        d.post(&packet);
        probe.describe("idle: ping", d.wait(Duration::from_secs(5)), sent);
        match d.idle_until_closed(Duration::from_secs(400)) {
            Some(after) => {
                println!("  idle keep-alive connection closed by the server after {:.1}s", after.as_secs_f64())
            }
            None => println!("  idle keep-alive connection still open after 400s"),
        }
    }
}
