//! An on-path attacker (no proxy secret hides the obfuscation keys) forging, injecting and flooding
//! transport frames: what it can and cannot make the engine do.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, DropReason, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration,
    PfsSetup, SessionHandle, SessionSetup, unix_seconds,
};
use mtproto_testserver::*;

#[allow(dead_code)]
#[path = "support/sec_audit_mitm.rs"]
mod mitm;
use mitm::{Mitm, Mode};

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, EngineEvent)>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, event));
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("LOG {message}");
        }
    }
}

impl Collector {
    fn wait<F: Fn(&[(SessionHandle, EngineEvent)]) -> bool>(&self, timeout: Duration, predicate: F) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            if predicate(&events) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
    }

    fn count(&self, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, event)| predicate(event)).count()
    }

    fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    fn since(&self, start: usize) -> Vec<EngineEvent> {
        self.events.lock().unwrap()[start..].iter().map(|(_, event)| event.clone()).collect()
    }
}

fn completions(events: &[(SessionHandle, EngineEvent)]) -> usize {
    events.iter().filter(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))).count()
}

/// The call completed, or failed in a way the host may send it again (`TEMP_KEY_ROTATED`).
fn settled(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events.iter().any(|(_, event)| match event {
        EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) => done.0 == id,
        EngineEvent::Rpc(RpcEvent::Failed { id: failed, message, .. }) => {
            failed.0 == id && message == "TEMP_KEY_ROTATED"
        }
        _ => false,
    })
}

fn completed(events: &[(SessionHandle, EngineEvent)], id: u64) -> bool {
    events
        .iter()
        .any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id))
}

fn key_lost(event: &EngineEvent) -> bool {
    matches!(event, EngineEvent::AuthKeyInvalid { .. } | EngineEvent::PermanentKeyInvalid)
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn setup_through(address: std::net::SocketAddr, key: &AuthKey) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: address.ip().to_string(), port: address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.keep_connected = true;
    setup
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

const WAIT: Duration = Duration::from_secs(15);

/// The same attack against engine PFS only ever costs a temporary key: the permanent key is never
/// reported, and calls go through again once the attacker stops.
#[test]
fn forged_404_frames_under_engine_pfs_never_report_the_permanent_key() {
    let perm = random_key(9002);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let attacker = Mitm::start(server.address, Mode::Relay);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup_through(attacker.address, &perm);
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup.http_port = None;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let before = collector.len();
    attacker.switch(Mode::Forge(-404));
    engine.send(session, request(2, 2));
    std::thread::sleep(Duration::from_secs(6));
    let during = collector.since(before);
    attacker.switch(Mode::Relay);
    let settled = collector.wait(Duration::from_secs(70), |events| settled(events, 2));
    engine.send(session, request(3, 3));
    let done = collector.wait(Duration::from_secs(70), |events| completed(events, 3));
    let temporary_keys =
        during.iter().filter(|event| matches!(event, EngineEvent::AuthKeyCreated { expires_at: Some(_), .. })).count();
    engine.shutdown();
    assert_eq!(collector.count(key_lost), 0, "the permanent key is never reported");
    assert!(temporary_keys <= 4, "{temporary_keys} temporary keys made in 6 s of forged -404s");
    assert!(settled, "the call made during the attack completes, or fails as TEMP_KEY_ROTATED");
    assert!(done, "calls go through once the attacker stops");
}

/// Plaintext packets, packets under another key and odd transport codes injected into the stream
/// cost the connection, never the key, the clock or the salts.
#[test]
fn injected_frames_never_touch_the_key_clock_or_salts() {
    let key = random_key(9004);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut plain = Vec::new();
    plain.extend_from_slice(&0u64.to_le_bytes());
    plain.extend_from_slice(&((unix_seconds() as i64 + 100_000) << 32 | 1).to_le_bytes());
    plain.extend_from_slice(&20u32.to_le_bytes());
    plain.extend_from_slice(&[0x63, 0x24, 0x16, 0x05]);
    plain.extend_from_slice(&[7u8; 16]);
    let mut foreign = random_key(1).id().to_le_bytes().to_vec();
    foreign.extend_from_slice(&[0x42u8; 88]);
    let codes: Vec<i32> = vec![-444, -403, 1, i32::MIN, i32::MAX, -1];
    let attacker = Mitm::start(server.address, Mode::Relay);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_through(attacker.address, &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let before = collector.len();
    let mut id = 2;
    for injected in [vec![plain.clone()], vec![foreign.clone()]]
        .into_iter()
        .chain(codes.iter().map(|code| vec![code.to_le_bytes().to_vec()]))
    {
        attacker.switch(Mode::InjectThenRelay(injected));
        engine.send(session, request(id, id as u32));
        std::thread::sleep(Duration::from_millis(1500));
        id += 1;
    }
    attacker.switch(Mode::Relay);
    let all = id - 1;
    let done = collector.wait(Duration::from_secs(40), |events| completions(events) as u64 == all);
    let during = collector.since(before);
    engine.shutdown();
    assert!(done, "calls complete once the injection stops");
    for event in &during {
        assert!(
            !matches!(
                event,
                EngineEvent::AuthKeyInvalid { .. }
                    | EngineEvent::PermanentKeyInvalid
                    | EngineEvent::AuthKeyRequired
                    | EngineEvent::Rpc(RpcEvent::UpdatesReset)
            ),
            "injected frames changed state: {event:?}"
        );
        if let EngineEvent::Rpc(RpcEvent::SaltsUpdated { salts }) = event {
            assert!(salts.iter().all(|salt| salt.salt == SERVER_SALT), "salts from outside the server: {salts:?}");
        }
        if let EngineEvent::Rpc(RpcEvent::TimeDifferenceUpdated { difference }) = event {
            assert!(difference.abs() < 30.0, "the clock moved to {difference}");
        }
    }
    let protocol_drops = during
        .iter()
        .filter(|event| matches!(event, EngineEvent::ConnectionDropped { reason: DropReason::SessionError, .. }))
        .count();
    assert!(protocol_drops >= 1);
}

#[allow(unsafe_code)]
fn process_cpu_seconds() -> f64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let user = usage.ru_utime.tv_sec as f64 + usage.ru_utime.tv_usec as f64 * 1e-6;
    let system = usage.ru_stime.tv_sec as f64 + usage.ru_stime.tv_usec as f64 * 1e-6;
    user + system
}

/// An on-path attacker floods a working connection with forged quick acks (4 bytes each, 31 bits of
/// guessed token): they cost little CPU, never count as liveness, and the session keeps working.
#[test]
fn a_flood_of_forged_quick_acks_is_cheap_and_harmless() {
    let key = random_key(9006);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let attacker = Mitm::start(server.address, Mode::Relay);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup_through(attacker.address, &key));
    engine.send(session, request(1, 1));
    assert!(collector.wait(WAIT, |events| completions(events) == 1));
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut flood = Vec::with_capacity(4 << 20);
    for _ in 0..(1 << 20) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        flood.extend_from_slice(&((state as u32) | 0x8000_0000).to_be_bytes());
    }
    attacker.switch(Mode::RawThenRelay(flood));
    let before = process_cpu_seconds();
    let started = Instant::now();
    engine.send(session, request(2, 2));
    let done = collector.wait(Duration::from_secs(20), |events| completions(events) == 2);
    let cpu = process_cpu_seconds() - before;
    let elapsed = started.elapsed();
    engine.shutdown();
    eprintln!("1M forged quick acks: {cpu:.2} s CPU, completed after {elapsed:?}");
    assert!(done, "the session keeps working under the flood");
    assert!(cpu < 3.0, "{cpu:.2} s of CPU for 4 MB of forged quick acks");
}

/// An on-path attacker answers every key handshake with a forged transport error: no key is made or
/// reported lost, and handshakes back off instead of storming.
#[test]
fn forged_transport_errors_during_key_creation_back_off() {
    for code in [-404, -429, -444] {
        let server = TestServer::start(Vec::new(), ServerOptions::default());
        let attacker = Mitm::start(server.address, Mode::Forge(code));
        let collector = Arc::new(Collector::default());
        let engine = engine(&collector);
        let mut setup = SessionSetup::new(
            2,
            SessionRole::Main,
            vec![DcAddress { host: attacker.address.ip().to_string(), port: attacker.address.port(), secret: None }],
        );
        setup.key_generation = Some(KeyGeneration {
            public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
            temporary_expires_in: None,
        });
        setup.keep_connected = true;
        setup.http_port = None;
        let session = engine.create_session(setup);
        engine.send(session, request(1, 1));
        std::thread::sleep(Duration::from_secs(10));
        let attempts = attacker.connections();
        engine.shutdown();
        assert_eq!(collector.count(key_lost), 0, "code {code}");
        assert_eq!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreated { .. })), 0, "code {code}");
        assert!(collector.count(|event| matches!(event, EngineEvent::AuthKeyCreationFailed { .. })) >= 1);
        assert!((2..=12).contains(&attempts), "code {code}: {attempts} handshakes in 10 s");
    }
}

/// Route memory comes back from the host's storage: any bytes are taken without a panic, and what
/// the engine keeps and gives back stays bounded.
#[test]
fn route_memory_from_storage_is_bounded_and_never_panics() {
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let now = unix_seconds();
    for round in 0..2000 {
        let length = (next() % 4096) as usize;
        let mut memory: Vec<u8> = (0..length).map(|_| next() as u8).collect();
        if round % 2 == 0 && memory.len() > 2 {
            memory[0] = 1;
            let count = (next() % 256) as usize;
            memory[1] = count as u8;
            let mut entries = Vec::new();
            for _ in 0..count {
                let key_length = 1 + (next() % 64) as usize;
                entries.push(key_length as u8);
                entries.extend((0..key_length).map(|_| next() as u8));
                for value in [now - (next() % 100_000) as f64, 0.0, now] {
                    entries.extend_from_slice(&value.to_le_bytes());
                }
            }
            memory.truncate(2);
            memory.extend(entries);
        }
        engine.set_route_memory(&memory);
    }
    let exported = engine.route_memory();
    engine.shutdown();
    assert!(exported.len() <= 2 + 64 * (1 + 64 + 24), "{} bytes of route memory", exported.len());
}
