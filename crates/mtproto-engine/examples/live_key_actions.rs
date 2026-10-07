//! Live probe of what the app's MTContext actions ask of the engine, against production datacenter 2,
//! with throwaway keys and no account:
//! 1. a key-only session (no key, no requests) makes a permanent key over plain HTTP, port 80;
//! 2. the same with the datacenter address unreachable, so only Telegram Web's WebSocket gets through;
//! 3. a key check (PFS session, no requests) binds a fresh temporary key to the key made in 1;
//! 4. a key check against a random permanent key the server never saw;
//! 5. `auth.importAuthorization` with made-up bytes under the key made in 1;
//! 6. checks 3 and 4 again with the address unreachable, so the binds go over Telegram Web only.
//!
//! Run: `cargo run --release -p mtproto-engine --example live_key_actions`.

#[path = "../tests/support/stream_host.rs"]
mod stream_host;

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::crypto::RsaPublicKey;
use mtproto_engine::mtproto_core::rpc::{ApiEnvironment, RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::tl::Writer;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, LogLevel, PfsSetup,
    SessionHandle, SessionSetup, TransportPreference,
};
use stream_host::TestStreamHost;

const PRODUCTION_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----";
const DC2: &str = "149.154.167.50";
/// TEST-NET-1: never answers, so Auto has to look past TCP and plain HTTP.
const UNREACHABLE: &str = "192.0.2.1";
const AUTH_IMPORT_AUTHORIZATION: u32 = 0xa57a_7dad;

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<(SessionHandle, EngineEvent, Instant)>>,
    condvar: Condvar,
}

impl EngineCallbacks for Recorder {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, event, Instant::now()));
        self.condvar.notify_all();
    }

    fn on_log(&self, level: LogLevel, message: &str) {
        if level <= LogLevel::Info {
            println!("    [engine] {message}");
        }
    }
}

impl Recorder {
    fn wait<T>(
        &self,
        session: SessionHandle,
        timeout: Duration,
        pick: impl Fn(&EngineEvent) -> Option<T>,
    ) -> Option<T> {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            if let Some(found) = events.iter().filter(|(s, _, _)| *s == session).find_map(|(_, event, _)| pick(event)) {
                return Some(found);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            events = self.condvar.wait_timeout(events, left.min(Duration::from_millis(100))).unwrap().0;
        }
    }
}

fn public_keys() -> Vec<RsaPublicKey> {
    vec![RsaPublicKey::from_pem(PRODUCTION_KEY).expect("production key")]
}

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "Rust MTProto engine probe".into(),
        system_version: "macOS".into(),
        app_version: "0.1".into(),
        system_lang_code: "en".into(),
        lang_pack: String::new(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: String::new(),
        disable_updates: true,
    }
}

fn key_maker(address: &str, transport: TransportPreference) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: address.into(), port: 443, secret: None }],
    );
    setup.transport = transport;
    setup.http_port = Some(80);
    setup.key_generation = Some(KeyGeneration { public_keys: public_keys(), temporary_expires_in: None });
    setup.environment = Some(environment());
    setup
}

fn key_check(permanent: &AuthKey, salt: Option<i64>) -> SessionSetup {
    key_check_at(DC2, TransportPreference::Http, permanent, salt)
}

fn key_check_at(address: &str, transport: TransportPreference, permanent: &AuthKey, salt: Option<i64>) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Worker { requires_auth_token: false },
        vec![DcAddress { host: address.into(), port: 443, secret: None }],
    );
    setup.transport = transport;
    setup.http_port = Some(80);
    setup.environment = Some(environment());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    setup.auth_key = Some(AuthKeyMaterial {
        key: permanent.clone(),
        salts: salt
            .map(|salt| vec![ServerSalt { salt, valid_since: now - 60.0, valid_until: now + 1800.0 }])
            .unwrap_or_default(),
        init_hash: None,
    });
    setup.pfs = Some(PfsSetup {
        lifetime: 3600,
        public_keys: public_keys(),
        permanent_key_from_host: true,
        temporary_key: None,
    });
    setup
}

fn made_key(event: &EngineEvent) -> Option<(AuthKey, i64, f64, i32)> {
    match event {
        EngineEvent::AuthKeyCreated { key, salt, time_difference, expires_at: None, dc_id } => {
            AuthKey::from_slice(key).map(|key| (key, *salt, *time_difference, *dc_id))
        }
        _ => None,
    }
}

fn bind_outcome(event: &EngineEvent) -> Option<String> {
    match event {
        EngineEvent::Rpc(RpcEvent::TemporaryKeyBound) => Some("bound".into()),
        EngineEvent::Rpc(RpcEvent::TemporaryKeyBindFailed { code, message }) => {
            Some(format!("refused: {code} {message}"))
        }
        EngineEvent::PermanentKeyInvalid => Some("PermanentKeyInvalid".into()),
        _ => None,
    }
}

fn main() {
    let recorder = Arc::new(Recorder::default());
    let engine = Engine::new(EngineConfig::default(), recorder.clone()).expect("engine");
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);

    println!("1. permanent key over plain HTTP (port 80)");
    let started = Instant::now();
    let session = engine.create_session(key_maker(DC2, TransportPreference::Http));
    let http_key = recorder.wait(session, Duration::from_secs(30), made_key);
    engine.destroy_session(session);
    let Some((http_key, http_salt, time_difference, dc_id)) = http_key else {
        println!("RESULT 1: no key in 30 s");
        engine.shutdown();
        return;
    };
    println!(
        "RESULT 1: permanent key {:016x} made over HTTP in {:.2} s, handshake dc {dc_id}, time difference {time_difference:.1} s",
        http_key.id(),
        started.elapsed().as_secs_f64()
    );

    println!("2. permanent key with the address unreachable: Telegram Web only");
    let started = Instant::now();
    let session = engine.create_session(key_maker(UNREACHABLE, TransportPreference::Auto));
    engine.use_telegram_web(session, false);
    match recorder.wait(session, Duration::from_secs(60), made_key) {
        Some((key, _, _, dc_id)) => {
            let targets = host.targets.lock().unwrap().clone();
            println!(
                "RESULT 2: permanent key {:016x} made in {:.2} s, handshake dc {dc_id}; host streams {:?}",
                key.id(),
                started.elapsed().as_secs_f64(),
                targets.iter().map(|target| format!("{}:{}", target.host, target.port)).collect::<Vec<_>>()
            );
        }
        None => println!("RESULT 2: no key in 60 s"),
    }
    engine.destroy_session(session);

    println!("3. key check of the key made in 1");
    let session = engine.create_session(key_check(&http_key, Some(http_salt)));
    let outcome = recorder.wait(session, Duration::from_secs(30), bind_outcome);
    println!("RESULT 3: {}", outcome.unwrap_or_else(|| "no outcome in 30 s".into()));

    println!("5. auth.importAuthorization with made-up bytes under the key made in 1");
    let mut body = Writer::new();
    body.write_u32(AUTH_IMPORT_AUTHORIZATION);
    body.write_i64(0x0123_4567_89ab_cdef);
    body.write_bytes(&[7u8; 32]);
    engine.send(
        session,
        RpcRequest { id: RequestId(5), body: body.into_inner(), flags: RequestFlags::default(), invoke_after: None },
    );
    let answer = recorder.wait(session, Duration::from_secs(30), |event| match event {
        EngineEvent::Rpc(RpcEvent::Completed { id: RequestId(5), body, .. }) => Some(format!(
            "completed with {} bytes, constructor {:08x}",
            body.len(),
            u32::from_le_bytes(body[..4].try_into().unwrap_or([0; 4]))
        )),
        EngineEvent::Rpc(RpcEvent::Failed { id: RequestId(5), code, message, .. }) => {
            Some(format!("failed: {code} {message}"))
        }
        _ => None,
    });
    println!("RESULT 5: {}", answer.unwrap_or_else(|| "no answer in 30 s".into()));
    engine.destroy_session(session);

    println!("4. key check of a random permanent key");
    let mut bytes = [0u8; 256];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(97).wrapping_add(http_key.bytes()[index]);
    }
    let unknown = AuthKey::new(bytes);
    let session = engine.create_session(key_check(&unknown, None));
    let outcome = recorder.wait(session, Duration::from_secs(30), bind_outcome);
    println!("RESULT 4: {}", outcome.unwrap_or_else(|| "no outcome in 30 s".into()));
    engine.destroy_session(session);

    println!("6. key checks over Telegram Web only (address unreachable)");
    let streams = host.targets.lock().unwrap().len();
    let started = Instant::now();
    let session =
        engine.create_session(key_check_at(UNREACHABLE, TransportPreference::Auto, &http_key, Some(http_salt)));
    engine.use_telegram_web(session, false);
    let known = recorder.wait(session, Duration::from_secs(60), bind_outcome);
    println!(
        "RESULT 6a (key of 1): {} in {:.2} s",
        known.unwrap_or_else(|| "no outcome in 60 s".into()),
        started.elapsed().as_secs_f64()
    );
    engine.destroy_session(session);
    let started = Instant::now();
    let session = engine.create_session(key_check_at(UNREACHABLE, TransportPreference::Auto, &unknown, None));
    engine.use_telegram_web(session, false);
    let unknown_outcome = recorder.wait(session, Duration::from_secs(60), bind_outcome);
    let targets = host.targets.lock().unwrap().clone();
    println!(
        "RESULT 6b (random key): {} in {:.2} s; host streams since 6: {:?}",
        unknown_outcome.unwrap_or_else(|| "no outcome in 60 s".into()),
        started.elapsed().as_secs_f64(),
        targets[streams..].iter().map(|target| format!("{}:{}", target.host, target.port)).collect::<Vec<_>>()
    );
    engine.destroy_session(session);

    engine.shutdown();
}
