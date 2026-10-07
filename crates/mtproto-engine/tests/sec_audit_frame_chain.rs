use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    unix_seconds,
};
use mtproto_testserver::*;

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
    fn wait_completed(&self, session: SessionHandle, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut events = self.events.lock().unwrap();
        loop {
            let done = events.iter().any(|(handle, event)| {
                *handle == session && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { .. }))
            });
            if done {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            events = self.condvar.wait_timeout(events, deadline - now).unwrap().0;
        }
    }
}

fn setup(server: &TestServer, key: &AuthKey) -> SessionSetup {
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: server.address.ip().to_string(), port: server.address.port(), secret: None }],
    );
    let now = unix_seconds();
    setup.auth_key = Some(AuthKeyMaterial {
        key: key.clone(),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup
}

/// A peer on the path (or a proxy, or a TLS-intercepting box in front of Telegram Web) answers a query
/// with an endless chain of frames that never carry an answer: empty transport frames (mode 4) or
/// packets sealed under the key for another session, replayed (mode 5). Every frame completes inside
/// the grace a partial frame gets and the next one is already started, so without a bound the
/// connection looks like it is receiving a frame for ever and is never abandoned.
#[test]
fn chained_frames_without_answers_do_not_keep_a_dead_connection() {
    std::thread::scope(|scope| {
        for mode in [4u64, 5] {
            scope.spawn(move || {
                let key = random_key(9100 + mode);
                let server = TestServer::start(vec![key.clone()], ServerOptions::default());
                let collector = Arc::new(Collector::default());
                let engine =
                    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone())
                        .unwrap();
                let session = engine.create_session(setup(&server, &key));
                let started = Instant::now();
                engine.send(
                    session,
                    RpcRequest {
                        id: RequestId(1),
                        body: call(TAG_TRICKLE_ONCE, &mode.to_le_bytes()),
                        flags: RequestFlags::default(),
                        invoke_after: None,
                    },
                );
                let completed = collector.wait_completed(session, Duration::from_secs(50));
                engine.shutdown();
                assert!(
                    completed,
                    "mode {mode}: a chain of empty frames held the connection for {:?}",
                    started.elapsed()
                );
                assert!(server.with_stats(|stats| stats.connections) >= 2, "mode {mode}: reconnected");
            });
        }
    });
}
