use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, unix_seconds,
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
}

impl Collector {
    fn wait(&self, timeout: Duration, predicate: impl Fn(&[(SessionHandle, EngineEvent)]) -> bool) -> bool {
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

    fn memories(&self) -> Vec<Vec<u8>> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(session, event)| match event {
                EngineEvent::RouteMemory { memory } if session.0 == 0 => Some(memory.clone()),
                _ => None,
            })
            .collect()
    }
}

const KEY_SEED: u64 = 77;

fn setup(server: &TestServer) -> SessionSetup {
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: "127.0.0.1".into(), port: server.address.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key: random_key(KEY_SEED),
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = TransportPreference::Auto;
    setup.http_port = None;
    setup
}

/// One call on a fresh engine and session: how long it took, and the engine's route memory events.
fn first_call(server: &TestServer, network: &[u8], memory: Option<&[u8]>) -> (Duration, Vec<Vec<u8>>, Engine) {
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    if let Some(memory) = memory {
        engine.set_route_memory(memory);
    }
    engine.set_network(network);
    let started = Instant::now();
    let session = engine.create_session(setup(server));
    engine.send(
        session,
        RpcRequest { id: RequestId(1), body: call(1, &[1, 2, 3]), flags: RequestFlags::default(), invoke_after: None },
    );
    assert!(
        collector.wait(Duration::from_secs(20), |events| {
            events
                .iter()
                .any(|(_, event)| matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id, .. }) if id.0 == 1))
        }),
        "the call never completed"
    );
    let elapsed = started.elapsed();
    std::thread::sleep(Duration::from_millis(200));
    (elapsed, collector.memories(), engine)
}

#[test]
fn a_network_known_to_block_tcp_gets_http_from_the_first_call_of_the_next_run() {
    let server = TestServer::start(vec![random_key(KEY_SEED)], ServerOptions::default());
    server.set_tcp_blackhole(true);

    let (learning, memories, engine) = first_call(&server, b"office", None);
    engine.shutdown();
    assert!(learning >= Duration::from_millis(2000), "the first run waits out TCP's silence: {learning:?}");
    let memory = memories.last().cloned().expect("the finding was reported for the host to store");

    let (remembered, _, engine) = first_call(&server, b"office", Some(&memory));
    engine.shutdown();
    assert!(
        remembered < Duration::from_millis(1500),
        "the next run on the same network goes to HTTP early: {remembered:?}"
    );

    let (elsewhere, _, engine) = first_call(&server, b"home", Some(&memory));
    engine.shutdown();
    assert!(elsewhere >= Duration::from_millis(2000), "another network knows nothing: {elsewhere:?}");

    server.set_tcp_blackhole(false);
    let (unblocked, memories, engine) = first_call(&server, b"office", Some(&memory));
    let after = engine.route_memory();
    engine.shutdown();
    eprintln!(
        "first call: learning {learning:?}, remembered {remembered:?}, another network {elsewhere:?}, unblocked {unblocked:?}"
    );
    assert!(unblocked < Duration::from_millis(1500), "{unblocked:?}");
    assert!(!memories.is_empty(), "TCP answering again on the network is reported");
    assert!(after.len() < memory.len(), "and the network is forgotten: {after:?}");
}
