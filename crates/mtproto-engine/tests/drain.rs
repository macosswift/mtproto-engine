//! `Engine::drain` (`mt_session_drain`): a live engine switch hands the session's requests back without
//! running any of them twice.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::test_support::{ServerHandshake, ServerHandshakeBehavior};
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, PfsSetup, SessionHandle,
    SessionSetup, TransportPreference, unix_seconds,
};
use mtproto_testserver::*;

#[derive(Default)]
struct Collector {
    events: Mutex<Vec<(SessionHandle, Instant, EngineEvent)>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        self.events.lock().unwrap().push((session, Instant::now(), event));
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("LOG {message}");
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Outcome {
    Completed,
    Failed(String),
    Released { may_have_run: bool, retry_after: f64 },
}

impl Collector {
    fn wait(&self, timeout: Duration, predicate: impl Fn(&[(SessionHandle, Instant, EngineEvent)]) -> bool) -> bool {
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

    fn outcomes(&self, session: SessionHandle) -> Vec<(u64, Outcome)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|(handle, _, _)| *handle == session)
            .filter_map(|(_, _, event)| match event {
                EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => Some((id.0, Outcome::Completed)),
                EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) => {
                    Some((id.0, Outcome::Failed(message.clone())))
                }
                EngineEvent::Rpc(RpcEvent::Released { id, may_have_run, retry_after }) => {
                    Some((id.0, Outcome::Released { may_have_run: *may_have_run, retry_after: *retry_after }))
                }
                _ => None,
            })
            .collect()
    }

    fn closed_at(&self, session: SessionHandle) -> Option<Instant> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .find(|(handle, _, event)| *handle == session && matches!(event, EngineEvent::Closed))
            .map(|(_, at, _)| *at)
    }

    fn count(&self, predicate: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.lock().unwrap().iter().filter(|(_, _, event)| predicate(event)).count()
    }
}

fn closed(session: SessionHandle) -> impl Fn(&[(SessionHandle, Instant, EngineEvent)]) -> bool {
    move |events| events.iter().any(|(handle, _, event)| *handle == session && matches!(event, EngineEvent::Closed))
}

fn salts() -> Vec<ServerSalt> {
    let now = unix_seconds();
    vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }]
}

fn setup(port: u16, key: &AuthKey) -> SessionSetup {
    let mut setup =
        SessionSetup::new(2, SessionRole::Main, vec![DcAddress { host: "127.0.0.1".into(), port, secret: None }]);
    setup.auth_key = Some(AuthKeyMaterial { key: key.clone(), salts: salts(), init_hash: None });
    setup.http_port = None;
    setup
}

fn pfs_setup(port: u16, perm: &AuthKey) -> SessionSetup {
    let mut setup = setup(port, perm);
    setup.pfs = Some(PfsSetup {
        lifetime: 86_400,
        public_keys: vec![ServerHandshake::new(ServerHandshakeBehavior::default()).public_key()],
        ..Default::default()
    });
    setup
}

fn request(id: u64, tag: u32) -> RpcRequest {
    RpcRequest {
        id: RequestId(id),
        body: call(tag, &id.to_le_bytes()),
        flags: RequestFlags::default(),
        invoke_after: None,
    }
}

fn engine(collector: &Arc<Collector>) -> Engine {
    Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap()
}

fn executions(server: &TestServer, tag: u32) -> usize {
    server.with_stats(|stats| stats.executions.get(&tag).copied().unwrap_or(0))
}

fn wait_for_execution(server: &TestServer, tag: u32, count: usize) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if executions(server, tag) >= count {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

fn completes(collector: &Collector, session: SessionHandle, id: u64) -> bool {
    collector.wait(Duration::from_secs(10), |events| {
        events.iter().any(|(handle, _, event)| {
            *handle == session
                && matches!(event, EngineEvent::Rpc(RpcEvent::Completed { id: done, .. }) if done.0 == id)
        })
    })
}

const WAIT: Duration = Duration::from_secs(15);

#[test]
fn requests_that_never_went_out_are_released_at_once_in_their_order() {
    let key = random_key(500);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup(server.address.port(), &key);
    setup.paused = true;
    let session = engine.create_session(setup);
    for id in 1..=3 {
        engine.send(session, request(id, 7));
    }
    let started = Instant::now();
    engine.drain(session, 10.0);
    assert!(collector.wait(WAIT, closed(session)));
    assert!(started.elapsed() < Duration::from_secs(2), "nothing to wait for: {:?}", started.elapsed());
    let released = Outcome::Released { may_have_run: false, retry_after: 0.0 };
    assert_eq!(collector.outcomes(session), vec![(1, released.clone()), (2, released.clone()), (3, released)]);
    engine.send(session, request(4, 7));
    assert!(collector.wait(WAIT, |events| events.iter().any(|(_, _, event)| matches!(
        event,
        EngineEvent::Rpc(RpcEvent::Released { id: RequestId(4), may_have_run: false, .. })
    ))));
    engine.shutdown();
    assert_eq!(executions(&server, 7), 0);
}

#[test]
fn a_call_answered_while_draining_completes_once_and_the_session_closes() {
    let key = random_key(501);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(server.address.port(), &key));
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    engine.send(session, request(2, TAG_SLOW));
    assert!(wait_for_execution(&server, TAG_SLOW, 1));
    engine.drain(session, 10.0);
    engine.send(session, request(3, 7));
    assert!(collector.wait(WAIT, closed(session)));
    let outcomes = collector.outcomes(session);
    assert!(outcomes.contains(&(2, Outcome::Completed)), "{outcomes:?}");
    assert!(outcomes.contains(&(3, Outcome::Released { may_have_run: false, retry_after: 0.0 })), "{outcomes:?}");
    std::thread::sleep(Duration::from_millis(500));
    engine.shutdown();
    assert_eq!(executions(&server, TAG_SLOW), 1);
    assert_eq!(executions(&server, 7), 1, "the request sent to the draining session never went out");
}

#[test]
fn at_the_deadline_an_unanswered_call_is_released_as_possibly_run_and_never_sent_again() {
    let key = random_key(502);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(server.address.port(), &key));
    engine.send(session, request(1, TAG_NEVER));
    assert!(wait_for_execution(&server, TAG_NEVER, 1));
    let started = Instant::now();
    engine.drain(session, 1.0);
    assert!(collector.wait(WAIT, closed(session)));
    let took = collector.closed_at(session).unwrap() - started;
    assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(3), "{took:?}");
    assert_eq!(collector.outcomes(session), vec![(1, Outcome::Released { may_have_run: true, retry_after: 0.0 })]);
    std::thread::sleep(Duration::from_secs(1));
    engine.shutdown();
    assert_eq!(executions(&server, TAG_NEVER), 1);
}

#[test]
fn answers_that_keep_coming_extend_the_deadline() {
    let key = random_key(503);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut profile = mtproto_netsim::Profile::perfect();
    profile.latency = Duration::from_millis(100);
    let sim = mtproto_netsim::NetSim::start(server.address, profile, 43).unwrap();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(sim.address.port(), &key));
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    engine.send(session, request(2, TAG_NEVER));
    engine.send(session, request(3, 7));
    std::thread::sleep(Duration::from_millis(30));
    let started = Instant::now();
    engine.drain(session, 0.5);
    assert!(collector.wait(WAIT, closed(session)));
    let took = collector.closed_at(session).unwrap() - started;
    let outcomes = collector.outcomes(session);
    engine.shutdown();
    assert!(outcomes.contains(&(3, Outcome::Completed)), "{outcomes:?}");
    assert!(outcomes.contains(&(2, Outcome::Released { may_have_run: true, retry_after: 0.0 })), "{outcomes:?}");
    assert!(
        took >= Duration::from_millis(5300) && took < Duration::from_secs(7),
        "an answer at 0.2 s extends the 0.5 s deadline by 5 s once: {took:?}"
    );
}

#[test]
fn a_drain_across_a_closed_connection_gets_the_answer_without_running_the_call_again() {
    let key = random_key(504);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let mut profile = mtproto_netsim::Profile::perfect();
    profile.latency = Duration::from_millis(200);
    let sim = mtproto_netsim::NetSim::start(server.address, profile, 41).unwrap();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(sim.address.port(), &key));
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    engine.send(session, request(2, TAG_DROP_CONNECTION_ONCE));
    std::thread::sleep(Duration::from_millis(60));
    engine.drain(session, 15.0);
    assert!(collector.wait(Duration::from_secs(20), closed(session)));
    let outcomes = collector.outcomes(session);
    let drops = collector.count(|event| matches!(event, EngineEvent::ConnectionDropped { .. }));
    engine.shutdown();
    assert!(
        outcomes.contains(&(2, Outcome::Completed)),
        "the answer the server re-sends on the new connection: {outcomes:?}"
    );
    assert!(drops >= 1, "the server closed the connection after running the call");
    assert_eq!(executions(&server, TAG_DROP_CONNECTION_ONCE), 1);
}

#[test]
fn a_key_change_while_draining_releases_the_kept_calls_instead_of_failing_them() {
    let perm = random_key(505);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), &perm));
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    let handshakes = server.with_stats(|stats| stats.handshakes);
    engine.send(session, request(2, TAG_NEVER));
    engine.send(session, request(3, TAG_SLOW));
    assert!(wait_for_execution(&server, TAG_NEVER, 1));
    engine.drain(session, 20.0);
    engine.set_obfuscation_dc_id(session, -2);
    assert!(collector.wait(WAIT, closed(session)));
    std::thread::sleep(Duration::from_millis(500));
    let outcomes = collector.outcomes(session);
    engine.shutdown();
    assert!(outcomes.contains(&(2, Outcome::Released { may_have_run: true, retry_after: 0.0 })), "{outcomes:?}");
    assert!(
        outcomes.contains(&(3, Outcome::Completed))
            || outcomes.contains(&(3, Outcome::Released { may_have_run: true, retry_after: 0.0 })),
        "{outcomes:?}"
    );
    assert!(
        !outcomes.iter().any(|(_, outcome)| matches!(outcome, Outcome::Failed(_))),
        "no TEMP_KEY_ROTATED: {outcomes:?}"
    );
    assert_eq!(
        server.with_stats(|stats| stats.handshakes),
        handshakes,
        "no new key is made for a session that is leaving"
    );
    assert_eq!(executions(&server, TAG_NEVER), 1);
}

#[test]
fn a_temporary_key_the_server_loses_while_draining_releases_the_kept_calls_at_once() {
    let perm = random_key(507);
    let server = TestServer::start(
        vec![perm.clone()],
        ServerOptions {
            handshake: ServerHandshakeBehavior { live_time: true, ..Default::default() },
            ..Default::default()
        },
    );
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(pfs_setup(server.address.port(), &perm));
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    let handshakes = server.with_stats(|stats| stats.handshakes);
    engine.send(session, request(2, TAG_NEVER));
    assert!(wait_for_execution(&server, TAG_NEVER, 1));
    let started = Instant::now();
    engine.drain(session, 20.0);
    server.drop_temporary_keys();
    engine.reset_connections();
    assert!(collector.wait(WAIT, closed(session)));
    let closed_after = collector.closed_at(session).map(|at| at.duration_since(started));
    std::thread::sleep(Duration::from_millis(500));
    let outcomes = collector.outcomes(session);
    engine.shutdown();
    assert_eq!(
        outcomes,
        vec![(1, Outcome::Completed), (2, Outcome::Released { may_have_run: true, retry_after: 0.0 })]
    );
    assert!(closed_after.is_some_and(|after| after < Duration::from_secs(10)), "not at the deadline: {closed_after:?}");
    assert_eq!(server.with_stats(|stats| stats.handshakes), handshakes, "no new key for a session that is leaving");
    assert_eq!(executions(&server, TAG_NEVER), 1);
}

#[test]
fn over_http_a_draining_session_takes_answers_from_its_long_polls_then_stops_polling() {
    let key = random_key(506);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let mut setup = setup(server.address.port(), &key);
    setup.transport = TransportPreference::Http;
    let session = engine.create_session(setup);
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    std::thread::sleep(Duration::from_millis(300));
    engine.send(session, request(2, TAG_SLOW));
    engine.send(session, request(3, TAG_NEVER));
    assert!(wait_for_execution(&server, TAG_SLOW, 1) && wait_for_execution(&server, TAG_NEVER, 1));
    engine.drain(session, 2.0);
    assert!(collector.wait(WAIT, closed(session)));
    let outcomes = collector.outcomes(session);
    let requests = server.with_stats(|stats| stats.http.requests);
    std::thread::sleep(Duration::from_secs(2));
    let later = server.with_stats(|stats| stats.http.requests);
    engine.shutdown();
    assert!(outcomes.contains(&(2, Outcome::Completed)), "{outcomes:?}");
    assert!(outcomes.contains(&(3, Outcome::Released { may_have_run: true, retry_after: 0.0 })), "{outcomes:?}");
    assert_eq!(later, requests, "a closed session sends no more HTTP requests");
    assert_eq!(executions(&server, TAG_SLOW), 1);
    assert_eq!(executions(&server, TAG_NEVER), 1);
}

#[test]
fn a_flood_wait_is_released_with_the_time_left_and_never_resent_by_the_old_session() {
    let key = random_key(507);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let session = engine.create_session(setup(server.address.port(), &key));
    engine.send(session, request(1, 7));
    assert!(completes(&collector, session, 1));
    let mut flooded = request(2, TAG_FLOOD_ONCE);
    flooded.flags.automatic_flood_wait = true;
    engine.send(session, flooded);
    assert!(wait_for_execution(&server, TAG_FLOOD_ONCE, 1));
    std::thread::sleep(Duration::from_millis(100));
    engine.drain(session, 10.0);
    assert!(collector.wait(WAIT, closed(session)));
    let outcomes = collector.outcomes(session);
    std::thread::sleep(Duration::from_millis(1500));
    engine.shutdown();
    let retry_after = outcomes.iter().find_map(|(id, outcome)| match outcome {
        Outcome::Released { may_have_run: false, retry_after } if *id == 2 => Some(*retry_after),
        _ => None,
    });
    assert!(retry_after.is_some_and(|after| after > 0.0 && after <= 1.0), "{outcomes:?}");
    assert_eq!(executions(&server, TAG_FLOOD_ONCE), 1, "the host sends it again elsewhere, after the wait");
}
