//! Hard review R4-2: over HTTP an answer whose response is lost is announced with msg_detailed_info
//! rather than sent again, and the session asks for it. On a slow link that drops connections every
//! few seconds, asking for several large answers in one request never got them (a response is lost
//! whole), and after three unanswered requests the session sent the call again under a new msg_id,
//! which ran it on the server a second and third time.

use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::rpc::{RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, SessionHandle, SessionSetup,
    TransportPreference, WebEndpoint, unix_seconds,
};
use mtproto_netsim::{NetSim, Profile};
use mtproto_testserver::*;

#[path = "support/stream_host.rs"]
mod stream_host;

use stream_host::TestStreamHost;

#[derive(Default)]
struct Collector {
    finished: Mutex<Vec<(u64, Option<String>)>>,
    condvar: Condvar,
}

impl EngineCallbacks for Collector {
    fn on_event(&self, _session: SessionHandle, event: EngineEvent) {
        let finished = match event {
            EngineEvent::Rpc(RpcEvent::Completed { id, .. }) => (id.0, None),
            EngineEvent::Rpc(RpcEvent::Failed { id, message, .. }) => (id.0, Some(message)),
            _ => return,
        };
        self.finished.lock().unwrap().push(finished);
        self.condvar.notify_all();
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_TEST_LOG").is_some() {
            eprintln!("{:?} LOG {message}", Instant::now());
        }
    }
}

impl Collector {
    fn wait(&self, count: usize, timeout: Duration) -> Vec<(u64, Option<String>)> {
        let deadline = Instant::now() + timeout;
        let mut finished = self.finished.lock().unwrap();
        while finished.len() < count && Instant::now() < deadline {
            finished = self.condvar.wait_timeout(finished, deadline - Instant::now()).unwrap().0;
        }
        finished.clone()
    }
}

const CALLS: u64 = 40;

/// The calls that did not complete (with the failure, if any) and those the server ran other than once.
struct Outcome {
    incomplete: Vec<(u64, Option<String>)>,
    not_once: Vec<(u64, usize)>,
}

/// Every fifth call has a 40 KB answer.
fn calls_over(profile: &str, web: bool, seed: u64) -> Outcome {
    let key = random_key(4800 + seed);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = Engine::new(EngineConfig { worker_threads: 1, ..EngineConfig::default() }, collector.clone()).unwrap();
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let front = web.then(|| WebFront::start(server.address));
    let dead = web.then(Blackhole::start);
    let target = front.as_ref().map_or(server.address, |front| front.address);
    let sim = NetSim::start(target, Profile::by_name(profile).unwrap(), seed).unwrap();
    let dc = dead.as_ref().map_or(sim.address, |dead| dead.address);
    let now = unix_seconds();
    let mut setup = SessionSetup::new(
        2,
        SessionRole::Main,
        vec![DcAddress { host: dc.ip().to_string(), port: dc.port(), secret: None }],
    );
    setup.auth_key = Some(AuthKeyMaterial {
        key,
        salts: vec![ServerSalt { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 }],
        init_hash: None,
    });
    setup.transport = TransportPreference::Http;
    setup.http_port = None;
    setup.web = web.then(|| WebEndpoint {
        host: WEB_FRONT_NAME.into(),
        port: sim.address.port(),
        path: "/apiw1".into(),
        ws_path: "/apiws".into(),
        address: Some("127.0.0.1".into()),
    });
    let session = engine.create_session(setup);
    for id in 1..=CALLS {
        let tag = (id + 100) as u32;
        let body = if id % 5 == 0 { call(tag, &vec![7u8; 40_000]) } else { call(tag, &id.to_le_bytes()) };
        engine
            .send(session, RpcRequest { id: RequestId(id), body, flags: RequestFlags::default(), invoke_after: None });
        if id % 5 == 0 {
            std::thread::sleep(Duration::from_millis(400 + id * 20));
        }
    }
    let finished = collector.wait(CALLS as usize, Duration::from_secs(240));
    let completed: HashSet<u64> = finished.iter().filter(|(_, failure)| failure.is_none()).map(|(id, _)| *id).collect();
    let mut incomplete: Vec<(u64, Option<String>)> =
        finished.iter().filter(|(_, failure)| failure.is_some()).cloned().collect();
    incomplete.extend((1..=CALLS).filter(|id| !finished.iter().any(|(done, _)| done == id)).map(|id| (id, None)));
    let not_once: Vec<(u64, usize)> = (1..=CALLS)
        .map(|id| (id, server.executions((id + 100) as u32)))
        .filter(|(_, executions)| *executions != 1)
        .collect();
    eprintln!(
        "{profile}{}: {}/{CALLS} completed, incomplete {incomplete:?}, run other than once {not_once:?}",
        if web { " over HTTPS" } else { "" },
        completed.len()
    );
    engine.shutdown();
    Outcome { incomplete, not_once }
}

#[test]
fn large_answers_lost_on_a_flaky_link_arrive_and_no_call_runs_twice() {
    let runs: Vec<Outcome> = std::thread::scope(|scope| {
        let plain = scope.spawn(|| calls_over("gprs", false, 1));
        let web = scope.spawn(|| calls_over("edge-flaky", true, 2));
        vec![plain.join().unwrap(), web.join().unwrap()]
    });
    for outcome in runs {
        assert!(outcome.not_once.is_empty(), "calls the server ran other than once: {:?}", outcome.not_once);
        assert!(outcome.incomplete.is_empty(), "calls that did not complete: {:?}", outcome.incomplete);
    }
}
