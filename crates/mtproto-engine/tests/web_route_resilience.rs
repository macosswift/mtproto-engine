use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use mtproto_engine::TransportPreference;
use mtproto_engine::mtproto_core::rpc::SessionRole;
use mtproto_netsim::{NetSim, Profile};
use mtproto_testserver::*;

#[path = "support/route_rig.rs"]
mod route_rig;
#[path = "support/stream_host.rs"]
mod stream_host;
#[path = "support/ws_front.rs"]
mod ws_front;

use route_rig::*;
use stream_host::TestStreamHost;
use ws_front::WsFront;

/// A link with `one_way_ms` each way, where opening a connection (lookup and TCP) takes two round
/// trips before TLS starts.
fn slow_link(one_way_ms: u64) -> Profile {
    Profile {
        name: format!("latency-{one_way_ms}"),
        latency: Duration::from_millis(one_way_ms),
        connect_delay: Duration::from_millis(4 * one_way_ms),
        ..Profile::perfect()
    }
}

fn worker(mut setup: mtproto_engine::SessionSetup, datacenter: i32) -> mtproto_engine::SessionSetup {
    setup.datacenter_id = datacenter;
    setup.role = SessionRole::Worker { requires_auth_token: false };
    setup
}

/// TCP and plain HTTP are dead and only Telegram Web's front answers, over a link with 1.4 s round
/// trips: its routes need about eight seconds to answer a probe, past the first round's six.
#[test]
fn web_routes_reach_telegram_over_links_with_second_long_round_trips() {
    let key = random_key(4401);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let sim = NetSim::start(front.address, slow_link(700), 7).unwrap();
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let started = Instant::now();
    let session = engine.create_session(setup(
        dead.address,
        &key,
        TransportPreference::Auto,
        Some(web_endpoint_at(sim.address.port())),
    ));
    engine.send(session, request(1));
    let done = collector.wait_completed(session, 1, Duration::from_secs(60));
    let streams = host.targets.lock().unwrap().len();
    eprintln!("first call after {:?}, host streams opened {streams}", started.elapsed());
    assert!(done, "the web routes never answered in time");
    engine.shutdown();
}

/// A filter lets the WebSocket probe through and cuts the session's real traffic there, while HTTPS on
/// the same front works: the session ends up on HTTPS instead of cycling through the WebSocket.
#[test]
fn a_websocket_that_cuts_sessions_gives_way_to_https() {
    let key = random_key(4605);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WsFront::start(server.address);
    front.switches.cut_after_client_bytes.store(200, Ordering::Relaxed);
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    let session = engine.create_session(setup(
        dead.address,
        &key,
        TransportPreference::Auto,
        Some(web_endpoint_at(front.address.port())),
    ));
    engine.send(session, request(1));
    let done = collector.wait_completed(session, 1, Duration::from_secs(90));
    let stats = front.stats();
    eprintln!(
        "completed {done}: upgrades {}, cuts {}, https requests {}, gave up on the WebSocket {} times",
        stats.upgrades,
        stats.cuts,
        stats.https_requests,
        collector.count_logged("keeps failing; trying TCP again"),
    );
    assert!(done, "HTTPS never got its turn");
    assert!(stats.https_requests > 0);
    engine.shutdown();
}

/// Pausing a session while its probes are out closes them: nothing is adopted or learned while paused.
#[test]
fn pausing_a_session_ends_its_probes() {
    let key = random_key(4404);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let front_sim = NetSim::start(front.address, slow_link(500), 13).unwrap();
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    engine.set_network(b"office");
    let session = engine.create_session(setup(
        dead.address,
        &key,
        TransportPreference::Auto,
        Some(web_endpoint_at(front_sim.address.port())),
    ));
    engine.send(session, request(1));
    let deadline = Instant::now() + Duration::from_secs(10);
    while host.targets.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(300));
    let paused_at = Instant::now();
    engine.set_paused(session, true);
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(host.open_streams(), 0, "a probe stream stayed open after the pause");
    std::thread::sleep(Duration::from_secs(8));
    assert!(!collector.logged_after("moving", paused_at), "a route was adopted while paused");
    assert!(collector.memories().is_empty(), "the route memory changed while paused");
    engine.set_paused(session, false);
    assert!(collector.wait_completed(session, 1, Duration::from_secs(30)), "works after resume");
    engine.shutdown();
}

/// The device moves to another network while a probe round from the old one is out: those probes are
/// closed (what they find is about the old network) and the round starts over.
#[test]
fn probes_out_when_the_network_changes_are_closed() {
    let key = random_key(4405);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let front_sim = NetSim::start(front.address, slow_link(400), 14).unwrap();
    let dead = Blackhole::start();
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    engine.set_network(b"censored-office");
    let session = engine.create_session(setup(
        dead.address,
        &key,
        TransportPreference::Auto,
        Some(web_endpoint_at(front_sim.address.port())),
    ));
    engine.send(session, request(1));
    let deadline = Instant::now() + Duration::from_secs(10);
    while host.targets.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let closed_before = host.closed_by_engine.load(Ordering::Relaxed);
    engine.set_network(b"home");
    std::thread::sleep(Duration::from_millis(300));
    assert!(host.closed_by_engine.load(Ordering::Relaxed) > closed_before, "the old network's probes stayed out");
    assert!(collector.wait_completed(session, 1, Duration::from_secs(60)), "the round started over");
    engine.shutdown();
}

/// One datacenter's TCP is blocked on this network while another's works, and sessions to both come
/// and go: the network's memory is not stored again on every one of them.
#[test]
fn one_blocked_datacenter_does_not_flip_the_route_memory() {
    let key = random_key(4406);
    let blocked = TestServer::start(vec![key.clone()], ServerOptions::default());
    blocked.set_tcp_blackhole(true);
    let open = TestServer::start(vec![key.clone()], ServerOptions::default());
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    engine.set_network(b"office");
    let main = engine.create_session(setup(open.address, &key, TransportPreference::Auto, None));
    engine.send(main, request(1));
    assert!(collector.wait_completed(main, 1, Duration::from_secs(10)));
    let started = Instant::now();
    let mut id = 100;
    let mut sessions = Vec::new();
    while started.elapsed() < Duration::from_secs(30) {
        for (address, datacenter) in [(blocked.address, 4), (open.address, 2)] {
            let session =
                engine.create_session(worker(setup(address, &key, TransportPreference::Auto, None), datacenter));
            id += 1;
            engine.send(session, request(id));
            sessions.push(session);
        }
        std::thread::sleep(Duration::from_secs(5));
        while sessions.len() > 6 {
            engine.destroy_session(sessions.remove(0));
        }
    }
    let reports = collector.memories().len();
    eprintln!("route memory reports in 30 s: {reports}, adoptions {}", collector.count_logged("moving to HTTP"));
    assert!(collector.logged("moving to HTTP"), "the blocked datacenter never moved to HTTP");
    assert!(reports <= 2, "the memory was stored {reports} times");
    engine.shutdown();
}

/// A session on the WebSocket moves to a network where TCP works without the host seeing reachability
/// change (only `set_network` does): TCP is checked at once rather than at the next scheduled recheck.
#[test]
fn a_network_change_checks_tcp_at_once() {
    let key = random_key(4407);
    let direct = TestServer::start(vec![key.clone()], ServerOptions { http_disabled: true, ..Default::default() });
    direct.set_tcp_blackhole(true);
    let behind_front = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(behind_front.address);
    let collector = Arc::new(Collector::default());
    let engine = engine(&collector);
    let host = Arc::new(TestStreamHost::default());
    host.attach(&engine);
    engine.set_network(b"censored");
    let mut session_setup =
        setup(direct.address, &key, TransportPreference::Auto, Some(web_endpoint_at(front.address.port())));
    session_setup.tcp_recheck_after = 60.0;
    let session = engine.create_session(session_setup);
    engine.send(session, request(1));
    assert!(collector.wait_completed(session, 1, Duration::from_secs(30)));
    assert!(collector.logged("moving the stream there"));
    direct.set_tcp_blackhole(false);
    engine.set_network(b"home");
    let switched = Instant::now();
    let mut id = 1;
    while !collector.logged_after("leaving the WebSocket endpoint", switched)
        && switched.elapsed() < Duration::from_secs(20)
    {
        id += 1;
        engine.send(session, request(id));
        std::thread::sleep(Duration::from_millis(250));
    }
    let back = collector.logged_after("leaving the WebSocket endpoint", switched).then(|| switched.elapsed());
    eprintln!("back on TCP {back:?} after the network changed");
    assert!(back.is_some_and(|after| after < Duration::from_secs(10)), "TCP waited for the scheduled recheck");
    engine.shutdown();
}
