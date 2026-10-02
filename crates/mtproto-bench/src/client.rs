use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::crypto::RsaPublicKey;
use mtproto_engine::mtproto_core::rpc::{ApiEnvironment, RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole};
use mtproto_engine::mtproto_core::session::ServerSalt;
use mtproto_engine::mtproto_core::tl::Writer;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, ProxyConfig,
    SessionHandle, SessionSetup, unix_seconds,
};
use mtproto_testserver::{TAG_SIZED, call, parse_result, sized_call};

use crate::args::{ClientArgs, unhex};
use crate::report::{ClientReport, Latency};

pub const PRODUCTION_KEY: &str = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA6LszBcC1LGzyr992NzE0ieY+BSaOW622Aa9Bd4ZHLl+TuFQ4lo4g\n5nKaMBwK/BIb9xUfg0Q29/2mgIR6Zr9krM7HjuIcCzFvDtr+L0GQjae9H0pRB2OO\n62cECs5HKhT5DZ98K33vmWiLowc621dQuwKWSQKjWf50XYFw42h21P2KXUGyp2y/\n+aEyZ+uVgLLQbRA1dEjSDZ2iGRy12Mk5gpYc397aYp438fsJoHIgJ2lgMv5h7WY9\nt6N/byY9Nw9p21Og3AoXSL2q/2IJ1WRUhebgAdGVMlV1fkuOQoEzR7EdpqtQD9Cs\n5+bfo3Nhmcyvk5ftB0WkJ9z6bNZ7yxrP8wIDAQAB\n-----END RSA PUBLIC KEY-----";

struct Forwarder {
    sender: Mutex<Sender<(SessionHandle, EngineEvent)>>,
}

impl EngineCallbacks for Forwarder {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        if let Ok(sender) = self.sender.lock() {
            let _ = sender.send((session, event));
        }
    }

    fn on_log(&self, _level: mtproto_engine::LogLevel, message: &str) {
        if std::env::var_os("MTPROTO_BENCH_LOG").is_some() {
            eprintln!("{message}");
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Small { tag: u32 },
    Sized { size: u32 },
    Real,
}

struct Pending {
    index: usize,
    kind: Kind,
    session: SessionHandle,
}

struct Driver {
    engine: Engine,
    events: Receiver<(SessionHandle, EngineEvent)>,
    start: Instant,
    records: Vec<(f64, Option<f64>)>,
    probes: Vec<usize>,
    pending: HashMap<RequestId, Pending>,
    outstanding: HashMap<SessionHandle, usize>,
    completed: usize,
    failed: usize,
    bytes: u64,
}

impl Driver {
    fn elapsed(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    fn issue(&mut self, session: SessionHandle, kind: Kind, probe: bool, flags: RequestFlags) {
        let id = self.engine.next_request_id();
        let index = self.records.len();
        let body = match kind {
            Kind::Small { tag } => call(tag, &(index as u64).to_le_bytes()),
            Kind::Sized { size } => sized_call(size),
            Kind::Real => {
                let mut writer = Writer::new();
                writer.write_u32(if index.is_multiple_of(2) { 0xc4f9186b } else { 0x1fb33026 });
                writer.into_inner()
            }
        };
        self.records.push((self.elapsed(), None));
        if probe {
            self.probes.push(index);
        }
        self.pending.insert(id, Pending { index, kind, session });
        *self.outstanding.entry(session).or_insert(0) += 1;
        self.engine.send(session, RpcRequest { id, body, flags, invoke_after: None });
    }

    fn outstanding(&self, session: SessionHandle) -> usize {
        self.outstanding.get(&session).copied().unwrap_or(0)
    }

    fn pump(&mut self, timeout: Duration) {
        match self.events.recv_timeout(timeout) {
            Ok((_, event)) => self.handle(event),
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return,
        }
        while let Ok((_, event)) = self.events.try_recv() {
            self.handle(event);
        }
    }

    fn handle(&mut self, event: EngineEvent) {
        let EngineEvent::Rpc(event) = event else {
            return;
        };
        match event {
            RpcEvent::Completed { id, body, .. } => {
                let Some(pending) = self.pending.remove(&id) else {
                    return;
                };
                *self.outstanding.entry(pending.session).or_insert(1) -= 1;
                let valid = match pending.kind {
                    Kind::Small { tag } => parse_result(&body).is_some_and(|(result, _)| result == tag),
                    Kind::Sized { size } => parse_result(&body)
                        .is_some_and(|(result, payload)| result == TAG_SIZED && payload.len() == size as usize),
                    Kind::Real => body.len() >= 4,
                };
                if valid {
                    self.completed += 1;
                    self.records[pending.index].1 = Some(self.elapsed());
                    if let Kind::Sized { size } = pending.kind {
                        self.bytes += u64::from(size);
                    }
                } else {
                    self.failed += 1;
                }
            }
            RpcEvent::Failed { id, .. } => {
                if let Some(pending) = self.pending.remove(&id) {
                    *self.outstanding.entry(pending.session).or_insert(1) -= 1;
                    self.failed += 1;
                }
            }
            _ => {}
        }
    }

    fn report(&self, args: &ClientArgs, elapsed: f64) -> ClientReport {
        let latency_indices: Vec<usize> =
            if args.workload == "mixed" { self.probes.clone() } else { (0..self.records.len()).collect() };
        let samples: Vec<f64> = latency_indices
            .iter()
            .filter_map(|index| {
                let (sent, done) = self.records[*index];
                done.map(|done| (done - sent) * 1000.0)
            })
            .collect();
        ClientReport {
            engine: args.engine_label.clone(),
            workload: args.workload.clone(),
            completed: self.completed,
            failed: self.failed + self.pending.len(),
            elapsed,
            latency: Latency::from_samples(samples),
            bytes: self.bytes,
            throughput_mbps: if elapsed > 0.0 { self.bytes as f64 / 1e6 / elapsed } else { 0.0 },
            requests: self.records.clone(),
        }
    }
}

fn environment() -> ApiEnvironment {
    ApiEnvironment {
        layer: 230,
        api_id: 9,
        device_model: "MTProto engine benchmark".into(),
        system_version: "macOS".into(),
        app_version: "1.0".into(),
        system_lang_code: "en".into(),
        lang_pack: "macos".into(),
        lang_code: "en".into(),
        proxy: None,
        params: None,
        init_hash: "bench".into(),
        disable_updates: false,
    }
}

fn setup(args: &ClientArgs, role: SessionRole) -> SessionSetup {
    let (host, port) = args.address.rsplit_once(':').expect("host:port");
    let port: u16 = port.parse().expect("port");
    let mut setup = SessionSetup::new(args.dc, role, vec![DcAddress { host: host.to_string(), port, secret: None }]);
    if let Some(secret) = &args.secret {
        setup.proxy = Some(ProxyConfig::MtProxy { host: host.to_string(), port, secret: unhex(secret) });
        setup.addresses = vec![DcAddress { host: "149.154.167.51".into(), port: 443, secret: None }];
    }
    setup.environment = Some(environment());
    setup.keep_connected = true;
    setup.idle_disconnect_after = None;
    if args.mode == "real" {
        setup.key_generation = Some(KeyGeneration {
            public_keys: vec![RsaPublicKey::from_pem(PRODUCTION_KEY).expect("key")],
            temporary_expires_in: None,
        });
    } else {
        let key = AuthKey::from_slice(&unhex(args.key_hex.as_deref().expect("--key-hex"))).expect("256-byte key");
        let now = unix_seconds();
        setup.auth_key = Some(AuthKeyMaterial {
            key,
            salts: vec![ServerSalt { salt: args.salt, valid_since: now - 86_400.0, valid_until: now + 86_400.0 }],
            init_hash: None,
        });
    }
    setup
}

pub fn run(args: ClientArgs) -> ClientReport {
    let (sender, receiver) = channel();
    let engine =
        Engine::new(EngineConfig::default(), Arc::new(Forwarder { sender: Mutex::new(sender) })).expect("engine");
    let mut driver = Driver {
        engine: engine.clone(),
        events: receiver,
        start: Instant::now(),
        records: Vec::new(),
        probes: Vec::new(),
        pending: HashMap::new(),
        outstanding: HashMap::new(),
        completed: 0,
        failed: 0,
        bytes: 0,
    };
    let deadline = Instant::now() + Duration::from_secs_f64(args.deadline);
    let main = engine.create_session(setup(&args, SessionRole::Main));
    let small_flags = RequestFlags::default();
    let media_flags = RequestFlags { timeout_timer: true, without_updates: true, ..RequestFlags::default() };
    driver.start = Instant::now();
    let tag = |index: usize| 1 + (index % 900) as u32;

    match args.workload.as_str() {
        "latency" => {
            for index in 0..args.requests {
                driver.issue(main, Kind::Small { tag: tag(index) }, false, small_flags);
                while driver.outstanding(main) > 0 && Instant::now() < deadline {
                    driver.pump(Duration::from_millis(100));
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
        }
        "small" | "real-config" => {
            let real = args.workload == "real-config";
            let mut issued = 0;
            while (issued < args.requests || driver.outstanding(main) > 0) && Instant::now() < deadline {
                while issued < args.requests && driver.outstanding(main) < args.concurrency {
                    let kind = if real { Kind::Real } else { Kind::Small { tag: tag(issued) } };
                    driver.issue(main, kind, false, small_flags);
                    issued += 1;
                }
                driver.pump(Duration::from_millis(100));
            }
        }
        "media" | "mixed" => {
            let workers: Vec<SessionHandle> = (0..args.sessions)
                .map(|_| engine.create_session(setup(&args, SessionRole::Worker { requires_auth_token: false })))
                .collect();
            let parts = args.total_bytes.div_ceil(args.part_size as u64) as usize;
            let mut issued = 0;
            let probe_interval = if args.rate > 0.0 { 1.0 / args.rate } else { f64::INFINITY };
            let mut next_probe = 0.0;
            let mut probe_count = 0usize;
            while Instant::now() < deadline {
                for worker in &workers {
                    while issued < parts && driver.outstanding(*worker) < args.session_concurrency {
                        driver.issue(*worker, Kind::Sized { size: args.part_size }, false, media_flags);
                        issued += 1;
                    }
                }
                let media_done = issued >= parts && workers.iter().all(|worker| driver.outstanding(*worker) == 0);
                if args.workload == "mixed" && !media_done && driver.elapsed() >= next_probe {
                    driver.issue(main, Kind::Small { tag: tag(probe_count) }, true, small_flags);
                    probe_count += 1;
                    next_probe += probe_interval;
                }
                if media_done && driver.outstanding(main) == 0 {
                    break;
                }
                driver.pump(Duration::from_millis(10));
            }
        }
        "steady" => {
            let interval = 1.0 / args.rate.max(0.1);
            let mut next = 0.0;
            let mut index = 0;
            while Instant::now() < deadline {
                let now = driver.elapsed();
                if now < args.duration && now >= next {
                    driver.issue(main, Kind::Small { tag: tag(index) }, false, small_flags);
                    index += 1;
                    next += interval;
                }
                if now >= args.duration && driver.outstanding(main) == 0 {
                    break;
                }
                driver.pump(Duration::from_millis(5));
            }
        }
        other => panic!("unknown workload {other}"),
    }
    let elapsed = driver.elapsed();
    let report = driver.report(&args, elapsed);
    engine.shutdown();
    report
}
