use std::ffi::c_void;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use mtproto_engine::{StreamId, StreamTarget};
use mtproto_engine_ffi::*;
use mtproto_testserver::*;

#[path = "../../mtproto-engine/tests/support/stream_host.rs"]
mod stream_host;

use stream_host::{StreamSink, TestStreamHost};

struct Context {
    host: Arc<TestStreamHost>,
    completed: Mutex<Vec<u64>>,
    condvar: Condvar,
}

unsafe extern "C" fn on_event(context: *mut c_void, _session: u64, event: *const MTEvent) {
    let context = unsafe { &*(context as *const Context) };
    let event = unsafe { &*event };
    if !event.payload.is_null() {
        unsafe { mt_buffer_free(event.payload) };
    }
    if event.kind == 1 {
        context.completed.lock().unwrap().push(event.request_id);
        context.condvar.notify_all();
    }
}

fn text(value: MTString) -> String {
    if value.data.is_null() {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(value.data, value.length) }).into_owned()
}

unsafe extern "C" fn open(context: *mut c_void, stream: u64, target: *const MTStreamTarget) {
    let context = unsafe { &*(context as *const Context) };
    let target = unsafe { &*target };
    let alpn = text(target.alpn);
    let target = StreamTarget {
        host: text(target.host),
        port: target.port,
        tls_server_name: (target.tls != 0).then(|| text(target.server_name)),
        alpn: alpn.split(',').filter(|protocol| !protocol.is_empty()).map(str::to_string).collect(),
        carrier: target.carrier != 0,
    };
    mtproto_engine::StreamHost::open(context.host.as_ref(), StreamId(stream), &target);
}

unsafe extern "C" fn write(context: *mut c_void, stream: u64, bytes: MTBytes) {
    let context = unsafe { &*(context as *const Context) };
    let data = unsafe { std::slice::from_raw_parts(bytes.data, bytes.length) };
    mtproto_engine::StreamHost::write(context.host.as_ref(), StreamId(stream), data);
}

unsafe extern "C" fn close(context: *mut c_void, stream: u64) {
    let context = unsafe { &*(context as *const Context) };
    mtproto_engine::StreamHost::close(context.host.as_ref(), StreamId(stream));
}

unsafe extern "C" fn resume(context: *mut c_void, stream: u64) {
    let context = unsafe { &*(context as *const Context) };
    mtproto_engine::StreamHost::resume(context.host.as_ref(), StreamId(stream));
}

struct FfiSink(usize);

impl FfiSink {
    fn engine(&self) -> *mut MTEngine {
        self.0 as *mut MTEngine
    }
}

impl StreamSink for FfiSink {
    fn opened(&self, stream: StreamId) {
        unsafe { mt_stream_opened(self.engine(), stream.0) };
    }

    fn received(&self, stream: StreamId, bytes: &[u8]) -> bool {
        let accepted = unsafe {
            mt_stream_received(self.engine(), stream.0, MTBytes { data: bytes.as_ptr(), length: bytes.len() })
        };
        accepted != 0
    }

    fn sent(&self, stream: StreamId, count: usize) {
        unsafe { mt_stream_sent(self.engine(), stream.0, count) };
    }

    fn closed(&self, stream: StreamId, error: Option<String>) {
        let error = error.unwrap_or_default();
        unsafe { mt_stream_closed(self.engine(), stream.0, MTString { data: error.as_ptr(), length: error.len() }) };
    }
}

fn bytes(data: &[u8]) -> MTBytes {
    MTBytes { data: data.as_ptr(), length: data.len() }
}

fn string(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

fn blackhole() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut held: Vec<TcpStream> = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    address
}

#[test]
fn the_c_abi_carries_the_stream_over_a_host_stream_to_telegram_webs_websocket() {
    let key = random_key(9201);
    let server = TestServer::start(vec![key.clone()], ServerOptions::default());
    let front = WebFront::start(server.address);
    let dead = blackhole();
    let context: &'static Context = Box::leak(Box::new(Context {
        host: Arc::new(TestStreamHost::default()),
        completed: Mutex::new(Vec::new()),
        condvar: Condvar::new(),
    }));
    let engine = unsafe { mt_engine_create(1, context as *const Context as *mut c_void, Some(on_event), None) };
    assert!(!engine.is_null());
    context.host.attach_sink(Arc::new(FfiSink(engine as usize)));
    let callbacks = MTStreamHost { open: Some(open), write: Some(write), close: Some(close), resume: Some(resume) };
    unsafe { mt_engine_set_stream_host(engine, &callbacks) };

    let host = dead.ip().to_string();
    let address = MTAddress { host: string(&host), port: dead.port(), secret: bytes(&[]) };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64();
    let salt = MTSaltEntry { salt: SERVER_SALT, valid_since: now - 60.0, valid_until: now + 3600.0 };
    let setup = MTSessionSetup {
        datacenter_id: 2,
        obfuscation_dc_id: 2,
        role: 0,
        framing: 0,
        addresses: &address,
        address_count: 1,
        proxy: MTProxy {
            kind: 0,
            host: string(""),
            port: 0,
            username: string(""),
            password: string(""),
            secret: bytes(&[]),
        },
        auth_key: bytes(key.bytes()),
        salts: &salt,
        salt_count: 1,
        has_init_hash: 0,
        init_hash: string(""),
        generate_key: 0,
        public_keys_pem: std::ptr::null(),
        public_key_count: 0,
        temp_key_expires_in: 0,
        environment: std::ptr::null(),
        time_difference: 0.0,
        online: 1,
        paused: 0,
        keep_connected: 1,
        idle_disconnect_after: 0.0,
        request_timeout: 5.0,
        pfs_lifetime: 0,
        pfs_make_permanent_key: 0,
        pfs_temporary_key: std::ptr::null(),
    };
    let session = unsafe { mt_session_create(engine, &setup) };
    unsafe { mt_session_set_transport(engine, session, 2, 0) };
    let endpoint = MTWebEndpoint {
        host: string(WEB_FRONT_NAME),
        port: front.address.port(),
        path: string("/apiw1"),
        address: string("127.0.0.1"),
        ws_path: string("/apiws"),
    };
    unsafe { mt_session_set_web_endpoint(engine, session, &endpoint) };
    let mut ids = Vec::new();
    for tag in 1..=4u32 {
        let id = unsafe { mt_engine_next_request_id(engine) };
        let body = call(tag, &[tag as u8; 3]);
        let request = MTRequest { id, body: bytes(&body), flags: 0, expected_response_size: 0, invoke_after: 0 };
        unsafe { mt_session_send(engine, session, &request) };
        ids.push(id);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut completed = context.completed.lock().unwrap();
    while completed.len() < ids.len() && Instant::now() < deadline {
        completed = context.condvar.wait_timeout(completed, Duration::from_millis(100)).unwrap().0;
    }
    assert!(ids.iter().all(|id| completed.contains(id)), "{completed:?}");
    drop(completed);
    let stats = front.stats();
    assert!(stats.websockets >= 1 && stats.violations == 0, "{stats:?}");
    assert!(
        stats
            .requests
            .iter()
            .all(|line| line == &format!("GET /apiws HTTP/1.1 @ {WEB_FRONT_NAME}:{}", front.address.port())),
        "{stats:?}"
    );
    let targets = context.host.targets.lock().unwrap().clone();
    assert!(!targets.is_empty());
    assert!(targets.iter().all(|target| target.tls_server_name.as_deref() == Some(WEB_FRONT_NAME)
        && target.alpn == ["http/1.1"]
        && target.host == "127.0.0.1"));

    unsafe { mt_session_use_telegram_web(engine, session, 0) };
    unsafe { mt_session_destroy(engine, session) };
    unsafe { mt_engine_destroy(engine) };
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(context.host.open_streams(), 0, "streams are let go after the engine is destroyed too");
    assert!(context.host.closed_by_engine.load(Ordering::Relaxed) > 0);
}
