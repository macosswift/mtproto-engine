#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

use mtproto_engine::mtproto_core::auth_key::AuthKey;
use mtproto_engine::mtproto_core::crypto::RsaPublicKey;
use mtproto_engine::mtproto_core::rpc::{
    ApiEnvironment, ClientProxy, RequestFlags, RequestId, RpcEvent, RpcRequest, SessionRole, Verification,
    VerificationKind,
};
use mtproto_engine::mtproto_core::session::{DestroyAuthKeyOutcome, ServerSalt};
use mtproto_engine::mtproto_core::transport::Framing;
use mtproto_engine::{
    AuthKeyMaterial, DcAddress, Engine, EngineCallbacks, EngineConfig, EngineEvent, KeyGeneration, LogLevel,
    ProxyConfig, SessionHandle, SessionSetup,
};

pub const ABI_VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTBytes {
    pub data: *const u8,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTString {
    pub data: *const u8,
    pub length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTSaltEntry {
    pub salt: i64,
    pub valid_since: f64,
    pub valid_until: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTAddress {
    pub host: MTString,
    pub port: u16,
    pub secret: MTBytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTProxy {
    pub kind: u8,
    pub host: MTString,
    pub port: u16,
    pub username: MTString,
    pub password: MTString,
    pub secret: MTBytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTEnvironment {
    pub layer: i32,
    pub api_id: i32,
    pub device_model: MTString,
    pub system_version: MTString,
    pub app_version: MTString,
    pub system_lang_code: MTString,
    pub lang_pack: MTString,
    pub lang_code: MTString,
    pub has_proxy: u8,
    pub proxy_address: MTString,
    pub proxy_port: i32,
    pub has_params: u8,
    pub params: MTBytes,
    pub init_hash: MTString,
    pub disable_updates: u8,
}

#[repr(C)]
pub struct MTSessionSetup {
    pub datacenter_id: i32,
    pub obfuscation_dc_id: i16,
    pub role: u8,
    pub framing: u8,
    pub addresses: *const MTAddress,
    pub address_count: usize,
    pub proxy: MTProxy,
    pub auth_key: MTBytes,
    pub salts: *const MTSaltEntry,
    pub salt_count: usize,
    pub has_init_hash: u8,
    pub init_hash: MTString,
    pub generate_key: u8,
    pub public_keys_pem: *const MTString,
    pub public_key_count: usize,
    pub temp_key_expires_in: i32,
    pub environment: *const MTEnvironment,
    pub time_difference: f64,
    pub online: u8,
    pub paused: u8,
    pub keep_connected: u8,
    pub idle_disconnect_after: f64,
    pub request_timeout: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MTRequest {
    pub id: u64,
    pub body: MTBytes,
    pub flags: u32,
    pub expected_response_size: u32,
    pub invoke_after: u64,
}

#[repr(C)]
pub struct MTEvent {
    pub kind: u32,
    pub request_id: u64,
    pub code: i32,
    pub flags: u32,
    pub text: MTString,
    pub text2: MTString,
    pub payload: *mut MTBuffer,
    pub value1: f64,
    pub value2: f64,
    pub integer1: i64,
    pub integer2: i64,
    pub salts: *const MTSaltEntry,
    pub salt_count: usize,
}

pub struct MTBuffer {
    data: Vec<u8>,
    secret: bool,
}

impl Drop for MTBuffer {
    fn drop(&mut self) {
        if self.secret {
            self.data.zeroize();
        }
    }
}

pub type MTEventCallback = Option<unsafe extern "C" fn(context: *mut c_void, session: u64, event: *const MTEvent)>;
pub type MTLogCallback = Option<unsafe extern "C" fn(context: *mut c_void, level: i32, message: MTString)>;

pub struct MTEngine {
    engine: Engine,
    bridge: Arc<Bridge>,
}

struct ContextPointer(*mut c_void);

unsafe impl Send for ContextPointer {}
unsafe impl Sync for ContextPointer {}

struct Bridge {
    context: ContextPointer,
    on_event: MTEventCallback,
    on_log: MTLogCallback,
    closed: AtomicBool,
}

const EMPTY_STRING: MTString = MTString { data: std::ptr::null(), length: 0 };

fn string_ref(text: &str) -> MTString {
    MTString { data: text.as_ptr(), length: text.len() }
}

fn buffer(data: Vec<u8>, secret: bool) -> *mut MTBuffer {
    Box::into_raw(Box::new(MTBuffer { data, secret }))
}

impl Bridge {
    fn emit(&self, session: SessionHandle, event: MTEvent, payload: Option<Vec<u8>>) {
        self.deliver(session, event, payload, false);
    }

    fn emit_secret(&self, session: SessionHandle, event: MTEvent, mut payload: Vec<u8>) {
        if self.on_event.is_none() || self.closed.load(Ordering::Acquire) {
            payload.zeroize();
            return;
        }
        self.deliver(session, event, Some(payload), true);
    }

    fn deliver(&self, session: SessionHandle, mut event: MTEvent, payload: Option<Vec<u8>>, secret: bool) {
        let Some(callback) = self.on_event else {
            return;
        };
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if let Some(data) = payload {
            event.payload = buffer(data, secret);
        }
        unsafe { callback(self.context.0, session.0, &event) };
    }
}

fn blank(kind: u32) -> MTEvent {
    MTEvent {
        kind,
        request_id: 0,
        code: 0,
        flags: 0,
        text: EMPTY_STRING,
        text2: EMPTY_STRING,
        payload: std::ptr::null_mut(),
        value1: 0.0,
        value2: 0.0,
        integer1: 0,
        integer2: 0,
        salts: std::ptr::null(),
        salt_count: 0,
    }
}

impl EngineCallbacks for Bridge {
    fn on_event(&self, session: SessionHandle, event: EngineEvent) {
        match event {
            EngineEvent::Rpc(event) => self.on_rpc_event(session, event),
            EngineEvent::Progress { id, progress, packet_length } => {
                let mut event = blank(4);
                event.request_id = id.0;
                event.value1 = progress as f64;
                event.value2 = packet_length as f64;
                self.emit(session, event, None);
            }
            EngineEvent::ConnectionState { state, proxy_address } => {
                let mut event = blank(18);
                let mut flags = 0u32;
                if state.network_available {
                    flags |= 1;
                }
                if state.connected {
                    flags |= 2;
                }
                if state.updating_connection_context {
                    flags |= 4;
                }
                if state.performing_service_tasks {
                    flags |= 8;
                }
                if state.proxy_has_connection_issues {
                    flags |= 16;
                }
                event.flags = flags;
                let address = proxy_address.unwrap_or_default();
                event.text = string_ref(&address);
                self.emit(session, event, None);
            }
            EngineEvent::AuthKeyRequired => self.emit(session, blank(19), None),
            EngineEvent::AuthKeyInvalid { code } => {
                let mut event = blank(20);
                event.code = code;
                self.emit(session, event, None);
            }
            EngineEvent::AuthKeyCreated { key, salt, time_difference, expires_at } => {
                let mut event = blank(21);
                event.integer1 = salt;
                event.integer2 = expires_at.map(i64::from).unwrap_or(0);
                event.value1 = time_difference;
                self.emit_secret(session, event, key);
            }
            EngineEvent::AuthKeyCreationFailed { reason } => {
                let mut event = blank(22);
                event.text = string_ref(&reason);
                self.emit(session, event, None);
            }
            EngineEvent::TransportFlood => self.emit(session, blank(23), None),
            EngineEvent::NetworkUsage { incoming, outgoing, cellular } => {
                let mut event = blank(24);
                event.flags = u32::from(cellular);
                event.integer1 = incoming as i64;
                event.integer2 = outgoing as i64;
                self.emit(session, event, None);
            }
            EngineEvent::AddressResult { index, success } => {
                let mut event = blank(25);
                event.integer1 = index as i64;
                event.code = i32::from(success);
                self.emit(session, event, None);
            }
            EngineEvent::Closed => self.emit(session, blank(26), None),
        }
    }

    fn on_log(&self, level: LogLevel, message: &str) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if let Some(callback) = self.on_log {
            let level = match level {
                LogLevel::Error => 0,
                LogLevel::Warning => 1,
                LogLevel::Info => 2,
                LogLevel::Debug => 3,
            };
            unsafe { callback(self.context.0, level, string_ref(message)) };
        }
    }
}

impl Bridge {
    fn on_rpc_event(&self, session: SessionHandle, event: RpcEvent) {
        match event {
            RpcEvent::Completed { id, body, response_time, duration } => {
                let mut event = blank(1);
                event.request_id = id.0;
                event.value1 = response_time;
                event.value2 = duration;
                self.emit(session, event, Some(body));
            }
            RpcEvent::Failed { id, code, message, response_time, duration } => {
                let mut event = blank(2);
                event.request_id = id.0;
                event.code = code;
                event.text = string_ref(&message);
                event.value1 = response_time;
                event.value2 = duration;
                self.emit(session, event, None);
            }
            RpcEvent::Acknowledged { id } => {
                let mut event = blank(3);
                event.request_id = id.0;
                self.emit(session, event, None);
            }
            RpcEvent::FloodWaitReported { id, message } => {
                let mut event = blank(5);
                event.request_id = id.0;
                event.text = string_ref(&message);
                self.emit(session, event, None);
            }
            RpcEvent::AuthorizationRequired { message } => {
                let mut event = blank(6);
                event.text = string_ref(&message);
                self.emit(session, event, None);
            }
            RpcEvent::SoftAuthReset { message } => {
                let mut event = blank(7);
                event.text = string_ref(&message);
                self.emit(session, event, None);
            }
            RpcEvent::AuthTokenRequired => self.emit(session, blank(8), None),
            RpcEvent::TemporaryKeyRejected => self.emit(session, blank(9), None),
            RpcEvent::InitHashStored { hash } => {
                let mut event = blank(10);
                event.text = string_ref(&hash);
                self.emit(session, event, None);
            }
            RpcEvent::InitHashCleared => self.emit(session, blank(11), None),
            RpcEvent::VerificationRequired { id, kind } => {
                let mut event = blank(12);
                event.request_id = id.0;
                match kind {
                    VerificationKind::Apns { nonce } => {
                        event.code = 1;
                        event.text = string_ref(&nonce);
                        self.emit(session, event, None);
                    }
                    VerificationKind::Recaptcha { method, site_key } => {
                        event.code = 2;
                        event.text = string_ref(&method);
                        event.text2 = string_ref(&site_key);
                        self.emit(session, event, None);
                    }
                }
            }
            RpcEvent::UpdatesReset => self.emit(session, blank(13), None),
            RpcEvent::Update { body } => self.emit(session, blank(14), Some(body)),
            RpcEvent::TimeDifferenceUpdated { difference } => {
                let mut event = blank(15);
                event.value1 = difference;
                self.emit(session, event, None);
            }
            RpcEvent::SaltsUpdated { salts } => {
                let entries: Vec<MTSaltEntry> = salts
                    .iter()
                    .map(|salt| MTSaltEntry {
                        salt: salt.salt,
                        valid_since: salt.valid_since,
                        valid_until: salt.valid_until,
                    })
                    .collect();
                let mut event = blank(16);
                event.salts = entries.as_ptr();
                event.salt_count = entries.len();
                self.emit(session, event, None);
            }
            RpcEvent::Pong { rtt } => {
                let mut event = blank(17);
                event.value1 = rtt;
                self.emit(session, event, None);
            }
            RpcEvent::ConnectionShouldReset => {}
            RpcEvent::AuthKeyDestroyed { outcome } => {
                let mut event = blank(28);
                event.code = match outcome {
                    DestroyAuthKeyOutcome::Ok => 0,
                    DestroyAuthKeyOutcome::None => 1,
                    DestroyAuthKeyOutcome::Fail => 2,
                };
                self.emit(session, event, None);
            }
            RpcEvent::RetryDecisionRequired {
                id,
                code,
                message,
                flood_wait_seconds,
                flood_wait_text,
                server_errors,
            } => {
                let mut event = blank(27);
                event.request_id = id.0;
                event.code = code;
                event.text = string_ref(&message);
                let flood_text = flood_wait_text.unwrap_or_default();
                event.text2 = string_ref(&flood_text);
                event.integer1 = flood_wait_seconds;
                event.integer2 = i64::from(server_errors);
                self.emit(session, event, None);
            }
        }
    }
}

unsafe fn bytes(value: MTBytes) -> Vec<u8> {
    if value.data.is_null() || value.length == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(value.data, value.length) }.to_vec()
}

unsafe fn text(value: MTString) -> String {
    if value.data.is_null() || value.length == 0 {
        return String::new();
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(value.data, value.length) }).into_owned()
}

unsafe fn slice<'a, T>(pointer: *const T, count: usize) -> &'a [T] {
    if pointer.is_null() || count == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(pointer, count) }
}

unsafe fn salts(pointer: *const MTSaltEntry, count: usize) -> Vec<ServerSalt> {
    unsafe { slice(pointer, count) }
        .iter()
        .map(|entry| ServerSalt { salt: entry.salt, valid_since: entry.valid_since, valid_until: entry.valid_until })
        .collect()
}

unsafe fn addresses(pointer: *const MTAddress, count: usize) -> Vec<DcAddress> {
    unsafe { slice(pointer, count) }
        .iter()
        .map(|address| {
            let secret = unsafe { bytes(address.secret) };
            DcAddress {
                host: unsafe { text(address.host) },
                port: address.port,
                secret: (!secret.is_empty()).then_some(secret),
            }
        })
        .collect()
}

unsafe fn proxy(value: &MTProxy) -> Option<ProxyConfig> {
    match value.kind {
        1 => {
            let username = unsafe { text(value.username) };
            let password = unsafe { text(value.password) };
            Some(ProxyConfig::Socks5 {
                host: unsafe { text(value.host) },
                port: value.port,
                username: (!username.is_empty()).then_some(username),
                password: (!password.is_empty() || value.username.length > 0).then_some(password),
            })
        }
        2 => Some(ProxyConfig::MtProxy {
            host: unsafe { text(value.host) },
            port: value.port,
            secret: unsafe { bytes(value.secret) },
        }),
        _ => None,
    }
}

unsafe fn environment(value: &MTEnvironment) -> ApiEnvironment {
    unsafe {
        ApiEnvironment {
            layer: value.layer,
            api_id: value.api_id,
            device_model: text(value.device_model),
            system_version: text(value.system_version),
            app_version: text(value.app_version),
            system_lang_code: text(value.system_lang_code),
            lang_pack: text(value.lang_pack),
            lang_code: text(value.lang_code),
            proxy: (value.has_proxy != 0)
                .then(|| ClientProxy { address: text(value.proxy_address), port: value.proxy_port }),
            params: (value.has_params != 0).then(|| bytes(value.params)),
            init_hash: text(value.init_hash),
            disable_updates: value.disable_updates != 0,
        }
    }
}

unsafe fn request(value: &MTRequest) -> RpcRequest {
    let flags = value.flags;
    RpcRequest {
        id: RequestId(value.id),
        body: unsafe { bytes(value.body) },
        flags: RequestFlags {
            automatic_flood_wait: flags & 1 != 0,
            report_flood_wait: flags & 2 != 0,
            retry_server_errors: flags & 4 != 0,
            quick_ack: flags & 8 != 0,
            progress: flags & 16 != 0,
            timeout_timer: flags & 32 != 0,
            without_updates: flags & 64 != 0,
            delegate_retry_decisions: flags & 128 != 0,
            expected_response_size: value.expected_response_size,
        },
        invoke_after: (value.invoke_after != 0).then_some(RequestId(value.invoke_after)),
    }
}

unsafe fn engine<'a>(pointer: *mut MTEngine) -> Option<&'a Engine> {
    if pointer.is_null() { None } else { Some(unsafe { &(*pointer).engine }) }
}

#[unsafe(no_mangle)]
pub extern "C" fn mt_engine_abi_version() -> u32 {
    ABI_VERSION
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_engine_create(
    worker_threads: u32,
    context: *mut c_void,
    on_event: MTEventCallback,
    on_log: MTLogCallback,
) -> *mut MTEngine {
    let mut config = EngineConfig::default();
    if worker_threads > 0 {
        config.worker_threads = worker_threads as usize;
    }
    let bridge =
        Arc::new(Bridge { context: ContextPointer(context), on_event, on_log, closed: AtomicBool::new(false) });
    match Engine::new(config, bridge.clone()) {
        Ok(engine) => Box::into_raw(Box::new(MTEngine { engine, bridge })),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_engine_destroy(pointer: *mut MTEngine) {
    if pointer.is_null() {
        return;
    }
    let engine = unsafe { Box::from_raw(pointer) };
    engine.bridge.closed.store(true, Ordering::Release);
    engine.engine.shutdown();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_engine_next_request_id(pointer: *mut MTEngine) -> u64 {
    unsafe { engine(pointer) }.map(|engine| engine.next_request_id().0).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_engine_set_network_available(pointer: *mut MTEngine, available: u8) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_network_available(available != 0);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_engine_reset_connections(pointer: *mut MTEngine) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.reset_connections();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_create(pointer: *mut MTEngine, setup: *const MTSessionSetup) -> u64 {
    let (Some(engine), false) = (unsafe { engine(pointer) }, setup.is_null()) else {
        return 0;
    };
    let setup = unsafe { &*setup };
    let role = match setup.role {
        0 => SessionRole::Main,
        2 => SessionRole::Worker { requires_auth_token: true },
        3 => SessionRole::Cdn,
        _ => SessionRole::Worker { requires_auth_token: false },
    };
    let mut config =
        SessionSetup::new(setup.datacenter_id, role, unsafe { addresses(setup.addresses, setup.address_count) });
    config.obfuscation_dc_id = setup.obfuscation_dc_id;
    config.framing = match setup.framing {
        1 => Framing::Intermediate,
        2 => Framing::PaddedIntermediate,
        _ => Framing::Abridged,
    };
    config.proxy = unsafe { proxy(&setup.proxy) };
    let mut key = unsafe { bytes(setup.auth_key) };
    let parsed = AuthKey::from_slice(&key);
    key.zeroize();
    if let Some(key) = parsed {
        config.auth_key = Some(AuthKeyMaterial {
            key,
            salts: unsafe { salts(setup.salts, setup.salt_count) },
            init_hash: (setup.has_init_hash != 0).then(|| unsafe { text(setup.init_hash) }),
        });
    }
    if setup.generate_key != 0 {
        let public_keys: Vec<RsaPublicKey> = unsafe { slice(setup.public_keys_pem, setup.public_key_count) }
            .iter()
            .filter_map(|pem| RsaPublicKey::from_pem(&unsafe { text(*pem) }).ok())
            .collect();
        config.key_generation = Some(KeyGeneration {
            public_keys,
            temporary_expires_in: (setup.temp_key_expires_in > 0).then_some(setup.temp_key_expires_in),
        });
    }
    if !setup.environment.is_null() {
        config.environment = Some(unsafe { environment(&*setup.environment) });
    }
    config.time_difference = setup.time_difference;
    config.online = setup.online != 0;
    config.paused = setup.paused != 0;
    config.keep_connected = setup.keep_connected != 0;
    config.idle_disconnect_after = (setup.idle_disconnect_after > 0.0).then_some(setup.idle_disconnect_after);
    if setup.request_timeout > 0.0 {
        config.request_timeout = setup.request_timeout;
    }
    engine.create_session(config).0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_destroy(pointer: *mut MTEngine, session: u64) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.destroy_session(SessionHandle(session));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_send(pointer: *mut MTEngine, session: u64, value: *const MTRequest) {
    if let (Some(engine), false) = (unsafe { engine(pointer) }, value.is_null()) {
        engine.send(SessionHandle(session), unsafe { request(&*value) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_cancel(pointer: *mut MTEngine, session: u64, id: u64) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.cancel(SessionHandle(session), RequestId(id));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_paused(pointer: *mut MTEngine, session: u64, paused: u8) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_paused(SessionHandle(session), paused != 0);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_online(pointer: *mut MTEngine, session: u64, online: u8) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_online(SessionHandle(session), online != 0);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_auth_key(
    pointer: *mut MTEngine,
    session: u64,
    key: MTBytes,
    salt_entries: *const MTSaltEntry,
    salt_count: usize,
    has_init_hash: u8,
    init_hash: MTString,
) {
    let Some(engine) = (unsafe { engine(pointer) }) else {
        return;
    };
    let mut key = unsafe { bytes(key) };
    let parsed = AuthKey::from_slice(&key);
    key.zeroize();
    let material = parsed.map(|key| AuthKeyMaterial {
        key,
        salts: unsafe { salts(salt_entries, salt_count) },
        init_hash: (has_init_hash != 0).then(|| unsafe { text(init_hash) }),
    });
    engine.set_auth_key(SessionHandle(session), material);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_addresses(
    pointer: *mut MTEngine,
    session: u64,
    values: *const MTAddress,
    count: usize,
) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_addresses(SessionHandle(session), unsafe { addresses(values, count) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_obfuscation_dc_id(pointer: *mut MTEngine, session: u64, dc_id: i16) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_obfuscation_dc_id(SessionHandle(session), dc_id);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_proxy(pointer: *mut MTEngine, session: u64, value: *const MTProxy) {
    if let Some(engine) = unsafe { engine(pointer) } {
        let proxy = if value.is_null() { None } else { unsafe { proxy(&*value) } };
        engine.set_proxy(SessionHandle(session), proxy);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_update_environment(
    pointer: *mut MTEngine,
    session: u64,
    value: *const MTEnvironment,
    noop: *const MTRequest,
) {
    if let (Some(engine), false) = (unsafe { engine(pointer) }, value.is_null()) {
        let noop = (!noop.is_null()).then(|| unsafe { request(&*noop) });
        engine.update_environment(SessionHandle(session), unsafe { environment(&*value) }, noop);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_auth_token_ready(pointer: *mut MTEngine, session: u64, ready: u8) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_auth_token_ready(SessionHandle(session), ready != 0);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_resolve_apns(
    pointer: *mut MTEngine,
    session: u64,
    id: u64,
    nonce: MTString,
    secret: MTString,
) {
    if let Some(engine) = unsafe { engine(pointer) } {
        let verification = Verification::Apns { nonce: unsafe { text(nonce) }, secret: unsafe { text(secret) } };
        engine.resolve_verification(SessionHandle(session), RequestId(id), verification);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_resolve_recaptcha(pointer: *mut MTEngine, session: u64, id: u64, token: MTString) {
    if let Some(engine) = unsafe { engine(pointer) } {
        let verification = Verification::Recaptcha { token: unsafe { text(token) } };
        engine.resolve_verification(SessionHandle(session), RequestId(id), verification);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_fail_request(
    pointer: *mut MTEngine,
    session: u64,
    id: u64,
    code: i32,
    message: MTString,
) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.fail_request(SessionHandle(session), RequestId(id), code, unsafe { text(message) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_decide_retry(pointer: *mut MTEngine, session: u64, id: u64, retry: u8) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.decide_retry(SessionHandle(session), RequestId(id), retry != 0);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_invalidate_initialization(pointer: *mut MTEngine, session: u64) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.invalidate_initialization(SessionHandle(session));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_set_time_difference(pointer: *mut MTEngine, session: u64, difference: f64) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.set_time_difference(SessionHandle(session), difference);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_session_destroy_auth_key(pointer: *mut MTEngine, session: u64) {
    if let Some(engine) = unsafe { engine(pointer) } {
        engine.destroy_auth_key(SessionHandle(session));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_buffer_data(buffer: *const MTBuffer) -> *const u8 {
    if buffer.is_null() {
        return std::ptr::null();
    }
    unsafe { (*buffer).data.as_ptr() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_buffer_length(buffer: *const MTBuffer) -> usize {
    if buffer.is_null() {
        return 0;
    }
    unsafe { (*buffer).data.len() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mt_buffer_free(buffer: *mut MTBuffer) {
    if !buffer.is_null() {
        drop(unsafe { Box::from_raw(buffer) });
    }
}
