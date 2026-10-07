use std::sync::Arc;

use mio::Registry;
use mtproto_core::crypto::{OsRandom, RsaPublicKey};
use mtproto_core::handshake::HandshakeConfig;
use mtproto_core::rpc::{RpcEvent, flood_wait_seconds};
use mtproto_core::session::Now;

use super::SessionRuntime;
use crate::types::{AuthKeyMaterial, BoundTemporaryKey, EngineCallbacks, EngineEvent, LogLevel, PfsSetup};

/// The shortest a temporary key is replaced before it expires, and the longest: a quarter of its
/// lifetime in between, so short test lifetimes still rotate.
pub const PFS_ROTATE_MARGIN_MIN: f64 = 2.0;
pub const PFS_ROTATE_MARGIN_MAX: f64 = 3600.0;
/// Until this share of the margin is left, a replacement waits for nothing to be in flight; then the
/// queries the server may have are failed to the host rather than sent again under the new session,
/// where they would run twice.
pub const PFS_URGENT_SHARE: f64 = 0.25;
pub const PFS_HARD_MARGIN_MAX: f64 = 120.0;
/// A key is not replaced before this share of its lifetime, whatever the clocks say.
pub const PFS_MIN_AGE_SHARE: f64 = 0.5;
/// `enable_pfs` on a busy session waits this long for a quiet moment.
pub const PFS_SWITCH_WAIT: f64 = 60.0;
pub const PFS_ROTATED_ERROR: &str = "TEMP_KEY_ROTATED";
pub const PFS_BIND_RETRY_MAX: f64 = 30.0;
/// Binds of one temporary key that may fail (500s, boolFalse and the like) before the key is replaced,
/// as in MtProtoKit.
pub const PFS_SAME_KEY_BINDS: u32 = 3;
/// A temporary key the server refused is replaced at once the first time, then after 1 s, doubling up
/// to a minute, until one is bound.
pub const PFS_REGENERATE_BACKOFF_BASE: f64 = 1.0;
pub const PFS_REGENERATE_BACKOFF_MAX: f64 = 60.0;
/// `ENCRYPTED_MESSAGE_INVALID` on binds with this many fresh temporary keys in a row means the
/// permanent key is not the server's.
pub const PFS_INVALID_PERMANENT_AFTER: u32 = 2;
pub const PFS_INVALID_PERMANENT_RETRY: f64 = 60.0;
/// A permanent key younger than this is not reported unknown to the server, as in tdlib: binds under
/// it are tried again after `PFS_INVALID_PERMANENT_RETRY` instead.
pub const PFS_PERMANENT_KEY_IMMUNITY: f64 = 60.0;
/// Temporary keys the server stopped taking that a host offer cannot bring back.
const PFS_DROPPED_KEYS_KEPT: usize = 8;
/// Lifetime of the temporary keys a session without PFS makes to check its permanent key after -404s.
pub const PFS_KEY_CHECK_LIFETIME: i32 = 86_400;

#[derive(Default)]
pub(super) struct PfsState {
    pub(super) lifetime: i32,
    pub(super) public_keys: Vec<RsaPublicKey>,
    /// The permanent key; the session never talks under it.
    pub(super) perm: Option<AuthKeyMaterial>,
    /// When the session got the permanent key, unless it came with the session.
    perm_since: Option<f64>,
    /// When the current temporary key expires, in server time.
    pub(super) temp_expires_at: Option<f64>,
    pub(super) bound: bool,
    binding: bool,
    bind_failures: u32,
    bind_retry_at: f64,
    invalid_in_a_row: u32,
    need_regenerate: bool,
    need_rebind: bool,
    held_until: f64,
    /// Temporary keys the server refused since one was last bound, and when the next may be made.
    refusals: u32,
    regenerate_at: f64,
    /// Temporary keys the server lost (-404) with no fresh packet since: the next one waits longer.
    lost_in_a_row: u32,
    /// Rebinds after AUTH_KEY_PERM_EMPTY with no fresh packet since: a second one replaces the key.
    perm_empty_rebinds: u32,
    /// The key went while the session was idle: the next one is made when there is work for it.
    pub(super) lazy: bool,
    /// `destroy_auth_key` goes under the permanent key, with every request held; once it is answered
    /// the session starts over with a new permanent key.
    destroying: bool,
    destroyed: bool,
    temp_created_at: f64,
    /// `enable_pfs` on a session talking under the permanent key: the switch waits until then at most
    /// for a quiet moment.
    switch_by: Option<f64>,
    /// The datacenter id the temporary key in use was made for.
    temp_dc_id: i32,
    /// Without a permanent key the host is asked for one instead of the session making it.
    pub(super) permanent_key_from_host: bool,
    /// A bound temporary key the host offered: taken instead of a handshake whenever the session
    /// needs a new key.
    offered: Option<BoundTemporaryKey>,
    dropped: std::collections::VecDeque<u64>,
    /// PFS runs to check the permanent key after -404s (`check_permanent_key_with_pfs`): binds refused
    /// with ENCRYPTED_MESSAGE_INVALID report the key as the -404 would have, with `AuthKeyInvalid`.
    checks_permanent_key: bool,
}

impl PfsState {
    pub(super) fn new(setup: PfsSetup, perm: Option<AuthKeyMaterial>) -> Self {
        Self {
            lifetime: setup.lifetime.max(60),
            public_keys: setup.public_keys,
            perm,
            permanent_key_from_host: setup.permanent_key_from_host,
            offered: setup.temporary_key,
            ..Self::default()
        }
    }

    /// The address class changed: a temporary key is made for one class of addresses, so the one in
    /// use goes, and an offer made for the old class is no good.
    pub(super) fn replace_temporary_key_now(&mut self, now: Now) {
        if self.destroying || self.switch_by.is_some() {
            return;
        }
        self.need_regenerate = true;
        self.regenerate_at = now.mono;
    }

    /// The host turns PFS on while the session runs it only to check its permanent key: the session
    /// goes on with the host's PFS, and the next temporary key is made with its lifetime and reported.
    pub(super) fn take_over_key_check(&mut self, setup: crate::types::PfsSetup) -> bool {
        if !self.checks_permanent_key {
            return false;
        }
        self.checks_permanent_key = false;
        self.lifetime = setup.lifetime.max(60);
        self.public_keys = setup.public_keys;
        self.permanent_key_from_host = setup.permanent_key_from_host;
        self.offered = setup.temporary_key;
        true
    }

    pub(super) fn forget_offer(&mut self) {
        self.offered = None;
    }

    /// An offer bound to another permanent key than the session's would run calls under another
    /// authorization.
    fn binding_fits(&self, key: &BoundTemporaryKey) -> bool {
        match (key.bound_to, &self.perm) {
            (Some(bound_to), Some(perm)) => bound_to == perm.key.id(),
            _ => true,
        }
    }

    /// The session waits for the host's permanent key and makes none itself.
    pub(super) fn temporary_key_dc_id(&self) -> i32 {
        self.temp_dc_id
    }

    pub(super) fn awaits_permanent_key(&self) -> bool {
        self.perm.is_none() && self.permanent_key_from_host
    }

    fn note_dropped(&mut self, key_id: u64) {
        if self.dropped.len() >= PFS_DROPPED_KEYS_KEPT {
            self.dropped.pop_front();
        }
        self.dropped.push_back(key_id);
        if self.offered.as_ref().is_some_and(|offered| offered.material.key.id() == key_id) {
            self.offered = None;
        }
    }

    /// Keeps a key the host offers when it could serve: one the session did not see the server drop,
    /// that outlives the urgent margin, and that lives longer than an offer already kept.
    fn keep_offer(&mut self, key: BoundTemporaryKey, server_now: f64) -> bool {
        let id = key.material.key.id();
        if self.dropped.contains(&id) || f64::from(key.expires_at) - server_now <= self.hard_margin() {
            return false;
        }
        if !self.binding_fits(&key) {
            return false;
        }
        if self.offered.as_ref().is_some_and(|offered| offered.expires_at >= key.expires_at) {
            return false;
        }
        self.offered = Some(key);
        true
    }

    fn margin(&self) -> f64 {
        (f64::from(self.lifetime) / 4.0).clamp(PFS_ROTATE_MARGIN_MIN, PFS_ROTATE_MARGIN_MAX)
    }

    fn hard_margin(&self) -> f64 {
        (self.margin() * PFS_URGENT_SHARE).min(PFS_HARD_MARGIN_MAX)
    }

    /// The session keeps talking under its permanent key until a quiet moment, by `deadline` at most.
    pub(super) fn switch_when_quiet(&mut self, deadline: f64) {
        self.switch_by = Some(deadline);
    }

    /// The session was destroying its key when PFS was enabled: the destroy finishes first, then the
    /// session starts over with new keys.
    pub(super) fn continue_destroy(&mut self) {
        self.destroying = true;
        self.switch_by = None;
    }

    pub(super) fn is_binding(&self) -> bool {
        self.binding
    }

    #[cfg(test)]
    pub(super) fn describe(&self, now: f64) -> String {
        format!(
            "pfs(perm {} temp_expires {:?} bound {} binding {} bind_failures {} bind_retry {:+.2} invalid {} regen {} regen_at {:+.2} rebind {} held {:+.2} refusals {} lazy {} destroying {} destroyed {} switch_by {:?})",
            self.perm.is_some(),
            self.temp_expires_at,
            self.bound,
            self.binding,
            self.bind_failures,
            self.bind_retry_at - now,
            self.invalid_in_a_row,
            self.need_regenerate,
            self.regenerate_at - now,
            self.need_rebind,
            self.held_until - now,
            self.refusals,
            self.lazy,
            self.destroying,
            self.destroyed,
            self.switch_by.map(|at| at - now)
        )
    }

    /// The server refused the temporary key: another is made, at once the first time, then backing off.
    fn regenerate_after_refusal(&mut self, now: Now) {
        let delay = match self.refusals {
            0 => 0.0,
            refusals => (PFS_REGENERATE_BACKOFF_BASE * f64::from(1u32 << (refusals - 1).min(10)))
                .min(PFS_REGENERATE_BACKOFF_MAX),
        };
        self.refusals = self.refusals.saturating_add(1);
        self.need_regenerate = true;
        self.regenerate_at = now.mono + delay;
    }

    /// The host gave another permanent key: with a session running, the temporary key bound to the old
    /// one goes at once, so that no call made from now on runs under the old authorization.
    pub(super) fn replace_permanent_key(&mut self, perm: AuthKeyMaterial, running: bool, now: Now) {
        let replaced = self.perm.is_some();
        self.perm = Some(perm);
        self.perm_since = Some(now.mono);
        if replaced || self.offered.as_ref().is_some_and(|offer| !self.binding_fits(offer)) {
            self.offered = None;
        }
        self.invalid_in_a_row = 0;
        self.held_until = 0.0;
        self.switch_by = None;
        self.destroying = false;
        self.destroyed = false;
        if running {
            self.need_regenerate = true;
            self.regenerate_at = now.mono;
        }
    }

    /// The host dropped the key: the next handshake makes a new permanent key before any temporary one.
    pub(super) fn forget_permanent_key(&mut self) {
        *self = Self {
            lifetime: self.lifetime,
            public_keys: std::mem::take(&mut self.public_keys),
            permanent_key_from_host: self.permanent_key_from_host,
            dropped: std::mem::take(&mut self.dropped),
            checks_permanent_key: self.checks_permanent_key,
            ..Self::default()
        };
    }
}

impl SessionRuntime {
    /// The handshake the next key needs: the permanent key first if there is none, then temporary
    /// ones; without PFS, what the host asked for.
    pub(super) fn handshake_config(&self) -> Option<HandshakeConfig> {
        if let Some(pfs) = &self.pfs {
            if pfs.awaits_permanent_key() {
                return None;
            }
            return Some(HandshakeConfig {
                dc_id: self.handshake_dc_id(),
                temp_key_expires_in: pfs.perm.is_some().then_some(pfs.lifetime),
                public_keys: pfs.public_keys.clone(),
            });
        }
        self.setup.key_generation.as_ref().map(|generation| HandshakeConfig {
            dc_id: self.handshake_dc_id(),
            temp_key_expires_in: generation.temporary_expires_in,
            public_keys: generation.public_keys.clone(),
        })
    }

    /// The server answered -404 again on a fresh connection to a session talking under its permanent
    /// key. A transport error is not authenticated: anything on the path can send one, so it is no
    /// proof that the server lost the key. As tdlib does, the session moves to PFS: a temporary key
    /// the server binds to the permanent key proves it, and only binds refused with
    /// ENCRYPTED_MESSAGE_INVALID, which come encrypted under the temporary key, report it invalid.
    /// False when the session cannot check: no RSA keys to make a temporary key with, a CDN key (which
    /// is replaced, not checked), or a key being destroyed.
    pub(super) fn check_permanent_key_with_pfs(&mut self) -> bool {
        if self.pfs.is_some() || matches!(self.setup.role, mtproto_core::rpc::SessionRole::Cdn) {
            return false;
        }
        let Some(public_keys) = self
            .setup
            .key_generation
            .as_ref()
            .filter(|generation| generation.temporary_expires_in.is_none() && !generation.public_keys.is_empty())
            .map(|generation| generation.public_keys.clone())
        else {
            return false;
        };
        let Some(rpc) = self.rpc.as_ref().filter(|rpc| !rpc.session().is_destroying_auth_key()) else {
            return false;
        };
        let perm =
            AuthKeyMaterial { key: rpc.session().auth_key().clone(), salts: rpc.session().salts(), init_hash: None };
        let setup = crate::types::PfsSetup {
            lifetime: PFS_KEY_CHECK_LIFETIME,
            public_keys,
            permanent_key_from_host: false,
            temporary_key: None,
        };
        let mut state = PfsState::new(setup, Some(perm));
        state.checks_permanent_key = true;
        self.pfs = Some(state);
        self.setup.key_generation = None;
        true
    }

    /// The check proved the permanent key gone: the session drops PFS and goes on as before the -404s,
    /// with the key reported invalid, so that it makes a new permanent key itself.
    fn end_permanent_key_check(&mut self, registry: &Registry, now: Now) {
        let Some(pfs) = self.pfs.take() else {
            return;
        };
        self.setup.key_generation =
            Some(crate::types::KeyGeneration { public_keys: pfs.public_keys, temporary_expires_in: None });
        self.retire_rpc();
        self.close_connection(registry, now, false);
        if let Some(http) = &mut self.http {
            http.forget_opened();
        }
        self.next_attempt_at = now.mono;
    }

    /// A temporary key made only to check the permanent key stays inside the session: the host runs no
    /// PFS for it and would take any key it hears of for the session's permanent key.
    pub(super) fn reports_created_key(&self, temporary: bool) -> bool {
        !(temporary && self.pfs.as_ref().is_some_and(|pfs| pfs.checks_permanent_key))
    }

    /// The datacenter a new key is made for, as MtProtoKit and tdlib send it: the obfuscation id,
    /// which carries the test offset and is negative for a media key; a CDN key is never a media key.
    pub(super) fn handshake_dc_id(&self) -> i32 {
        let id = i32::from(self.setup.obfuscation_dc_id);
        if id == 0 {
            return self.setup.datacenter_id;
        }
        if matches!(self.setup.role, mtproto_core::rpc::SessionRole::Cdn) { id.abs() } else { id }
    }

    /// A key came out of the handshake. Under PFS a permanent one is kept aside and a temporary one
    /// is made next; a temporary one becomes the session's and is bound before anything else goes.
    /// True when the key was installed.
    pub(super) fn take_handshake_key(
        &mut self,
        material: AuthKeyMaterial,
        expires_at: Option<i32>,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) -> bool {
        let dc_id = self.handshake_dc_id();
        let Some(pfs) = &mut self.pfs else {
            self.install_key(material, now, rng);
            return true;
        };
        match expires_at {
            None => {
                if pfs.perm.is_some() {
                    self.log(
                        callbacks,
                        LogLevel::Info,
                        "the host gave a permanent key during the handshake; the one made is dropped",
                    );
                } else {
                    pfs.perm = Some(material);
                    pfs.perm_since = Some(now.mono);
                    pfs.offered = None;
                    self.log(callbacks, LogLevel::Info, "permanent key made; making a temporary key");
                }
                if let Some(config) = self.handshake_config() {
                    let (handshake, packet) =
                        mtproto_core::handshake::Handshake::start(config, now.unix + self.setup.time_difference, rng);
                    self.handshake = Some(handshake);
                    self.handshake_started_at = Some(now.mono);
                    self.pending_plain.push_back(packet);
                }
                false
            }
            Some(expires_at) => {
                pfs.lazy = false;
                let local = now.unix + self.setup.time_difference + f64::from(pfs.lifetime);
                pfs.temp_dc_id = dc_id;
                pfs.temp_expires_at = Some(f64::from(expires_at).min(local));
                pfs.temp_created_at = now.mono;
                pfs.switch_by = None;
                pfs.bound = false;
                pfs.binding = false;
                pfs.bind_failures = 0;
                pfs.need_regenerate = false;
                pfs.need_rebind = false;
                self.install_key(material, now, rng);
                self.bind_temporary_key(now, callbacks, rng);
                true
            }
        }
    }

    /// A bound temporary key from the host. Taken at once when the session has none in use; kept for
    /// the next time it needs one otherwise.
    pub fn offer_temporary_key(
        &mut self,
        key: BoundTemporaryKey,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let server_now = now.unix + self.time_difference();
        let current = self.rpc.as_ref().map(|rpc| rpc.session().auth_key_id());
        let Some(pfs) = &mut self.pfs else {
            return;
        };
        if current == Some(key.material.key.id()) || !pfs.keep_offer(key, server_now) {
            return;
        }
        if self.rpc.is_none() {
            self.take_offered_key(registry, now, callbacks, rng);
        }
    }

    /// Starts talking under the key the host offered instead of making one; a handshake under way is
    /// dropped with its connection. A key whose binding the host does not know (MtProtoKit's) is bound
    /// again before any call goes out under it, which leaves it bound to this session's permanent key:
    /// Telegram moves the binding of a key that carried initConnection (it does not refuse it), and
    /// refuses the rebind of one that never did with CONNECTION_NOT_INITED, which replaces the key. True
    /// when the key was taken.
    pub(super) fn take_offered_key(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) -> bool {
        let server_now = now.unix + self.time_difference();
        let dc_id = self.handshake_dc_id();
        let Some(pfs) = &mut self.pfs else {
            return false;
        };
        if pfs.perm.is_none() || pfs.destroying || pfs.switch_by.is_some() {
            return false;
        }
        let Some(key) = pfs.offered.take() else {
            return false;
        };
        let remaining = f64::from(key.expires_at) - server_now;
        if remaining <= pfs.hard_margin() || pfs.dropped.contains(&key.material.key.id()) || !pfs.binding_fits(&key) {
            return false;
        }
        let permanent_key_id = pfs.perm.as_ref().map_or(0, |perm| perm.key.id());
        let unverified = key.bound_to.is_none();
        pfs.temp_expires_at = Some(f64::from(key.expires_at));
        pfs.temp_dc_id = dc_id;
        pfs.temp_created_at = now.mono - (f64::from(pfs.lifetime) - remaining).max(0.0);
        pfs.bound = !unverified;
        pfs.binding = false;
        pfs.bind_failures = 0;
        pfs.need_regenerate = false;
        pfs.need_rebind = false;
        pfs.lazy = false;
        let key_id = key.material.key.id();
        if self.handshake.is_some() {
            self.close_connection(registry, now, false);
            self.next_attempt_at = now.mono;
        }
        self.install_key(key.material, now, rng);
        if unverified {
            self.log(callbacks, LogLevel::Info, "taking the temporary key the host offered; binding it first");
            self.bind_temporary_key(now, callbacks, rng);
            return true;
        }
        self.log(callbacks, LogLevel::Info, "taking the temporary key the host offered");
        callbacks.on_event(
            self.handle,
            EngineEvent::TemporaryKeyInUse {
                key_id: key_id as i64,
                expires_at: key.expires_at,
                adopted: true,
                dc_id,
                permanent_key_id: permanent_key_id as i64,
            },
        );
        true
    }

    /// The host makes permanent keys (false) or lets this session make one when it has none (true).
    pub fn allow_permanent_key(&mut self, allowed: bool, now: Now) {
        let Some(pfs) = &mut self.pfs else {
            return;
        };
        let waited = pfs.awaits_permanent_key();
        pfs.permanent_key_from_host = !allowed;
        if waited && !pfs.awaits_permanent_key() {
            self.next_attempt_at = now.mono;
        }
    }

    /// The server no longer takes the session's temporary key: the host hears so it can drop its copy,
    /// and an offer of the same key is refused from now on.
    pub(super) fn drop_temporary_key(&mut self, key_id: u64, callbacks: &Arc<dyn EngineCallbacks>) {
        let Some(pfs) = &mut self.pfs else {
            return;
        };
        pfs.note_dropped(key_id);
        callbacks.on_event(self.handle, EngineEvent::TemporaryKeyDropped { key_id: key_id as i64 });
    }

    /// The bind answers that mean the server will never take this temporary key: every 400, such as
    /// CONNECTION_NOT_INITED for a key another client (MtProtoKit) bound and used without
    /// initConnection, which no retry of the same key gets past, and the 401, 403 and 406 refusals.
    pub(super) fn refuses_temporary_key(event: &RpcEvent) -> bool {
        matches!(
            event,
            RpcEvent::TemporaryKeyBindFailed { code, message }
                if matches!(*code, 400 | 401 | 403 | 406)
                    || matches!(message.as_str(), "ENCRYPTED_MESSAGE_INVALID" | "TEMP_AUTH_KEY_EMPTY" | "TEMP_AUTH_KEY_ALREADY_BOUND" | "EXPIRES_AT_INVALID")
        )
    }

    fn bind_temporary_key(&mut self, now: Now, callbacks: &Arc<dyn EngineCallbacks>, rng: &mut OsRandom) {
        let (Some(pfs), Some(rpc)) = (&mut self.pfs, &mut self.rpc) else {
            return;
        };
        let (Some(perm), Some(expires_at)) = (&pfs.perm, pfs.temp_expires_at) else {
            return;
        };
        rpc.hold_until_bound();
        rpc.bind_temporary_key(perm.key.clone(), expires_at.floor() as i32, now, rng);
        pfs.binding = true;
        pfs.need_rebind = false;
        self.log(callbacks, LogLevel::Info, "binding the temporary key");
    }

    /// Notes what a bind answer or a rejected temporary key asks for; `drive_pfs` acts on it. False
    /// when the event is the engine's own business and not the host's.
    pub(super) fn observe_pfs_event(&mut self, event: &RpcEvent, now: Now) -> bool {
        let Some(pfs) = &mut self.pfs else {
            return true;
        };
        match event {
            RpcEvent::TemporaryKeyBound => {
                pfs.bound = true;
                pfs.binding = false;
                pfs.bind_failures = 0;
                pfs.invalid_in_a_row = 0;
                pfs.refusals = 0;
                true
            }
            RpcEvent::TemporaryKeyBindFailed { code, message } => {
                pfs.binding = false;
                pfs.bind_failures = pfs.bind_failures.saturating_add(1);
                match message.as_str() {
                    "ENCRYPTED_MESSAGE_INVALID" => {
                        pfs.invalid_in_a_row = pfs.invalid_in_a_row.saturating_add(1);
                        pfs.regenerate_after_refusal(now);
                    }
                    "TEMP_AUTH_KEY_EMPTY" | "TEMP_AUTH_KEY_ALREADY_BOUND" | "EXPIRES_AT_INVALID" => {
                        pfs.regenerate_after_refusal(now);
                    }
                    _ if matches!(*code, 400 | 401 | 403 | 406) => {
                        pfs.regenerate_after_refusal(now);
                    }
                    _ if let Some(seconds) = flood_wait_seconds(message).filter(|_| *code == 420) => {
                        pfs.bind_retry_at = now.mono + seconds.clamp(1, 86_400) as f64;
                        pfs.need_rebind = true;
                    }
                    _ if pfs.bind_failures >= PFS_SAME_KEY_BINDS => {
                        pfs.regenerate_after_refusal(now);
                    }
                    _ => {
                        let delay = f64::from(1u32 << pfs.bind_failures.min(5)).min(PFS_BIND_RETRY_MAX);
                        pfs.bind_retry_at = now.mono + delay;
                        pfs.need_rebind = true;
                    }
                }
                true
            }
            RpcEvent::AuthKeyDestroyed { .. } => {
                if pfs.destroying {
                    pfs.destroyed = true;
                }
                true
            }
            RpcEvent::TemporaryKeyRejected => {
                if pfs.bound && pfs.perm_empty_rebinds >= 1 {
                    pfs.bound = false;
                    pfs.regenerate_after_refusal(now);
                } else if pfs.bound {
                    pfs.bound = false;
                    pfs.perm_empty_rebinds += 1;
                    pfs.need_rebind = true;
                } else if !pfs.binding {
                    pfs.regenerate_after_refusal(now);
                }
                false
            }
            _ => true,
        }
    }

    /// The server lost the temporary key (`-404`): the next one is made without asking the host.
    pub(super) fn forget_temporary_key(&mut self, now: Now) -> bool {
        let Some(pfs) = &mut self.pfs else {
            return false;
        };
        if pfs.destroying {
            pfs.forget_permanent_key();
            return false;
        }
        pfs.temp_expires_at = None;
        pfs.bound = false;
        pfs.binding = false;
        pfs.lost_in_a_row = pfs.lost_in_a_row.saturating_add(1);
        if pfs.lost_in_a_row > 1 {
            let delay = (PFS_REGENERATE_BACKOFF_BASE * f64::from(1u32 << (pfs.lost_in_a_row - 2).min(10)))
                .min(PFS_REGENERATE_BACKOFF_MAX);
            self.next_attempt_at = self.next_attempt_at.max(now.mono + delay);
        }
        true
    }

    /// A call completed under the temporary key: it works end to end. Bind answers and errors do not
    /// count, so a server that keeps losing the binding or the key still gets a new key, with backoff.
    pub(super) fn note_pfs_progress(&mut self) {
        if let Some(pfs) = &mut self.pfs {
            pfs.lost_in_a_row = 0;
            pfs.perm_empty_rebinds = 0;
        }
    }

    /// Drops the session's temporary key so that the next handshake makes another; the requests wait
    /// for it. Requests the server may already have would run twice under a new session, so with
    /// `fail_transmitted` they fail to the host instead, and so do the ones chained after them with
    /// `invoke_after`. The new key starts on fresh connections, as in tdlib: the old session's late
    /// packets would otherwise meet the new handshake.
    fn regenerate_temporary_key(
        &mut self,
        fail_transmitted: bool,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        if fail_transmitted {
            self.fail_unanswered_requests(registry, now, callbacks);
        }
        if self.rpc.is_none() {
            return;
        }
        self.retire_rpc();
        let idle = !self.setup.keep_connected && self.queued.is_empty();
        if let Some(pfs) = &mut self.pfs {
            pfs.temp_expires_at = None;
            pfs.bound = false;
            pfs.binding = false;
            pfs.need_regenerate = false;
            pfs.need_rebind = false;
            pfs.bind_failures = 0;
            pfs.perm_empty_rebinds = 0;
            pfs.switch_by = None;
            pfs.lazy = idle;
        }
        self.log(
            callbacks,
            LogLevel::Info,
            if idle {
                "dropping the temporary key; the next is made with the next call"
            } else {
                "replacing the temporary key"
            },
        );
        self.close_connection(registry, now, false);
        if let Some(http) = &mut self.http {
            http.forget_opened();
        }
        self.take_offered_key(registry, now, callbacks, rng);
    }

    /// Requests the server may already have would run twice under a new session: they fail to the host
    /// instead, and so do the ones chained after them with `invoke_after`.
    pub(super) fn fail_unanswered_requests(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
    ) {
        let transmitted = self.rpc.as_ref().map(mtproto_core::rpc::RpcClient::transmitted_requests).unwrap_or_default();
        if !transmitted.is_empty() {
            let chained = self.rpc.as_ref().map(|rpc| rpc.dependents_of(&transmitted)).unwrap_or_default();
            self.log(
                callbacks,
                LogLevel::Warning,
                &format!(
                    "{} requests still unanswered when the temporary key had to go, {} chained after them",
                    transmitted.len(),
                    chained.len()
                ),
            );
            if let Some(rpc) = &mut self.rpc {
                let mut failed: Vec<_> = transmitted.into_iter().chain(chained).collect();
                rpc.sort_by_submission(&mut failed);
                for &id in &failed {
                    rpc.fail_request(id, 500, PFS_ROTATED_ERROR, now);
                }
                for id in failed {
                    self.note_rotated(id);
                }
            }
            self.pump_rpc_events(now, registry, callbacks);
        }
    }

    /// `destroy_auth_key` is about the permanent key: as tdlib's destroying session, this one talks
    /// under the permanent key, on fresh connections, and sends nothing else; the requests wait under the
    /// bind gate and go with the next keys once the answer came.
    pub(super) fn hold_requests_for_destroy(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let Some(perm) = self.pfs.as_ref().filter(|pfs| !pfs.destroying).and_then(|pfs| pfs.perm.clone()) else {
            return;
        };
        self.fail_unanswered_requests(registry, now, callbacks);
        self.retire_rpc();
        let held = std::mem::take(&mut self.queued);
        self.close_connection(registry, now, false);
        if let Some(pfs) = &mut self.pfs {
            pfs.temp_expires_at = None;
            pfs.bound = false;
            pfs.binding = false;
            pfs.need_regenerate = false;
            pfs.need_rebind = false;
            pfs.switch_by = None;
            pfs.lazy = false;
            pfs.destroying = true;
            pfs.destroyed = false;
        }
        self.log(callbacks, LogLevel::Info, "destroying the permanent key; requests wait for the next keys");
        self.install_key(perm, now, rng);
        if let Some(rpc) = &mut self.rpc {
            rpc.hold_until_bound();
            for pending in held {
                rpc.adopt(pending, now);
            }
        }
    }

    /// The permanent key is gone: the requests wait for a new one, made with the next call.
    fn start_over_after_destroy(&mut self, registry: &Registry, now: Now, callbacks: &Arc<dyn EngineCallbacks>) {
        self.retire_rpc();
        let idle = !self.setup.keep_connected && self.queued.is_empty();
        if let Some(pfs) = &mut self.pfs {
            pfs.forget_permanent_key();
            pfs.lazy = idle;
        }
        self.close_connection(registry, now, false);
        if let Some(http) = &mut self.http {
            http.forget_opened();
        }
        self.log(callbacks, LogLevel::Info, "the permanent key is destroyed; a new one is made for the next call");
    }

    fn is_quiet(&self) -> bool {
        self.rpc.as_ref().is_some_and(|rpc| !rpc.has_transmitted_requests() && !rpc.session().is_awaiting_responses())
    }

    /// When the current temporary key is due for replacement, and when it has to go even with requests
    /// in flight; None while it is not.
    fn rotation_times(&self, now: Now) -> Option<(f64, f64)> {
        let pfs = self.pfs.as_ref()?;
        if let Some(by) = pfs.switch_by {
            return Some((now.mono, by));
        }
        let expires_at = pfs.temp_expires_at?;
        if !pfs.bound {
            return None;
        }
        let server_offset = now.unix + self.time_difference() - now.mono;
        let oldest = pfs.temp_created_at + f64::from(pfs.lifetime) * PFS_MIN_AGE_SHARE;
        let due = (expires_at - pfs.margin() - server_offset).max(oldest);
        let hard = (expires_at - pfs.hard_margin() - server_offset).max(due);
        Some((due, hard))
    }

    /// Replaces the temporary key ahead of its expiry at a quiet moment, retries binds, and makes a new
    /// key when the server refused the old one.
    pub(super) fn drive_pfs(
        &mut self,
        registry: &Registry,
        now: Now,
        callbacks: &Arc<dyn EngineCallbacks>,
        rng: &mut OsRandom,
    ) {
        let Some(pfs) = &self.pfs else {
            return;
        };
        if self.rpc.is_none() {
            if pfs.offered.is_some() {
                self.take_offered_key(registry, now, callbacks, rng);
            }
            return;
        }
        if now.mono < pfs.held_until {
            return;
        }
        if pfs.destroyed {
            self.start_over_after_destroy(registry, now, callbacks);
            return;
        }
        if pfs.destroying {
            return;
        }
        if pfs.invalid_in_a_row >= PFS_INVALID_PERMANENT_AFTER {
            let young = pfs.perm_since.is_some_and(|since| now.mono - since < PFS_PERMANENT_KEY_IMMUNITY);
            let checks = pfs.checks_permanent_key;
            if let Some(pfs) = &mut self.pfs {
                pfs.invalid_in_a_row = 0;
                pfs.held_until = now.mono + PFS_INVALID_PERMANENT_RETRY;
                pfs.need_regenerate = true;
            }
            if young {
                self.log(
                    callbacks,
                    LogLevel::Info,
                    "binds under the permanent key made just now fail; trying again before reporting it",
                );
                return;
            }
            self.log(callbacks, LogLevel::Warning, "the server does not know the permanent key");
            if checks {
                callbacks.on_event(self.handle, EngineEvent::AuthKeyInvalid { code: -404 });
                self.end_permanent_key_check(registry, now);
            } else {
                callbacks.on_event(self.handle, EngineEvent::PermanentKeyInvalid);
            }
            return;
        }
        if pfs.need_regenerate {
            if now.mono >= pfs.regenerate_at {
                self.regenerate_temporary_key(true, registry, now, callbacks, rng);
            }
            return;
        }
        if pfs.need_rebind && !pfs.binding && now.mono >= pfs.bind_retry_at {
            self.bind_temporary_key(now, callbacks, rng);
            return;
        }
        let Some((due, hard)) = self.rotation_times(now) else {
            return;
        };
        if now.mono < due {
            return;
        }
        let quiet = self.is_quiet();
        if quiet || now.mono >= hard {
            self.regenerate_temporary_key(!quiet, registry, now, callbacks, rng);
        }
    }

    pub(super) fn pfs_deadline(&self, now: Now) -> Option<f64> {
        let pfs = self.pfs.as_ref()?;
        if self.rpc.is_none() {
            return (pfs.offered.is_some() && pfs.perm.is_some() && !pfs.destroying && pfs.switch_by.is_none())
                .then_some(now.mono);
        }
        if pfs.held_until > now.mono {
            return Some(pfs.held_until);
        }
        if pfs.destroyed {
            return Some(now.mono);
        }
        if pfs.destroying {
            return None;
        }
        if pfs.invalid_in_a_row >= PFS_INVALID_PERMANENT_AFTER {
            return Some(now.mono);
        }
        if pfs.need_regenerate {
            return Some(pfs.regenerate_at.max(now.mono));
        }
        if pfs.need_rebind && !pfs.binding {
            return Some(pfs.bind_retry_at.max(now.mono));
        }
        let (due, hard) = self.rotation_times(now)?;
        Some(if now.mono < due {
            due
        } else if self.is_quiet() {
            now.mono
        } else {
            hard.max(now.mono)
        })
    }
}
