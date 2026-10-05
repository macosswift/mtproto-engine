use mio::Registry;
use mtproto_core::crypto::OsRandom;
use mtproto_core::session::Now;
use mtproto_core::transport::TransportConfig;

use super::SessionRuntime;
use crate::connection::Connection;
use crate::host_stream::StreamTarget;

impl SessionRuntime {
    /// Behind a WEB proxy: the stream connection goes over the host's carrier, obfuscated with the
    /// proxy's secret. Without a carrier the session fails closed rather than connecting directly.
    pub(super) fn start_carrier_connection(&mut self, registry: &Registry, now: Now, rng: &mut OsRandom) {
        let _ = registry;
        let count = self.setup.addresses.len();
        if count == 0 {
            return;
        }
        let index = self.best_address(None).unwrap_or(self.address_cursor) % count;
        let address = self.setup.addresses[index].clone();
        let token = self.free_token();
        let target = StreamTarget {
            host: address.host.clone(),
            port: address.port,
            tls_server_name: None,
            alpn: Vec::new(),
            carrier: true,
        };
        let pipe = self.host_streams.as_ref().and_then(|(streams, signal)| streams.open(&target, token, signal).ok());
        let Some(pipe) = pipe else {
            self.failures = self.failures.saturating_add(1);
            self.next_attempt_at = now.mono + self.reconnect_delay().max(1.0);
            return;
        };
        let transport = TransportConfig {
            framing: self.setup.framing,
            dc_id: self.setup.obfuscation_dc_id,
            secret: self.setup.proxy_secret(&address),
            unix_time: (now.unix + self.time_difference()) as i32,
        };
        self.connection = Some(Connection::over_carrier(pipe, token, &transport, index, now.mono, rng));
    }
}
