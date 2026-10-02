use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

pub fn parse_literal(host: &str, port: u16) -> Option<SocketAddr> {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    trimmed.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, port))
}

pub fn resolve_blocking(host: &str, port: u16) -> Vec<SocketAddr> {
    if let Some(address) = parse_literal(host, port) {
        return vec![address];
    }
    let mut addresses: Vec<SocketAddr> = (host, port).to_socket_addrs().map(|iter| iter.collect()).unwrap_or_default();
    addresses.sort_by_key(|address| address.is_ipv6());
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals() {
        assert_eq!(parse_literal("149.154.167.51", 443), Some("149.154.167.51:443".parse().unwrap()));
        assert_eq!(parse_literal("[2001:67c:4e8:f002::a]", 443), Some("[2001:67c:4e8:f002::a]:443".parse().unwrap()));
        assert_eq!(parse_literal("2001:67c:4e8:f002::a", 80), Some("[2001:67c:4e8:f002::a]:80".parse().unwrap()));
        assert_eq!(parse_literal("example.com", 443), None);
    }

    #[test]
    fn resolves_localhost() {
        assert!(!resolve_blocking("localhost", 80).is_empty());
    }
}
