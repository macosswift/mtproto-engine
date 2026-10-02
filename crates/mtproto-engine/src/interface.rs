use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[allow(unsafe_code)]
pub fn interface_name_for(address: IpAddr) -> Option<String> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut cursor = list;
    while !cursor.is_null() {
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        let family = unsafe { (*entry.ifa_addr).sa_family } as i32;
        let candidate = match family {
            libc::AF_INET => {
                let socket = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(socket.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let socket = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in6) };
                IpAddr::V6(Ipv6Addr::from(socket.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        if candidate == address {
            found = Some(unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy().into_owned());
            break;
        }
    }
    unsafe { libc::freeifaddrs(list) };
    found
}

pub fn is_cellular_interface(name: &str) -> bool {
    name.starts_with("pdp_ip")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_resolves_to_lo0() {
        assert_eq!(interface_name_for(IpAddr::V4(Ipv4Addr::LOCALHOST)).as_deref(), Some("lo0"));
        assert!(!is_cellular_interface("lo0"));
        assert!(is_cellular_interface("pdp_ip0"));
    }
}
