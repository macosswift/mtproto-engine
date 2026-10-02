#![forbid(unsafe_code)]

pub mod auth_key;
pub mod crypto;
pub mod handshake;
pub mod message;
pub mod msg_id;
pub mod rpc;
pub mod session;
pub mod tl;
pub mod transport;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
