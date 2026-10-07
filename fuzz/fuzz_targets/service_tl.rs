#![no_main]

use libfuzzer_sys::fuzz_target;
use mtproto_core::tl::mtproto::{
    BindAuthKeyInner, ClientDhInnerData, PqInnerData, ResPq, RpcResultBody, ServerDhInnerData, ServerDhParams,
    ServiceMessage, SetClientDhParamsAnswer, gunzip, gunzip_within, parse_rpc_result_limited,
};
use mtproto_core::tl::{TlRead, TlWrite};

const UNPACK_LIMIT: usize = 1 << 20;

fn walk(body: &[u8], depth: usize, budget: &mut usize) {
    if depth > 16 {
        return;
    }
    let Ok(message) = ServiceMessage::parse(body) else {
        return;
    };
    match message {
        ServiceMessage::Container(children) => {
            assert!(children.len() <= 1024);
            for child in children {
                assert!(child.body.len() % 4 == 0, "container child of {} bytes", child.body.len());
                walk(child.body, depth + 1, budget);
            }
        }
        ServiceMessage::MsgCopy(inner) => walk(inner.body, depth + 1, budget),
        ServiceMessage::GzipPacked(packed) => {
            let before = *budget;
            if let Ok(unpacked) = gunzip_within(packed, budget) {
                assert!(unpacked.len() <= before, "gunzip_within went over its budget");
                assert_eq!(*budget, before - unpacked.len());
                walk(&unpacked, depth + 1, budget);
            }
        }
        ServiceMessage::RpcResult { result, .. } => match parse_rpc_result_limited(result, UNPACK_LIMIT) {
            Ok(RpcResultBody::PackedValue(value)) => assert!(value.len() <= UNPACK_LIMIT),
            Ok(RpcResultBody::Error(error)) => {
                let normalized = error.normalized();
                assert!(normalized.code != 0 && normalized.code.abs() <= 9999);
            }
            _ => {}
        },
        ServiceMessage::FutureSalts { salts, .. } => assert!(salts.len() <= 1 << 16),
        ServiceMessage::MsgsAck(ids)
        | ServiceMessage::MsgResendReq(ids)
        | ServiceMessage::MsgResendAnsReq(ids)
        | ServiceMessage::MsgsStateReq(ids) => assert!(ids.len() <= 1 << 16),
        _ => {}
    }
}

/// What parses re-serializes to bytes that parse to the same value.
fn roundtrip<T>(data: &[u8])
where
    T: for<'a> TlRead<'a> + TlWrite + PartialEq + core::fmt::Debug,
{
    if let Ok(value) = T::from_bytes(data) {
        let bytes = value.to_bytes();
        assert!(bytes.len() <= data.len(), "canonical form is never longer");
        assert_eq!(T::from_bytes(&bytes).as_ref(), Ok(&value));
    }
}

fuzz_target!(|data: &[u8]| {
    let mut budget = 4 * UNPACK_LIMIT;
    walk(data, 0, &mut budget);
    if let Ok(unpacked) = gunzip(data, UNPACK_LIMIT) {
        assert!(unpacked.len() <= UNPACK_LIMIT);
    }
    let _ = parse_rpc_result_limited(data, UNPACK_LIMIT);
    roundtrip::<ResPq>(data);
    roundtrip::<PqInnerData>(data);
    roundtrip::<ServerDhParams>(data);
    roundtrip::<ServerDhInnerData>(data);
    roundtrip::<ClientDhInnerData>(data);
    roundtrip::<SetClientDhParamsAnswer>(data);
    roundtrip::<BindAuthKeyInner>(data);
});
