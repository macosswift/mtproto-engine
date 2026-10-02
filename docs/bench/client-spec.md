# Benchmark client contract

Every engine under test ships a command-line client that the orchestrator (`mtproto-bench run`)
spawns as a separate process, so CPU time and peak memory are measured the same way (`wait4`)
for every engine. The Rust client is `mtproto-bench client`; the MtProtoKit client is a Swift
command-line tool that implements exactly the same contract.

## Arguments

| Flag | Meaning |
|---|---|
| `--engine-label NAME` | echoed in the output |
| `--mode fake\|real` | `fake`: preloaded auth key against the fake server; `real`: real Telegram DC, the client runs the DH handshake with the production RSA key |
| `--address HOST:PORT` | where to connect (the impairment proxy in front of the server) |
| `--dc N` | datacenter id (2) |
| `--key-hex HEX` | fake mode: 256-byte auth key, hex |
| `--salt N` | fake mode: server salt (decimal i64), valid for the whole run |
| `--secret HEX` | optional MTProxy secret (simple, `dd…` padded or `ee…` fake-TLS); the address is then the proxy |
| `--workload NAME` | see below |
| `--requests N` | request count for `latency`, `small`, `real-config` |
| `--concurrency N` | max outstanding requests for `small` and `real-config` |
| `--part-size BYTES` | `media`/`mixed`: response size per request |
| `--total-bytes N` | `media`/`mixed`: bytes to download in total |
| `--sessions N` | `media`/`mixed`: worker sessions (separate MTProto sessions, separate TCP connections), default 4 |
| `--session-concurrency N` | `media`/`mixed`: outstanding requests per worker session, default 3 |
| `--rate N` | `steady`/`mixed`: requests per second on the main session |
| `--duration SECONDS` | `steady`: how long to issue requests |
| `--deadline SECONDS` | hard stop; requests still pending at the deadline count as failed |

## Fake-server calls

Every call is a raw TL body sent as the request payload (no API schema needed):

- small call: `CALL#7e570001 tag:int payload:bytes` with `tag` in 1..999, payload = 8-byte LE request index.
- sized call (media part): `CALL#7e570001 tag:int=1012 payload:bytes` where payload = 4-byte LE response size.
- response: `CALL_RESULT#7e570002 tag:int payload:bytes`; a client must verify the tag (and for
  sized calls the payload length) and count a mismatch as a failure.

The fake server unwraps `invokeAfterMsg`, `invokeWithoutUpdates`, `invokeWithLayer(initConnection(...))`
and verification wrappers, answers `ping`/`ping_delay_disconnect`, `get_future_salts`, `msgs_state_req`,
`msg_resend_req`, `msgs_ack`, re-sends unacknowledged answers when a session reconnects, and sends
`bad_server_salt` when the salt is wrong. It does not answer any real API method.

## Real-server calls (`--mode real`)

`help.getConfig#c4f9186b` (alternating with `help.getNearestDc#1fb33026`), wrapped in
`invokeWithLayer(230, initConnection(api_id 9, …))`. A completed request is any non-error result.

## Workloads

| Name | Definition |
|---|---|
| `latency` | `--requests` small calls strictly one after another on the main session |
| `small` | `--requests` small calls on the main session with at most `--concurrency` outstanding |
| `media` | `--total-bytes` downloaded as sized calls of `--part-size` over `--sessions` worker sessions with `--session-concurrency` outstanding each |
| `mixed` | `media` plus small calls on the main session at `--rate`/s for the whole media run; latency is reported for the small calls only |
| `steady` | one small call every `1/--rate` s for `--duration` s on the main session; every request is kept until it completes or the deadline |
| `real-config` | `--requests` real-server calls with at most `--concurrency` outstanding |

## Output

Exactly one JSON object on stdout, last line:

```json
{"engine":"rust","workload":"small","completed":2000,"failed":0,"elapsed":1.234,
 "latency_ms":{"p50":0.8,"p95":1.9,"p99":3.1,"max":12.0},
 "bytes":0,"throughput_mbps":0.0,
 "requests":[[0.000,0.0012],[0.001,0.0021]]}
```

`bytes` is the total response payload bytes of completed sized calls; `throughput_mbps` is
megabytes (10^6 bytes) of that payload per second of `elapsed`. `latency_ms` covers completed
requests (for `mixed`: only the small calls on the main session).

`requests` lists, per request in issue order, `[sent_at, completed_at]` in seconds since the
workload started (`completed_at` is `null` for failed requests). The orchestrator derives recovery
metrics (time to first answer after an outage ends, longest stall) from it. Anything else the
client prints must go to stderr.
