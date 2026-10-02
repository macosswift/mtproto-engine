# Security bench

`requirements.tsv` lists every security requirement the engine is held to: one row per check from the
official MTProto documentation (core.telegram.org, layer 225) and from tdlib (commit `e894536b2f`). It
also has rows for checks the engine adds on top of both. Each row names the tests that pin it.

Columns:

- **id**: `K` handshake, `C` crypto, `M` messages, `T` transport, `L` TL, `B` service messages,
  PFS, CDN and other, `H` hardening beyond both references.
- **sources**: `DOC-<AREA>-N` is a requirement taken from the official documentation, `TD-<AREA>-N` a check
  read in tdlib's source (`td/mtproto`, `td/telegram/net`, `td/telegram/files`). They are the identifiers of
  the catalogue the table was built from; each row's requirement text stands on its own.
- **status**:
  - `OK`: the engine meets the requirement.
  - `BETTER`: the engine is stricter than tdlib.
  - `FIXED`: the engine was changed to meet it.
  - `PARTIAL`, `MISSING`: known gaps.
  - `DEVIATION`: a deliberate difference, explained in `note`.
  - `REVIEW`: not applicable to this transport, or needs a host-level review.
- **owner**: `engine`, or `host` when the check belongs to the application around the engine
  (key lifetime, CDN file verification, logout).

Run:

```sh
./scripts/security-bench.py              # cargo test --workspace --release, then the per-requirement table
./scripts/security-bench.py --quiet      # only failing rows and the summary
./scripts/security-bench.py --area handshake --markdown
./scripts/security-bench.py --log target/security-bench.log   # re-read the last run
```

A row passes when every named test ran and passed. The script exits non-zero when a named test fails
or no longer exists, and also when any other test, doctest or build in the workspace fails. Rows without tests are reported as `untested`; most are host-owned, not
applicable, or covered only by the fuzzer and the hostile test-server faults.
