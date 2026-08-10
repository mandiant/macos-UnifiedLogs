# Running the example binaries

Three example binaries live in the `examples/` workspace (see `BUILDING.md` to build them):

- `unifiedlog_iterator` — parses a logarchive or a live macOS system into JSONL or CSV, with bookmark/resume support
- `dump` — minimal JSONL dump of a logarchive
- `logrs` — JSONL output for a logarchive or live system, including a timesync-only mode

Run from the repository root (`--manifest-path` keeps relative input paths working):

```bash
# A logarchive, as JSONL on stdout
cargo run --release --manifest-path examples/Cargo.toml -p unifiedlog_iterator -- \
    --mode log-archive --input system_logs.logarchive

# The live system (macOS only), as CSV into a file
cargo run --release --manifest-path examples/Cargo.toml -p unifiedlog_iterator -- \
    --mode live --format csv --output logs.csv

# A single tracev3 file (no timesync/string context: timestamps and
# referenced format strings stay unresolved)
cargo run --release --manifest-path examples/Cargo.toml -p unifiedlog_iterator -- \
    --mode single-file --input Persist/0000000000000004.tracev3
```

`unifiedlog_iterator --help` lists all options. Full-archive output is large (millions of entries).

## Getting a logarchive

Run `sudo log collect` on the target system. If the `log` command is unavailable, build one manually:

1. Create a directory
2. Copy the contents of `/private/var/db/uuidtext` into it
3. Copy the contents of `/private/var/db/diagnostics` into it
4. Point `--input` at that directory

Logs typically retain about 30 days of information. Starting points for reviewing log data:
<https://github.com/jamf/jamfprotect/tree/main/unified_log_filters>

## Warnings you may see

Unified Logs are complex; some warnings are expected on real data. Errors or crashes should be reported.

- `Failed to read UUIDText <uuid>` / `Failed to parse DSC <uuid>` — a string file referenced
  by a log entry is missing or malformed. The macOS `log` command reports the same
  situation as `error: ~~> Invalid image <UUID>`.
- `Failed to get string: Utf8Error { .. }` — string metadata on an entry is not valid
  UTF-8 (common in `Special/` files).
- `<Missing message data>` in output — the entry references data (often an oversize
  payload) living in a tracev3 file that rolled or was deleted. The macOS `log`
  command reports this as `<decode: missing data>`.
