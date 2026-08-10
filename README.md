# macos-unifiedlogs

A simple and high-performance Rust library that can help parse Apple's Unified Log files.

Unified Logs were introduced in macOS 10.12 (Sierra, 2016) as part of Apple's unified logging system across macOS, iOS, watchOS, and tvOS. This library can parse the binary tracev3 files and emit structured log entries.

Each entry exposes: the formatted message (plus raw message and raw log items), timestamp (Intel and ARM), event and log type, process and library paths with their UUIDs, subsystem, category, PID, thread ID, EUID, activity ID (and parent), boot UUID, and timezone.

## Running

Example binaries live in `examples/`:

- `unifiedlog_iterator` - Parses a logarchive (or the logs on a live macOS system)
  into a JSONL or CSV file, with bookmark/resume support. The output file will be
  quite large.
- `dump` - Minimal JSONL dump of a logarchive.
- `logrs` - JSONL output for a logarchive or live system, including a
  timesync-only mode.

```bash
cargo run --release --manifest-path examples/Cargo.toml -p unifiedlog_iterator -- --mode log-archive --input system_logs.logarchive
```

See `RUNNING.md` for more usage, how to create a logarchive, and expected warnings.

## Design

The core type is `LogEntry<'a, 'b>` — a zero-copy log entry that borrows directly
from the parsed file buffers. Messages are formatted lazily on demand via
`.message()`, avoiding heap allocation until explicitly needed. `UUIDText` and
shared-cache (DSC) string files are read lazily as log entries reference them,
keeping memory proportional to what the logs actually use; see `cache::StringStorage::preload`
for the eager mode. For long-running processes, `logarchive::VisitOptions::memory_budget`
caps loaded string data by reclaiming it between tracev3 files (off by default).
See `ARCHITECTURE.md` for the full pipeline.

## Usage

```toml
[dependencies]
macos-unifiedlogs = "0.8"
```

### Parsing a logarchive directory

```rust
use macos_unifiedlogs::logarchive::visit_logarchive;
use std::path::Path;

visit_logarchive(Path::new("system_logs.logarchive"), |entry| {
    let timestamp = entry.timestamp().to_rfc3339();
    let process = entry.process.unwrap_or("");
    let message = entry.message();

    println!("{timestamp} [{process}] {message}");
}).unwrap();
```

### Parsing a live macOS system

```rust
use macos_unifiedlogs::logarchive::visit_live_system;

visit_live_system(|entry| {
    let timestamp = entry.timestamp().to_rfc3339();
    let process = entry.process.unwrap_or("");
    let message = entry.message();

    println!("{timestamp} [{process}] {message}");
}).unwrap();
```

For mounted images or nonstandard roots, use `filesystem::LiveSystemProvider::with_roots`
with `logarchive::visit_provider`.

### Parsing a single tracev3 file

```rust
use macos_unifiedlogs::logarchive::visit_logarchive_tracev3_file;
use std::path::Path;

visit_logarchive_tracev3_file(
    Path::new("system_logs.logarchive"),
    "Persist/0000000000000004.tracev3",
    |entry| {
        let message = entry.message();
        println!("{:?} {:?} {message}", entry.event_type, entry.log_type);
    },
)
.unwrap();
```

### Parsing from a custom source (no filesystem required)

Implement `traits::FileProvider` to feed the parser from anywhere — a mounted
image, an evidence container, or plain memory. `filesystem::InMemoryProvider`
is a ready-made in-memory implementation:

```rust
use macos_unifiedlogs::filesystem::InMemoryProvider;
use macos_unifiedlogs::logarchive::visit_provider;

let mut provider = InMemoryProvider::default();
provider.tracev3.push(("mem://persist-1.tracev3".into(), tracev3_bytes));
provider.timesync.push(("mem://boot.timesync".into(), timesync_bytes));
provider.uuidtext.insert(some_uuid, uuidtext_bytes);
provider.dsc.insert(dsc_uuid, dsc_bytes);

visit_provider(&provider, |entry| {
    println!("{}", entry.message());
})
.unwrap();
```

`UUIDText`/DSC data is requested lazily by UUID as entries reference it. Use
`logarchive::visit_provider_preloaded` to load everything up front instead
(maximum throughput at maximum memory).


## Limitations

1. No printf-style error code lookup (`%m`). The library outputs the raw error number, not the human-readable string that the macOS `log` command provides.

2. Unsupported custom log objects are base64-encoded rather than decoded.

## References

- https://github.com/ydkhatri/UnifiedLogReader
- https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc
- https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how
- https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response
