# macos-unifiedlogs

A high-performance Rust library for parsing macOS Unified Log files (tracev3 format). Cross-platform — no Apple APIs required.

Unified Logs were introduced in macOS 10.12 (Sierra, 2016) as part of Apple's unified logging system across macOS, iOS, watchOS, and tvOS. This library parses the binary tracev3 files and emits structured log entries.

## Design

The core type is `LogEntry<'a, 'b>` — a zero-copy log entry that borrows directly from the parsed file buffers. Messages are formatted lazily on demand via `.message()`, avoiding heap allocation until explicitly needed.

Extracted fields:

- Process, Library, Subsystem, Category
- PID, Thread ID, Activity ID, EUID
- Timestamp (Intel and ARM)
- Event Type, Log Type
- Format string and lazy-formatted message
- Library UUID, Process UUID, Boot UUID
- Timezone

## Usage

### Parsing a logarchive directory

```rust
use macos_unifiedlogs::logarchive::visit_logarchive;
use std::path::Path;

visit_logarchive(Path::new("system_logs.logarchive"), |entry| {
    println!("{} [{}] {}", entry.timestamp(), entry.process.unwrap_or("?"), entry.message());
}).unwrap();
```

### Parsing a single tracev3 file

```rust
use macos_unifiedlogs::{
    logarchive::{load_timesync_data, load_file_buffers_by_uuid, load_uuidtext_buffers},
    timesync::TimestampResolver,
    tracev3::{visit_tracev3, OversizeCache},
    dsc::RawSharedCacheStrings,
    uuidtext::RawUUIDText,
};

// Load context from the logarchive directory
let base = std::path::Path::new("system_logs.logarchive");
let resolver = TimestampResolver::new(load_timesync_data(&base.join("timesync")).unwrap());

let dsc_buffers = load_file_buffers_by_uuid(&base.join("dsc"));
let dsc_files = dsc_buffers.iter()
    .filter_map(|(uuid, buf)| Some((*uuid, RawSharedCacheStrings::parse(buf).ok()?.1)))
    .collect();

let uuidtext_buffers = load_uuidtext_buffers(base);
let uuidtext_files = uuidtext_buffers.iter()
    .filter_map(|(uuid, buf)| Some((*uuid, RawUUIDText::parse(buf).ok()?.1)))
    .collect();

// Parse a single file
let data = std::fs::read(base.join("Persist/0000000000000004.tracev3")).unwrap();
let mut oversize_cache = OversizeCache::new();
visit_tracev3(&data, &resolver, &dsc_files, &uuidtext_files, &mut oversize_cache, |entry| {
    println!("{:?} {:?} {}", entry.event_type, entry.log_type, entry.message());
}).unwrap();
```

## Parsing pipeline

1. **Timesync** — Parse timesync files for timestamp boot/offset data
2. **TraceV3** — Parse tracev3 binary files into chunks (header, catalog, firehose, oversize, simpledump, statedump)
3. **Resolve** — Look up format strings from UUIDText files and DSC (shared string cache)
4. **Format** — Apply printf-style formatting with decoded message items
5. **Emit** — Deliver `LogEntry` via callback with resolved process/library names, timestamps, subsystem/category

## Building

```bash
cargo build --release
cargo test --release        # release mode recommended — debug is very slow
cargo clippy
```

### Test data

Test data is not in git. Download from GitHub releases:
```bash
cd tests
wget -O test_data.zip https://github.com/mandiant/macos-UnifiedLogs/releases/download/v1.0.0/test_data.zip
unzip test_data.zip
```

## Feature flags

| Feature | Default | Effect |
|---------|---------|--------|
| `rewrite` | **yes** | Zero-copy parsing pipeline (`LogEntry<'a,'b>`, lazy messages) |
| `rewrite-compat` | no | Adds backward-compatible API shim (`LogData`, `parse_log`, `build_log`) |
| (none) | — | Legacy implementation (owned types, eager allocation) |

Only one of `legacy` or `rewrite` is compiled — they are mutually exclusive.

## Limitations

1. No printf-style error code lookup (`%m`). The library outputs the raw error number, not the human-readable string that the macOS `log` command provides.

2. Unsupported custom log objects are base64-encoded rather than decoded.

## References

- https://github.com/ydkhatri/UnifiedLogReader
- https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc
- https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how
- https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response
