# macos-unifiedlogs

A simple and high-performance Rust library that can help parse Apple's Unified Log files.

Unified Logs were introduced in macOS 10.12 (Sierra, 2016) as part of Apple's unified logging system across macOS, iOS, watchOS, and tvOS. This library can parse the binary tracev3 files and emit structured log entries.

Data that is currently extracted includes:

- Process ID
- Thread ID
- Activity ID
- Parent Activity ID
- Log Message
- Timestamp (Intel and ARM supported)
- Effective User ID (EUID)
- Log Type
- Event Type
- Library
- Subsystem
- Category
- Process
- Raw message
- Raw log items
- Library UUID
- Process UUID
- Boot UUID
- Timezone

## Running

An example binary is available to download

- `unifiedlog_iterator` - Can parse a logarchive into a JSOL or CSV file. It can also parse the logs
  on a live system. The output file will be quite large


## Rewrite Design

Starting with version 0.7.0, the library received a large rewrite to speed up the parsing of Unified Log data.  
The rewrite parser is available with the `rewrite` feature. Its core type is
`LogEntry<'a, 'b>` — a zero-copy log entry that borrows directly from the parsed
file buffers. Messages are formatted lazily on demand via `.message()`, avoiding
heap allocation until explicitly needed.

## Usage

The default feature is still `legacy` so existing developers can upgrade without API
breakage. New integrations should use the rewrite parser by disabling default
features and enabling `rewrite`:

```toml
[dependencies]
macos-unifiedlogs = { version = "0.7", default-features = false, features = ["rewrite"] }
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
use macos_unifiedlogs::{
    dsc::RawSharedCacheStrings,
    logarchive::{load_timesync_data, load_file_buffers_by_uuid, load_uuidtext_buffers},
    timesync::TimestampResolver,
    tracev3::{visit_tracev3, OversizeCache},
    uuidtext::RawUUIDText,
};
use std::collections::HashMap;

// Load context from the logarchive directory
let base = std::path::Path::new("system_logs.logarchive");
let resolver = TimestampResolver::new(load_timesync_data(&base.join("timesync")).unwrap());

let dsc_buffers = load_file_buffers_by_uuid(&base.join("dsc"));
let dsc_files: HashMap<_, RawSharedCacheStrings<'_>> = dsc_buffers.iter()
    .filter_map(|(uuid, buf)| Some((*uuid, RawSharedCacheStrings::parse(buf).ok()?.1)))
    .collect();

let uuidtext_buffers = load_uuidtext_buffers(base);
let uuidtext_files: HashMap<_, RawUUIDText<'_>> = uuidtext_buffers.iter()
    .filter_map(|(uuid, buf)| Some((*uuid, RawUUIDText::parse(buf).ok()?.1)))
    .collect();

// Parse a single file
let data = std::fs::read(base.join("Persist/0000000000000004.tracev3")).unwrap();
let mut oversize_cache = OversizeCache::new();
visit_tracev3(&data, &resolver, &dsc_files, &uuidtext_files, &mut oversize_cache, |entry| {
    let message = entry.message();
    println!("{:?} {:?} {}", entry.event_type, entry.log_type, message);
}).unwrap();
```


## Limitations

1. No printf-style error code lookup (`%m`). The library outputs the raw error number, not the human-readable string that the macOS `log` command provides.

2. Unsupported custom log objects are base64-encoded rather than decoded.

## References

- https://github.com/ydkhatri/UnifiedLogReader
- https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc
- https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how
- https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response
