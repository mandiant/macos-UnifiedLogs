# macos-unifiedlogs

A high-performance Rust library for parsing macOS Unified Log files (tracev3 format). Cross-platform — no Apple APIs required.

Unified Logs were introduced in macOS 10.12 (Sierra, 2016) as part of Apple's unified logging system across macOS, iOS, watchOS, and tvOS. This library parses the binary tracev3 files and emits structured log entries.

## Rewrite Design

The rewrite parser is available with the `rewrite` feature. Its core type is
`LogEntry<'a, 'b>` — a zero-copy log entry that borrows directly from the parsed
file buffers. Messages are formatted lazily on demand via `.message()`, avoiding
heap allocation until explicitly needed.

Extracted fields:

- Process, Library, Subsystem, Category
- PID, Thread ID, Activity ID, Parent Activity ID, EUID
- Timestamp (Intel and ARM)
- Event Type, Log Type
- Format string and lazy-formatted message
- Library UUID, Process UUID, Boot UUID
- Timezone

## Usage

The default feature is still `legacy` so existing users can upgrade without API
breakage. New integrations should use the rewrite parser by disabling default
features and enabling `rewrite`:

```toml
[dependencies]
macos-unifiedlogs = { version = "0.6", default-features = false, features = ["rewrite"] }
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

## Parsing pipeline

1. **Timesync** — Parse timesync files for timestamp boot/offset data
2. **TraceV3** — Parse tracev3 binary files into chunks (header, catalog, firehose, oversize, simpledump, statedump)
3. **Resolve** — Look up format strings from UUIDText files and DSC (shared string cache)
4. **Format** — Apply printf-style formatting with decoded message items
5. **Emit** — Deliver `LogEntry` via callback with resolved process/library names, timestamps, subsystem/category

```
                        visit_logarchive(path, callback)
                                      │
          ┌───────────────────────────┼──────────────────────────┐
          │                           │                          │
    ┌─────┴──────┐  ┌────────────────┴────────────────┐  ┌─────┴──────────┐
    │ timesync/  │  │ Persist/ Special/ HighVolume/ … │  │ dsc/ UUIDText/ │
    └─────┬──────┘  │         .tracev3 files          │  └─────┬──────────┘
          │         └────────────────┬────────────────┘        │
          ▼                          │                          ▼
  TimestampResolver                  │              SharedCacheStrings (DSC)
                                     │              UUIDText files
                                     ▼
                       ┌──────────────────────────┐
                       │       ChunksReader       │  per .tracev3
                       └────────────┬─────────────┘
               ┌────────────────────┼────────────────────┐
               ▼                    ▼                    ▼
           Header              Catalog              Chunkset
                                                       │
                                                LZ4 decompress
                                                  (bv41/bv4-)
                                                       │
                                                       ▼
                                           ┌───────────────────┐
                                           │   ChunkSetReader  │
                                           └─────────┬─────────┘
                        ┌──────────┬─────────────────┼──────────┐
                        ▼          ▼                 ▼          ▼
                    Firehose    Oversize         Simpledump  Statedump
                        │     (→ cache)
                        ▼
                 entry iterator
          ┌─────┬──────┼──────┬──────┐
          ▼     ▼      ▼      ▼      ▼
      Activity Non-  Signpost Trace  Loss
             Activity
                        │
                        ▼
             resolve_strings() ◄── DSC + UUIDText + Oversize cache
                        │
                        ▼
              LogEntry<'a,'b>   zero-copy, borrows from buffers
                        │
                        │  .message()  lazy, allocated on demand
                        ▼
             format_message()   printf-style parser
                        │
                        │  %{annotation} specifiers → custom decoders
                        ▼
             ┌── decode_annotation() ──────────────────────────┐
             │ DNS · network · location · time · UUID           │
             │ OpenDirectory · Darwin · bool · config           │
             └──────────────────────────────────────────────────┘
```

## Format strings and message formatting

Log messages are assembled from two separate components stored in the tracev3 binary:

### Format strings (shared, dictionary-based)

Each firehose entry stores a **4-byte offset** (`format_string_location`) pointing into a shared string table — either a **DSC** (shared cache, for system libraries) or a **UUIDText** file (for individual executables). The format string itself (e.g. `"User %s with ID %d logged in"`) is never duplicated per entry; thousands of log lines from the same `os_log()` call site all reference the same offset.

### Items (unique per entry, inline binary)

Each entry carries its own packed `items_data` — a compact binary array of typed values (integers, strings, raw bytes). Items are consumed **positionally, left to right** by the format specifiers:

```
Format string:  "User %s with ID %d logged in"
                       ^^            ^^
                       │              └── items[1] = Int(42)
                       └───────────────── items[0] = String("alice")

→ "User alice with ID 42 logged in"
```

### Format specifier syntax

Apple extends standard printf with privacy annotations and custom type decoders:

```
%[flags][width][.precision][length]<conversion>      standard printf
%{annotation}[flags][width][.precision][length]<conversion>   Apple extension
```

**Privacy annotations** control redaction in logs:
- `%{public}s` — visible in collected logs
- `%{private}d` — always redacted as `<private>`
- `%s` — redacted by default in non-debug contexts

**Common conversions:**
- `%s` — C string, `%d`/`%u` — integers, `%f` — float, `%x` — hex
- `%@` — Objective-C object description (Apple-specific, calls `[object description]`)

**Custom type decoders** via annotations:
- `%{time_t}d` — Unix timestamp → human-readable date
- `%{uuid_t}.*P` — raw bytes → UUID string
- `%{network:in_addr}d` — integer → IPv4 address
- `%{darwin.errno}d` — errno → error name
- `%{bool}d` — 0/1 → `"true"`/`"false"`

**Dynamic width/precision** consume extra items: `%*d` uses one item for the width and the next for the value.

**Special case — dynamic strings:** When bit 31 of `format_string_location` is set (`0x80000000`), the format string becomes `"%s"` and the actual text is carried inline in the items.

## Building

```bash
cargo build --release
cargo build --release --no-default-features --features rewrite
cargo test --release        # release mode recommended — debug is very slow
cargo test --release --no-default-features --features rewrite --lib
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
| `legacy` | **yes** | Existing owned-data parser and public API (`LogData`, `parse_log`, `build_log`). Kept as the default to avoid breaking existing users. |
| `rewrite` | no | Recommended parser for new code. Provides the zero-copy rewrite API (`LogEntry<'a, 'b>`, lazy messages, `visit_logarchive`, `visit_tracev3`). Use with `--no-default-features`. |
| `rewrite-compat` | no | Rewrite parser behind the legacy-compatible API surface. Enables `rewrite` and exposes compatibility wrappers for callers that still need `LogData`-style output. |

Recommended commands:

```bash
# Current default legacy API
cargo test --release --no-default-features --features legacy

# Native rewrite API
cargo test --release --no-default-features --features rewrite --lib

# Rewrite engine through compatibility API
cargo test --release --no-default-features --features rewrite-compat
```

Do not enable `legacy` and `rewrite` together. Both parsers contain modules with
the same historical names, so the supported modes compile one API surface at a
time.

## Limitations

1. No printf-style error code lookup (`%m`). The library outputs the raw error number, not the human-readable string that the macOS `log` command provides.

2. Unsupported custom log objects are base64-encoded rather than decoded.

## References

- https://github.com/ydkhatri/UnifiedLogReader
- https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc
- https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how
- https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response
