# CLAUDE.md — macos-UnifiedLogs

## Project Overview

Rust library for parsing macOS Unified Logs (Apple's logging format since macOS 10.12).
Fork of `mandiant/macos-UnifiedLogs` maintained by `shindan-io`, focused on performance optimization.

- **Crate name:** `macos-unifiedlogs`
- **Edition:** 2024
- **License:** Apache-2.0
- **`#![forbid(unsafe_code)]`** — no unsafe allowed

## Build & Test Commands

```bash
# Build
cargo build --release

# Run all tests (requires test data — see below)
cargo test --release

# Clippy (strict — must pass clean)
cargo clippy

# Format check
cargo fmt -- --check

# Benchmarks (Criterion)
cargo bench

# Dependency audit
cargo deny check
cargo audit
```

### Test Data Setup

Tests require logarchive fixtures not stored in git:
```bash
cd tests && wget -O ./test_data.zip https://github.com/mandiant/macos-UnifiedLogs/releases/download/v1.0.0/test_data.zip && unzip test_data.zip
```

This creates `tests/test_data/` with logarchive directories for High Sierra, Big Sur, and Monterey.

## Architecture

```
src/
├── lib.rs              # Crate root, RcString type, lint config
├── parser.rs           # Main API: parse_log(), build_log(), collect_timesync()
├── iterator.rs         # UnifiedLogIterator (streaming tracev3 parsing)
├── unified_log.rs      # Core types: LogType, EventType, UnifiedLogData, LogData
├── traits.rs           # FileProvider & SourceFile traits
├── filesystem.rs       # LiveSystemProvider & LogarchiveProvider
├── catalog.rs          # Catalog chunk parsing
├── chunkset.rs         # Chunk set management
├── chunks/             # Chunk types (firehose/, oversize, simpledump, statedump)
│   └── firehose/       # Main log entries (activity, nonactivity, signpost, trace)
├── decoders/           # Custom log object decoders (~6400 LOC)
│   ├── decoder.rs      # Base decoder logic
│   ├── config.rs       # Configuration objects (~1000 LOC)
│   ├── dns.rs          # DNS objects (~1000 LOC)
│   ├── location.rs     # Geolocation objects (~900 LOC)
│   ├── darwin.rs       # Darwin/macOS objects
│   ├── opendirectory.rs # OpenDirectory/LDAP objects
│   ├── network.rs      # Network objects
│   ├── time.rs, uuid.rs, bool.rs  # Simple type decoders
│   └── mod.rs
├── dsc.rs              # Shared string cache (v1: ≤Big Sur, v2: Monterey+)
├── uuidtext.rs         # UUID text string files
├── timesync.rs         # Time synchronization data
├── header.rs           # Header chunk parsing
├── preamble.rs         # Chunk preamble detection
├── message.rs          # Printf-style format string expansion
├── error.rs            # ParserError enum
└── util.rs             # UUID formatting, encoding, timestamps

examples/
└── unifiedlog_iterator/ # CLI tool (logarchive → JSON/CSV)

benches/                 # Criterion benchmarks per macOS version
tests/                   # Integration tests with real logarchive data
```

### Key Design Patterns

- **Parser combinator:** uses `nom` 8 throughout for binary parsing
- **Trait abstraction:** `FileProvider` + `SourceFile` traits decouple I/O from parsing
- **RcString:** `Rc<String>` wrapper for shared string references (defined in `lib.rs`)
- **Iterator pattern:** `UnifiedLogIterator` for streaming chunk-by-chunk processing
- **Oversize persistence:** oversize log entries must be carried across tracev3 files

### Public API Entry Points

```rust
// Parse a tracev3 file
parser::parse_log(reader: impl Read) -> Result<UnifiedLogData, ParserError>

// Build human-readable log entries
parser::build_log(&UnifiedLogData, &mut dyn FileProvider, &timesync, exclude_missing) -> (Vec<LogData>, UnifiedLogData)

// Collect time sync data
parser::collect_timesync(&dyn FileProvider) -> Result<HashMap<Uuid, TimesyncBoot>>

// Streaming iterator
iterator::UnifiedLogIterator { data: Vec<u8>, header: Vec<HeaderChunkOwned> }
```

## Code Quality Standards

### Lint Configuration (lib.rs)
- `#![forbid(unsafe_code)]`
- `#![warn(clippy::all, ...)]` — extensive clippy warnings enabled
- `#![deny(clippy::cast_lossless, clippy::cast_possible_wrap, ...)]` — strict cast checks
- All `rust_2018_idioms` and `future_incompatible` warnings enabled

### Formatting (rustfmt.toml)
- Unix newlines, 4-space tabs, 100 char max width, 60 char chain width

### CI Pipeline (GitHub Actions)
- `cargo fmt -- --check`
- `cargo clippy`
- `cargo test --release` (on macOS x86_64 + aarch64)
- `cargo deny check` and `cargo audit`

## Current Work Context

### Active Refactoring (branch: `this_changes_nothing`)

Performance optimization effort — 42 files changed, +4143/-2378 lines, 31 commits ahead of `main`.

**Goals:**
1. Replace `String` with `Uuid` type for identifiers (stack-allocated 128-bit vs heap-allocated)
2. Delay/lazy formatting of log messages to avoid unnecessary allocations
3. Propagate optimized types through decoders, chunks, and catalog modules

**Key challenges encountered:**
- Rust lifetime complexity when replacing owned types with references (`lifetime_nightmare` branch)
- Multiple iterations on chunks and decoders modules

### Upstream Sync

The upstream `mandiant/macos-UnifiedLogs` remains active. Recent upstream additions:
- Stateful log parsing (feature flag)
- Evidence field
- CLI filtering and perf optimizations

Periodic rebase/sync from upstream will be needed.

## Dependencies (notable)

| Crate | Purpose |
|-------|---------|
| `nom` 8 | Parser combinators for binary data |
| `serde` / `serde_json` | Serialization |
| `lz4_flex` | LZ4 decompression |
| `uuid` | UUID type (v4, serde) |
| `chrono` | Timestamp handling |
| `plist` | Apple plist parsing |
| `strum` | Enum derive macros |
| `sunlight` | Protobuf parsing |
| `walkdir` | Directory traversal |

## Useful References

- [Apple Unified Logging docs](https://developer.apple.com/documentation/os/logging)
- [Mandiant blog on Unified Logs](https://www.mandiant.com/resources/blog/reviewing-macos-unified-logs)
- Upstream repo: https://github.com/mandiant/macos-UnifiedLogs
