# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust library for parsing macOS Unified Log files (tracev3 format). Cross-platform — no Apple APIs used. Upstream: `mandiant/macos-UnifiedLogs`, fork: `shindan-io/macos-UnifiedLogs`.

## Build & Test Commands

```bash
# Build
cargo build --release

# Run default-feature tests (release mode recommended — debug is very slow)
cargo test --release

# Run a single test
cargo test --release test_name -- --nocapture

# Clippy (strict — several lints are deny-level)
cargo clippy

# Format
cargo fmt

# Benchmarks (requires test data)
cargo bench
```

### Feature-gated testing (justfile tasks)

```bash
just test_legacy           # cargo t --release --no-default-features
just test_rewrite          # cargo t --release --no-default-features --features rewrite --lib --bins --tests
just test_compat           # cargo t --release --no-default-features --features rewrite-compat
just test                  # runs all three modes above
```

### Test data setup

Test data is **not in git**. Download from GitHub releases before running tests or benchmarks:
```bash
cd tests
wget -O test_data.zip https://github.com/mandiant/macos-UnifiedLogs/releases/download/v1.0.0/test_data.zip
unzip test_data.zip
```

## Architecture

### Feature flags and module switching

The crate uses feature flags to switch between two implementations at compile time via `src/lib.rs`:

| Feature | Default | Effect |
|---------|---------|--------|
| (none) | **yes** | Compiles `legacy` module only (original implementation) |
| `rewrite` | no | Compiles `rewrite` module only (performance-optimized, zero-copy) |
| `rewrite-compat` | no | Implies `rewrite` + adds `compat` module for backward-compatible API |

The default build uses the legacy implementation because `Cargo.toml` sets `default = []`. Enable `rewrite` for the new zero-copy pipeline, or `rewrite-compat` for the rewrite pipeline plus the compatibility shim. Only one of `legacy` or `rewrite` is compiled — they are mutually exclusive via `cfg(not(feature = "rewrite"))` / `cfg(feature = "rewrite")`.

### Module layout

**`src/legacy/`** — Original implementation. Owned types (`String`, `Vec`), allocates heavily. Public API: `parser`, `unified_log`, `filesystem`, `iterator`, `traits`, `dsc`, `uuidtext`, `timesync`.

**`src/rewrite/`** — Performance rewrite. Zero-copy types (`LogEntry<'a, 'b>` borrowing from buffers), lazy message formatting. Key files:
- `log_entry.rs` — Core `LogEntry` type with borrowed lifetimes
- `format.rs` — Lazy printf-style message formatting pipeline
- `tracev3.rs` — tracev3 file parsing
- `resolve.rs` — Symbol resolution from UUID text / DSC caches
- `logarchive.rs` — Logarchive directory provider
- `chunks_reader.rs` — Streaming chunk reader

**`src/compat/`** — Thin compatibility layer exposing legacy-like API names over the rewrite implementation. Contains `parser.rs`, `traits.rs`, `unified_log.rs`, `filesystem.rs`.

### Parsing pipeline (both implementations)

1. **Timesync** — Parse timesync files to get timestamp boot/offset data
2. **TraceV3** — Parse tracev3 binary files into chunks (header, catalog, firehose entries, oversize strings, simpledumps, statedumps)
3. **Resolve** — Look up format strings from UUID text files and DSC (shared string cache)
4. **Format** — Apply printf-style formatting with decoded message items (custom object decoders for DNS, network, location, time, UUID, etc.)
5. **Build** — Assemble final log entries with resolved process/library names, timestamps, subsystem/category

### Binary parser

Uses `nom` 8 for all binary parsing. Parsers return `IResult` types throughout.

### Custom object decoders (`decoders/`)

Both modules have matching decoder implementations: DNS, network, OpenDirectory, location, time, UUID, Darwin, bool, config. These decode custom binary objects embedded in log message items.

### Firehose subsystem (`chunks/firehose/`)

The most complex part of the codebase. Firehose log entries come in types: activity, nonactivity, signpost, trace, loss — each with distinct binary layouts and flag-dependent parsing.

## Code Quality

- `#![forbid(unsafe_code)]` — no unsafe allowed
- Strict clippy configuration with several `deny`-level lints (cast_lossless, cast_possible_wrap, checked_conversions, etc.)
- Rust edition 2024

## Example binary

`examples/unifiedlog_iterator/` — Standalone binary that parses logarchives or live macOS systems, outputs JSON/CSV/JSONL. Built separately:
```bash
cd examples && cargo build --release
```
