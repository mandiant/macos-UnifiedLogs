
## Building

You will need to install [Rust](https://www.rust-lang.org). Once instal the library can be built with cargo


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
