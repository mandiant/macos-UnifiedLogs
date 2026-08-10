
## Building

You will need to install [Rust](https://www.rust-lang.org). Once installed the library can be built with cargo

```bash
cargo build --release
cargo test --release        # release mode recommended — debug is very slow
cargo clippy
cargo fmt --check
```

The `examples/` directory is a separate cargo workspace:

```bash
cargo build --release --manifest-path examples/Cargo.toml --workspace
```

A [just](https://github.com/casey/just) file wraps the common flows:

```bash
just check        # cargo check for lib, tests, benches and both workspaces
just test         # release-mode test run
just dump         # dump a test logarchive with the dump example
```

### Test data

Test data is not in git. Download from GitHub releases:
```bash
cd tests
wget -O test_data.zip https://github.com/mandiant/macos-UnifiedLogs/releases/download/v1.0.0/test_data.zip
unzip test_data.zip
```
