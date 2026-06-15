# Repository Guidelines

## Project Structure & Module Organization

This is a Rust crate for parsing macOS Unified Logs without Apple APIs. Core library code lives in `src/`. The main module split is:

- `src/legacy/`: existing owned-data parser implementation.
- `src/rewrite/`: zero-copy rewrite parser gated by the `rewrite` feature.
- `src/compat/`: compatibility API enabled by `rewrite-compat`.
- `src/*/chunks/firehose/` and `src/*/decoders/`: firehose parsers and custom decoders.
- `tests/`: integration tests; external fixture data is required and is not stored in git.
- `benches/`: Criterion benchmarks for High Sierra, Big Sur, and Monterey data.
- `examples/unifiedlog_iterator/`: standalone parser example built from `examples/`.

Keep feature-specific changes inside the matching module unless shared public API changes require updates in `src/lib.rs`.

## Build, Test, and Development Commands

- `cargo build`: build the crate in debug mode.
- `cargo build --release`: build optimized artifacts for parser performance checks.
- `cargo fmt -- --check`: verify formatting used by CI.
- `cargo clippy`: run Rust lint checks used by CI.
- `just test` or `just t`: run all configured test modes.
- `just test_legacy`: test without default features.
- `just test_rewrite`: test with `--features rewrite`.
- `just test_compat`: test with `--features rewrite-compat`.
- `cd examples && cargo build --release`: build example binaries.
- `cargo bench`: run benchmarks after fixture data is installed.

Before full tests, download `test_data.zip` from GitHub releases, place it in `tests/`, and unzip it.

## Coding Style & Naming Conventions

Use Rust 2024 idioms and `rustfmt`. `rustfmt.toml` sets Unix newlines, 4-space indentation, and a 100-column width. `src/lib.rs` forbids unsafe code and enables strict clippy warnings/denies, so prefer checked conversions and explicit error handling. Binary parsers use `nom` 8 and should return `IResult` where appropriate. Keep modules snake_case, types PascalCase, and functions/tests snake_case.

## Testing Guidelines

Integration tests are grouped by macOS version and parser path, for example `tests/big_sur_tests.rs`, `tests/big_sur_rewrite_tests.rs`, and `tests/ordering_parity.rs`. Add focused regressions near the affected parser or parity area, especially for ordering, timestamp resolution, firehose entries, or decoders. Use release-mode tests:

```bash
just test
```

## Commit & Pull Request Guidelines

Recent commits use short summaries such as `Simpledump subsystem fix` and `order parity test`. Keep commits focused and mention the parser path or behavior changed. Pull requests should include the problem statement, test commands, linked issues when applicable, and fixture or feature-flag coverage. Add a `.changes/unreleased/` entry for public behavior changes.
