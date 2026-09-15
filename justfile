default:
    just --list

alias c:= check
check:
    cargo c --lib --bins --tests --examples --benches
    cargo c --manifest-path examples/Cargo.toml --workspace

alias t:= test
test: 
    cargo t --release --lib --bins --tests --examples

alias b:= bench
bench:
    cargo bench

[macos]
unifiedlog_iterator_live:
    cd examples && cargo run --release -p unifiedlog_iterator -- --mode live

unifiedlog_iterator_logarchive path="../tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive":
    cd examples && cargo run --release -p unifiedlog_iterator -- --mode log-archive --input "{{path}}"

