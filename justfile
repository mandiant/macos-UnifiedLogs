default:
    just --list

alias c:= check
check:
    cargo c --no-default-features --lib --bins --tests --examples --features rewrite
    cargo c --no-default-features --lib --bins --tests --examples --features rewrite-compat
    cargo c --no-default-features --lib --bins --tests --examples --features legacy
    cargo c --manifest-path examples/unifiedlog_iterator/Cargo.toml
    cargo c --manifest-path examples/unifiedlog_iterator/Cargo.toml --no-default-features --features rewrite-compat
    cargo c --manifest-path examples/dump_legacy/Cargo.toml
    cargo c --manifest-path examples/dump_compat/Cargo.toml
    cargo c --manifest-path examples/dump_rewrite/Cargo.toml

alias t:= test
test: test_rewrite test_compat test_legacy

test_rewrite:
    cargo t --release --no-default-features --lib --bins --tests --features rewrite
test_legacy:
    cargo t --release --no-default-features --lib --bins --tests --features legacy
test_compat:
    cargo t --release --no-default-features --lib --bins --tests --features rewrite-compat


dump_all_and_compare path="tests/test_data/system_logs_big_sur_private_enabled.logarchive":
    cargo run --release --manifest-path examples/dump_legacy/Cargo.toml -- "{{path}}" > dump_legacy.txt
    cargo run --release --manifest-path examples/dump_compat/Cargo.toml -- "{{path}}" > dump_compat.txt
    cargo run --release --manifest-path examples/dump_rewrite/Cargo.toml -- "{{path}}" > dump_rewrite.txt

    status=0; diff -u dump_legacy.txt dump_compat.txt || status=$?; diff -u dump_compat.txt dump_rewrite.txt || status=$?; exit $status

dump_all_and_compare_roundhouse:
    just dump_all_and_compare "tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive"
    just dump_all_and_compare "tests/test_data/system_logs_big_sur.logarchive"
    just dump_all_and_compare "tests/test_data/system_logs_high_sierra.logarchive"
    just dump_all_and_compare "tests/test_data/system_logs_monterey.logarchive"
    just dump_all_and_compare "tests/test_data/system_logs_tahoe.logarchive"
    just dump_all_and_compare "tests/test_data/system_logs_big_sur_private_enabled.logarchive"

perfs_compare path="tests/test_data/system_logs_big_sur_private_enabled.logarchive" $NO_OUTPUT="1":
    #!/bin/bash
    set -euo pipefail
    # build first
    cargo build --release --manifest-path examples/dump_legacy/Cargo.toml
    cargo build --release --manifest-path examples/dump_compat/Cargo.toml
    cargo build --release --manifest-path examples/dump_rewrite/Cargo.toml
    echo "=== Legacy ==="
    time cargo run --release --manifest-path examples/dump_legacy/Cargo.toml -- "{{path}}" 2>/dev/null
    echo "=== Compat ==="
    time cargo run --release --manifest-path examples/dump_compat/Cargo.toml -- "{{path}}" 2>/dev/null
    echo "=== Rewrite ==="
    time cargo run --release --manifest-path examples/dump_rewrite/Cargo.toml -- "{{path}}" 2>/dev/null

perfs_compare_roundhouse:
    just perfs_compare "tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive"
    just perfs_compare "tests/test_data/system_logs_big_sur.logarchive"
    just perfs_compare "tests/test_data/system_logs_high_sierra.logarchive"
    just perfs_compare "tests/test_data/system_logs_monterey.logarchive"
    just perfs_compare "tests/test_data/system_logs_tahoe.logarchive"
    just perfs_compare "tests/test_data/system_logs_big_sur_private_enabled.logarchive"

[macos]
unifiedlog_iterator_legacy_live:
    cd examples && cargo run --release -p unifiedlog_iterator -- --mode live

unifiedlog_iterator_legacy_logarchive path:
    cd examples && cargo run --release -p unifiedlog_iterator -- --mode log-archive --input "{{path}}"

[macos]
unifiedlog_iterator_rewrite_compat_live:
    cd examples && cargo run --release -p unifiedlog_iterator --no-default-features --features rewrite-compat -- --mode live

unifiedlog_iterator_rewrite_compat_logarchive path:
    cd examples && cargo run --release -p unifiedlog_iterator --no-default-features --features rewrite-compat -- --mode log-archive --input "{{path}}"
