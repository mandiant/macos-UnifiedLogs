default:
    just --list

alias t:= test
test: test_legacy test_rewrite test_compat

test_legacy:
    cargo t --release --no-default-features

test_rewrite:
    cargo t --release --no-default-features --features rewrite --lib --bins --tests

test_compat:
    cargo t --release --no-default-features --features rewrite-compat


compare_big_sur:
    cargo test --release --no-default-features                    --test big_sur_tests         -- test_parse_all_logs_big_sur
    cargo test --release --no-default-features --features rewrite --test big_sur_rewrite_tests -- test_parse_all_logs_big_sur


dump_all_and_compare:
    cargo run --release --example dump_legacy       -- tests/test_data/system_logs_big_sur_private_enabled.logarchive/system_logs_big_sur_private_enabled.logarchive > dump_legacy.txt
    cargo run --release --example dump_compat       -- tests/test_data/system_logs_big_sur_private_enabled.logarchive/system_logs_big_sur_private_enabled.logarchive > dump_compat.txt
    cargo run --release --example dump_rewrite      -- tests/test_data/system_logs_big_sur_private_enabled.logarchive/system_logs_big_sur_private_enabled.logarchive > dump_rewrite.txt

    diff -u dump_legacy.txt dump_compat.txt
    diff -u dump_compat.txt dump_rewrite.txt