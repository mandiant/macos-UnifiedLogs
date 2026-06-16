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


dump_all_and_compare path="tests/test_data/system_logs_big_sur_private_enabled.logarchive":
    cargo run --release --manifest-path examples/dump_legacy/Cargo.toml -- "{{path}}" > dump_legacy.txt
    cargo run --release --manifest-path examples/dump_compat/Cargo.toml -- "{{path}}" > dump_compat.txt
    cargo run --release --manifest-path examples/dump_rewrite/Cargo.toml -- "{{path}}" > dump_rewrite.txt

    status=0; diff -u dump_legacy.txt dump_compat.txt || status=$?; diff -u dump_compat.txt dump_rewrite.txt || status=$?; exit $status
