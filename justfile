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
    