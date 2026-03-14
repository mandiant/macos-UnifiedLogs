default:
    just --list

test_legacy:
    cargo t --release --no-default-features

test_rewrite:
    cargo t --release --no-default-features --features rewrite --lib --bins # --tests

test_compat:
    cargo t --release --no-default-features --features rewrite-compat