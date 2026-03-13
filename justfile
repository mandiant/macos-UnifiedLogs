default:
    just --list

test_legacy:
    cargo t --release

test_rewrite:
    cargo t --release --features rewrite --lib --bins # --tests

test_rewrite_compat:
    cargo t --release --features rewrite-compat --lib --bins --tests
