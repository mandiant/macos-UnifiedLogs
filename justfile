default:
    just --list

test_legacy:
    cargo t --release

test_rewrite:
    cargo t --release --features rewrite --lib --bins # --tests
