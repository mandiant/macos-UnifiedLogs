default:
    just --list

alias c:= check
check:
    cargo c --lib --bins --tests --examples 
    cargo c --manifest-path examples/Cargo.toml --workspace

alias t:= test
test: 
    cargo t --release --lib --bins --tests --examples 

dump path="tests/test_data/system_logs_big_sur_private_enabled.logarchive" dump_file="dump.txt":
    time cargo run --release --manifest-path examples/Cargo.toml -p dump -- "{{path}}" > "{{dump_file}}"

dump_roundhouse:
    just dump "tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive" "dump_1.txt"
    just dump "tests/test_data/system_logs_big_sur.logarchive" "dump_2.txt"
    just dump "tests/test_data/system_logs_high_sierra.logarchive" "dump_3.txt"
    just dump "tests/test_data/system_logs_monterey.logarchive" "dump_4.txt"
    just dump "tests/test_data/system_logs_tahoe.logarchive" "dump_5.txt"
    just dump "tests/test_data/system_logs_big_sur_private_enabled.logarchive" "dump_6.txt"

[macos]
unifiedlog_iterator_live:
    cd examples && cargo run --release -p unifiedlog_iterator -- --mode live

unifiedlog_iterator_logarchive path:
    cd examples && cargo run --release -p unifiedlog_iterator -- --mode log-archive --input "{{path}}"
