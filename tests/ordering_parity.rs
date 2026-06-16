use std::path::PathBuf;

fn log_archive_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_data/system_logs_big_sur.logarchive")
}

#[cfg(not(feature = "rewrite"))]
fn run_dump(base: &std::path::Path) {
    use macos_unifiedlogs::filesystem::LogarchiveProvider;
    use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
    use macos_unifiedlogs::traits::FileProvider;
    use std::io::Read;

    let mut provider = LogarchiveProvider::new(base);
    let timesync = collect_timesync(&provider).unwrap();

    let mut global_index = 0_usize;
    for mut source in provider.tracev3_files() {
        let evidence = source.source_path().to_string();
        let mut buf = Vec::new();
        source.reader().read_to_end(&mut buf).unwrap();

        let log_data = parse_log(std::io::Cursor::new(buf), &evidence).unwrap();
        let (entries, _) = build_log(&log_data, &mut provider, &timesync, false);

        for entry in &entries {
            eprintln!(
                "{global_index}|{pid}|{event_type:?}|{log_type:?}|{time}|{tid}|{subsystem}",
                pid = entry.pid,
                event_type = entry.event_type,
                log_type = entry.log_type,
                time = entry.time,
                tid = entry.thread_id,
                subsystem = entry.subsystem,
            );
            global_index += 1;
        }
    }
    eprintln!("TOTAL: {global_index}");
}

#[cfg(feature = "rewrite")]
fn run_dump(base: &std::path::Path) {
    use macos_unifiedlogs::logarchive::visit_logarchive;

    let mut global_index = 0_usize;
    visit_logarchive(base, |entry| {
        eprintln!(
            "{global_index}|{pid}|{event_type:?}|{log_type:?}|{time}|{tid}|{subsystem}",
            pid = entry.pid,
            event_type = entry.event_type,
            log_type = entry.log_type,
            time = entry.time,
            tid = entry.thread_id,
            subsystem = entry.subsystem.unwrap_or(""),
        );
        global_index += 1;
    })
    .unwrap();
    eprintln!("TOTAL: {global_index}");
}

#[test]
fn dump_entry_order() {
    let base = log_archive_path();
    run_dump(base.as_path());
}
