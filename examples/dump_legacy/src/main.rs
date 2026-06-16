#[path = "../../dump_common.rs"]
mod common;

use std::path::PathBuf;

use common::{parent_activity_id, write_entry, DumpEntry};
use macos_unifiedlogs::{
    filesystem::LogarchiveProvider,
    parser::{build_log, collect_timesync, parse_log},
    traits::FileProvider,
    unified_log::LogData,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = argument_path()?;
    let mut provider = LogarchiveProvider::new(&path);
    let timesync_data = collect_timesync(&provider)?;
    let mut index = 0;

    for mut source in provider.tracev3_files() {
        let evidence = source.source_path().to_string();
        let parsed = parse_log(source.reader(), &evidence)?;
        let (entries, _) = build_log(&parsed, &mut provider, &timesync_data, false);

        for entry in entries {
            write_entry(&dump_entry(index, entry))?;
            index += 1;
        }
    }

    Ok(())
}

fn argument_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| "usage: dump_legacy <sysdiagnose-logarchive-path>".into())
}

fn dump_entry(index: usize, entry: LogData) -> DumpEntry {
    DumpEntry {
        index,
        subsystem: entry.subsystem,
        category: entry.category,
        thread_id: entry.thread_id,
        pid: entry.pid,
        euid: entry.euid,
        library: entry.library,
        library_uuid: entry.library_uuid,
        activity_id: entry.activity_id,
        parent_activity_id: parent_activity_id(entry.parent_activity_id),
        timestamp: entry.timestamp,
        event_type: format!("{:?}", entry.event_type),
        log_type: format!("{:?}", entry.log_type),
        process: entry.process,
        process_uuid: entry.process_uuid,
        message: entry.message,
        raw_message: entry.raw_message,
        boot_uuid: entry.boot_uuid,
        timezone_name: entry.timezone_name,
        message_flags: entry
            .message_flags
            .into_iter()
            .map(|flag| format!("{flag:?}"))
            .collect(),
    }
}
