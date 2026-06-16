#[path = "../../dump_common/mod.rs"]
mod common;

use chrono::SecondsFormat;
use common::{DumpEntry, write_entry};
use macos_unifiedlogs::{
    log_entry::{EventType, LogEntry},
    logarchive::visit_logarchive,
};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = argument_path()?;
    let mut result: Result<(), Box<dyn std::error::Error>> = Ok(());
    let mut index = 0;

    visit_logarchive(&path, |entry| {
        if result.is_err() {
            return;
        }

        result = write_entry(&dump_entry(index, &entry));
        index += 1;
    })?;

    result
}

fn argument_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| "usage: dump_rewrite <sysdiagnose-logarchive-path>".into())
}

fn dump_entry(index: usize, entry: &LogEntry<'_, '_>) -> DumpEntry {
    DumpEntry {
        index,
        subsystem: entry.subsystem.unwrap_or("").to_string(),
        category: entry.category.unwrap_or("").to_string(),
        thread_id: entry.thread_id,
        pid: entry.pid,
        euid: entry.euid,
        library: dump_attribution_string(entry.event_type, entry.library),
        library_uuid: dump_uuid_string(
            entry.event_type,
            entry.library_uuid.is_nil(),
            format!("{:X}", entry.library_uuid.simple()),
        ),
        activity_id: entry.activity_id,
        parent_activity_id: entry.parent_activity_id,
        timestamp: entry
            .timestamp()
            .to_rfc3339_opts(SecondsFormat::Nanos, true),
        event_type: format!("{:?}", entry.event_type),
        log_type: format!("{:?}", entry.log_type),
        process: dump_attribution_string(entry.event_type, entry.process),
        process_uuid: dump_uuid_string(
            entry.event_type,
            entry.process_uuid.is_nil(),
            format!("{:X}", entry.process_uuid.simple()),
        ),
        message: entry.message().to_string(),
        raw_message: entry.raw_message().to_string(),
        boot_uuid: format!("{:X}", entry.boot_uuid.simple()),
        timezone_name: entry.timezone_name.to_string(),
        message_flags: entry
            .message_flags
            .iter()
            .map(|flag| format!("{flag:?}"))
            .collect(),
    }
}

fn dump_uuid_string(event_type: EventType, is_nil: bool, uuid: String) -> String {
    if (event_type == EventType::Statedump && is_nil) || event_type == EventType::Loss {
        String::new()
    } else {
        uuid
    }
}

fn dump_attribution_string(event_type: EventType, value: Option<&str>) -> String {
    if event_type == EventType::Loss {
        String::new()
    } else {
        value.unwrap_or("").to_string()
    }
}
