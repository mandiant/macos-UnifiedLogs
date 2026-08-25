use chrono::SecondsFormat;
use dump_helpers::{DumpEntry, memory_budget, no_output_enabled, write_entry};
use macos_unifiedlogs::{
    filesystem::LogarchiveProvider,
    log_entry::{EventType, LogEntry},
    logarchive::{StringLoading, VisitOptions, visit_provider_with_options},
};
use std::ops::ControlFlow;
use std::path::PathBuf;

mod dump_helpers;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = argument_path()?;
    let no_output = no_output_enabled();
    let options = VisitOptions {
        string_loading: memory_budget().map_or(StringLoading::Lazy, StringLoading::Budgeted),
    };
    let mut result: Result<(), Box<dyn std::error::Error>> = Ok(());
    let mut index = 0;

    let provider = LogarchiveProvider::new(&path);
    visit_provider_with_options(&provider, options, |entry| {
        if !no_output && let Err(e) = write_entry(&dump_entry(index, &entry)) {
            result = Err(e);
            return ControlFlow::Break(());
        }
        index += 1;
        ControlFlow::Continue(())
    })?;

    match result {
        // The consumer stopped reading (e.g. `| head`): not an error.
        Err(e) if is_broken_pipe(e.as_ref()) => Ok(()),
        result => result,
    }
}

fn is_broken_pipe(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(err) = source {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return io_err.kind() == std::io::ErrorKind::BrokenPipe;
        }
        source = err.source();
    }
    false
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
    if (event_type == EventType::Statedump && is_nil)
        || event_type == EventType::Loss
        || event_type == EventType::Unknown
    {
        String::new()
    } else {
        uuid
    }
}

fn dump_attribution_string(event_type: EventType, value: Option<&str>) -> String {
    if event_type == EventType::Loss || event_type == EventType::Unknown {
        String::new()
    } else {
        value.unwrap_or("").to_string()
    }
}
