use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
pub(crate) struct DumpEntry {
    pub(crate) index: usize,
    pub(crate) subsystem: String,
    pub(crate) category: String,
    pub(crate) thread_id: u64,
    pub(crate) pid: u64,
    pub(crate) euid: u32,
    pub(crate) library: String,
    pub(crate) library_uuid: String,
    pub(crate) activity_id: u64,
    pub(crate) parent_activity_id: Option<u64>,
    pub(crate) timestamp: String,
    pub(crate) event_type: String,
    pub(crate) log_type: String,
    pub(crate) process: String,
    pub(crate) process_uuid: String,
    pub(crate) message: String,
    pub(crate) raw_message: String,
    pub(crate) boot_uuid: String,
    pub(crate) timezone_name: String,
    pub(crate) message_flags: Vec<String>,
}

#[allow(dead_code)]
pub(crate) fn parent_activity_id(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

pub(crate) fn no_output_enabled() -> bool {
    std::env::var("NO_OUTPUT")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub(crate) fn write_entry(entry: &DumpEntry) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, entry)?;
    stdout.write_all(b"\n")?;
    Ok(())
}
