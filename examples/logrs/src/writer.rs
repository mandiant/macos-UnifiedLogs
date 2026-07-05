use chrono::SecondsFormat;
use macos_unifiedlogs::log_entry::LogEntry;
use macos_unifiedlogs::timesync::RawTimesyncBoot;
use serde::Serialize;
use std::{collections::HashMap, error::Error, io::Write};
use uuid::Uuid;

use crate::Format;

pub struct OutputWriter {
    writer: OutputWriterEnum,
}

enum OutputWriterEnum {
    //Csv(Box<Writer<Box<dyn Write>>>),
    Json(Box<dyn Write>),
}

#[derive(Serialize)]
pub(crate) struct LogValue {
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
    pub(crate) time: f64,
    pub(crate) event_type: String,
    pub(crate) log_type: String,
    pub(crate) process: String,
    pub(crate) process_uuid: String,
    pub(crate) message: String,
    pub(crate) raw_message: String,
    pub(crate) boot_uuid: String,
    pub(crate) timezone_name: String,
    pub(crate) message_flags: Vec<String>,
    pub(crate) evidence: String,
}

impl OutputWriter {
    pub fn new(writer: Box<dyn Write>, format: Format) -> Result<Self, Box<dyn Error>> {
        let writer_enum = match format {
            Format::Jsonl => OutputWriterEnum::Json(writer),
        };
        Ok(OutputWriter {
            writer: writer_enum,
        })
    }

    pub fn write_log(
        &mut self,
        index: usize,
        entry: &LogEntry<'_, '_>,
    ) -> Result<(), Box<dyn Error>> {
        let value = LogValue {
            index,
            subsystem: entry.subsystem.unwrap_or_default().to_string(),
            category: entry.category.unwrap_or_default().to_string(),
            thread_id: entry.thread_id,
            pid: entry.pid,
            euid: entry.euid,
            library: entry.library.unwrap_or_default().to_string(),
            library_uuid: entry.library_uuid.to_string(),
            activity_id: entry.activity_id,
            parent_activity_id: entry.parent_activity_id,
            timestamp: entry
                .timestamp()
                .to_rfc3339_opts(SecondsFormat::Nanos, true),
            time: entry.time,
            event_type: format!("{:?}", entry.event_type),
            log_type: format!("{:?}", entry.log_type),
            process: entry.process.unwrap_or_default().to_string(),
            process_uuid: entry.process_uuid.to_string(),
            message: entry.message().to_string(),
            raw_message: entry.raw_message().to_string(),
            boot_uuid: entry.boot_uuid.to_string(),
            timezone_name: entry.timezone_name.to_string(),
            message_flags: entry
                .message_flags
                .iter()
                .map(|flag| format!("{flag:?}"))
                .collect(),
            evidence: entry.evidence.display().to_string(),
        };

        match &mut self.writer {
            OutputWriterEnum::Json(json_writer) => {
                writeln!(json_writer, "{}", serde_json::to_string(&value).unwrap())?;
            }
        }

        Ok(())
    }

    pub fn write_timesync(
        &mut self,
        time: HashMap<Uuid, RawTimesyncBoot>,
    ) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Json(json_writer) => {
                writeln!(json_writer, "{}", serde_json::to_string(&time).unwrap())?;
            }
        }
        Ok(())
    }
}
