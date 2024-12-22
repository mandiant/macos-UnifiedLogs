// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::{SecondsFormat, TimeZone, Utc};
use log::LevelFilter;
use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::filesystem::{LiveSystemProvider, LogarchiveProvider};
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{
    build_log, collect_shared_strings, collect_strings, collect_timesync,
};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};
use macos_unifiedlogs::uuidtext::UUIDText;
use simplelog::{Config, SimpleLogger};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::Parser;
use csv::Writer;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Run on live system
    #[clap(short, long)]
    live: bool,

    /// Path to logarchive formatted directory
    #[clap(short, long)]
    input: Option<PathBuf>,

    /// Path to output file. Any directories must already exist
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Output format. Options: csv, jsonl. Default is autodetect.
    #[clap(short, long, default_value = "auto")]
    format: String,

    /// Append to output file
    /// If false, will overwrite output file
    #[clap(short, long, default_value = "false")]
    append: bool,
}

fn main() {
    eprintln!("Starting Unified Log parser...");
    // Set logging level to warning
    SimpleLogger::init(LevelFilter::Warn, Config::default())
        .expect("Failed to initialize simple logger");

    let args = Args::parse();
    let output_format = match args.format.as_str() {
        "csv" => "csv",
        "jsonl" => "jsonl",
        "auto" => "auto",
        _ => "auto",
    }
    .to_string();

    let handle: Box<dyn Write> = if let Some(path) = args.output {
        Box::new(
            fs::OpenOptions::new()
                .write(true)
                .append(true)
                .open(path)
                .unwrap(),
        )
    } else {
        Box::new(std::io::stdout())
    };

    let mut writer = OutputWriter::new(Box::new(handle), &output_format).unwrap();

    if let Some(path) = args.input {
        parse_log_archive(&path, &mut writer);
    } else if args.live {
        parse_live_system(&mut writer);
    }
}

// Parse a provided directory path. Currently, expect the path to follow macOS log collect structure
fn parse_log_archive(path: &Path, writer: &mut OutputWriter) {
    let provider = LogarchiveProvider::new(path);

    // Parse all UUID files which contain strings and other metadata
    let string_results = collect_strings(&provider).unwrap();
    // Parse UUID cache files which also contain strings and other metadata
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    // Parse all timesync files
    let timesync_data = collect_timesync(&provider).unwrap();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    parse_trace_file(
        &string_results,
        &shared_strings_results,
        &timesync_data,
        &provider,
        writer,
    );

    eprintln!("\nFinished parsing Unified Log data.");
}

// Parse a live macOS system
fn parse_live_system(writer: &mut OutputWriter) {
    let provider = LiveSystemProvider::default();
    let strings = collect_strings(&provider).unwrap();
    let shared_strings = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    parse_trace_file(&strings, &shared_strings, &timesync_data, &provider, writer);

    eprintln!("\nFinished parsing Unified Log data.");
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
// Currently, expect the path to follow macOS log collect structure
fn parse_trace_file(
    string_results: &[UUIDText],
    shared_strings_results: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    provider: &dyn FileProvider,
    writer: &mut OutputWriter,
) {
    // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
    // Some log entries have Oversize strings located in different tracev3 files.
    // This is very rare. Seen in ~20 log entries out of ~700,000. Seen in ~700 out of ~18 million
    let mut oversize_strings = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
    };

    let mut missing_data: Vec<UnifiedLogData> = Vec::new();

    // Loop through all tracev3 files in Persist directory
    let mut log_count = 0;
    for mut source in provider.tracev3_files() {
        log_count += iterate_chunks(
            source.reader(),
            &mut missing_data,
            string_results,
            shared_strings_results,
            timesync_data,
            writer,
            &mut oversize_strings,
        );
    }
    let include_missing = false;
    println!("Oversize cache size: {}", oversize_strings.oversize.len());
    println!("Logs with missing Oversize strings: {}", missing_data.len());
    println!("Checking Oversize cache one more time...");

    // Since we have all Oversize entries now. Go through any log entries that we were not able to build before
    for mut leftover_data in missing_data {
        // Add all of our previous oversize data to logs for lookups
        leftover_data.oversize = oversize_strings.oversize.clone();

        // Exclude_missing = false
        // If we fail to find any missing data its probably due to the logs rolling
        // Ex: tracev3A rolls, tracev3B references Oversize entry in tracev3A will trigger missing data since tracev3A is gone
        let (results, _) = build_log(
            &leftover_data,
            string_results,
            shared_strings_results,
            timesync_data,
            include_missing,
        );
        log_count += results.len();

        output(&results, writer).unwrap();
    }
    eprintln!("Parsed {} log entries", log_count);
}

fn iterate_chunks(
    mut reader: impl Read,
    missing: &mut Vec<UnifiedLogData>,
    strings_data: &[UUIDText],
    shared_strings: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    writer: &mut OutputWriter,
    oversize_strings: &mut UnifiedLogData,
) -> usize {
    let mut buf = Vec::new();

    if let Err(e) = reader.read(&mut buf) {
        log::error!("Failed to read tracev3 file: {:?}", e);
        return 0;
    }

    let log_iterator = UnifiedLogIterator {
        data: buf,
        header: Vec::new(),
    };

    // Exclude missing data from returned output. Keep separate until we parse all oversize entries.
    // Then after parsing all logs, go through all missing data and check all parsed oversize entries again
    let exclude_missing = true;

    let mut count = 0;
    for mut chunk in log_iterator {
        chunk.oversize.append(&mut oversize_strings.oversize);
        let (results, missing_logs) = build_log(
            &chunk,
            strings_data,
            shared_strings,
            timesync_data,
            exclude_missing,
        );
        count += results.len();
        oversize_strings.oversize = chunk.oversize;
        output(&results, writer).unwrap();
        if missing_logs.catalog_data.is_empty()
            && missing_logs.header.is_empty()
            && missing_logs.oversize.is_empty()
        {
            continue;
        }
        // Track possible missing log data due to oversize strings being in another file
        missing.push(missing_logs);
    }

    count
}

pub struct OutputWriter {
    writer: OutputWriterEnum,
}

enum OutputWriterEnum {
    Csv(Box<Writer<Box<dyn Write>>>),
    Json(Box<dyn Write>),
}

impl OutputWriter {
    pub fn new(writer: Box<dyn Write>, output_format: &str) -> Result<Self, Box<dyn Error>> {
        let writer_enum = match output_format {
            "csv" => {
                let mut csv_writer = Writer::from_writer(writer);
                // Write CSV headers
                csv_writer.write_record([
                    "Timestamp",
                    "Event Type",
                    "Log Type",
                    "Subsystem",
                    "Thread ID",
                    "PID",
                    "EUID",
                    "Library",
                    "Library UUID",
                    "Activity ID",
                    "Category",
                    "Process",
                    "Process UUID",
                    "Message",
                    "Raw Message",
                    "Boot UUID",
                    "System Timezone Name",
                ])?;
                csv_writer.flush()?;
                OutputWriterEnum::Csv(Box::new(csv_writer))
            }
            "jsonl" => OutputWriterEnum::Json(writer),
            _ => {
                eprintln!("Unsupported output format: {}", output_format);
                std::process::exit(1);
            }
        };

        Ok(OutputWriter {
            writer: writer_enum,
        })
    }

    pub fn write_record(&mut self, record: &LogData) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => {
                let date_time = Utc.timestamp_nanos(record.time as i64);
                csv_writer.write_record(&[
                    date_time.to_rfc3339_opts(SecondsFormat::Millis, true),
                    record.event_type.to_owned(),
                    record.log_type.to_owned(),
                    record.subsystem.to_owned(),
                    record.thread_id.to_string(),
                    record.pid.to_string(),
                    record.euid.to_string(),
                    record.library.to_owned(),
                    record.library_uuid.to_owned(),
                    record.activity_id.to_string(),
                    record.category.to_owned(),
                    record.process.to_owned(),
                    record.process_uuid.to_owned(),
                    record.message.to_owned(),
                    record.raw_message.to_owned(),
                    record.boot_uuid.to_owned(),
                    record.timezone_name.to_owned(),
                ])?;
            }
            OutputWriterEnum::Json(json_writer) => {
                writeln!(json_writer, "{}", serde_json::to_string(record).unwrap())?;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => csv_writer.flush()?,
            OutputWriterEnum::Json(json_writer) => json_writer.flush()?,
        }
        Ok(())
    }
}

// Append or create csv file
fn output(results: &Vec<LogData>, writer: &mut OutputWriter) -> Result<(), Box<dyn Error>> {
    for data in results {
        writer.write_record(data)?;
    }
    writer.flush()?;
    Ok(())
}
