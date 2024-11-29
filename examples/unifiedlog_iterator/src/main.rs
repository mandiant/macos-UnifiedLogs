// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::{SecondsFormat, TimeZone, Utc};
use log::LevelFilter;
use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{
    build_log, collect_shared_strings, collect_shared_strings_system, collect_strings,
    collect_strings_system, collect_timesync, collect_timesync_system,
};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};
use macos_unifiedlogs::uuidtext::UUIDText;
use simplelog::{Config, SimpleLogger};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::{fs, io};

use clap::Parser;
use csv::Writer;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Run on live system
    #[clap(short, long, default_value = "false")]
    live: String,

    /// Path to logarchive formatted directory
    #[clap(short, long, default_value = "")]
    input: String,

    /// Path to output file. Any directories must already exist
    #[clap(short, long, default_value = "")]
    output: String,

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
    let output_format = if args.format.is_empty() || args.format == "auto" {
        std::path::Path::new(&args.output)
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("csv")
            .to_string()
    } else {
        args.format.clone()
    };

    let mut writer = OutputWriter::new(&args.output, &output_format, args.append).unwrap();

    if !args.input.is_empty() {
        parse_log_archive(&args.input, &mut writer);
    } else if args.live != "false" {
        parse_live_system(&mut writer);
    }
}

// Parse a provided directory path. Currently, expect the path to follow macOS log collect structure
fn parse_log_archive(path: &str, writer: &mut OutputWriter) {
    let mut archive_path = PathBuf::from(path);

    // Parse all UUID files which contain strings and other metadata
    let string_results = collect_strings(&archive_path.display().to_string()).unwrap();

    archive_path.push("dsc");
    // Parse UUID cache files which also contain strings and other metadata
    let shared_strings_results =
        collect_shared_strings(&archive_path.display().to_string()).unwrap();
    archive_path.pop();

    archive_path.push("timesync");
    // Parse all timesync files
    let timesync_data = collect_timesync(&archive_path.display().to_string()).unwrap();
    archive_path.pop();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    parse_trace_file(
        &string_results,
        &shared_strings_results,
        &timesync_data,
        path,
        writer,
    );

    eprintln!("\nFinished parsing Unified Log data.");
}

// Parse a live macOS system
fn parse_live_system(writer: &mut OutputWriter) {
    let strings = collect_strings_system().unwrap();
    let shared_strings = collect_shared_strings_system().unwrap();
    let timesync_data = collect_timesync_system().unwrap();

    parse_trace_file(
        &strings,
        &shared_strings,
        &timesync_data,
        "/private/var/db/diagnostics",
        writer,
    );

    eprintln!("\nFinished parsing Unified Log data.");
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
// Currently, expect the path to follow macOS log collect structure
fn parse_trace_file(
    string_results: &[UUIDText],
    shared_strings_results: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    path: &str,
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

    let mut archive_path = PathBuf::from(path);
    archive_path.push("Persist");

    let mut log_count = 0;
    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in Persist directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            eprintln!("Parsing: {}", full_path);

            if data.path().exists() {
                let count = iterate_chunks(
                    &full_path,
                    &mut missing_data,
                    string_results,
                    shared_strings_results,
                    timesync_data,
                    writer,
                    &mut oversize_strings,
                );
                log_count += count;
            } else {
                eprintln!("File {} no longer on disk", full_path);
                continue;
            };
        }
    }

    archive_path.pop();
    archive_path.push("Special");

    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in Special directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            eprintln!("Parsing: {}", full_path);

            if data.path().exists() {
                let count = iterate_chunks(
                    &full_path,
                    &mut missing_data,
                    string_results,
                    shared_strings_results,
                    timesync_data,
                    writer,
                    &mut oversize_strings,
                );
                log_count += count;
            } else {
                eprintln!("File {} no longer on disk", full_path);
                continue;
            };
        }
    }

    archive_path.pop();
    archive_path.push("Signpost");

    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in Signpost directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            eprintln!("Parsing: {}", full_path);

            if data.path().exists() {
                let count = iterate_chunks(
                    &full_path,
                    &mut missing_data,
                    string_results,
                    shared_strings_results,
                    timesync_data,
                    writer,
                    &mut oversize_strings,
                );
                log_count += count;
            } else {
                eprintln!("File {} no longer on disk", full_path);
                continue;
            };
        }
    }
    archive_path.pop();
    archive_path.push("HighVolume");

    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in HighVolume directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            eprintln!("Parsing: {}", full_path);

            if data.path().exists() {
                let count = iterate_chunks(
                    &full_path,
                    &mut missing_data,
                    string_results,
                    shared_strings_results,
                    timesync_data,
                    writer,
                    &mut oversize_strings,
                );
                log_count += count;
            } else {
                eprintln!("File {} no longer on disk", full_path);
                continue;
            };
        }
    }
    archive_path.pop();

    archive_path.push("logdata.LiveData.tracev3");

    // Check if livedata exists. We only have it if 'log collect' was used
    if archive_path.exists() {
        eprintln!("Parsing: logdata.LiveData.tracev3");

        let count = iterate_chunks(
            &archive_path.display().to_string(),
            &mut missing_data,
            string_results,
            shared_strings_results,
            timesync_data,
            writer,
            &mut oversize_strings,
        );
        log_count += count;
        archive_path.pop();
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
    path: &str,
    missing: &mut Vec<UnifiedLogData>,
    strings_data: &[UUIDText],
    shared_strings: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    writer: &mut OutputWriter,
    oversize_strings: &mut UnifiedLogData,
) -> usize {
    let log_bytes = fs::read(path).unwrap();
    let log_iterator = UnifiedLogIterator {
        data: log_bytes,
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
    pub fn new(
        output_path: &str,
        output_format: &str,
        append: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let writer: Box<dyn Write> = if !output_path.is_empty() {
            Box::new(
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(!append)
                    .append(append)
                    .open(output_path)?,
            )
        } else {
            Box::new(io::stdout())
        };

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
