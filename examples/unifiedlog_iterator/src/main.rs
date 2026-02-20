// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use log::{LevelFilter, debug, error, info};
use macos_unifiedlogs::filesystem::{LiveSystemProvider, LogarchiveProvider};
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::{LogData, LogType, UnifiedLogData};
use regex::Regex;
use rusqlite::Connection;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use clap::{Parser, ValueEnum, builder};
use csv::Writer;

#[derive(Clone, Debug)]
enum RuntimeError {
    FileOpen { path: String, message: String },
    FileParse { path: String, message: String },
}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            RuntimeError::FileOpen { path, message } => {
                f.write_str(&format!("Failed to open source file {path}: {message}"))
            }
            RuntimeError::FileParse { path, message } => {
                f.write_str(&format!("Failed to parse {path}: {message}"))
            }
        }
    }
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Mode of operation
    #[clap(short, long)]
    mode: Mode,

    /// Path to logarchive formatted directory (log-archive mode) or tracev3 file (single-file
    /// mode)
    #[clap(short, long)]
    input: Option<PathBuf>,

    /// Filename to save results to
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Output format. Options: csv, jsonl, sqlite
    #[clap(short, long, default_value = Format::Jsonl)]
    format: Format,

    /// Append to output file.
    /// If false, will overwrite output file
    #[clap(short, long, default_value = "false")]
    append: bool,

    /// Filter by subsystem (e.g., "com.apple.sandbox")
    #[clap(long)]
    subsystem: Option<String>,

    /// Filter by process name
    #[clap(long)]
    process: Option<String>,

    /// Filter by PID
    #[clap(long)]
    pid: Option<u64>,

    /// Filter by log level (repeatable: Debug, Info, Default, Error, Fault)
    #[clap(long)]
    level: Vec<FilterLevel>,

    /// Only include logs after this ISO timestamp (e.g., "2022-01-15T19:00:00Z")
    #[clap(long)]
    after: Option<String>,

    /// Only include logs before this ISO timestamp (e.g., "2022-01-16T00:00:00Z")
    #[clap(long)]
    before: Option<String>,

    /// Regex pattern to match against message content
    #[clap(long)]
    grep: Option<String>,

    /// Print match count instead of records
    #[clap(long, default_value = "false")]
    count: bool,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum Mode {
    Live,
    LogArchive,
    SingleFile,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum Format {
    Csv,
    Jsonl,
    Sqlite,
}

#[derive(Debug, Clone, ValueEnum)]
enum FilterLevel {
    Debug,
    Info,
    Default,
    Error,
    Fault,
}

impl From<Format> for builder::OsStr {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv".into(),
            Format::Jsonl => "jsonl".into(),
            Format::Sqlite => "sqlite".into(),
        }
    }
}

impl From<Format> for &str {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv",
            Format::Jsonl => "jsonl",
            Format::Sqlite => "sqlite",
        }
    }
}

struct LogFilter {
    subsystem: Option<String>,
    process: Option<String>,
    pid: Option<u64>,
    levels: Vec<LogType>,
    after: Option<f64>,
    before: Option<f64>,
    grep: Option<Regex>,
}

impl LogFilter {
    fn from_args(args: &Args) -> Result<Self, Box<dyn Error>> {
        let levels: Vec<LogType> = args
            .level
            .iter()
            .map(|l| match l {
                FilterLevel::Debug => LogType::Debug,
                FilterLevel::Info => LogType::Info,
                FilterLevel::Default => LogType::Default,
                FilterLevel::Error => LogType::Error,
                FilterLevel::Fault => LogType::Fault,
            })
            .collect();

        let after = if let Some(ref ts) = args.after {
            let dt: DateTime<Utc> = ts.parse()?;
            Some(dt.timestamp_nanos_opt().unwrap_or(0) as f64)
        } else {
            None
        };

        let before = if let Some(ref ts) = args.before {
            let dt: DateTime<Utc> = ts.parse()?;
            Some(dt.timestamp_nanos_opt().unwrap_or(0) as f64)
        } else {
            None
        };

        let grep = if let Some(ref pattern) = args.grep {
            Some(Regex::new(pattern)?)
        } else {
            None
        };

        Ok(LogFilter {
            subsystem: args.subsystem.clone(),
            process: args.process.clone(),
            pid: args.pid,
            levels,
            after,
            before,
            grep,
        })
    }

    fn matches(&self, record: &LogData) -> bool {
        if let Some(ref sub) = self.subsystem
            && !record.subsystem.contains(sub.as_str())
        {
            return false;
        }
        if let Some(ref proc_name) = self.process
            && !record.process.contains(proc_name.as_str())
        {
            return false;
        }
        if let Some(pid) = self.pid
            && record.pid != pid
        {
            return false;
        }
        if !self.levels.is_empty() && !self.levels.contains(&record.log_type) {
            return false;
        }
        if let Some(after) = self.after
            && record.time < after
        {
            return false;
        }
        if let Some(before) = self.before
            && record.time > before
        {
            return false;
        }
        if let Some(ref re) = self.grep
            && !re.is_match(&record.message)
        {
            return false;
        }
        true
    }

    fn is_active(&self) -> bool {
        self.subsystem.is_some()
            || self.process.is_some()
            || self.pid.is_some()
            || !self.levels.is_empty()
            || self.after.is_some()
            || self.before.is_some()
            || self.grep.is_some()
    }
}

fn main() {
    TermLogger::init(
        LevelFilter::Warn,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Failed to initialize simple logger");
    info!("Starting Unified Log parser...");

    let args = Args::parse();

    if matches!(args.format, Format::Sqlite) && args.output.is_none() {
        error!("--output is required when using --format sqlite");
        std::process::exit(1);
    }

    let filter = match LogFilter::from_args(&args) {
        Ok(f) => f,
        Err(e) => {
            error!("Invalid filter argument: {e}");
            std::process::exit(1);
        }
    };

    let count_mode = args.count;
    let match_count = AtomicUsize::new(0);

    let output_format = args.format;

    let mut writer = match &output_format {
        Format::Sqlite => {
            let path = args.output.as_ref().unwrap();
            OutputWriter::new_sqlite(path).unwrap()
        }
        _ => {
            let handle: Box<dyn Write> = if let Some(ref path) = args.output {
                Box::new(
                    fs::OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path)
                        .unwrap(),
                )
            } else {
                Box::new(std::io::stdout())
            };
            OutputWriter::new(Box::new(handle), output_format.clone().into()).unwrap()
        }
    };

    match (args.mode, args.input) {
        (Mode::Live, None) => {
            parse_live_system(&mut writer, &filter, count_mode, &match_count);
        }
        (Mode::LogArchive, Some(path)) => {
            parse_log_archive(&path, &mut writer, &filter, count_mode, &match_count);
        }
        (Mode::SingleFile, Some(path)) => {
            parse_single_file(&path, &mut writer, &filter, count_mode, &match_count);
        }
        _ => {
            error!("log-archive and single-file modes require an --input argument");
        }
    }

    if count_mode {
        println!("{}", match_count.load(Ordering::Relaxed));
    }
}

fn parse_single_file(
    path: &Path,
    writer: &mut OutputWriter,
    filter: &LogFilter,
    count_mode: bool,
    match_count: &AtomicUsize,
) {
    let mut provider = LogarchiveProvider::new(path);
    let results = match fs::File::open(path)
        .map_err(|e| RuntimeError::FileOpen {
            path: path.to_string_lossy().to_string(),
            message: e.to_string(),
        })
        .and_then(|mut reader| {
            parse_log(&mut reader, path.to_str().unwrap_or_default()).map_err(|err| {
                RuntimeError::FileParse {
                    path: path.to_string_lossy().to_string(),
                    message: format!("{err}"),
                }
            })
        })
        .map(|ref log| {
            let (results, _) = build_log(log, &mut provider, &HashMap::new(), false);
            results
        }) {
        Ok(reader) => reader,
        Err(e) => {
            error!("Failed to parse {path:?}: {e}");
            return;
        }
    };
    for row in results {
        if filter.is_active() && !filter.matches(&row) {
            continue;
        }
        if count_mode {
            match_count.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if let Err(e) = writer.write_record(&row) {
            error!("Error writing record: {e}");
        };
    }
}

// Parse a provided directory path. Currently, expect the path to follow macOS log collect structure
fn parse_log_archive(
    path: &Path,
    writer: &mut OutputWriter,
    filter: &LogFilter,
    count_mode: bool,
    match_count: &AtomicUsize,
) {
    let mut provider = LogarchiveProvider::new(path);

    // Parse all timesync files
    let timesync_data = collect_timesync(&provider).unwrap();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    parse_trace_file(
        &timesync_data,
        &mut provider,
        writer,
        filter,
        count_mode,
        match_count,
    );

    info!("Finished parsing Unified Log data.");
}

// Parse a live macOS system
fn parse_live_system(
    writer: &mut OutputWriter,
    filter: &LogFilter,
    count_mode: bool,
    match_count: &AtomicUsize,
) {
    let mut provider = LiveSystemProvider::default();
    let timesync_data = collect_timesync(&provider).unwrap();

    parse_trace_file(
        &timesync_data,
        &mut provider,
        writer,
        filter,
        count_mode,
        match_count,
    );

    info!("Finished parsing Unified Log data.");
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
fn parse_trace_file(
    timesync_data: &HashMap<String, TimesyncBoot>,
    provider: &mut dyn FileProvider,
    writer: &mut OutputWriter,
    filter: &LogFilter,
    count_mode: bool,
    match_count: &AtomicUsize,
) {
    // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
    // Some log entries have Oversize strings located in different tracev3 files.
    // This is very rare. Seen in ~20 log entries out of ~700,000. Seen in ~700 out of ~18 million
    let mut oversize_strings = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
        evidence: String::new(),
    };

    let mut missing_data: Vec<UnifiedLogData> = Vec::new();

    // Loop through all tracev3 files in Persist directory
    let mut log_count = 0;
    for mut source in provider.tracev3_files() {
        if Path::new(source.source_path())
            .file_name()
            .is_some_and(|f| f.to_str().unwrap().starts_with("._"))
        {
            continue;
        }
        let path = source.source_path().to_string();
        info!("Parsing: {path}");
        log_count += iterate_chunks(
            source.reader(),
            &mut missing_data,
            provider,
            timesync_data,
            writer,
            &mut oversize_strings,
            &path,
            filter,
            count_mode,
            match_count,
        );
        debug!("count: {log_count}");
    }
    let include_missing = false;
    debug!("Oversize cache size: {}", oversize_strings.oversize.len());
    debug!("Logs with missing Oversize strings: {}", missing_data.len());
    debug!("Checking Oversize cache one more time...");

    // Since we have all Oversize entries now. Go through any log entries that we were not able to build before
    for mut leftover_data in missing_data {
        // Add all of our previous oversize data to logs for lookups
        leftover_data.oversize = oversize_strings.oversize.clone();

        // Exclude_missing = false
        // If we fail to find any missing data its probably due to the logs rolling
        // Ex: tracev3A rolls, tracev3B references Oversize entry in tracev3A will trigger missing data since tracev3A is gone
        let (results, _) = build_log(&leftover_data, provider, timesync_data, include_missing);
        log_count += results.len();

        if let Err(err) = output(&results, writer, filter, count_mode, match_count) {
            log::error!("Failed to output remaining log data: {err:?}");
        }
    }
    info!("Parsed {log_count} log entries");
}

#[allow(clippy::too_many_arguments)]
fn iterate_chunks(
    mut reader: impl Read,
    missing: &mut Vec<UnifiedLogData>,
    provider: &mut dyn FileProvider,
    timesync_data: &HashMap<String, TimesyncBoot>,
    writer: &mut OutputWriter,
    oversize_strings: &mut UnifiedLogData,
    evidence: &str,
    filter: &LogFilter,
    count_mode: bool,
    match_count: &AtomicUsize,
) -> usize {
    let mut buf = Vec::new();

    if let Err(err) = reader.read_to_end(&mut buf) {
        log::error!("Failed to read tracev3 file: {err:?}");
        return 0;
    }

    let log_iterator = UnifiedLogIterator {
        data: buf,
        header: Vec::new(),
        evidence: evidence.to_string(),
    };

    // Exclude missing data from returned output. Keep separate until we parse all oversize entries.
    // Then after parsing all logs, go through all missing data and check all parsed oversize entries again
    let exclude_missing = true;

    let mut count = 0;
    for mut chunk in log_iterator {
        chunk.oversize.append(&mut oversize_strings.oversize);
        let (results, missing_logs) = build_log(&chunk, provider, timesync_data, exclude_missing);
        count += results.len();
        oversize_strings.oversize = chunk.oversize;
        if let Err(err) = output(&results, writer, filter, count_mode, match_count) {
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
            {
                debug!("Broken pipe. Exiting.");
                std::process::exit(141); // 128 + 13 (SIGPIPE)
            }
            log::error!("Failed to output log data: {err:?}");
        }
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
    Sqlite(SqliteWriter),
}

struct SqliteWriter {
    conn: Connection,
    batch_count: usize,
}

impl SqliteWriter {
    fn new(path: &Path) -> Result<Self, Box<dyn Error>> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS logs (
                timestamp TEXT NOT NULL,
                time REAL NOT NULL,
                event_type TEXT NOT NULL,
                log_type TEXT NOT NULL,
                subsystem TEXT,
                category TEXT,
                process TEXT,
                process_uuid TEXT,
                pid INTEGER,
                euid INTEGER,
                thread_id INTEGER,
                library TEXT,
                library_uuid TEXT,
                activity_id INTEGER,
                message TEXT,
                raw_message TEXT,
                boot_uuid TEXT,
                timezone_name TEXT,
                evidence TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_logs_subsystem ON logs(subsystem);
            CREATE INDEX IF NOT EXISTS idx_logs_process ON logs(process);
            CREATE INDEX IF NOT EXISTS idx_logs_pid ON logs(pid);
            CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(time);
            CREATE INDEX IF NOT EXISTS idx_logs_log_type ON logs(log_type);",
        )?;
        conn.execute_batch("BEGIN TRANSACTION;")?;
        Ok(SqliteWriter {
            conn,
            batch_count: 0,
        })
    }

    fn write_record(&mut self, record: &LogData) -> Result<(), Box<dyn Error>> {
        let date_time = Utc.timestamp_nanos(record.time as i64);
        self.conn.execute(
            "INSERT INTO logs (timestamp, time, event_type, log_type, subsystem, category,
             process, process_uuid, pid, euid, thread_id, library, library_uuid,
             activity_id, message, raw_message, boot_uuid, timezone_name, evidence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18, ?19)",
            rusqlite::params![
                date_time.to_rfc3339_opts(SecondsFormat::Millis, true),
                record.time,
                format!("{:?}", record.event_type),
                format!("{:?}", record.log_type),
                record.subsystem,
                record.category,
                record.process,
                record.process_uuid,
                record.pid,
                record.euid,
                record.thread_id,
                record.library,
                record.library_uuid,
                record.activity_id,
                record.message,
                record.raw_message,
                record.boot_uuid,
                record.timezone_name,
                record.evidence,
            ],
        )?;
        self.batch_count += 1;
        if self.batch_count >= 5000 {
            self.conn.execute_batch("COMMIT; BEGIN TRANSACTION;")?;
            self.batch_count = 0;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        if self.batch_count > 0 {
            self.conn.execute_batch("COMMIT;")?;
            self.batch_count = 0;
        }
        Ok(())
    }
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
                error!("Unsupported output format: {output_format}");
                std::process::exit(1);
            }
        };

        Ok(OutputWriter {
            writer: writer_enum,
        })
    }

    pub fn new_sqlite(path: &Path) -> Result<Self, Box<dyn Error>> {
        Ok(OutputWriter {
            writer: OutputWriterEnum::Sqlite(SqliteWriter::new(path)?),
        })
    }

    pub fn write_record(&mut self, record: &LogData) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => {
                let date_time = Utc.timestamp_nanos(record.time as i64);
                csv_writer.write_record(&[
                    date_time.to_rfc3339_opts(SecondsFormat::Millis, true),
                    format!("{:?}", record.event_type),
                    format!("{:?}", record.log_type),
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
            OutputWriterEnum::Sqlite(sqlite_writer) => {
                sqlite_writer.write_record(record)?;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => csv_writer.flush()?,
            OutputWriterEnum::Json(json_writer) => json_writer.flush()?,
            OutputWriterEnum::Sqlite(sqlite_writer) => sqlite_writer.flush()?,
        }
        Ok(())
    }
}

fn output(
    results: &Vec<LogData>,
    writer: &mut OutputWriter,
    filter: &LogFilter,
    count_mode: bool,
    match_count: &AtomicUsize,
) -> Result<(), Box<dyn Error>> {
    for data in results {
        if filter.is_active() && !filter.matches(data) {
            continue;
        }
        if count_mode {
            match_count.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        writer.write_record(data)?;
    }
    writer.flush()?;
    Ok(())
}
