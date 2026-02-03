// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::{SecondsFormat, TimeZone, Utc};
use log::{debug, error, info, warn, LevelFilter};
use macos_unifiedlogs::filesystem::{LiveSystemProvider, LogarchiveProvider};
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{build_log, collect_timesync, filter_log_data_by_time, parse_log};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{builder, Parser, ValueEnum};
use csv::Writer;
use serde::{Deserialize, Serialize};

/// Global atomic flag to track SIGINT signal
static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Signal handler function for SIGINT
extern "C" fn handle_sigint(_sig: libc::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

#[derive(Copy, Clone, Debug, PartialEq)]
struct TimeFilter {
    start: Option<f64>,
    end: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Bookmark {
    last_timestamp: f64,
    processed_files: HashMap<String, u64>,
    /// Boot UUID to detect system reboots (resets bookmark if changed)
    /// TODO: Implement boot UUID checking - currently stored but never compared.
    /// Should extract boot UUID from first log entry and compare against current
    /// system boot UUID. If different, reset bookmark since timestamps are only
    /// valid within a single boot session.
    boot_uuid: Option<String>,
    last_updated: String,
    /// path for archive/file mode, "live" for live mode
    source_id: String,
}

impl Bookmark {
    /// Create a new bookmark for a given source
    fn new(source_id: String) -> Self {
        Self {
            last_timestamp: 0.0,
            processed_files: HashMap::new(),
            boot_uuid: None,
            last_updated: chrono::Utc::now().to_rfc3339(),
            source_id,
        }
    }

    fn load(path: &Path) -> Option<Self> {
        let contents = fs::read_to_string(path).ok()?;
        serde_json::from_str(&contents).ok()
    }

    fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    fn should_process_entry(&self, timestamp: f64) -> bool {
        timestamp > self.last_timestamp
    }

    fn update_timestamp(&mut self, timestamp: f64) {
        if timestamp > self.last_timestamp {
            self.last_timestamp = timestamp;
            self.last_updated = chrono::Utc::now().to_rfc3339();
        }
    }

    fn default_path(mode: &str) -> PathBuf {
        // Get data directory following XDG Base Directory spec
        // macOS: ~/Library/Application Support/
        // Linux: ~/.local/share/
        let data_dir = if cfg!(target_os = "macos") {
            std::env::var("HOME")
                .map(|home| PathBuf::from(home).join("Library/Application Support"))
                .unwrap_or_else(|_| PathBuf::from("."))
        } else {
            // Linux/Unix fallback
            std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    std::env::var("HOME")
                        .map(|home| PathBuf::from(home).join(".local/share"))
                        .unwrap_or_else(|_| PathBuf::from("."))
                })
        };

        let bookmark_dir = data_dir.join("unifiedlog_iterator");

        // Create directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&bookmark_dir) {
            eprintln!(
                "Warning: Failed to create bookmark directory {:?}: {}",
                bookmark_dir, e
            );
        }

        bookmark_dir.join(format!("{}.bookmark", mode))
    }
}

struct IterationContext {
    missing_data: Vec<UnifiedLogData>,
    oversize_strings: UnifiedLogData,
}

struct ParseContext<'a> {
    time_filter: TimeFilter,
    bookmark: Arc<Mutex<Bookmark>>,
    context: &'a mut IterationContext,
}

fn parse_time_filter(from: &Option<String>, to: &Option<String>) -> Result<TimeFilter, String> {
    let start = match from {
        Some(value) => Some(parse_rfc3339_to_nanos(value)?),
        None => None,
    };
    let end = match to {
        Some(value) => Some(parse_rfc3339_to_nanos(value)?),
        None => None,
    };

    Ok(TimeFilter { start, end })
}

fn parse_rfc3339_to_nanos(value: &str) -> Result<f64, String> {
    let dt = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|err| format!("Invalid RFC3339 time '{value}': {err}"))?;
    let timestamp = dt
        .timestamp_nanos_opt()
        .ok_or_else(|| format!("Timestamp out of range for '{value}'"))?;
    Ok(timestamp as f64)
}

#[cfg(test)]
mod tests {
    use super::{parse_rfc3339_to_nanos, parse_time_filter};

    #[test]
    fn test_parse_time_filter_empty() {
        let filter = parse_time_filter(&None, &None).unwrap();
        assert_eq!(filter.start, None);
        assert_eq!(filter.end, None);
    }

    #[test]
    fn test_parse_rfc3339_to_nanos() {
        let nanos = parse_rfc3339_to_nanos("2026-02-01T00:00:00Z").unwrap();
        assert!(nanos > 0.0);
    }
}

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

/// Error type to signal broken pipe (output consumer closed)
#[derive(Debug)]
struct BrokenPipeError;

impl std::fmt::Display for BrokenPipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Broken pipe")
    }
}

impl std::error::Error for BrokenPipeError {}

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

    /// Output format. Options: csv, jsonl
    #[clap(short, long, default_value = Format::Jsonl)]
    format: Format,

    /// Append to output file.
    /// If false, will overwrite output file
    #[clap(short, long, default_value = "false")]
    append: bool,

    /// Resume from last position using bookmark
    #[clap(long, default_value = "false")]
    resume: bool,

    /// Path to bookmark file for resuming (defaults to ~/.local/share or ~/Library/Application Support/)
    #[clap(long)]
    bookmark_path: Option<PathBuf>,

    /// Filter logs from this time (RFC3339, ex: 2026-02-03T14:03:04Z)
    #[clap(long)]
    from: Option<String>,

    /// Filter logs until this time (RFC3339, ex: 2026-02-03T14:03:04Z)
    #[clap(long)]
    to: Option<String>,
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
}

impl From<Format> for builder::OsStr {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv".into(),
            Format::Jsonl => "jsonl".into(),
        }
    }
}

impl From<Format> for &str {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv",
            Format::Jsonl => "jsonl",
        }
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
    let output_format = args.format;
    let time_filter = match parse_time_filter(&args.from, &args.to) {
        Ok(filter) => filter,
        Err(message) => {
            error!("Invalid time filter: {error}", error = message);
            return;
        }
    };

    // Determine source ID for bookmark
    let source_id = match (&args.mode, &args.input) {
        (Mode::Live, _) => "live".to_string(),
        (Mode::LogArchive, Some(path)) => path.to_string_lossy().to_string(),
        (Mode::SingleFile, Some(path)) => path.to_string_lossy().to_string(),
        _ => "unknown".to_string(),
    };

    let mode_str = format!("{:?}", args.mode).to_lowercase();
    let bookmark_path = args
        .bookmark_path
        .clone()
        .unwrap_or_else(|| Bookmark::default_path(&mode_str));

    info!("Using bookmark path: {path:?}", path = bookmark_path);

    let mut bookmark = if args.resume {
        Bookmark::load(&bookmark_path).unwrap_or_else(|| {
            info!("Creating new bookmark at {path:?}", path = bookmark_path);
            Bookmark::new(source_id.clone())
        })
    } else {
        Bookmark::new(source_id.clone())
    };

    // Check if source changed
    // TODO: Also check boot UUID for live mode to detect system reboots.
    // When boot UUID changes, timestamps reset, so we should start fresh.
    if args.resume && bookmark.source_id != source_id {
        warn!(
            "Bookmark source mismatch: expected '{expected}', got '{actual}'. Starting fresh.",
            expected = bookmark.source_id,
            actual = source_id
        );
        bookmark = Bookmark::new(source_id.clone());
    }

    let handle: Box<dyn Write> = if let Some(path) = args.output {
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

    let mut writer = OutputWriter::new(Box::new(handle), output_format.into()).unwrap();

    // Wrap bookmark in Arc<Mutex<>> for shared access
    let bookmark = Arc::new(Mutex::new(bookmark));

    // Set up signal handler using libc
    if args.resume {
        unsafe {
            libc::signal(
                libc::SIGINT,
                handle_sigint as *const () as libc::sighandler_t,
            );
        }
    }

    let result = match (args.mode.clone(), args.input.clone()) {
        (Mode::Live, None) => parse_live_system(&mut writer, Arc::clone(&bookmark), time_filter),
        (Mode::LogArchive, Some(path)) => {
            parse_log_archive(&path, &mut writer, Arc::clone(&bookmark), time_filter)
        }
        (Mode::SingleFile, Some(path)) => {
            parse_single_file(&path, &mut writer, Arc::clone(&bookmark), time_filter)
        }
        _ => {
            error!("log-archive and single-file modes require an --input argument");
            Ok(())
        }
    };

    // Check if interrupted by signal
    if SIGINT_RECEIVED.load(Ordering::SeqCst) {
        eprintln!("\nReceived interrupt signal, saving bookmark...");
        match bookmark.lock() {
            Ok(bookmark) => {
                if let Err(e) = bookmark.save(&bookmark_path) {
                    eprintln!("Failed to save bookmark on interrupt: {error}", error = e);
                } else {
                    eprintln!("Bookmark saved to {path:?}", path = bookmark_path);
                }
            }
            Err(_) => {
                eprintln!("Warning: Could not acquire bookmark lock (mutex poisoned). Bookmark not saved.");
            }
        }
        std::process::exit(0);
    }

    // Save bookmark on normal exit
    if args.resume {
        match bookmark.lock() {
            Ok(bookmark) => {
                if let Err(e) = bookmark.save(&bookmark_path) {
                    error!("Failed to save bookmark: {error}", error = e);
                } else {
                    info!("Bookmark saved to {path:?}", path = bookmark_path);
                }
            }
            Err(_) => {
                error!("Could not acquire bookmark lock (mutex poisoned). Bookmark not saved.");
            }
        }
    }

    if let Err(e) = result {
        error!("Error during parsing: {error}", error = e);
    }
}

fn parse_single_file(
    path: &Path,
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    time_filter: TimeFilter,
) -> Result<(), Box<dyn Error>> {
    let mut provider = LogarchiveProvider::new(path);
    let results = match fs::File::open(path)
        .map_err(|e| RuntimeError::FileOpen {
            path: path.to_string_lossy().to_string(),
            message: e.to_string(),
        })
        .and_then(|mut reader| {
            parse_log(&mut reader).map_err(|err| RuntimeError::FileParse {
                path: path.to_string_lossy().to_string(),
                message: format!("{err}"),
            })
        })
        .map(|ref log| {
            let (results, _) = build_log(log, &mut provider, &HashMap::new(), false);
            results
        }) {
        Ok(reader) => reader,
        Err(e) => {
            error!("Failed to parse {path:?}: {error}", path = path, error = e);
            return Ok(());
        }
    };

    let results = match filter_log_data_by_time(results, time_filter.start, time_filter.end) {
        Ok(results) => results,
        Err(err) => {
            error!("Invalid time filter: {error}", error = err);
            return Ok(());
        }
    };
    let total_count = results.len();
    let mut count = 0;
    let mut max_seen_timestamp: f64 = 0.0;

    for row in results {
        // Track max timestamp seen (including filtered) to advance bookmark
        if row.time > max_seen_timestamp {
            max_seen_timestamp = row.time;
        }

        // Skip entries older than bookmark
        let should_process = {
            let bookmark = bookmark.lock().unwrap();
            bookmark.should_process_entry(row.time)
        };

        if !should_process {
            continue;
        }

        if let Err(e) = writer.write_record(&row) {
            error!("Error writing record: {error}", error = e);
        } else {
            count += 1;
        }
    }

    // Update bookmark with max timestamp seen (not just written) to avoid re-scanning
    if max_seen_timestamp > 0.0 {
        let mut bookmark = bookmark.lock().unwrap();
        bookmark.update_timestamp(max_seen_timestamp);
    }

    info!(
        "Wrote {written} new log entries (skipped {skipped} older)",
        written = count,
        skipped = total_count - count
    );
    Ok(())
}

// Parse a provided directory path. Currently, expect the path to follow macOS log collect structure
fn parse_log_archive(
    path: &Path,
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    time_filter: TimeFilter,
) -> Result<(), Box<dyn Error>> {
    let mut provider = LogarchiveProvider::new(path);

    // Parse all timesync files
    let timesync_data = collect_timesync(&provider).unwrap();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    match parse_trace_file(&timesync_data, &mut provider, writer, bookmark, time_filter) {
        Ok(()) => {
            info!("Finished parsing Unified Log data.");
            Ok(())
        }
        Err(BrokenPipeError) => {
            info!("Stopped early due to broken pipe (output closed)");
            Ok(())
        }
    }
}

// Parse a live macOS system
fn parse_live_system(
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    time_filter: TimeFilter,
) -> Result<(), Box<dyn Error>> {
    let mut provider = LiveSystemProvider::default();
    let timesync_data = collect_timesync(&provider).unwrap();

    match parse_trace_file(&timesync_data, &mut provider, writer, bookmark, time_filter) {
        Ok(()) => {
            info!("Finished parsing Unified Log data.");
            Ok(())
        }
        Err(BrokenPipeError) => {
            info!("Stopped early due to broken pipe (output closed)");
            Ok(())
        }
    }
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
fn parse_trace_file(
    timesync_data: &HashMap<String, TimesyncBoot>,
    provider: &mut dyn FileProvider,
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    time_filter: TimeFilter,
) -> Result<(), BrokenPipeError> {
    let mut context = IterationContext {
        missing_data: Vec::new(),
        oversize_strings: UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        },
    };
    let mut parse_context = ParseContext {
        time_filter,
        bookmark,
        context: &mut context,
    };
    // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
    // Some log entries have Oversize strings located in different tracev3 files.
    // This is very rare. Seen in ~20 log entries out of ~700,000. Seen in ~700 out of ~18 million
    // Loop through all tracev3 files in Persist directory
    let mut log_count = 0;
    let mut skipped_count = 0;
    for mut source in provider.tracev3_files() {
        // Check for interrupt signal
        if SIGINT_RECEIVED.load(Ordering::SeqCst) {
            info!("Interrupted by signal, stopping log parsing");
            return Err(BrokenPipeError);
        }
        if Path::new(source.source_path())
            .file_name()
            .is_some_and(|f| f.to_str().unwrap().starts_with("._"))
        {
            continue;
        }
        info!("Parsing: {path}", path = source.source_path());
        match iterate_chunks(
            source.reader(),
            provider,
            timesync_data,
            writer,
            &mut parse_context,
        ) {
            Ok((new_count, new_skipped)) => {
                log_count += new_count;
                skipped_count += new_skipped;
                debug!(
                    "count: {count}, skipped: {skipped}",
                    count = log_count,
                    skipped = skipped_count
                );
            }
            Err(BrokenPipeError) => {
                info!("Broken pipe detected, stopping log parsing");
                return Err(BrokenPipeError);
            }
        }
    }
    let include_missing = false;
    debug!(
        "Oversize cache size: {size}",
        size = parse_context.context.oversize_strings.oversize.len()
    );
    debug!(
        "Logs with missing Oversize strings: {count}",
        count = parse_context.context.missing_data.len()
    );
    debug!("Checking Oversize cache one more time...");

    // Since we have all Oversize entries now. Go through any log entries that we were not able to build before
    let leftover_data = std::mem::take(&mut parse_context.context.missing_data);
    for mut leftover_data in leftover_data {
        // Add all of our previous oversize data to logs for lookups
        leftover_data.oversize = parse_context.context.oversize_strings.oversize.clone();

        // Exclude_missing = false
        // If we fail to find any missing data its probably due to the logs rolling
        // Ex: tracev3A rolls, tracev3B references Oversize entry in tracev3A will trigger missing data since tracev3A is gone
        let (results, _) = build_log(&leftover_data, provider, timesync_data, include_missing);
        let results = match filter_log_data_by_time(
            results,
            parse_context.time_filter.start,
            parse_context.time_filter.end,
        ) {
            Ok(results) => results,
            Err(err) => {
                error!("Invalid time filter: {error}", error = err);
                return Err(BrokenPipeError);
            }
        };

        // Track max timestamp seen (including filtered) to advance bookmark even if all filtered
        let max_seen_timestamp = results
            .iter()
            .map(|r| r.time)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Filter results by bookmark
        let filtered_results: Vec<LogData> = results
            .into_iter()
            .filter(|r| {
                let should_process = {
                    let bookmark = parse_context.bookmark.lock().unwrap();
                    bookmark.should_process_entry(r.time)
                };
                if should_process {
                    true
                } else {
                    skipped_count += 1;
                    false
                }
            })
            .collect();

        log_count += filtered_results.len();

        // Update bookmark with max timestamp seen (not just filtered) to avoid re-scanning
        if let Some(max_time) = max_seen_timestamp {
            let mut bookmark = parse_context.bookmark.lock().unwrap();
            bookmark.update_timestamp(max_time);
        }

        if let Err(err) = output(&filtered_results, writer) {
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
            {
                return Err(BrokenPipeError);
            }
            log::error!("Failed to output remaining log data: {err:?}");
        }
    }
    info!(
        "Parsed {count} log entries (skipped {skipped} older entries)",
        count = log_count,
        skipped = skipped_count
    );
    Ok(())
}

fn iterate_chunks(
    mut reader: impl Read,
    provider: &mut dyn FileProvider,
    timesync_data: &HashMap<String, TimesyncBoot>,
    writer: &mut OutputWriter,
    parse_context: &mut ParseContext,
) -> Result<(usize, usize), BrokenPipeError> {
    let mut buf = Vec::new();

    if let Err(err) = reader.read_to_end(&mut buf) {
        log::error!("Failed to read tracev3 file: {err:?}");
        return Ok((0, 0));
    }

    let log_iterator = UnifiedLogIterator {
        data: buf,
        header: Vec::new(),
    };

    // Exclude missing data from returned output. Keep separate until we parse all oversize entries.
    // Then after parsing all logs, go through all missing data and check all parsed oversize entries again
    let exclude_missing = true;

    let mut count = 0;
    let mut skipped = 0;
    for mut chunk in log_iterator {
        // Check for interrupt signal
        if SIGINT_RECEIVED.load(Ordering::SeqCst) {
            debug!("Interrupted by signal in chunk processing");
            return Err(BrokenPipeError);
        }

        chunk
            .oversize
            .append(&mut parse_context.context.oversize_strings.oversize);
        let (results, missing_logs) = build_log(&chunk, provider, timesync_data, exclude_missing);
        let results = match filter_log_data_by_time(
            results,
            parse_context.time_filter.start,
            parse_context.time_filter.end,
        ) {
            Ok(results) => results,
            Err(err) => {
                error!("Invalid time filter: {error}", error = err);
                return Err(BrokenPipeError);
            }
        };

        // Track max timestamp seen (including filtered) to advance bookmark even if all filtered
        let max_seen_timestamp = results
            .iter()
            .map(|r| r.time)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Filter results by bookmark timestamp
        let filtered_results: Vec<LogData> = results
            .into_iter()
            .filter(|r| {
                let should_process = {
                    let bookmark = parse_context.bookmark.lock().unwrap();
                    bookmark.should_process_entry(r.time)
                };
                if should_process {
                    true
                } else {
                    skipped += 1;
                    false
                }
            })
            .collect();

        count += filtered_results.len();
        parse_context.context.oversize_strings.oversize = chunk.oversize;

        // Update bookmark with max timestamp seen (not just filtered) to avoid re-scanning
        if let Some(max_time) = max_seen_timestamp {
            let mut bookmark = parse_context.bookmark.lock().unwrap();
            bookmark.update_timestamp(max_time);
        }

        if let Err(err) = output(&filtered_results, writer) {
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
            {
                debug!("Broken pipe detected, saving bookmark before exit...");
                return Err(BrokenPipeError);
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
        parse_context.context.missing_data.push(missing_logs);
    }

    Ok((count, skipped))
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
                error!("Unsupported output format: {output_format}");
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
