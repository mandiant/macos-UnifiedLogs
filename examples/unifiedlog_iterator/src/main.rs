// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::SecondsFormat;
use log::{LevelFilter, error, info, warn};
use macos_unifiedlogs::cache::{StringCatalog, StringStorage};
use macos_unifiedlogs::filesystem::{InMemoryProvider, LiveSystemProvider, LogarchiveProvider};
use macos_unifiedlogs::log_entry::LogEntry;
use macos_unifiedlogs::logarchive::load_timesync_data;
use macos_unifiedlogs::timesync::TimestampResolver;
use macos_unifiedlogs::tracev3::{OversizeCache, visit_tracev3};
use macos_unifiedlogs::traits::{FileProvider, SourceFile};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{Parser, ValueEnum, builder};
use csv::Writer;

/// Global atomic flag to track SIGINT signal
static SIGINT_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Signal handler function for SIGINT
extern "C" fn handle_sigint(_sig: libc::c_int) {
    SIGINT_RECEIVED.store(true, Ordering::SeqCst);
}

use crate::bookmark::Bookmark;

mod bookmark;

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

    // Determine source ID for bookmark
    let source_id = match (&args.mode, &args.input) {
        (Mode::Live, _) => "live".to_string(),
        (Mode::LogArchive | Mode::SingleFile, Some(path)) => path.to_string_lossy().to_string(),
        _ => "unknown".to_string(),
    };

    let mode_str = format!("{:?}", args.mode).to_lowercase();
    let bookmark_path = args
        .bookmark_path
        .clone()
        .unwrap_or_else(|| Bookmark::default_path(&mode_str));

    info!(
        "Using bookmark path: {path}",
        path = bookmark_path.display()
    );

    let mut bookmark = if args.resume {
        Bookmark::load_bookmark(&bookmark_path).unwrap_or_else(|| {
            info!(
                "Creating new bookmark at {path}",
                path = bookmark_path.display()
            );
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

    let resume = args.resume;
    let result = match (args.mode.clone(), args.input.clone()) {
        (Mode::Live, None) => parse_live_system(&mut writer, Arc::clone(&bookmark), resume),
        (Mode::LogArchive, Some(path)) => {
            parse_log_archive(&path, &mut writer, Arc::clone(&bookmark), resume)
        }
        (Mode::SingleFile, Some(path)) => {
            parse_single_file(&path, &mut writer, Arc::clone(&bookmark), resume);
            Ok(())
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
                if let Err(e) = bookmark.save_bookmark(&bookmark_path) {
                    eprintln!("Failed to save bookmark on interrupt: {e}");
                } else {
                    eprintln!("Bookmark saved to {path}", path = bookmark_path.display());
                }
            }
            Err(_) => {
                eprintln!(
                    "Warning: Could not acquire bookmark lock (mutex poisoned). Bookmark not saved."
                );
            }
        }
        std::process::exit(0);
    }

    // Save bookmark on normal exit
    if args.resume {
        match bookmark.lock() {
            Ok(bookmark) => {
                if let Err(e) = bookmark.save_bookmark(&bookmark_path) {
                    error!("Failed to save bookmark: {e}");
                } else {
                    info!("Bookmark saved to {path}", path = bookmark_path.display());
                }
            }
            Err(_) => {
                error!("Could not acquire bookmark lock (mutex poisoned). Bookmark not saved.");
            }
        }
    }

    if let Err(e) = result {
        error!("Error during parsing: {e}");
    }
}

/// Tracks per-run visit state: bookmark filtering, counters, early-stop conditions.
struct VisitState<'w> {
    writer: &'w mut OutputWriter,
    resume: bool,
    // Snapshot of bookmark timestamp at start of this run.
    // Important: tracev3 files are not guaranteed to be processed in timestamp order.
    // We must not advance the filter threshold mid-run, or we can incorrectly drop
    // older entries from later-processed files.
    resume_timestamp: f64,
    max_seen_timestamp: f64,
    log_count: usize,
    skipped_count: usize,
    broken_pipe: bool,
}

impl<'w> VisitState<'w> {
    fn new(writer: &'w mut OutputWriter, bookmark: &Arc<Mutex<Bookmark>>, resume: bool) -> Self {
        let resume_timestamp = if resume {
            bookmark.lock().map(|b| b.last_timestamp).unwrap_or(0.0)
        } else {
            0.0
        };
        Self {
            writer,
            resume,
            resume_timestamp,
            max_seen_timestamp: 0.0,
            log_count: 0,
            skipped_count: 0,
            broken_pipe: false,
        }
    }

    /// Handle one log entry: bookmark filter, write, track counters.
    fn handle(&mut self, entry: &LogEntry<'_, '_>) {
        if self.broken_pipe {
            return;
        }
        if entry.time > self.max_seen_timestamp {
            self.max_seen_timestamp = entry.time;
        }
        // Filter using the timestamp captured at the start of the run.
        if self.resume && entry.time <= self.resume_timestamp {
            self.skipped_count += 1;
            return;
        }
        match self.writer.write_record(entry) {
            Ok(()) => self.log_count += 1,
            Err(e) if is_broken_pipe(e.as_ref()) => {
                info!("Broken pipe detected, stopping output");
                self.broken_pipe = true;
            }
            Err(e) => error!("Error writing record: {e}"),
        }
    }

    /// Update bookmark with max timestamp seen (not just written) to avoid re-scanning.
    fn finish(self, bookmark: &Arc<Mutex<Bookmark>>) {
        if self.resume
            && self.max_seen_timestamp > 0.0
            && let Ok(mut book) = bookmark.lock()
        {
            book.update_timestamp(self.max_seen_timestamp);
        }
        let _ = self.writer.flush();
        info!(
            "Parsed {count} log entries (skipped {skipped} older entries)",
            count = self.log_count,
            skipped = self.skipped_count
        );
    }
}

fn is_broken_pipe(err: &(dyn Error + 'static)) -> bool {
    let mut source = Some(err);
    while let Some(err) = source {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return io_err.kind() == std::io::ErrorKind::BrokenPipe;
        }
        source = err.source();
    }
    false
}

/// Parse a bare tracev3 file without logarchive context (no timesync or string files:
/// timestamps stay unresolved and format strings come from the entries themselves).
fn parse_single_file(
    path: &Path,
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    resume: bool,
) {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            error!(
                "Failed to open source file {path}: {e}",
                path = path.display()
            );
            return;
        }
    };

    let resolver = TimestampResolver::new(HashMap::new());
    let storage = StringStorage::new(InMemoryProvider::default());
    let strings = StringCatalog::new(&storage);
    let mut oversize_cache = OversizeCache::new();

    let mut state = VisitState::new(writer, &bookmark, resume);
    if let Err(e) = visit_tracev3(
        &data,
        &resolver,
        &strings,
        &mut oversize_cache,
        Rc::new(path.to_path_buf()),
        |entry| state.handle(&entry),
    ) {
        error!("Failed to parse {path}: {e}", path = path.display());
    }
    state.finish(&bookmark);
}

// Parse a provided directory path. Currently, expect the path to follow macOS log collect structure
fn parse_log_archive(
    path: &Path,
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    resume: bool,
) -> Result<(), Box<dyn Error>> {
    let provider = LogarchiveProvider::new(path);
    visit_with_provider(&provider, writer, bookmark, resume)
}

// Parse a live macOS system
fn parse_live_system(
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    resume: bool,
) -> Result<(), Box<dyn Error>> {
    let provider = LiveSystemProvider::default();
    visit_with_provider(&provider, writer, bookmark, resume)
}

/// Visit all tracev3 sources from the provider, writing entries through the bookmark filter.
///
/// This mirrors `logarchive::visit_provider` but drives the per-file loop itself so it
/// can stop between files on SIGINT or a broken pipe. String data loads lazily; the
/// oversize cache is carried across files (oversize payloads can live in another file).
fn visit_with_provider(
    provider: &impl FileProvider,
    writer: &mut OutputWriter,
    bookmark: Arc<Mutex<Bookmark>>,
    resume: bool,
) -> Result<(), Box<dyn Error>> {
    let timesync_data = load_timesync_data(provider)?;
    let resolver = TimestampResolver::new(timesync_data);
    let storage = StringStorage::new(provider);
    let strings = StringCatalog::new(&storage);
    let mut oversize_cache = OversizeCache::new();

    let mut state = VisitState::new(writer, &bookmark, resume);
    for mut source in provider.tracev3_files() {
        // Check for interrupt signal or closed output between files
        if SIGINT_RECEIVED.load(Ordering::SeqCst) {
            info!("Interrupted by signal, stopping log parsing");
            break;
        }
        if state.broken_pipe {
            break;
        }
        if Path::new(source.source_path())
            .file_name()
            .is_some_and(|f| f.to_str().unwrap_or_default().starts_with("._"))
        {
            continue;
        }
        info!("Parsing: {path}", path = source.source_path());

        let mut data = Vec::new();
        let read_result = source.reader().read_to_end(&mut data);
        if let Err(e) = read_result {
            error!("Failed to read {path}: {e}", path = source.source_path());
            continue;
        }
        let evidence = Rc::new(PathBuf::from(source.source_path()));
        if let Err(e) = visit_tracev3(
            &data,
            &resolver,
            &strings,
            &mut oversize_cache,
            evidence,
            |entry| state.handle(&entry),
        ) {
            error!("Failed to parse {path}: {e}", path = source.source_path());
        }
    }
    state.finish(&bookmark);

    info!("Finished parsing Unified Log data.");
    Ok(())
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
                    "Parent Activity ID",
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

    pub fn write_record(&mut self, entry: &LogEntry<'_, '_>) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => {
                csv_writer.write_record(&[
                    entry
                        .timestamp()
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    format!("{:?}", entry.event_type),
                    format!("{:?}", entry.log_type),
                    entry.subsystem.unwrap_or_default().to_string(),
                    entry.thread_id.to_string(),
                    entry.pid.to_string(),
                    entry.euid.to_string(),
                    entry.library.unwrap_or_default().to_string(),
                    format_uuid(entry.library_uuid),
                    entry.activity_id.to_string(),
                    entry.parent_activity_id.unwrap_or(0).to_string(),
                    entry.category.unwrap_or_default().to_string(),
                    entry.process.unwrap_or_default().to_string(),
                    format_uuid(entry.process_uuid),
                    entry.message().to_string(),
                    entry.raw_message().to_string(),
                    format_uuid(entry.boot_uuid),
                    entry.timezone_name.to_string(),
                ])?;
            }
            OutputWriterEnum::Json(json_writer) => {
                writeln!(json_writer, "{}", serde_json::to_string(entry)?)?;
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

/// Uppercase hex UUID without hyphens, matching the historical output format.
fn format_uuid(uuid: uuid::Uuid) -> String {
    let mut buffer = uuid::Uuid::encode_buffer();
    uuid.simple().encode_upper(&mut buffer).to_string()
}
