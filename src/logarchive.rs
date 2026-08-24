//! Parsing-pipeline orchestration over a [`FileProvider`].
//!
//! Loads timesync data, then processes all tracev3 sources in order, emitting
//! `LogEntry` via callback. `UUIDText`/DSC string data is loaded lazily as
//! entries reference it (see [`crate::cache`]); use [`visit_provider_preloaded`]
//! to load everything up front instead.

use super::cache::{StringCatalog, StringStorage};
use super::error::ParseError;
use super::filesystem::{LiveSystemProvider, LogarchiveProvider};
use super::log_entry::LogEntry;
use super::timesync::{RawTimesyncBoot, TimestampResolver, parse_timesync_file};
use super::tracev3::{OversizeCache, visit_tracev3};
use super::traits::{FileProvider, SourceFile, VisitOutcome};
use log::{info, warn};
use std::collections::HashMap;
use std::io::Read;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use uuid::Uuid;

#[derive(thiserror::Error, Debug)]
pub enum VisitTracev3FileError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

/// Process all tracev3 files in a logarchive directory, emitting log entries via callback.
///
/// The callback receives each `LogEntry` as it is produced. Individual file or parse
/// failures are logged as warnings and skipped — only a missing timesync directory
/// is a hard error.
pub fn visit_logarchive<O: VisitOutcome>(
    path: &Path,
    callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> O,
) -> Result<(), std::io::Error> {
    let provider = LogarchiveProvider::new(path);
    visit_provider(&provider, callback)
}

/// Process all tracev3 files on the live macOS system, emitting log entries via callback.
///
/// This reads tracev3/timesync data from `/private/var/db/diagnostics` and UUIDText/DSC
/// support files from `/private/var/db/uuidtext`.
pub fn visit_live_system<O: VisitOutcome>(
    callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> O,
) -> Result<(), std::io::Error> {
    let provider = LiveSystemProvider::new();
    visit_provider(&provider, callback)
}

/// Process all tracev3 files from a provider, loading string data lazily.
///
/// The callback receives each `LogEntry` as it is produced. Individual file or parse
/// failures are logged as warnings and skipped — only missing timesync data
/// is a hard error. `UUIDText`/DSC files are read on demand as entries
/// reference them, keeping memory proportional to what the logs actually use.
pub fn visit_provider<O: VisitOutcome>(
    provider: &impl FileProvider,
    callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> O,
) -> Result<(), std::io::Error> {
    visit_provider_with_options(provider, VisitOptions::default(), callback)
}

/// Like [`visit_provider`], but eagerly loads every `UUIDText`/DSC file up front.
///
/// Maximum throughput at maximum memory — the pre-lazy-loading behavior.
pub fn visit_provider_preloaded<O: VisitOutcome>(
    provider: &impl FileProvider,
    callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> O,
) -> Result<(), std::io::Error> {
    visit_provider_with_options(
        provider,
        VisitOptions {
            string_loading: StringLoading::Preload,
        },
        callback,
    )
}

/// How `UUIDText`/DSC string data is loaded during a visit.
///
/// One axis, because the strategies are mutually exclusive: preloading pays
/// maximum memory for maximum throughput, while budgeting bounds memory by
/// reclaiming — combining them could only re-read every support file over
/// and over.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StringLoading {
    /// Load files on demand as log entries reference them (default).
    #[default]
    Lazy,
    /// Eagerly load every file up front: maximum throughput, maximum memory.
    Preload,
    /// Load on demand, reclaiming the string storage once the loaded
    /// `UUIDText`/DSC bytes exceed this soft threshold.
    ///
    /// The check runs between tracev3 files — the only points where no log
    /// entry borrows the storage — so a single file's working set may
    /// overshoot the threshold before reclaim happens. Reclaimed files are
    /// re-read and re-parsed if later entries reference them again: lower
    /// thresholds trade throughput for a bounded footprint in long-running
    /// processes.
    Budgeted(usize),
}

/// Tuning knobs for [`visit_provider_with_options`].
#[derive(Debug, Clone, Copy, Default)]
pub struct VisitOptions {
    /// How `UUIDText`/DSC string data is loaded.
    pub string_loading: StringLoading,
}

/// Like [`visit_provider`], with explicit [`VisitOptions`].
///
/// The callback may return [`ControlFlow::Break`] to stop the visit early
/// (see [`VisitOutcome`]); the remaining entries and files are skipped and
/// the function returns `Ok(())`.
pub fn visit_provider_with_options<O: VisitOutcome>(
    provider: &impl FileProvider,
    options: VisitOptions,
    mut callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> O,
) -> Result<(), std::io::Error> {
    // 1. Timesync → TimestampResolver
    let timesync_data = load_timesync_data(provider)?;
    let resolver = TimestampResolver::new(timesync_data);

    // 2. Oversize entries (owned) survive storage reclaims
    let oversize_cache = OversizeCache::with_provider(provider);
    let mut sources = provider.tracev3_files();

    // 3. Process all tracev3 sources, one storage generation at a time.
    // Entries only live inside the callback, so dropping the storage between
    // two files is safe; the budget decides when a fresh generation starts.
    'generations: loop {
        let storage = StringStorage::new(provider);
        if options.string_loading == StringLoading::Preload {
            // Preload never starts a second generation, so this runs once
            storage.preload();
        }
        let strings = StringCatalog::new(&storage);

        loop {
            let Some(mut source) = sources.next() else {
                break 'generations;
            };
            info!("Parsing: {}", source.source_path());
            let mut data = Vec::new();
            let read_result = source.reader().read_to_end(&mut data);
            if let Err(e) = read_result {
                warn!("Failed to read {}: {e}", source.source_path());
                continue;
            }

            oversize_cache.mark_covered(source.source_path());
            match visit_tracev3(
                &data,
                &resolver,
                &strings,
                &oversize_cache,
                Rc::new(PathBuf::from(source.source_path())),
                |entry| callback(entry).into_flow(),
            ) {
                Ok(ControlFlow::Break(())) => return Ok(()),
                Ok(ControlFlow::Continue(())) => {}
                Err(e) => warn!("Failed to process {}: {e}", source.source_path()),
            }

            if let StringLoading::Budgeted(budget) = options.string_loading
                && storage.loaded_bytes() > budget
            {
                break; // start a new generation, dropping all loaded strings
            }
        }
    }

    Ok(())
}

/// Helper function to process one tracev3 file from a logarchive, emitting log entries via callback.
///
/// The tracev3 path is resolved relative to `logarchive_path`. This helper loads
/// the logarchive's timesync, DSC, and `UUIDText` support files before visiting the
/// selected tracev3 file.
pub fn visit_logarchive_tracev3_file<O: VisitOutcome>(
    logarchive_path: &Path,
    tracev3_path: impl AsRef<Path>,
    mut callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> O,
) -> Result<(), VisitTracev3FileError> {
    visit_logarchive_tracev3_files(logarchive_path, &[tracev3_path], |_, entry| callback(entry))
}

/// Helper function to process selected tracev3 files from a logarchive in the provided order.
///
/// Tracev3 paths are resolved relative to `logarchive_path`. A single oversize
/// cache is shared across all files, so callers can visit neighboring Persist,
/// Special, and `LiveData` files when oversize payloads are referenced across files.
/// The callback receives the zero-based index of the tracev3 path that produced
/// each entry.
pub fn visit_logarchive_tracev3_files<P: AsRef<Path>, O: VisitOutcome>(
    logarchive_path: &Path,
    tracev3_paths: &[P],
    mut callback: impl for<'a, 'b> FnMut(usize, LogEntry<'a, 'b>) -> O,
) -> Result<(), VisitTracev3FileError> {
    let provider = LogarchiveProvider::new(logarchive_path);
    let timesync_data = load_timesync_data(&provider)?;
    let resolver = TimestampResolver::new(timesync_data);
    let storage = StringStorage::new(&provider);
    let strings = StringCatalog::new(&storage);
    let oversize_cache = OversizeCache::with_provider(&provider);

    for (index, tracev3_path) in tracev3_paths.iter().enumerate() {
        let evidence = logarchive_path.join(tracev3_path);
        let data = std::fs::read(&evidence)?;
        // Must match LocalFile's source_path() string for the same file
        oversize_cache.mark_covered(&evidence.to_string_lossy());
        if visit_tracev3(
            &data,
            &resolver,
            &strings,
            &oversize_cache,
            Rc::new(evidence),
            |entry| callback(index, entry).into_flow(),
        )?
        .is_break()
        {
            return Ok(());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Support-file loading
// ---------------------------------------------------------------------------

/// Load and merge all `.timesync` sources from the provider.
///
/// Errors with [`std::io::ErrorKind::NotFound`] when the provider yields no
/// timesync sources at all — without timesync data no timestamp can be
/// resolved. (Unreadable/unparsable individual files are warned and skipped.)
pub fn load_timesync_data(
    provider: &impl FileProvider,
) -> Result<HashMap<Uuid, RawTimesyncBoot>, std::io::Error> {
    let mut all_data: HashMap<Uuid, RawTimesyncBoot> = HashMap::new();
    let mut found_any = false;

    for mut source in provider.timesync_files() {
        found_any = true;
        let mut buffer = Vec::new();
        let read_result = source.reader().read_to_end(&mut buffer);
        if let Err(e) = read_result {
            warn!("Failed to read timesync {}: {e}", source.source_path());
            continue;
        }
        let (_, file_data) = match parse_timesync_file(&buffer) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to parse timesync {}: {e}", source.source_path());
                continue;
            }
        };
        for (uuid, mut boot) in file_data {
            if let Some(existing) = all_data.get_mut(&uuid) {
                existing.records.append(&mut boot.records);
            } else {
                all_data.insert(uuid, boot);
            }
        }
    }

    if !found_any {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no timesync files found",
        ));
    }
    Ok(all_data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::collect_tracev3_paths;
    use crate::helpers::tests::test_data_path;

    #[test]
    fn test_log_entry_json_schema() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");

        let mut first: Option<serde_json::Value> = None;
        let mut count = 0_usize;
        visit_logarchive_tracev3_file(&base, "Persist/0000000000000001.tracev3", |entry| {
            first = Some(serde_json::to_value(&entry).unwrap());
            count += 1;
            ControlFlow::Break(())
        })
        .unwrap();
        assert_eq!(count, 1, "Break must stop after the first entry");
        let entry = first.unwrap();

        // UUIDs are uppercase hex without hyphens, matching CSV and the
        // historical JSONL format
        for field in ["library_uuid", "process_uuid", "boot_uuid"] {
            let uuid = entry[field].as_str().unwrap();
            assert_eq!(uuid.len(), 32, "{field} should be bare hex: {uuid}");
            assert!(
                uuid.chars()
                    .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase()),
                "{field} should be uppercase hex: {uuid}"
            );
        }
        assert_eq!(
            entry["boot_uuid"].as_str().unwrap(),
            "9A6A3124274A44B29ABF2BC9E4599B3B"
        );

        // RFC3339 timestamp restored, consistent with the nanosecond `time`
        let timestamp = entry["timestamp"].as_str().unwrap();
        let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
        let time = entry["time"].as_f64().unwrap();
        let delta = (parsed.timestamp_nanos_opt().unwrap() as f64 - time).abs();
        assert!(
            delta < 1_000.0,
            "timestamp {timestamp} should match time {time}"
        );

        // Renames/removals locked in
        assert!(entry.get("format_string").is_some());
        assert!(entry.get("raw_message").is_none());
        assert!(entry.get("message_entries").is_none());
    }

    #[test]
    fn test_visit_early_exit_breaks_mid_archive() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");

        let mut count = 0_usize;
        visit_logarchive(&base, |_entry| {
            count += 1;
            if count == 100 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();

        // The first tracev3 file alone holds far more than 100 entries,
        // so an exact count proves the visit stopped mid-file.
        assert_eq!(count, 100);
    }

    #[test]
    fn test_visit_files_break_stops_path_loop() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");

        let mut count = 0_usize;
        visit_logarchive_tracev3_files(
            &base,
            &[
                "Persist/0000000000000001.tracev3",
                "Persist/0000000000000002.tracev3",
            ],
            |index, _entry| {
                assert_eq!(index, 0, "Break during file 0 must skip file 1");
                count += 1;
                if count == 10 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            },
        )
        .unwrap();

        assert_eq!(count, 10);
    }

    #[test]
    fn test_visit_logarchive_big_sur() {
        use crate::log_entry::{EventType, LogType};

        let base = test_data_path().join("system_logs_big_sur.logarchive");

        let mut count = 0_usize;
        visit_logarchive(&base, |entry| {
            // Regression assertions on the first entry (from Persist/0000000000000001.tracev3)
            if count == 0 {
                assert_eq!(
                    entry.process,
                    Some("/usr/libexec/lightsoutmanagementRecoveryOSd")
                );
                assert_eq!(
                    entry.library,
                    Some("/usr/libexec/lightsoutmanagementRecoveryOSd")
                );
                assert_eq!(entry.subsystem, None);
                assert_eq!(entry.category, None);
                assert_eq!(entry.pid, 50);
                assert_eq!(entry.euid, 0);
                assert_eq!(entry.thread_id, 663);
                assert_eq!(entry.activity_id, 0);
                assert_eq!(entry.event_type, EventType::Log);
                assert_eq!(entry.log_type, LogType::Default);
                assert_eq!(entry.time, 1_642_302_211_489_633_000.0);
                assert_eq!(
                    entry.boot_uuid,
                    Uuid::parse_str("9a6a3124-274a-44b2-9abf-2bc9e4599b3b").unwrap()
                );
                assert_eq!(entry.timezone_name, "Pacific");
                assert_eq!(entry.format_string, Some("%s"));
                assert_eq!(entry.message().as_str(), "main");
            }
            count += 1;
        })
        .unwrap();

        assert_eq!(
            count, 747_616,
            "expected 747,616 entries from full logarchive, got {count}"
        );
    }

    #[test]
    fn test_collect_tracev3_paths_order() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");
        let paths = collect_tracev3_paths(&base);

        // Should have files from Persist, Special, Signpost (HighVolume is empty in test data)
        // plus logdata.LiveData.tracev3
        assert!(!paths.is_empty(), "should find at least one tracev3 file");

        // Persist files should come first
        let first = paths[0].to_string_lossy();
        assert!(
            first.contains("Persist"),
            "first tracev3 should be from Persist/, got: {first}"
        );

        // LiveData should be last
        let last = paths.last().unwrap().to_string_lossy();
        assert!(
            last.contains("LiveData"),
            "last tracev3 should be LiveData, got: {last}"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_visit_live_system() {
        use crate::log_entry::EventType;
        use chrono::SecondsFormat;

        visit_live_system(|entry| {
            assert_ne!(
                entry.event_type,
                EventType::Unknown,
                "Got unknown event type for {entry:?}"
            );

            assert!(
                !entry
                    .timestamp()
                    .to_rfc3339_opts(SecondsFormat::Nanos, true)
                    .starts_with("1970-")
            );
        })
        .unwrap();
    }

    #[test]
    fn test_visit_with_memory_budget_matches_unbudgeted() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(&base);

        // 1-byte budget: a fresh storage generation after every tracev3 file.
        let options = VisitOptions {
            string_loading: StringLoading::Budgeted(1),
        };
        let mut count = 0_usize;
        let mut messages = 0_usize;
        visit_provider_with_options(&provider, options, |entry| {
            count += 1;
            if count.is_multiple_of(1000) {
                messages += entry.message().len();
            }
        })
        .unwrap();

        let mut unbudgeted_count = 0_usize;
        let mut unbudgeted_messages = 0_usize;
        visit_provider(&provider, |entry| {
            unbudgeted_count += 1;
            if unbudgeted_count.is_multiple_of(1000) {
                unbudgeted_messages += entry.message().len();
            }
        })
        .unwrap();

        assert_eq!(count, 747_616);
        assert_eq!(count, unbudgeted_count);
        assert_eq!(messages, unbudgeted_messages);
    }

    #[test]
    fn test_load_timsync_data() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(&base);
        let times = load_timesync_data(&provider).unwrap();
        assert_eq!(times.len(), 5);
    }

    #[test]
    fn test_load_timesync_data_errors_without_sources() {
        let provider = crate::filesystem::InMemoryProvider::default();
        let err = load_timesync_data(&provider).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
