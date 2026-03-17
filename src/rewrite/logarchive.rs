//! Logarchive directory walker — orchestrates the full parsing pipeline.
//!
//! Scans a `.logarchive` directory, loads timesync/DSC/UUIDText data,
//! then processes all tracev3 files in order, emitting `LogEntry` via callback.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use log::warn;
use uuid::Uuid;

use super::dsc::RawSharedCacheStrings;
use super::log_entry::LogEntry;
use super::timesync::{RawTimesyncBoot, TimestampResolver, parse_timesync_file};
use super::tracev3::{OversizeCache, visit_tracev3};
use super::uuidtext::RawUUIDText;

/// Process all tracev3 files in a logarchive directory, emitting log entries via callback.
///
/// The callback receives each `LogEntry` as it is produced. Individual file or parse
/// failures are logged as warnings and skipped — only a missing timesync directory
/// is a hard error.
pub fn visit_logarchive(
    path: &Path,
    mut callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>),
) -> Result<(), std::io::Error> {
    // 1. Timesync → TimestampResolver
    let timesync_data = load_timesync_data(&path.join("timesync"))?;
    let resolver = TimestampResolver::new(timesync_data);

    // 2. DSC files → HashMap<Uuid, RawSharedCacheStrings>
    let dsc_buffers = load_file_buffers_by_uuid(&path.join("dsc"));
    let dsc_files: HashMap<Uuid, RawSharedCacheStrings<'_>> = dsc_buffers
        .iter()
        .filter_map(|(uuid, buffer)| {
            let (_, dsc) = RawSharedCacheStrings::parse(buffer)
                .inspect_err(|e| warn!("Failed to parse DSC {uuid}: {e}"))
                .ok()?;
            Some((*uuid, dsc))
        })
        .collect();

    // 3. UUIDText files → HashMap<Uuid, RawUUIDText>
    let uuidtext_buffers = load_uuidtext_buffers(path);
    let uuidtext_files: HashMap<Uuid, RawUUIDText<'_>> = uuidtext_buffers
        .iter()
        .filter_map(|(uuid, buffer)| {
            let (_, uuidtext) = RawUUIDText::parse(buffer)
                .inspect_err(|e| warn!("Failed to parse UUIDText {uuid}: {e}"))
                .ok()?;
            Some((*uuid, uuidtext))
        })
        .collect();

    // 4. Collect and process all tracev3 files
    let tracev3_paths = collect_tracev3_paths(path);
    let mut oversize_cache = OversizeCache::new();

    for tracev3_path in &tracev3_paths {
        let data = match std::fs::read(tracev3_path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read {}: {e}", tracev3_path.display());
                continue;
            }
        };

        if let Err(e) = visit_tracev3(
            &data,
            &resolver,
            &dsc_files,
            &uuidtext_files,
            &mut oversize_cache,
            |entry| {
                callback(entry);
            },
        ) {
            warn!("Failed to process {}: {e}", tracev3_path.display());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Load and merge all `.timesync` files from the timesync directory.
pub fn load_timesync_data(dir: &Path) -> Result<HashMap<Uuid, RawTimesyncBoot>, std::io::Error> {
    let mut all_data: HashMap<Uuid, RawTimesyncBoot> = HashMap::new();

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("timesync") {
            continue;
        }
        let buffer = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to read timesync {}: {e}", path.display());
                continue;
            }
        };
        let (_, file_data) = match parse_timesync_file(&buffer) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to parse timesync {}: {e}", path.display());
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

    Ok(all_data)
}

/// Load files from a directory where filenames are UUIDs (e.g. `dsc/`).
pub fn load_file_buffers_by_uuid(dir: &Path) -> Vec<(Uuid, Vec<u8>)> {
    let mut buffers = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return buffers,
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(uuid) = Uuid::parse_str(name) else {
            continue;
        };
        match std::fs::read(&path) {
            Ok(buffer) => buffers.push((uuid, buffer)),
            Err(e) => warn!("Failed to read DSC {}: {e}", path.display()),
        }
    }
    buffers
}

/// Load `UUIDText` files from 2-char hex directories at the logarchive root.
///
/// Directory layout: `{XX}/{YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY}`
/// Full UUID = `XX` + `YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY` (32 hex chars).
pub fn load_uuidtext_buffers(base: &Path) -> Vec<(Uuid, Vec<u8>)> {
    let mut buffers = Vec::new();
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return buffers,
    };
    for dir_entry in entries {
        let dir_entry = match dir_entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let dir_name = dir_entry.file_name();
        let dir_name_str = dir_name.to_string_lossy();
        // Only 2-char hex directories
        if dir_name_str.len() != 2 || !dir_name_str.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let dir_path = dir_entry.path();
        if !dir_path.is_dir() {
            continue;
        }
        let file_entries = match std::fs::read_dir(&dir_path) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for file_entry in file_entries {
            let file_entry = match file_entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let file_path = file_entry.path();
            if !file_path.is_file() {
                continue;
            }
            let file_name = file_entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            let uuid_str = format!("{dir_name_str}{file_name_str}");
            let Ok(uuid) = Uuid::parse_str(&uuid_str) else {
                continue;
            };
            match std::fs::read(&file_path) {
                Ok(buffer) => buffers.push((uuid, buffer)),
                Err(e) => warn!("Failed to read UUIDText {}: {e}", file_path.display()),
            }
        }
    }
    buffers
}

/// Collect all tracev3 file paths in processing order.
///
/// Order: `HighVolume` → `Persist` → `Signpost` → `Special` → `logdata.LiveData.tracev3` (alphabetical)
/// Within each directory, files are sorted by name (numeric ordering).
fn collect_tracev3_paths(base: &Path) -> Vec<PathBuf> {
    let subdirs = ["HighVolume", "Persist", "Signpost", "Special"];
    let mut paths = Vec::new();

    for subdir in &subdirs {
        let dir = base.join(subdir);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let mut dir_paths: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("tracev3"))
                .collect();
            dir_paths.sort();
            paths.extend(dir_paths);
        }
    }

    // LiveData is a single file at the root
    let live_data = base.join("logdata.LiveData.tracev3");
    if live_data.is_file() {
        paths.push(live_data);
    }

    paths
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::helpers::tests::test_data_path;

    #[test]
    fn test_visit_logarchive_big_sur() {
        use crate::rewrite::log_entry::{EventType, LogType};

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
}
