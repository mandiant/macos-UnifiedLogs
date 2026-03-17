//! `TraceV3` file processor — threads all parsing modules together to produce log entries.

use std::cell::RefCell;
use std::collections::HashMap;

use log::warn;
use uuid::Uuid;

use super::catalog::RawCatalogChunk;
use super::chunk::{ChunksReader, TopChunk};
use super::chunks::ChunkTag;
use super::chunkset::firehose::RawFirehose;
use super::chunkset::firehose::body::{RawFirehoseBody, RawFormatterFlags};
use super::chunkset::firehose::entry::FirehoseLogType;
use super::chunkset::oversize::RawOversize;
use super::chunkset::simpledump::RawSimpleDump;
use super::chunkset::statedump::RawStatedump;
use super::dsc::RawSharedCacheStrings;
use super::error::{NomExt, ParseError};
use super::header::RawHeaderChunk;
use super::log_entry::{EventType, ItemsData, LogEntry, LogType, PrivateDataContext};
use super::resolve::resolve_strings;
use super::timesync::TimestampResolver;
use super::uuidtext::RawUUIDText;

// ---------------------------------------------------------------------------
// OversizeCache
// ---------------------------------------------------------------------------

/// Cache for oversize log entries, threaded across chunksets and tracev3 files.
///
/// Oversize entries carry strings too large for regular firehose entries.
/// They must be cached and looked up when a firehose entry references them
/// via `data_ref`.
#[derive(Debug, Default)]
pub struct OversizeCache {
    pub(crate) entries: HashMap<(u32, u64, u32), Vec<u8>>,
}

impl OversizeCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, oversize: &RawOversize<'_>) {
        self.entries.insert(
            (
                oversize.data_ref_index,
                oversize.first_proc_id,
                oversize.second_proc_id,
            ),
            oversize.oversize_data.to_vec(),
        );
    }

    fn get(&self, data_ref: u32, first_proc_id: u64, second_proc_id: u32) -> Option<&[u8]> {
        self.entries
            .get(&(data_ref, first_proc_id, second_proc_id))
            .map(|v| v.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Process a single tracev3 file buffer, emitting `LogEntry` via callback.
///
/// The callback receives each log entry as it is produced. Entry-level errors
/// (bad body parse, missing oversize data) are logged as warnings and skipped.
#[allow(clippy::too_many_arguments)]
pub fn visit_tracev3<'a>(
    data: &'a [u8],
    resolver: &TimestampResolver,
    dsc_files: &'a HashMap<Uuid, RawSharedCacheStrings<'a>>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
    oversize_cache: &mut OversizeCache,
    mut callback: impl for<'b> FnMut(LogEntry<'a, 'b>),
) -> Result<(), ParseError> {
    let mut current_header: Option<RawHeaderChunk<'a>> = None;
    let mut current_catalog: Option<RawCatalogChunk<'a>> = None;

    for top_chunk in ChunksReader::new(data) {
        let top_chunk = match top_chunk {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse top chunk: {e}");
                break;
            }
        };
        match top_chunk {
            TopChunk::Header(h) => current_header = Some(h),
            TopChunk::Catalog(c) => current_catalog = Some(c),
            TopChunk::Chunkset(mut reader) => {
                while let Some(inner) = reader.next() {
                    let inner = match inner {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("Failed to parse inner chunk: {e}");
                            break;
                        }
                    };
                    match inner.preamble.tag {
                        ChunkTag::Oversize => match RawOversize::parse(inner.data) {
                            Ok((_, ov)) => oversize_cache.insert(&ov),
                            Err(e) => {
                                warn!("Failed to parse oversize chunk: {}", e.to_parse_error());
                            }
                        },
                        ChunkTag::Firehose => {
                            let fh = match RawFirehose::parse(inner.data) {
                                Ok((_, fh)) => fh,
                                Err(e) => {
                                    warn!("Failed to parse firehose chunk: {}", e.to_parse_error());
                                    continue;
                                }
                            };

                            let Some(header) = &current_header else {
                                continue;
                            };
                            let Some(catalog) = &current_catalog else {
                                continue;
                            };

                            // Compute the extended private data region for compat mode.
                            // The old pipeline had access to the full chunkset buffer past the public data,
                            // not just the current chunk's private data. This affected oversized items.
                            #[cfg(feature = "rewrite-compat")]
                            let extended_private_data = {
                                const FIREHOSE_HEADER_SIZE: usize = 32;
                                let offset = FIREHOSE_HEADER_SIZE + fh.public_data_len();
                                if offset < inner.data_and_tail.len() {
                                    Some(&inner.data_and_tail[offset..])
                                } else {
                                    None
                                }
                            };

                            visit_firehose_entries(
                                &fh,
                                header,
                                catalog,
                                resolver,
                                dsc_files,
                                uuidtext_files,
                                oversize_cache,
                                #[cfg(feature = "rewrite-compat")]
                                extended_private_data,
                                &mut callback,
                            );
                        }
                        ChunkTag::Simpledump => match RawSimpleDump::parse(inner.data) {
                            Ok((_, sd)) => {
                                let Some(header) = &current_header else {
                                    continue;
                                };
                                let time =
                                    resolver.resolve(&header.boot_uuid, sd.continuous_time, 1);
                                let timezone_name = extract_timezone_name(header.timezone_path);
                                callback(LogEntry {
                                    subsystem: None,
                                    category: None,
                                    thread_id: sd.thread_id,
                                    pid: sd.first_proc_id,
                                    euid: 0,
                                    library: None,
                                    library_uuid: sd.sender_uuid,
                                    activity_id: 0,
                                    time,
                                    event_type: EventType::Simpledump,
                                    log_type: LogType::Simpledump,
                                    process: None,
                                    process_uuid: sd.dsc_uuid,
                                    format_string: None,
                                    boot_uuid: header.boot_uuid,
                                    timezone_name,
                                    items: ItemsData::Simpledump {
                                        subsystem: sd.subsystem,
                                        message: sd.message_string,
                                    },
                                    signpost_id: 0,
                                    signpost_name: 0,
                                    resolved_message: RefCell::new(None),
                                    #[cfg(feature = "rewrite-compat")]
                                    format_string_error: None,
                                });
                            }
                            Err(e) => {
                                warn!("Failed to parse simpledump chunk: {}", e.to_parse_error())
                            }
                        },
                        ChunkTag::Statedump => match RawStatedump::parse(inner.data) {
                            Ok((_, sd)) => {
                                let Some(header) = &current_header else {
                                    continue;
                                };
                                let time =
                                    resolver.resolve(&header.boot_uuid, sd.continuous_time, 1);
                                let timezone_name = extract_timezone_name(header.timezone_path);
                                callback(LogEntry {
                                    subsystem: None,
                                    category: None,
                                    thread_id: 0,
                                    pid: sd.first_proc_id,
                                    euid: 0,
                                    library: None,
                                    library_uuid: Uuid::nil(),
                                    activity_id: sd.activity_id,
                                    time,
                                    event_type: EventType::Statedump,
                                    log_type: LogType::Statedump,
                                    process: None,
                                    process_uuid: Uuid::nil(),
                                    format_string: None,
                                    boot_uuid: header.boot_uuid,
                                    timezone_name,
                                    items: ItemsData::Statedump {
                                        title_name: sd.title_name,
                                        decoder_library: sd.decoder_library,
                                        decoder_type: sd.decoder_type,
                                        statedump_data: sd.statedump_data,
                                        data_type: sd.data_type,
                                    },
                                    signpost_id: 0,
                                    signpost_name: 0,
                                    resolved_message: RefCell::new(None),
                                    #[cfg(feature = "rewrite-compat")]
                                    format_string_error: None,
                                });
                            }
                            Err(e) => {
                                warn!("Failed to parse statedump chunk: {}", e.to_parse_error())
                            }
                        },
                        _ => {} // truly unknown chunk types
                    }
                }
            }
            TopChunk::Unknown(_) => {}
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Per-entry processing
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn visit_firehose_entries<'a, 'b>(
    fh: &RawFirehose<'b>,
    header: &RawHeaderChunk<'a>,
    catalog: &RawCatalogChunk<'a>,
    resolver: &TimestampResolver,
    dsc_files: &'a HashMap<Uuid, RawSharedCacheStrings<'a>>,
    uuidtext_files: &'a HashMap<Uuid, RawUUIDText<'a>>,
    oversize_cache: &'b OversizeCache,
    #[cfg(feature = "rewrite-compat")] extended_private_data: Option<&'b [u8]>,
    callback: &mut impl FnMut(LogEntry<'a, 'b>),
) {
    let boot_uuid = header.boot_uuid;
    let timezone_name = extract_timezone_name(header.timezone_path);

    // In compat mode, pre-compute adjusted private data that includes any leftover
    // (unconsumed) public data bytes. The legacy code prepends these to the private
    // data region (see legacy firehose_log.rs lines 186-198).
    #[cfg(feature = "rewrite-compat")]
    let adjusted_private_data = {
        let mut reader = fh.entries();
        while reader.next().is_some() {}
        let leftover = reader.remaining();
        if !leftover.is_empty() && fh.private_data_virtual_offset != 0x1000 {
            let start = fh.public_data_len() - leftover.len();
            Some(&fh.firehose_data[start..])
        } else {
            fh.private_data()
        }
    };

    for entry in fh.entries() {
        let body = match entry.parse_body() {
            Ok(body) => body,
            Err(e) => {
                warn!("Failed to parse firehose entry body: {e}");
                continue;
            }
        };

        // Extract body-specific fields
        let (event_type, log_type, activity_id, subsystem_value, data_ref, pc_id, formatter) =
            match &body {
                RawFirehoseBody::Activity(b) => (
                    EventType::Activity,
                    map_activity_log_type(entry.log_type),
                    combine_activity_id(b.activity_id),
                    None,
                    None,
                    b.pc_id,
                    b.formatter,
                ),
                RawFirehoseBody::NonActivity(b) => (
                    EventType::Log,
                    map_default_log_type(entry.log_type),
                    combine_activity_id(b.activity_id),
                    b.subsystem,
                    b.data_ref,
                    b.pc_id,
                    b.formatter,
                ),
                RawFirehoseBody::Signpost(b) => (
                    EventType::Signpost,
                    map_signpost_log_type(entry.log_type),
                    combine_activity_id(b.activity_id),
                    b.subsystem,
                    b.data_ref,
                    b.pc_id,
                    b.formatter,
                ),
                RawFirehoseBody::Trace(b) => (
                    EventType::Trace,
                    LogType::Default,
                    0,
                    None,
                    None,
                    b.pc_id,
                    RawFormatterFlags::default(),
                ),
                RawFirehoseBody::Loss(b) => {
                    let abs_ct = entry.absolute_continuous_time(fh.base_continuous_time);
                    let time = resolver.resolve(&boot_uuid, abs_ct, fh.base_continuous_time);
                    callback(LogEntry {
                        subsystem: None,
                        category: None,
                        thread_id: entry.thread_id,
                        pid: 0,
                        euid: 0,
                        library: None,
                        library_uuid: Uuid::nil(),
                        activity_id: 0,
                        time,
                        event_type: EventType::Loss,
                        log_type: LogType::Loss,
                        process: None,
                        process_uuid: Uuid::nil(),
                        format_string: None,
                        boot_uuid,
                        timezone_name,
                        items: ItemsData::Loss {
                            count: b.count,
                            start_time: b.start_time,
                            end_time: b.end_time,
                        },
                        signpost_id: 0,
                        signpost_name: 0,
                        resolved_message: RefCell::new(None),
                        #[cfg(feature = "rewrite-compat")]
                        format_string_error: None,
                    });
                    continue;
                }
                RawFirehoseBody::Unknown(_) => continue,
            };

        // Signpost-specific fields
        let (signpost_id, signpost_name) = match &body {
            RawFirehoseBody::Signpost(b) => (b.signpost_id, b.signpost_name.unwrap_or(0)),
            _ => (0, 0),
        };

        // Timestamp
        let abs_ct = entry.absolute_continuous_time(fh.base_continuous_time);
        let time = resolver.resolve(&boot_uuid, abs_ct, fh.base_continuous_time);

        // Resolve strings (format string, library, process paths)
        let resolved = resolve_strings(
            entry.format_string_location,
            pc_id,
            &formatter,
            fh.first_proc_id,
            fh.second_proc_id,
            catalog,
            dsc_files,
            uuidtext_files,
        );

        // Generate error string for invalid format string offsets (old pipeline parity)
        #[cfg(feature = "rewrite-compat")]
        let format_string_error = if resolved.format_string.is_none() {
            let string_offset = u64::from(entry.format_string_location);
            Some(format_string_error_message(
                string_offset,
                &formatter,
                resolved.library_uuid,
                resolved.process_uuid,
                resolved.source_found,
            ))
        } else {
            None
        };

        // Build deferred items data — message formatted on demand via LogEntry::message()
        // All variants borrow raw bytes zero-copy from the chunk data or oversize cache.
        // Lifetime 'b is scoped to the current chunkset iteration, which outlives the callback.
        let private_data_context = {
            let private_strings = match &body {
                RawFirehoseBody::NonActivity(b) => b.private_strings,
                RawFirehoseBody::Signpost(b) => b.private_strings,
                _ => None,
            };
            #[cfg(feature = "rewrite-compat")]
            let pd = adjusted_private_data;
            #[cfg(not(feature = "rewrite-compat"))]
            let pd = fh.private_data();
            match (pd, private_strings) {
                (Some(pd), Some((offset, size))) if size > 0 => Some(PrivateDataContext {
                    private_data: pd,
                    private_strings_offset: offset,
                    private_data_virtual_offset: fh.private_data_virtual_offset,
                    collapsed: fh.collapsed,
                    #[cfg(feature = "rewrite-compat")]
                    extended_private_data,
                }),
                _ => None,
            }
        };
        let items = if let Some(data_ref) = data_ref {
            match oversize_cache.get(data_ref, fh.first_proc_id, fh.second_proc_id) {
                Some(d) => ItemsData::Regular {
                    data: d,
                    flags: entry.flags,
                    private_data_context,
                },
                None => {
                    warn!(
                        "Missing oversize data for data_ref={data_ref}, \
             proc=({}, {})",
                        fh.first_proc_id, fh.second_proc_id
                    );
                    ItemsData::None
                }
            }
        } else {
            match &body {
                RawFirehoseBody::Trace(t) => ItemsData::Trace { data: t.items_data },
                _ => match body.standard_items_data() {
                    Some(d) => ItemsData::Regular {
                        data: d,
                        flags: entry.flags,
                        private_data_context,
                    },
                    None => ItemsData::None,
                },
            }
        };

        // Catalog lookups
        let (subsystem, category) = subsystem_value
            .and_then(|sv| catalog.get_subsystem(sv, fh.first_proc_id, fh.second_proc_id))
            .map_or((None, None), |s| (Some(s.subsystem), Some(s.category)));
        let pid = catalog
            .get_pid(fh.first_proc_id, fh.second_proc_id)
            .unwrap_or(0);
        let euid = catalog
            .get_euid(fh.first_proc_id, fh.second_proc_id)
            .unwrap_or(0);

        callback(LogEntry {
            subsystem,
            category,
            thread_id: entry.thread_id,
            pid,
            euid,
            library: resolved.library,
            library_uuid: resolved.library_uuid,
            activity_id,
            time,
            event_type,
            log_type,
            process: resolved.process,
            process_uuid: resolved.process_uuid,
            format_string: resolved.format_string,
            boot_uuid,
            timezone_name,
            items,
            signpost_id,
            signpost_name,
            resolved_message: RefCell::new(None),
            #[cfg(feature = "rewrite-compat")]
            format_string_error,
        });
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

fn map_activity_log_type(log_type: FirehoseLogType) -> LogType {
    match log_type {
        FirehoseLogType::Info => LogType::Create,
        FirehoseLogType::Useraction => LogType::Useraction,
        _ => LogType::Default,
    }
}

fn map_default_log_type(log_type: FirehoseLogType) -> LogType {
    match log_type {
        FirehoseLogType::Debug => LogType::Debug,
        FirehoseLogType::Info => LogType::Info,
        FirehoseLogType::Error => LogType::Error,
        FirehoseLogType::Fault => LogType::Fault,
        _ => LogType::Default,
    }
}

fn map_signpost_log_type(log_type: FirehoseLogType) -> LogType {
    match log_type {
        FirehoseLogType::ProcessSignpostEvent => LogType::ProcessSignpostEvent,
        FirehoseLogType::ProcessSignpostStart => LogType::ProcessSignpostStart,
        FirehoseLogType::ProcessSignpostEnd => LogType::ProcessSignpostEnd,
        FirehoseLogType::SystemSignpostEvent => LogType::SystemSignpostEvent,
        FirehoseLogType::SystemSignpostStart => LogType::SystemSignpostStart,
        FirehoseLogType::SystemSignpostEnd => LogType::SystemSignpostEnd,
        FirehoseLogType::ThreadSignpostEvent => LogType::ThreadSignpostEvent,
        FirehoseLogType::ThreadSignpostStart => LogType::ThreadSignpostStart,
        FirehoseLogType::ThreadSignpostEnd => LogType::ThreadSignpostEnd,
        _ => LogType::Default,
    }
}

fn combine_activity_id(ids: Option<(u32, u32)>) -> u64 {
    match ids {
        Some((lo, hi)) => {
            let raw = u64::from(lo) | (u64::from(hi) << 32);
            // Under the feature flag, mask off the high bit sentinel (0x80000000 in hi)
            // to match the old pipeline which used only the lower u32: u64::from(lo).
            #[cfg(feature = "rewrite-compat")]
            {
                raw & 0x7FFFFFFFFFFFFFFF
            }
            #[cfg(not(feature = "rewrite-compat"))]
            {
                raw
            }
        }
        None => 0,
    }
}

fn extract_timezone_name(timezone_path: &str) -> &str {
    timezone_path.rsplit('/').next().unwrap_or(timezone_path)
}

/// Generate error message matching the old pipeline's format when format string lookup fails.
///
/// Two levels of error, distinguished by `uuid_found`:
/// - **Level 1** (`uuid_found = false`): UUID/DSC file not found → "Failed to get…" / "Unknown…"
/// - **Level 2** (`uuid_found = true`): File found but offset invalid → "Error: Invalid offset…"
#[cfg(feature = "rewrite-compat")]
fn format_string_error_message(
    string_offset: u64,
    formatter: &RawFormatterFlags,
    library_uuid: Uuid,
    process_uuid: Uuid,
    uuid_found: bool,
) -> String {
    if formatter.shared_cache || formatter.large_shared_cache != 0 {
        if uuid_found {
            "Error: Invalid shared string offset".to_string()
        } else {
            "Unknown shared string message".to_string()
        }
    } else if formatter.absolute {
        if uuid_found {
            format!(
                "Error: Invalid offset {} for absolute UUID {:X}",
                string_offset,
                library_uuid.simple()
            )
        } else {
            format!(
                "Failed to get string message from absolute UUIDText file: {:X}",
                library_uuid.simple()
            )
        }
    } else if formatter.uuid_relative != [0u8; 16] {
        let uuid = Uuid::from_bytes(formatter.uuid_relative);
        if uuid_found {
            format!(
                "Error: Invalid offset {} for alternative UUID {:X}",
                string_offset,
                uuid.simple()
            )
        } else {
            format!(
                "Failed to get string message from alternative UUIDText file: {:X}",
                uuid.simple()
            )
        }
    } else if uuid_found {
        format!(
            "Error: Invalid offset {} for UUID {:X}",
            string_offset,
            process_uuid.simple()
        )
    } else {
        format!(
            "Failed to get string message from UUIDText file: {:X}",
            process_uuid.simple()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    // --- map_log_type tests ---

    #[test_case(FirehoseLogType::Info        => LogType::Create    ; "info is create")]
    #[test_case(FirehoseLogType::Useraction  => LogType::Useraction; "useraction")]
    #[test_case(FirehoseLogType::Debug       => LogType::Default   ; "debug fallback")]
    #[test_case(FirehoseLogType::Error       => LogType::Default   ; "error fallback")]
    #[test_case(FirehoseLogType::Default     => LogType::Default   ; "default fallback")]
    fn test_map_activity_log_type(input: FirehoseLogType) -> LogType {
        map_activity_log_type(input)
    }

    #[test_case(FirehoseLogType::Debug   => LogType::Debug  ; "debug")]
    #[test_case(FirehoseLogType::Info    => LogType::Info   ; "info")]
    #[test_case(FirehoseLogType::Error   => LogType::Error  ; "error")]
    #[test_case(FirehoseLogType::Fault   => LogType::Fault  ; "fault")]
    #[test_case(FirehoseLogType::Default => LogType::Default; "default")]
    fn test_map_default_log_type(input: FirehoseLogType) -> LogType {
        map_default_log_type(input)
    }

    #[test_case(FirehoseLogType::ProcessSignpostEvent => LogType::ProcessSignpostEvent; "process event")]
    #[test_case(FirehoseLogType::ProcessSignpostStart => LogType::ProcessSignpostStart; "process start")]
    #[test_case(FirehoseLogType::ProcessSignpostEnd   => LogType::ProcessSignpostEnd  ; "process end")]
    #[test_case(FirehoseLogType::SystemSignpostEvent  => LogType::SystemSignpostEvent ; "system event")]
    #[test_case(FirehoseLogType::SystemSignpostStart  => LogType::SystemSignpostStart ; "system start")]
    #[test_case(FirehoseLogType::SystemSignpostEnd    => LogType::SystemSignpostEnd   ; "system end")]
    #[test_case(FirehoseLogType::ThreadSignpostEvent  => LogType::ThreadSignpostEvent ; "thread event")]
    #[test_case(FirehoseLogType::ThreadSignpostStart  => LogType::ThreadSignpostStart ; "thread start")]
    #[test_case(FirehoseLogType::ThreadSignpostEnd    => LogType::ThreadSignpostEnd   ; "thread end")]
    #[test_case(FirehoseLogType::Default              => LogType::Default             ; "default")]
    fn test_map_signpost_log_type(input: FirehoseLogType) -> LogType {
        map_signpost_log_type(input)
    }

    // --- combine_activity_id tests ---

    #[test_case(None                    => 0                ; "none")]
    #[test_case(Some((0xDEAD, 0xBEEF)) => 0xBEEF_0000_DEAD; "some")]
    #[test_case(Some((0, 0))           => 0                ; "zero")]
    fn test_combine_activity_id(input: Option<(u32, u32)>) -> u64 {
        combine_activity_id(input)
    }

    // --- extract_timezone_name tests ---

    #[test_case("/var/db/timezone/zoneinfo/America/New_York" => "New_York" ; "full path")]
    #[test_case("/usr/share/zoneinfo/Pacific"                => "Pacific"  ; "short path")]
    #[test_case("UTC"                                        => "UTC"      ; "no slash")]
    #[test_case(""                                           => ""         ; "empty")]
    fn test_extract_timezone_name(input: &str) -> &str {
        extract_timezone_name(input)
    }

    // --- OversizeCache tests ---

    #[test]
    fn test_oversize_cache_insert_and_get() {
        let mut cache = OversizeCache::new();
        cache.entries.insert((1, 100, 200), vec![1, 2, 3, 4]);
        assert_eq!(cache.get(1, 100, 200), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn test_oversize_cache_miss() {
        let cache = OversizeCache::new();
        assert_eq!(cache.get(1, 100, 200), None);
    }

    #[test]
    fn test_oversize_cache_different_key() {
        let mut cache = OversizeCache::new();
        cache.entries.insert((1, 100, 200), vec![1, 2, 3]);
        // Different data_ref
        assert_eq!(cache.get(2, 100, 200), None);
        // Different first_proc_id
        assert_eq!(cache.get(1, 101, 200), None);
        // Different second_proc_id
        assert_eq!(cache.get(1, 100, 201), None);
    }
}
