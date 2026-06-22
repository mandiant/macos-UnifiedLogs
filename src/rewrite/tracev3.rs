//! `TraceV3` file processor — threads all parsing modules together to produce log entries.

use super::catalog::RawCatalogChunk;
use super::chunk::{ChunkSetReader, ChunksReader, TopChunk};
use super::chunks::ChunkTag;
use super::chunks::firehose::RawFirehose;
use super::chunks::firehose::body::{RawActivityBody, RawFirehoseBody, RawFormatterFlags};
use super::chunks::firehose::entry::FirehoseLogType;
use super::chunks::firehose::flags::{FirehoseFlags, FormatterType};
use super::chunks::oversize::RawOversize;
use super::chunks::simpledump::RawSimpleDump;
use super::chunks::statedump::RawStatedump;
use super::dsc::RawSharedCacheStrings;
use super::error::{NomExt, ParseError};
use super::header::RawHeaderChunk;
use super::log_entry::{EventType, ItemsData, LogEntry, LogType, MessageFlags, PrivateDataContext};
use super::resolve::resolve_strings;
use super::timesync::TimestampResolver;
use super::uuidtext::RawUUIDText;
use log::warn;
use std::cell::RefCell;
use std::collections::HashMap;
use uuid::Uuid;

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
        self.entries
            .entry((
                oversize.data_ref_index,
                oversize.first_proc_id,
                oversize.second_proc_id,
            ))
            .or_insert_with(|| oversize.oversize_data.to_vec());
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
    let mut deferred_readers: Vec<ChunkSetReader<'a>> = Vec::new();

    for top_chunk in ChunksReader::new(data) {
        let top_chunk = match top_chunk {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse top chunk: {e}");
                break;
            }
        };
        match top_chunk {
            TopChunk::Header(h) => {
                // Flush deferred simpledump/statedump before switching header context
                flush_deferred_entries(
                    &mut deferred_readers,
                    &current_header,
                    resolver,
                    &mut callback,
                );
                current_header = Some(h);
            }
            TopChunk::Catalog(c) => {
                // Flush deferred simpledump/statedump at catalog boundary —
                // legacy groups firehose→simpledump→statedump per catalog, not per chunkset.
                flush_deferred_entries(
                    &mut deferred_readers,
                    &current_header,
                    resolver,
                    &mut callback,
                );
                current_catalog = Some(c);
            }
            TopChunk::Chunkset(mut reader) => {
                // Single pass: Oversize + Firehose emitted immediately.
                // Simpledump/Statedump deferred until catalog boundary.
                let mut has_deferred = false;
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
                        ChunkTag::Simpledump | ChunkTag::Statedump => has_deferred = true,
                        _ => {}
                    }
                }

                // Defer this reader for later simpledump/statedump passes
                if has_deferred {
                    reader.reset();
                    deferred_readers.push(reader);
                }
            }
            TopChunk::Unknown(_) => {}
        }
    }

    // Flush remaining deferred entries at EOF
    flush_deferred_entries(
        &mut deferred_readers,
        &current_header,
        resolver,
        &mut callback,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Deferred simpledump/statedump flushing
// ---------------------------------------------------------------------------

/// Flush deferred chunkset readers, emitting all simpledump entries first,
/// then all statedump entries. This matches the legacy per-catalog ordering:
/// all firehose → all simpledump → all statedump within each catalog.
fn flush_deferred_entries<'a>(
    deferred_readers: &mut Vec<ChunkSetReader<'a>>,
    current_header: &Option<RawHeaderChunk<'a>>,
    resolver: &TimestampResolver,
    callback: &mut impl for<'b> FnMut(LogEntry<'a, 'b>),
) {
    if deferred_readers.is_empty() {
        return;
    }

    // --- Simpledump pass ---
    for reader in deferred_readers.iter_mut() {
        reader.reset();
        while let Some(inner) = reader.next() {
            let inner = match inner {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to parse inner chunk (simpledump pass): {e}");
                    break;
                }
            };
            if inner.preamble.tag != ChunkTag::Simpledump {
                continue;
            }
            match RawSimpleDump::parse(inner.data) {
                Ok((_, sd)) => {
                    let Some(header) = current_header else {
                        continue;
                    };
                    let time = resolver.resolve(&header.boot_uuid, sd.continuous_time, 1);
                    let timezone_name = extract_timezone_name(header.timezone_path);
                    callback(LogEntry {
                        subsystem: Some(sd.subsystem),
                        category: None,
                        thread_id: sd.thread_id,
                        pid: sd.first_proc_id,
                        euid: 0,
                        library: None,
                        library_uuid: sd.sender_uuid,
                        activity_id: 0,
                        parent_activity_id: None,
                        time,
                        event_type: EventType::Simpledump,
                        log_type: LogType::Simpledump,
                        process: None,
                        process_uuid: sd.dsc_uuid,
                        format_string: None,
                        boot_uuid: header.boot_uuid,
                        timezone_name,
                        message_flags: Vec::new(),
                        items: ItemsData::Simpledump {
                            subsystem: sd.subsystem,
                            message: sd.message_string,
                        },
                        signpost_id: 0,
                        signpost_name: 0,
                        resolved_message: RefCell::new(None),
                        format_string_error: None,
                    });
                }
                Err(e) => {
                    warn!("Failed to parse simpledump chunk: {}", e.to_parse_error())
                }
            }
        }
    }

    // --- Statedump pass ---
    for reader in deferred_readers.iter_mut() {
        reader.reset();
        while let Some(inner) = reader.next() {
            let inner = match inner {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to parse inner chunk (statedump pass): {e}");
                    break;
                }
            };
            if inner.preamble.tag != ChunkTag::Statedump {
                continue;
            }
            match RawStatedump::parse(inner.data) {
                Ok((_, sd)) => {
                    let Some(header) = current_header else {
                        continue;
                    };
                    let time = resolver.resolve(&header.boot_uuid, sd.continuous_time, 1);
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
                        parent_activity_id: None,
                        time,
                        event_type: EventType::Statedump,
                        log_type: LogType::Statedump,
                        process: None,
                        process_uuid: Uuid::nil(),
                        format_string: None,
                        boot_uuid: header.boot_uuid,
                        timezone_name,
                        message_flags: Vec::new(),
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
                        format_string_error: None,
                    });
                }
                Err(e) => {
                    warn!("Failed to parse statedump chunk: {}", e.to_parse_error())
                }
            }
        }
    }

    deferred_readers.clear();
}

fn legacy_private_data_start<'a>(fh: &RawFirehose<'a>) -> Option<&'a [u8]> {
    const NO_PRIVATE_DATA: u16 = 0x1000;
    const PRIVATE_OFFSET_BASE: usize = 0x1000;
    const PUBLIC_DATA_SIZE_OFFSET: usize = 16;

    if fh.private_data_virtual_offset == NO_PRIVATE_DATA {
        return None;
    }

    let log_data = fh.firehose_data;
    let public_data_len = fh.public_data_len();
    if public_data_len > log_data.len() {
        return None;
    }

    let mut reader = fh.entries();
    while reader.next().is_some() {}
    let remaining_public_len = reader.remaining().len();
    let input_after_public = &log_data[public_data_len..];
    let private_data_offset =
        PRIVATE_OFFSET_BASE.saturating_sub(usize::from(fh.private_data_virtual_offset));

    let start = if input_after_public.len() > private_data_offset && remaining_public_len == 0 {
        public_data_len + (input_after_public.len() - private_data_offset)
    } else if log_data.len() == public_data_len {
        usize::from(fh.private_data_virtual_offset)
            .wrapping_sub(PUBLIC_DATA_SIZE_OFFSET)
            .wrapping_sub(remaining_public_len)
    } else {
        public_data_len.saturating_sub(remaining_public_len)
    };

    if start > log_data.len() {
        return None;
    }

    Some(&log_data[start..])
}

// ---------------------------------------------------------------------------
// Per-entry processing
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn visit_firehose_entries<'a: 'b, 'b>(
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

    let adjusted_private_data = legacy_private_data_start(fh);

    for entry in fh.entries() {
        let body = match entry.parse_body() {
            Ok(body) => body,
            Err(e) => {
                warn!("Failed to parse firehose entry body: {e}");
                continue;
            }
        };

        // Extract body-specific fields
        let (
            event_type,
            log_type,
            activity_id,
            parent_activity_id,
            subsystem_value,
            data_ref,
            pc_id,
            formatter,
        ) = match &body {
            RawFirehoseBody::Activity(b) => {
                let (activity_id, parent_activity_id) = activity_and_parent_ids(b);
                (
                    EventType::Activity,
                    map_activity_log_type(entry.log_type),
                    activity_id,
                    parent_activity_id,
                    None,
                    None,
                    b.pc_id,
                    b.formatter,
                )
            }
            RawFirehoseBody::NonActivity(b) => (
                EventType::Log,
                map_default_log_type(entry.log_type),
                combine_activity_id(b.activity_id),
                None,
                b.subsystem,
                b.data_ref,
                b.pc_id,
                b.formatter,
            ),
            RawFirehoseBody::Signpost(b) => (
                EventType::Signpost,
                map_signpost_log_type(entry.log_type),
                combine_activity_id(b.activity_id),
                None,
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
                None,
                b.pc_id,
                RawFormatterFlags::default(),
            ),
            RawFirehoseBody::Loss(b) => {
                let abs_ct = entry.absolute_continuous_time(fh.base_continuous_time);
                let time = resolver.resolve(&boot_uuid, abs_ct, fh.base_continuous_time);

                // Catalog lookups — same as other entry types
                let pid = catalog
                    .get_pid(fh.first_proc_id, fh.second_proc_id)
                    .unwrap_or(0);
                let euid = catalog
                    .get_euid(fh.first_proc_id, fh.second_proc_id)
                    .unwrap_or(0);

                // Process/library from UUIDText via main_uuid
                let entry_info = catalog.get_process_info(fh.first_proc_id, fh.second_proc_id);
                let main_uuid = entry_info.map_or(Uuid::nil(), |e| e.main_uuid);
                let process = uuidtext_files.get(&main_uuid).and_then(|u| u.image_path());

                callback(LogEntry {
                    subsystem: None,
                    category: None,
                    thread_id: entry.thread_id,
                    pid,
                    euid,
                    library: process,
                    library_uuid: main_uuid,
                    activity_id: 0,
                    parent_activity_id: None,
                    time,
                    event_type: EventType::Loss,
                    log_type: LogType::Loss,
                    process,
                    process_uuid: main_uuid,
                    format_string: None,
                    boot_uuid,
                    timezone_name,
                    message_flags: Vec::new(),
                    items: ItemsData::Loss {
                        count: b.count,
                        start_time: b.start_time,
                        end_time: b.end_time,
                    },
                    signpost_id: 0,
                    signpost_name: 0,
                    resolved_message: RefCell::new(None),
                    format_string_error: None,
                });
                continue;
            }
            RawFirehoseBody::Unknown(_) => {
                let abs_ct = entry.absolute_continuous_time(fh.base_continuous_time);
                let time = resolver.resolve(&boot_uuid, abs_ct, fh.base_continuous_time);
                let pid = catalog
                    .get_pid(fh.first_proc_id, fh.second_proc_id)
                    .unwrap_or(0);
                let euid = catalog
                    .get_euid(fh.first_proc_id, fh.second_proc_id)
                    .unwrap_or(0);

                callback(LogEntry {
                    subsystem: None,
                    category: None,
                    thread_id: entry.thread_id,
                    pid,
                    euid,
                    library: None,
                    library_uuid: Uuid::nil(),
                    activity_id: 0,
                    parent_activity_id: None,
                    time,
                    event_type: EventType::Unknown,
                    log_type: LogType::Default,
                    process: None,
                    process_uuid: Uuid::nil(),
                    format_string: None,
                    boot_uuid,
                    timezone_name,
                    message_flags: Vec::new(),
                    items: ItemsData::None,
                    signpost_id: 0,
                    signpost_name: 0,
                    resolved_message: RefCell::new(None),
                    format_string_error: None,
                });
                continue;
            }
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
        let process = if format_string_error.is_some() && !resolved.source_found {
            None
        } else {
            resolved.process
        };

        // Build deferred items data — message formatted on demand via LogEntry::message()
        // All variants borrow raw bytes zero-copy from the chunk data or oversize cache.
        // Lifetime 'b is scoped to the current chunkset iteration, which outlives the callback.
        let private_data_context = {
            let private_strings = match &body {
                RawFirehoseBody::NonActivity(b) => b.private_strings,
                _ => None,
            };
            let pd = adjusted_private_data;
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
        let message_flags = message_flags_for_body(&body, entry.flags, &formatter);
        let items = if let Some(data_ref) = data_ref {
            match oversize_cache.get(data_ref, fh.first_proc_id, fh.second_proc_id) {
                Some(d) => ItemsData::Regular {
                    data: d,
                    flags: entry.flags,
                    is_oversize: true,
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
                        is_oversize: false,
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
            parent_activity_id,
            time,
            event_type,
            log_type,
            process,
            process_uuid: resolved.process_uuid,
            format_string: resolved.format_string,
            boot_uuid,
            timezone_name,
            message_flags,
            items,
            signpost_id,
            signpost_name,
            resolved_message: RefCell::new(None),
            format_string_error,
        });
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

fn message_flags_for_body(
    body: &RawFirehoseBody<'_>,
    flags: FirehoseFlags,
    formatter: &RawFormatterFlags,
) -> Vec<MessageFlags> {
    let mut message_flags = Vec::new();

    match body {
        RawFirehoseBody::Activity(body) => {
            if body.pid.is_some() {
                message_flags.push(MessageFlags::HasUniquePid);
            }
            if body.current_aid.is_some() {
                message_flags.push(MessageFlags::HasCurrentAid);
            }
            if body.other_aid.is_some() {
                message_flags.push(MessageFlags::HasOtherAid);
            }
            push_formatter_message_flags(flags, formatter, &mut message_flags);
        }
        RawFirehoseBody::NonActivity(body) => {
            if body.activity_id.is_some() {
                message_flags.push(MessageFlags::HasCurrentAid);
            }
            if body.private_strings.is_some() {
                message_flags.push(MessageFlags::HasPrivateData);
            }
            push_formatter_message_flags(flags, formatter, &mut message_flags);
            if body.subsystem.is_some() {
                message_flags.push(MessageFlags::HasSubsystem);
            }
            if body.ttl.is_some() {
                message_flags.push(MessageFlags::HasRules);
            }
            if body.data_ref.is_some() {
                message_flags.push(MessageFlags::HasOversize);
            }
        }
        RawFirehoseBody::Signpost(body) => {
            if body.activity_id.is_some() {
                message_flags.push(MessageFlags::HasCurrentAid);
            }
            if body.private_strings.is_some() {
                message_flags.push(MessageFlags::HasPrivateData);
            }
            push_formatter_message_flags(flags, formatter, &mut message_flags);
            if body.subsystem.is_some() {
                message_flags.push(MessageFlags::HasSubsystem);
            }
            if body.ttl.is_some() {
                message_flags.push(MessageFlags::HasRules);
            }
            if body.data_ref.is_some() {
                message_flags.push(MessageFlags::HasOversize);
            }
        }
        _ => {}
    }

    message_flags
}

fn push_formatter_message_flags(
    flags: FirehoseFlags,
    formatter: &RawFormatterFlags,
    message_flags: &mut Vec<MessageFlags>,
) {
    match FormatterType::from((flags.bits() & 0x000E) as u8) {
        FormatterType::LargeSharedCache => {
            if formatter.has_large_offset != 0 {
                message_flags.push(MessageFlags::HasLargeOffset);
            }
            message_flags.push(MessageFlags::LargeSharedCache);
        }
        FormatterType::Absolute => {
            message_flags.push(MessageFlags::Absolute);
            message_flags.push(MessageFlags::AltIndex);
        }
        FormatterType::MainExe => {
            message_flags.push(MessageFlags::MainExe);
        }
        FormatterType::SharedCache => {
            message_flags.push(MessageFlags::SharedCache);
            if formatter.has_large_offset != 0 {
                message_flags.push(MessageFlags::HasLargeOffset);
            }
        }
        FormatterType::UuidRelative => {
            message_flags.push(MessageFlags::UuidRelative);
        }
        FormatterType::Unknown => {
            message_flags.push(MessageFlags::Unknown);
        }
    }
}

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
            raw & 0x7FFF_FFFF_FFFF_FFFF
        }
        None => 0,
    }
}

fn activity_and_parent_ids(activity: &RawActivityBody<'_>) -> (u64, Option<u64>) {
    match activity.other_aid {
        Some(other_aid) if combine_activity_id(Some(other_aid)) != 0 => {
            let parent_activity_id = combine_activity_id(activity.activity_id);
            (
                combine_activity_id(Some(other_aid)),
                (parent_activity_id != 0).then_some(parent_activity_id),
            )
        }
        _ => (combine_activity_id(activity.activity_id), None),
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
    #[test_case(Some((0xDEAD, 0x8000_BEEF)) => 0x0000_BEEF_0000_DEAD; "high bit sentinel")]
    #[test_case(Some((0, 0))           => 0                ; "zero")]
    fn test_combine_activity_id(input: Option<(u32, u32)>) -> u64 {
        combine_activity_id(input)
    }

    #[test]
    fn test_activity_and_parent_ids() {
        let activity = RawActivityBody {
            activity_id: Some((10, 0)),
            pid: None,
            current_aid: None,
            other_aid: Some((30, 0)),
            pc_id: 0,
            formatter: RawFormatterFlags::default(),
            items_data: &[],
        };

        assert_eq!(activity_and_parent_ids(&activity), (30, Some(10)));
    }

    #[test]
    fn test_message_flags_for_activity() {
        let activity = RawActivityBody {
            activity_id: Some((10, 0)),
            pid: Some(236),
            current_aid: Some((10, 0)),
            other_aid: Some((30, 0)),
            pc_id: 0,
            formatter: RawFormatterFlags {
                has_large_offset: 1,
                large_shared_cache: 2,
                ..Default::default()
            },
            items_data: &[],
        };
        let body = RawFirehoseBody::Activity(activity);
        let flags = FirehoseFlags::HAS_UNIQUE_PID
            | FirehoseFlags::HAS_CURRENT_AID
            | FirehoseFlags::HAS_SUBSYSTEM
            | FirehoseFlags::HAS_LARGE_OFFSET
            | FirehoseFlags::from_bits_retain(0x000c);

        assert_eq!(
            message_flags_for_body(&body, flags, &activity.formatter),
            vec![
                MessageFlags::HasUniquePid,
                MessageFlags::HasCurrentAid,
                MessageFlags::HasOtherAid,
                MessageFlags::HasLargeOffset,
                MessageFlags::LargeSharedCache,
            ]
        );
    }

    #[test]
    fn test_message_flags_for_non_activity() {
        use crate::rewrite::chunks::firehose::nonactivity::RawNonActivityBody;

        let nonactivity = RawNonActivityBody {
            activity_id: Some((10, 0)),
            private_strings: Some((1, 2)),
            pc_id: 0,
            formatter: RawFormatterFlags {
                main_exe: true,
                ..Default::default()
            },
            subsystem: Some(41),
            ttl: Some(1),
            data_ref: Some(2),
            items_data: &[],
        };
        let body = RawFirehoseBody::NonActivity(nonactivity);
        let flags = FirehoseFlags::HAS_CURRENT_AID
            | FirehoseFlags::HAS_PRIVATE_DATA
            | FirehoseFlags::HAS_SUBSYSTEM
            | FirehoseFlags::HAS_RULES
            | FirehoseFlags::HAS_OVERSIZE
            | FirehoseFlags::from_bits_retain(0x0002);

        assert_eq!(
            message_flags_for_body(&body, flags, &nonactivity.formatter),
            vec![
                MessageFlags::HasCurrentAid,
                MessageFlags::HasPrivateData,
                MessageFlags::MainExe,
                MessageFlags::HasSubsystem,
                MessageFlags::HasRules,
                MessageFlags::HasOversize,
            ]
        );
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
