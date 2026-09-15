// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//! `TraceV3` file processor — threads all parsing modules together to produce log entries.

use super::cache::StringCatalog;
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
use super::error::NomExt;
use super::header::RawHeaderChunk;
use super::log_entry::{EventType, ItemsData, LogEntry, LogType, MessageFlags, PrivateDataContext};
use super::resolve::{main_process, resolve_strings};
use super::timesync::TimestampResolver;
use super::traits::{FileProvider, VisitOutcome};
use log::warn;
use std::cell::RefCell;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::rc::Rc;
use uuid::Uuid;

mod oversize;
pub use oversize::OversizeCache;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Process a single tracev3 file buffer.
///
/// The callback receives each log entry as it is produced. Entry-level errors
/// (bad body parse, missing oversize data) are logged as warnings and skipped.
/// The same evidence path is attached to every emitted `LogEntry`.
///
/// The callback may return [`ControlFlow::Break`] to stop the visit early (see
/// [`VisitOutcome`]): the remainder of the file — deferred simpledump and
/// statedump entries included — is not emitted, and the function returns
/// `Ok(ControlFlow::Break(()))`.
pub fn visit_tracev3<'d, 's: 'd, O: VisitOutcome>(
    data: &'d [u8],
    resolver: &TimestampResolver,
    strings: &StringCatalog<'s, impl FileProvider>,
    oversize_cache: &OversizeCache<'_>,
    evidence: Rc<PathBuf>,
    mut callback: impl for<'b> FnMut(LogEntry<'d, 'b>) -> O,
) -> ControlFlow<()> {
    let mut callback = move |entry: LogEntry<'d, '_>| callback(entry).into_flow();
    let mut current_header: Option<RawHeaderChunk<'d>> = None;
    let mut current_catalog: Option<RawCatalogChunk<'d>> = None;
    let mut deferred_readers: Vec<ChunkSetReader<'d>> = Vec::new();

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
                if flush_deferred_entries(
                    &mut deferred_readers,
                    &current_header,
                    &current_catalog,
                    resolver,
                    strings,
                    &evidence,
                    &mut callback,
                )
                .is_break()
                {
                    return ControlFlow::Break(());
                }
                current_header = Some(h);
            }
            TopChunk::Catalog(c) => {
                // Flush deferred simpledump/statedump at catalog boundary —
                // legacy groups firehose→simpledump→statedump per catalog, not per chunkset.
                if flush_deferred_entries(
                    &mut deferred_readers,
                    &current_header,
                    &current_catalog,
                    resolver,
                    strings,
                    &evidence,
                    &mut callback,
                )
                .is_break()
                {
                    return ControlFlow::Break(());
                }
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
                            Ok((_, ov)) => {
                                let boot_uuid = current_header
                                    .as_ref()
                                    .map(|h| h.boot_uuid)
                                    .unwrap_or_default();
                                oversize_cache.insert(boot_uuid, &ov);
                            }
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

                            if visit_firehose_entries(
                                &fh,
                                header,
                                catalog,
                                resolver,
                                strings,
                                oversize_cache,
                                &evidence,
                                &mut callback,
                            )
                            .is_break()
                            {
                                return ControlFlow::Break(());
                            }
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
    if flush_deferred_entries(
        &mut deferred_readers,
        &current_header,
        &current_catalog,
        resolver,
        strings,
        &evidence,
        &mut callback,
    )
    .is_break()
    {
        return ControlFlow::Break(());
    }

    ControlFlow::Continue(())
}

// ---------------------------------------------------------------------------
// Deferred simpledump/statedump flushing
// ---------------------------------------------------------------------------

/// Flush deferred chunkset readers, emitting all simpledump entries first,
/// then all statedump entries. This matches the legacy per-catalog ordering:
/// all firehose → all simpledump → all statedump within each catalog.
#[allow(clippy::too_many_arguments)]
fn flush_deferred_entries<'d, 's: 'd>(
    deferred_readers: &mut Vec<ChunkSetReader<'d>>,
    current_header: &Option<RawHeaderChunk<'d>>,
    current_catalog: &Option<RawCatalogChunk<'d>>,
    resolver: &TimestampResolver,
    strings: &StringCatalog<'s, impl FileProvider>,
    evidence: &Rc<PathBuf>,
    callback: &mut impl for<'b> FnMut(LogEntry<'d, 'b>) -> ControlFlow<()>,
) -> ControlFlow<()> {
    if deferred_readers.is_empty() {
        return ControlFlow::Continue(());
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

                    // Process info from the catalog's main executable UUIDText,
                    // resolved only when the associated DSC file is available
                    // (parity with the shared-strings extraction, PR #136).
                    let entry_info = current_catalog.as_ref().and_then(|c| {
                        c.get_process_info(sd.first_proc_id, sd.second_proc_id as u32)
                    });
                    let dsc_available = entry_info
                        .and_then(|e| e.dsc_uuid)
                        .and_then(|dsc_uuid| strings.get_dsc(&dsc_uuid))
                        .is_some();
                    let (process_uuid, process) = if dsc_available {
                        main_process(entry_info, strings)
                    } else {
                        (Uuid::nil(), None)
                    };

                    // `first_proc_id` is the Catalog proc id key, not a PID: both the
                    // real PID and the euid live in the Catalog process info entry.
                    let pid = entry_info.map_or(0, |e| u64::from(e.pid));
                    let euid = entry_info.map_or(0, |e| e.effective_user_id);

                    callback(LogEntry {
                        subsystem: Some(sd.subsystem),
                        category: None,
                        thread_id: sd.thread_id,
                        pid,
                        euid,
                        persona_id: None,
                        library: None,
                        library_uuid: sd.sender_uuid,
                        activity_id: 0,
                        parent_activity_id: None,
                        time,
                        event_type: EventType::Simpledump,
                        log_type: LogType::Simpledump,
                        process,
                        process_uuid,
                        format_string: None,
                        boot_uuid: header.boot_uuid,
                        timezone_name,
                        evidence: Rc::clone(evidence),
                        message_flags: Vec::new(),
                        items: ItemsData::Simpledump {
                            subsystem: sd.subsystem,
                            message: sd.message_string,
                        },
                        signpost_id: 0,
                        signpost_name: 0,
                        resolved_message: RefCell::new(None),
                        format_string_error: None,
                    })?;
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
                    let entry_info = current_catalog
                        .as_ref()
                        .and_then(|c| c.get_process_info(sd.first_proc_id, sd.second_proc_id));
                    let (process_uuid, process) = main_process(entry_info, strings);

                    // `first_proc_id` is the Catalog proc id key, not a PID.
                    let pid = entry_info.map_or(0, |e| u64::from(e.pid));
                    let euid = entry_info.map_or(0, |e| e.effective_user_id);

                    callback(LogEntry {
                        subsystem: None,
                        category: None,
                        thread_id: 0,
                        pid,
                        euid,
                        persona_id: None,
                        library: None,
                        library_uuid: sd.uuid,
                        activity_id: sd.activity_id,
                        parent_activity_id: None,
                        time,
                        event_type: EventType::Statedump,
                        log_type: LogType::Statedump,
                        process,
                        process_uuid,
                        format_string: None,
                        boot_uuid: header.boot_uuid,
                        timezone_name,
                        evidence: Rc::clone(evidence),
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
                    })?;
                }
                Err(e) => {
                    warn!("Failed to parse statedump chunk: {}", e.to_parse_error())
                }
            }
        }
    }

    deferred_readers.clear();
    ControlFlow::Continue(())
}

/// Start of the private data region, or `None` when the entry carries none.
///
/// Upstream #151 replaced a set of heuristics (leftover-data / equal-length /
/// prepended-private-data cases) with the two rules below.
fn private_data_start<'a>(fh: &RawFirehose<'a>) -> Option<&'a [u8]> {
    const PRIVATE_DATA_OFFSET_DEFAULT: u16 = 0x1000;

    if fh.private_data_virtual_offset == PRIVATE_DATA_OFFSET_DEFAULT {
        return None;
    }

    let virtual_offset = usize::from(fh.private_data_virtual_offset);

    // If Firehose data has been collapsed. Then private data needs to be calculated slightly differently
    // We need to subtract the private data offset for this chunk from the default private data offset (4096)
    // And then take whatever is remaining from the public data
    //
    // See: https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc#27-firehose-chunk
    if fh.collapsed == 1 || virtual_offset > fh.data_start.len() {
        let public_len = fh.public_data_len();
        let public_remaining = fh.firehose_data.get(public_len..)?;
        let size = usize::from(PRIVATE_DATA_OFFSET_DEFAULT - fh.private_data_virtual_offset);
        return public_remaining.get(..size);
    }

    // Jump to start of private data
    fh.data_start.get(virtual_offset..)
}

// ---------------------------------------------------------------------------
// Per-entry processing
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn visit_firehose_entries<'d: 'b, 'b, 's: 'd>(
    fh: &RawFirehose<'b>,
    header: &RawHeaderChunk<'d>,
    catalog: &RawCatalogChunk<'d>,
    resolver: &TimestampResolver,
    strings: &StringCatalog<'s, impl FileProvider>,
    oversize_cache: &'b OversizeCache<'_>,
    evidence: &Rc<PathBuf>,
    callback: &mut impl FnMut(LogEntry<'d, 'b>) -> ControlFlow<()>,
) -> ControlFlow<()> {
    let boot_uuid = header.boot_uuid;
    let timezone_name = extract_timezone_name(header.timezone_path);

    let adjusted_private_data = private_data_start(fh);
    let mut emitted_unknown_markers = Vec::new();

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
                let (main_uuid, process) = main_process(entry_info, strings);

                callback(LogEntry {
                    subsystem: None,
                    category: None,
                    thread_id: entry.thread_id,
                    pid,
                    euid,
                    persona_id: None,
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
                    evidence: Rc::clone(evidence),
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
                })?;
                continue;
            }
            RawFirehoseBody::Unknown(_) => {
                emitted_unknown_markers.push((
                    entry.thread_id,
                    entry.continuous_time_delta,
                    entry.continuous_time_delta_upper,
                ));
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
                    persona_id: None,
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
                    evidence: Rc::clone(evidence),
                    message_flags: Vec::new(),
                    items: ItemsData::None,
                    signpost_id: 0,
                    signpost_name: 0,
                    resolved_message: RefCell::new(Some(Rc::new(String::new()))),
                    format_string_error: None,
                })?;
                continue;
            }
        };

        // Persona ID — only firehose bodies that carry the HAS_PERSONA field
        let persona_id = match &body {
            RawFirehoseBody::Activity(b) => b.persona_id,
            RawFirehoseBody::NonActivity(b) => b.persona_id,
            RawFirehoseBody::Signpost(b) => b.persona_id,
            _ => None,
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
            strings,
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
                }),
                _ => None,
            }
        };
        let message_flags = message_flags_for_body(&body, entry.flags, &formatter);
        let items = if let Some(data_ref) = data_ref {
            match oversize_cache.get_or_harvest(
                boot_uuid,
                data_ref,
                fh.first_proc_id,
                fh.second_proc_id,
            ) {
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
            persona_id,
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
            evidence: Rc::clone(evidence),
            message_flags,
            items,
            signpost_id,
            signpost_name,
            resolved_message: RefCell::new(None),
            format_string_error,
        })?;
    }

    emit_embedded_unknown_markers(
        fh,
        resolver,
        catalog,
        boot_uuid,
        timezone_name,
        &emitted_unknown_markers,
        evidence,
        callback,
    )
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------
#[allow(clippy::too_many_arguments)]
fn emit_embedded_unknown_markers<'a: 'b, 'b>(
    fh: &RawFirehose<'b>,
    resolver: &TimestampResolver,
    catalog: &RawCatalogChunk<'a>,
    boot_uuid: Uuid,
    timezone_name: &'a str,
    emitted_unknown_markers: &[(u64, u32, u16)],
    evidence: &Rc<PathBuf>,
    callback: &mut impl FnMut(LogEntry<'a, 'b>) -> ControlFlow<()>,
) -> ControlFlow<()> {
    const HEADER_SIZE: usize = 24;

    let public_data = fh.public_data();
    for (pos, marker) in public_data.windows(HEADER_SIZE).enumerate() {
        if pos + HEADER_SIZE != public_data.len() {
            continue;
        }

        if marker[0] != 0x96
            || marker[1] != 0x9b
            || marker[2..8] != [0; 6]
            || marker[22..24] != [0; 2]
        {
            continue;
        }

        let thread_id = u64::from_le_bytes(marker[8..16].try_into().expect("slice length checked"));
        let continuous_time_delta =
            u32::from_le_bytes(marker[16..20].try_into().expect("slice length checked"));
        let continuous_time_delta_upper =
            u16::from_le_bytes(marker[20..22].try_into().expect("slice length checked"));

        if emitted_unknown_markers.iter().any(|seen| {
            *seen
                == (
                    thread_id,
                    continuous_time_delta,
                    continuous_time_delta_upper,
                )
        }) {
            continue;
        }

        let abs_ct = fh.base_continuous_time
            + (u64::from(continuous_time_delta_upper) << 32)
            + u64::from(continuous_time_delta);
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
            thread_id,
            pid,
            euid,
            persona_id: None,
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
            evidence: Rc::clone(evidence),
            message_flags: Vec::new(),
            items: ItemsData::None,
            signpost_id: 0,
            signpost_name: 0,
            resolved_message: RefCell::new(Some(Rc::new(String::new()))),
            format_string_error: None,
        })?;
    }
    ControlFlow::Continue(())
}

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
            if body.persona_id.is_some() {
                message_flags.push(MessageFlags::HasPersona);
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
            if body.persona_id.is_some() {
                message_flags.push(MessageFlags::HasPersona);
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
            if body.persona_id.is_some() {
                message_flags.push(MessageFlags::HasPersona);
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
            persona_id: None,
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
            persona_id: None,
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
        use crate::chunks::firehose::nonactivity::RawNonActivityBody;

        let nonactivity = RawNonActivityBody {
            activity_id: Some((10, 0)),
            persona_id: None,
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

    /// Upstream #150 asserts the persona flag lands first in the message-flag
    /// vector. Our bodies carry no flag vec, so the ordering is checked here,
    /// where `message_flags_for_body` builds it.
    #[test]
    fn test_message_flags_persona_ordering() {
        use crate::chunks::firehose::nonactivity::RawNonActivityBody;
        use crate::chunks::firehose::signpost::RawSignpostBody;

        let non_activity = [
            200, 0, 0, 0, 72, 5, 91, 0, 6, 0, 34, 6, 0, 8, 16, 148, 64, 1, 1, 0, 0, 0, 34, 4, 0, 0,
            11, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 34, 4, 11, 0, 54, 0, 97,
            99, 116, 105, 118, 97, 116, 105, 110, 103, 0, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 99, 102, 112, 114, 101, 102, 115, 100, 46, 100, 97, 101, 109, 111, 110, 46, 115,
            121, 115, 116, 101, 109, 46, 112, 101, 101, 114, 91, 54, 53, 93, 46, 48, 120, 49, 48,
            49, 52, 48, 57, 52, 49, 48, 0,
        ];
        let flags = FirehoseFlags::from_bits_retain(580);
        let (_, body) = RawNonActivityBody::parse(&non_activity, flags).unwrap();
        let formatter = body.formatter;
        assert_eq!(
            message_flags_for_body(&RawFirehoseBody::NonActivity(body), flags, &formatter),
            vec![
                MessageFlags::HasPersona,
                MessageFlags::SharedCache,
                MessageFlags::HasSubsystem
            ]
        );

        let signpost = [
            232, 3, 0, 0, 248, 253, 216, 218, 1, 0, 1, 0, 1, 53, 45, 172, 71, 70, 1, 18, 99, 57,
            219, 90, 1, 0, 0, 3, 0, 4, 1, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 10, 0, 0, 0,
        ];
        let flags = FirehoseFlags::from_bits_retain(33380);
        let (_, body) = RawSignpostBody::parse(&signpost, flags).unwrap();
        let formatter = body.formatter;
        assert_eq!(
            message_flags_for_body(&RawFirehoseBody::Signpost(body), flags, &formatter),
            vec![
                MessageFlags::HasPersona,
                MessageFlags::SharedCache,
                MessageFlags::HasLargeOffset,
                MessageFlags::HasSubsystem
            ]
        );
    }
}
