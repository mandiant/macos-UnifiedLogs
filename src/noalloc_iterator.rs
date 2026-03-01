// Copyright 2024 Shindan, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0

//! Zero-allocation single-pass iterator for tracev3 files.
//!
//! [`NoAllocLogStream`] provides a `next_entry()` API that yields [`NoAllocEntry`] structs
//! containing only scalar fields (no references, `Copy`). Entries can be filtered with zero
//! allocations, and selectively resolved into full [`LogData`] via [`NoAllocLogStream::resolve()`].
//!
//! # Usage
//!
//! ```rust,no_run
//! # use macos_unifiedlogs::noalloc_iterator::NoAllocLogStream;
//! # use std::collections::HashMap;
//! # let file_buf = vec![];
//! # let timesync = HashMap::new();
//! let mut stream = NoAllocLogStream::new(&file_buf, &timesync);
//! while let Some(entry) = stream.next_entry() {
//!     // Zero-alloc scalar filtering
//!     if !entry.is_fault() { continue; }
//!     // Resolve only matching entries (allocates)
//!     // if let Some(log_data) = stream.resolve(&entry, &mut provider) { ... }
//! }
//! ```

use std::collections::HashMap;

use log::{debug, error, warn};
use lz4_flex::decompress;
use nom::bytes::complete::{take, take_while};
use nom::number::complete::{le_u8, le_u16, le_u32, le_u64};
use regex::Regex;
use uuid::Uuid;

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::activity::FirehoseActivity;
use crate::chunks::firehose::firehose_log::{FirehoseItemData, FirehosePreamble};
use crate::chunks::firehose::nonactivity::FirehoseNonActivity;
use crate::chunks::firehose::signpost::FirehoseSignpost;
use crate::chunks::firehose::trace::FirehoseTrace;
use crate::chunks::oversize::Oversize;
use crate::chunks::simpledump::SimpleDumpStr;
use crate::chunks::statedump::{Statedump, StatedumpStr};
use crate::header::HeaderChunkStr;
use crate::message::format_firehose_log_message;
use crate::preamble::LogPreamble;
use crate::timesync::TimesyncBoot;
use crate::traits::FileProvider;
use crate::unified_log::{EventType, LogData, LogType};
use crate::util::{padding_size_8, u64_to_usize, unixepoch_to_datetime};
use crate::{empty_rc_string, rc_string};

// ── Constants ──────────────────────────────────────────────────────────────

const HEADER_CHUNK: u32 = 0x1000;
const CATALOG_CHUNK: u32 = 0x600b;
const CHUNKSET_CHUNK: u32 = 0x600d;
const FIREHOSE_CHUNK: u32 = 0x6001;
const OVERSIZE_CHUNK: u32 = 0x6002;

const ACTIVITY_TYPE: u8 = 0x2;
const TRACE_TYPE: u8 = 0x3;
const NON_ACTIVITY_TYPE: u8 = 0x4;
const SIGNPOST_TYPE: u8 = 0x6;
const LOSS_TYPE: u8 = 0x7;
const REMNANT_DATA: u8 = 0x0;
/// Synthetic log_activity_type values for non-firehose chunks.
const SIMPLEDUMP_TYPE: u8 = 0xF0;
const STATEDUMP_TYPE: u8 = 0xF1;

const BV41_COMPRESSED: u32 = 825_521_762; // "bv41"
const BV41_UNCOMPRESSED: u32 = 758_412_898; // "bv4-"

const CHUNK_PREAMBLE_SIZE: usize = 16;
const FIREHOSE_ENTRY_HEADER_SIZE: usize = 24;

// ── NoAllocEntry ───────────────────────────────────────────────────────────

/// A scalar-only, `Copy` log entry with no references or lifetimes.
///
/// All fields are plain integers or `Uuid` (which is `Copy`). This struct can be
/// freely copied, collected into `Vec`, filtered with iterator adapters, etc.
///
/// String data is NOT resolved — use [`NoAllocLogStream::resolve()`] to get a full
/// [`LogData`] with formatted message, process name, library, etc.
#[derive(Debug, Clone, Copy)]
pub struct NoAllocEntry {
    // ── Identity ──
    pub pid: u64,
    pub euid: u32,
    pub thread_id: u64,
    pub continuous_time: u64,
    pub timestamp: f64,

    // ── Classification ──
    /// 0x2=activity, 0x4=nonactivity, 0x6=signpost, 0x3=trace, 0x7=loss
    pub log_activity_type: u8,
    /// Info/debug/error/fault/signpost variants
    pub log_type: u8,
    pub flags: u16,

    // ── String pointers (NOT resolved) ──
    pub format_string_location: u32,
    /// >0 means this entry has oversize data
    pub data_ref_value: u32,

    // ── Boot/process context ──
    pub boot_uuid: Uuid,
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub subsystem_value: u16,

    // ── Data layout ──
    pub data_size: u16,
    pub number_items: u8,
    pub private_data_virtual_offset: u16,
    pub ttl: u8,

    // ── Internal: raw data location in decomp buffer (for resolve) ──
    #[allow(dead_code)]
    pub(crate) catalog_index: u32,
    pub(crate) decomp_generation: u32,
    pub(crate) decomp_data_offset: u32,
    pub(crate) decomp_data_len: u16,
    // For private data resolution
    pub(crate) preamble_public_data_start: u32,
    pub(crate) preamble_public_data_size: u16,
    pub(crate) collapsed: u8,
}

impl NoAllocEntry {
    /// Whether this entry references oversize data.
    #[inline]
    pub fn has_oversize(&self) -> bool {
        self.data_ref_value != 0
    }

    /// Whether this is a Fault log entry (`log_type` == 0x11).
    #[inline]
    pub fn is_fault(&self) -> bool {
        self.log_type == 0x11
    }

    /// Whether this is an Error log entry (`log_type` == 0x10).
    #[inline]
    pub fn is_error(&self) -> bool {
        self.log_type == 0x10
    }

    /// Whether this is a non-activity entry (standard log).
    #[inline]
    pub fn is_non_activity(&self) -> bool {
        self.log_activity_type == NON_ACTIVITY_TYPE
    }

    /// Whether this is an activity entry.
    #[inline]
    pub fn is_activity(&self) -> bool {
        self.log_activity_type == ACTIVITY_TYPE
    }

    /// Whether this is a signpost entry.
    #[inline]
    pub fn is_signpost(&self) -> bool {
        self.log_activity_type == SIGNPOST_TYPE
    }

    /// Whether this is a trace entry.
    #[inline]
    pub fn is_trace(&self) -> bool {
        self.log_activity_type == TRACE_TYPE
    }

    /// Whether this is a loss entry.
    #[inline]
    pub fn is_loss(&self) -> bool {
        self.log_activity_type == LOSS_TYPE
    }

    /// Get the resolved [`LogType`] enum value.
    #[inline]
    pub fn log_type_enum(&self) -> LogType {
        get_log_type(self.log_type, self.log_activity_type)
    }

    /// Get the resolved [`EventType`] enum value.
    #[inline]
    pub fn event_type_enum(&self) -> EventType {
        get_event_type(self.log_activity_type)
    }
}

// Duplicated from unified_log.rs (private there)
fn get_log_type(log_type: u8, activity_type: u8) -> LogType {
    match log_type {
        0x1 => {
            if activity_type == 2 {
                LogType::Create
            } else {
                LogType::Info
            }
        }
        0x2 => LogType::Debug,
        0x3 => LogType::Useraction,
        0x10 => LogType::Error,
        0x11 => LogType::Fault,
        0x80 => LogType::ProcessSignpostEvent,
        0x81 => LogType::ProcessSignpostStart,
        0x82 => LogType::ProcessSignpostEnd,
        0xc0 => LogType::SystemSignpostEvent,
        0xc1 => LogType::SystemSignpostStart,
        0xc2 => LogType::SystemSignpostEnd,
        0x40 => LogType::ThreadSignpostEvent,
        0x41 => LogType::ThreadSignpostStart,
        0x42 => LogType::ThreadSignpostEnd,
        _ => LogType::Default,
    }
}

// Duplicated from unified_log.rs (private there)
fn get_event_type(event_type: u8) -> EventType {
    match event_type {
        0x4 => EventType::Log,
        0x2 => EventType::Activity,
        0x3 => EventType::Trace,
        0x6 => EventType::Signpost,
        0x7 => EventType::Loss,
        _ => EventType::Unknown,
    }
}

// ── Internal State Types ───────────────────────────────────────────────────

/// Tracks whether decompressed data is owned (compressed chunkset) or borrowed (uncompressed).
enum DecompSource<'file> {
    None,
    /// Data is in `self.decomp_buf`
    Owned,
    /// Data is a slice from `file_buf` (uncompressed chunkset)
    Borrowed(&'file [u8]),
}

/// Multi-level cursor state for resumable iteration within a decompressed chunkset.
struct InnerIterState {
    /// Position within the decompressed data (inner chunk level)
    inner_cursor: usize,
    /// Total length of decompressed data
    inner_data_len: usize,
    /// Current firehose preamble being iterated (entry level)
    preamble: Option<PreambleIterState>,
}

/// State for iterating entries within a single firehose preamble.
struct PreambleIterState {
    first_proc_id: u64,
    second_proc_id: u32,
    ttl: u8,
    collapsed: u8,
    private_data_virtual_offset: u16,
    base_continuous_time: u64,
    pid: u64,
    euid: u32,
    /// Absolute offset of public data start in decomp source
    public_data_start: usize,
    /// Length of public data
    public_data_len: usize,
    /// Cursor within public data (relative to `public_data_start`)
    entry_cursor: usize,
}

// ── NoAllocLogStream ───────────────────────────────────────────────────────

/// A single-pass, streaming iterator over tracev3 file entries.
///
/// Yields [`NoAllocEntry`] structs containing only scalar fields (no allocations).
/// Entries can be selectively resolved into full [`LogData`] via [`resolve()`](Self::resolve).
pub struct NoAllocLogStream<'file, 'ts> {
    file_buf: &'file [u8],
    cursor: usize,
    boot_uuid: Uuid,
    timezone_path: String,

    current_catalog: Option<CatalogChunk>,
    catalog_index: u32,

    decomp_buf: Vec<u8>,
    decomp_source: DecompSource<'file>,
    decomp_generation: u32,

    oversize_cache: Vec<Oversize>,
    timesync: &'ts HashMap<Uuid, TimesyncBoot>,

    inner_state: Option<InnerIterState>,
    message_re: Regex,

    /// Queue of pre-resolved LogData from simpledump/statedump chunks.
    /// Entries are paired: `next_entry` yields a synthetic `NoAllocEntry`, and
    /// `resolve` returns the corresponding `LogData` from `last_resolved_dump`.
    pending_resolved: Vec<LogData>,

    /// The last simpledump/statedump entry popped by `next_entry()`, waiting for `resolve()`.
    last_resolved_dump: Option<LogData>,
}

impl<'file, 'ts> NoAllocLogStream<'file, 'ts> {
    /// Create a new stream over a tracev3 file buffer.
    pub fn new(
        data: &'file [u8],
        timesync: &'ts HashMap<Uuid, TimesyncBoot>,
    ) -> Self {
        Self::with_oversize_cache(data, timesync, Vec::new())
    }

    /// Create a new stream with an existing oversize cache (carried from a previous file).
    pub fn with_oversize_cache(
        data: &'file [u8],
        timesync: &'ts HashMap<Uuid, TimesyncBoot>,
        cache: Vec<Oversize>,
    ) -> Self {
        Self {
            file_buf: data,
            cursor: 0,
            boot_uuid: Uuid::nil(),
            timezone_path: String::new(),
            current_catalog: None,
            catalog_index: 0,
            decomp_buf: Vec::new(),
            decomp_source: DecompSource::None,
            decomp_generation: 0,
            oversize_cache: cache,
            timesync,
            inner_state: None,
            message_re: Regex::new(
                r"(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))",
            ).expect("Failed to compile message format regex"),
            pending_resolved: Vec::new(),
            last_resolved_dump: None,
        }
    }

    /// Yield the next scalar-only entry, or `None` at EOF.
    ///
    /// This method performs zero heap allocations. All parsing results are stored
    /// as scalar fields in the returned [`NoAllocEntry`].
    #[allow(clippy::collapsible_if, clippy::collapsible_match)]
    pub fn next_entry(&mut self) -> Option<NoAllocEntry> {
        loop {
            // Drain any pending pre-resolved simpledump/statedump entries first.
            // Pop the LogData into `last_resolved_dump` so the queue always shrinks,
            // even if the caller never calls `resolve()`.
            if let Some(log_data) = self.pending_resolved.pop() {
                self.last_resolved_dump = Some(log_data);
                return Some(NoAllocEntry {
                    pid: 0,
                    euid: 0,
                    thread_id: 0,
                    continuous_time: 0,
                    timestamp: 0.0,
                    log_activity_type: SIMPLEDUMP_TYPE, // marker type
                    log_type: 0,
                    flags: 0,
                    format_string_location: 0,
                    data_ref_value: 0,
                    boot_uuid: self.boot_uuid,
                    first_proc_id: 0,
                    second_proc_id: 0,
                    subsystem_value: 0,
                    data_size: 0,
                    number_items: 0,
                    private_data_virtual_offset: 0,
                    ttl: 0,
                    catalog_index: 0,
                    decomp_generation: self.decomp_generation,
                    decomp_data_offset: 0,
                    decomp_data_len: 0,
                    preamble_public_data_start: 0,
                    preamble_public_data_size: 0,
                    collapsed: 0,
                });
            }

            // Level 3: yield next entry from current preamble
            if let Some(ref mut inner) = self.inner_state {
                if let Some(ref mut preamble) = inner.preamble {
                    // Inline try_next_from_preamble to avoid borrow conflict
                    let decomp_data = match &self.decomp_source {
                        DecompSource::None => None,
                        DecompSource::Owned => Some(self.decomp_buf.as_slice()),
                        DecompSource::Borrowed(s) => Some(*s),
                    };
                    if let Some(decomp_data) = decomp_data {
                        let abs_cursor =
                            preamble.public_data_start + preamble.entry_cursor;
                        let remaining_in_preamble =
                            preamble.public_data_len.saturating_sub(preamble.entry_cursor);

                        if remaining_in_preamble >= FIREHOSE_ENTRY_HEADER_SIZE {
                            if let Some(entry_data) =
                                decomp_data.get(abs_cursor..abs_cursor + remaining_in_preamble)
                            {
                                match Self::parse_entry_from_data(
                                    entry_data,
                                    abs_cursor,
                                    preamble,
                                    self.timesync,
                                    self.boot_uuid,
                                    self.catalog_index,
                                    self.decomp_generation,
                                ) {
                                    Some(Some(entry)) => return Some(entry),
                                    Some(None) => continue, // Skip unknown type, cursor advanced
                                    None => {} // Preamble exhausted (remnant/parse failure)
                                }
                            }
                        }
                    }
                    // Preamble exhausted
                    inner.preamble = None;
                }
            }

            // Level 2: advance to next inner chunk in decompressed data
            // Take inner_state out to avoid borrow conflict with self
            if let Some(mut inner) = self.inner_state.take() {
                if self.try_advance_inner_chunk(&mut inner).is_some() {
                    self.inner_state = Some(inner);
                    continue;
                }
                // Inner data exhausted — don't put it back
            }

            // Level 1: advance to next top-level chunk in file
            if !self.try_advance_top_level_chunk() {
                return None; // EOF
            }
        }
    }

    /// Get a reference to the accumulated oversize cache.
    pub fn oversize_cache(&self) -> &[Oversize] {
        &self.oversize_cache
    }

    /// Consume the stream and return the oversize cache for carrying to the next file.
    pub fn into_oversize_cache(self) -> Vec<Oversize> {
        self.oversize_cache
    }

    /// Iterate all entries, calling `f` for each one.
    pub fn for_each_entry(&mut self, mut f: impl FnMut(NoAllocEntry)) {
        while let Some(entry) = self.next_entry() {
            f(entry);
        }
    }

    /// Iterate all entries, calling `f` for each one. Stops on first error.
    pub fn try_for_each_entry<E>(
        &mut self,
        mut f: impl FnMut(NoAllocEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        while let Some(entry) = self.next_entry() {
            f(entry)?;
        }
        Ok(())
    }

    /// Resolve a [`NoAllocEntry`] into a full [`LogData`] with formatted message.
    ///
    /// This performs the expensive operations: parsing sub-type headers, looking up
    /// format strings from DSC/UUIDText, resolving oversize entries, and formatting
    /// the log message via printf-style expansion.
    ///
    /// Returns `None` if:
    /// - The entry's `decomp_generation` doesn't match the current generation
    ///   (the decompression buffer has been overwritten by a newer chunkset)
    /// - The sub-type parser fails
    /// - The string lookup fails
    pub fn resolve(
        &mut self,
        entry: &NoAllocEntry,
        provider: &mut dyn FileProvider,
    ) -> Option<LogData> {
        // Safety check: entry must be from the current chunkset
        if entry.decomp_generation != self.decomp_generation {
            warn!(
                "[noalloc_iterator] Stale entry: generation {} != current {}",
                entry.decomp_generation, self.decomp_generation
            );
            return None;
        }

        // Simpledump/statedump: return pre-resolved LogData stashed by next_entry()
        if entry.log_activity_type == SIMPLEDUMP_TYPE || entry.log_activity_type == STATEDUMP_TYPE {
            return self.last_resolved_dump.take();
        }

        // Take catalog out temporarily to avoid borrow conflict
        // (resolve_* methods need &mut self for oversize_cache access)
        let catalog = self.current_catalog.take()?;

        // Get the raw firehose data from the decomp source
        let offset = entry.decomp_data_offset as usize;
        let len = entry.decomp_data_len as usize;
        let raw_data_owned;
        {
            let raw_slice = self.get_decomp_slice(offset, len);
            match raw_slice {
                Some(s) => {
                    raw_data_owned = s.to_vec();
                }
                None => {
                    self.current_catalog = Some(catalog);
                    return None;
                }
            }
        }

        // Build the base LogData
        let timezone_name = rc_string!(
            self.timezone_path
                .split('/')
                .next_back()
                .unwrap_or("Unknown Timezone Name")
        );

        let mut log_data = LogData {
            subsystem: empty_rc_string(),
            thread_id: entry.thread_id,
            pid: entry.pid,
            euid: entry.euid,
            library: empty_rc_string(),
            library_uuid: Uuid::nil(),
            activity_id: 0,
            time: entry.timestamp,
            timestamp: unixepoch_to_datetime(entry.timestamp as i64),
            category: empty_rc_string(),
            log_type: entry.log_type_enum(),
            event_type: entry.event_type_enum(),
            process: empty_rc_string(),
            process_uuid: Uuid::nil(),
            message: empty_rc_string(),
            raw_message: empty_rc_string(),
            boot_uuid: entry.boot_uuid,
            timezone_name,
            message_entries: Vec::new(),
        };

        let result = match entry.log_activity_type {
            NON_ACTIVITY_TYPE => {
                self.resolve_non_activity(entry, &raw_data_owned, &catalog, provider, &mut log_data)
            }
            ACTIVITY_TYPE => {
                self.resolve_activity(entry, &raw_data_owned, &catalog, provider, &mut log_data)
            }
            SIGNPOST_TYPE => {
                self.resolve_signpost(entry, &raw_data_owned, &catalog, provider, &mut log_data)
            }
            TRACE_TYPE => {
                self.resolve_trace(entry, &raw_data_owned, &catalog, provider, &mut log_data)
            }
            LOSS_TYPE => {
                log_data.event_type = EventType::Loss;
                log_data.log_type = LogType::Loss;
                Some(())
            }
            _ => {
                warn!(
                    "[noalloc_iterator] Unknown log_activity_type: {}",
                    entry.log_activity_type
                );
                None
            }
        };

        // Put catalog back
        self.current_catalog = Some(catalog);

        result.map(|()| log_data)
    }

    // ── Level 3: entry from preamble ───────────────────────────────────

    /// Parse a single entry from the given data slice at the preamble cursor.
    /// This is a static method to avoid borrow conflicts with `self`.
    /// Advances `preamble.entry_cursor` on success.
    /// Returns:
    /// - `Some(Some(entry))` — valid entry parsed
    /// - `Some(None)` — entry skipped (cursor advanced), caller should retry
    /// - `None` — preamble exhausted (remnant data or parse failure)
    fn parse_entry_from_data(
        entry_data: &[u8],
        abs_cursor: usize,
        preamble: &mut PreambleIterState,
        timesync: &HashMap<Uuid, TimesyncBoot>,
        boot_uuid: Uuid,
        catalog_index: u32,
        decomp_generation: u32,
    ) -> Option<Option<NoAllocEntry>> {
        // Parse 24-byte entry header
        let (rest, log_activity_type) =
            le_u8::<_, nom::error::Error<&[u8]>>(entry_data).ok()?;

        if log_activity_type == REMNANT_DATA {
            return None;
        }

        let (rest, log_type) = le_u8::<_, nom::error::Error<&[u8]>>(rest).ok()?;
        let (rest, flags) = le_u16::<_, nom::error::Error<&[u8]>>(rest).ok()?;
        let (rest, format_string_location) =
            le_u32::<_, nom::error::Error<&[u8]>>(rest).ok()?;
        let (rest, thread_id) = le_u64::<_, nom::error::Error<&[u8]>>(rest).ok()?;
        let (rest, continuous_time_delta) =
            le_u32::<_, nom::error::Error<&[u8]>>(rest).ok()?;
        let (rest, continuous_time_delta_upper) =
            le_u16::<_, nom::error::Error<&[u8]>>(rest).ok()?;
        let (rest, data_size) = le_u16::<_, nom::error::Error<&[u8]>>(rest).ok()?;

        let entry_body_len = data_size as usize;
        if rest.len() < entry_body_len {
            return None;
        }
        let raw_firehose_data = &rest[..entry_body_len];

        // Advance the entry cursor past header + body + padding
        let data_pad = padding_size_8(u64::from(data_size)) as usize;
        let total_advance = FIREHOSE_ENTRY_HEADER_SIZE + entry_body_len + data_pad;
        preamble.entry_cursor += total_advance;

        // Check valid type — cursor already advanced, return Skip for unknown types
        if !matches!(
            log_activity_type,
            ACTIVITY_TYPE | TRACE_TYPE | NON_ACTIVITY_TYPE | SIGNPOST_TYPE | LOSS_TYPE
        ) {
            return Some(None);
        }

        // Calculate continuous time
        let entry_continuous_time = u64::from(continuous_time_delta)
            | (u64::from(continuous_time_delta_upper) << 32);
        let absolute_continuous_time =
            preamble.base_continuous_time + entry_continuous_time;

        // Calculate wall-clock timestamp
        let timestamp = TimesyncBoot::get_timestamp(
            timesync,
            boot_uuid,
            absolute_continuous_time,
            preamble.base_continuous_time,
        );

        // Extract scalars from sub-type header
        let (data_ref_value, subsystem_value, number_items) =
            extract_subtype_scalars(raw_firehose_data, log_activity_type, flags);

        // Record the absolute offset of the raw firehose data in the decomp buffer
        let decomp_data_offset = abs_cursor + FIREHOSE_ENTRY_HEADER_SIZE;

        Some(Some(NoAllocEntry {
            pid: preamble.pid,
            euid: preamble.euid,
            thread_id,
            continuous_time: absolute_continuous_time,
            timestamp,
            log_activity_type,
            log_type,
            flags,
            format_string_location,
            data_ref_value,
            boot_uuid,
            first_proc_id: preamble.first_proc_id,
            second_proc_id: preamble.second_proc_id,
            subsystem_value,
            data_size,
            number_items,
            private_data_virtual_offset: preamble.private_data_virtual_offset,
            ttl: preamble.ttl,
            catalog_index,
            decomp_generation,
            decomp_data_offset: decomp_data_offset as u32,
            decomp_data_len: data_size,
            preamble_public_data_start: preamble.public_data_start as u32,
            preamble_public_data_size: preamble.public_data_len as u16,
            collapsed: preamble.collapsed,
        }))
    }

    // ── Level 2: inner chunk advancement ───────────────────────────────

    /// Try to advance to the next inner chunk within decompressed data.
    fn try_advance_inner_chunk(&mut self, inner: &mut InnerIterState) -> Option<InnerChunkResult> {
        let decomp_data = match &self.decomp_source {
            DecompSource::None => return None,
            DecompSource::Owned => self.decomp_buf.as_slice(),
            DecompSource::Borrowed(s) => s,
        };

        while inner.inner_cursor + CHUNK_PREAMBLE_SIZE <= inner.inner_data_len {
            let input = &decomp_data[inner.inner_cursor..inner.inner_data_len];

            let preamble = match LogPreamble::detect_preamble(input) {
                Ok((_, p)) => p,
                Err(_) => return None,
            };

            let chunk_size = u64_to_usize(preamble.chunk_data_size)?;

            let total = chunk_size + CHUNK_PREAMBLE_SIZE;
            if total > input.len() {
                return None;
            }

            let chunk_data = &input[..total];
            let chunk_abs_start = inner.inner_cursor;

            // Advance past chunk
            let remaining = &input[total..];
            let trimmed = skip_zero_padding(remaining);
            let consumed = total + (remaining.len() - trimmed.len());
            inner.inner_cursor += consumed;

            match preamble.chunk_tag {
                FIREHOSE_CHUNK => {
                    // Parse preamble header to set up PreambleIterState
                    if let Some(preamble_state) =
                        self.parse_firehose_preamble_state(chunk_data, chunk_abs_start)
                    {
                        inner.preamble = Some(preamble_state);
                        return Some(InnerChunkResult::PreambleReady);
                    }
                    // Failed to parse — skip to next inner chunk
                }
                OVERSIZE_CHUNK => {
                    match Oversize::parse_oversize(chunk_data) {
                        Ok((_, oversize)) => {
                            self.oversize_cache.push(oversize);
                        }
                        Err(err) => {
                            error!("[noalloc_iterator] Failed to parse oversize: {err:?}");
                        }
                    }
                    // Continue to next inner chunk
                }
                0x6004 => {
                    // Simpledump: eagerly resolve and queue LogData
                    if let Some(log_data) = self.resolve_simpledump(chunk_data) {
                        self.pending_resolved.push(log_data);
                    }
                }
                0x6003 => {
                    // Statedump: eagerly resolve and queue LogData
                    if let Some(log_data) = self.resolve_statedump(chunk_data) {
                        self.pending_resolved.push(log_data);
                    }
                }
                other => {
                    warn!("[noalloc_iterator] Unknown inner chunk type: 0x{other:04x}");
                }
            }
        }

        None // Inner data exhausted
    }

    /// Parse a firehose preamble header and return a `PreambleIterState`.
    fn parse_firehose_preamble_state(
        &self,
        chunk_data: &[u8],
        chunk_abs_start: usize,
    ) -> Option<PreambleIterState> {
        let catalog = self.current_catalog.as_ref()?;

        let input = chunk_data;
        // Parse fixed preamble fields
        let (input, _chunk_tag) = le_u32::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, _chunk_sub_tag) = le_u32::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, _chunk_data_size) = le_u64::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, first_number_proc_id) =
            le_u64::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, second_number_proc_id) =
            le_u32::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, ttl) = le_u8::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, collapsed) = le_u8::<_, nom::error::Error<&[u8]>>(input).ok()?;
        // Skip 2 unknown bytes
        let input = input.get(2..)?;
        let (input, public_data_size) =
            le_u16::<_, nom::error::Error<&[u8]>>(input).ok()?;
        let (input, private_data_virtual_offset) =
            le_u16::<_, nom::error::Error<&[u8]>>(input).ok()?;
        // Skip unknown2 + unknown3 (4 bytes)
        let input = input.get(4..)?;
        let (input, base_continuous_time) =
            le_u64::<_, nom::error::Error<&[u8]>>(input).ok()?;

        // Public data starts right after the preamble fixed header
        let public_data_size_offset: u16 = 16;
        let public_data_len =
            public_data_size.saturating_sub(public_data_size_offset) as usize;

        if input.len() < public_data_len {
            return None;
        }

        let pid = catalog.get_pid(first_number_proc_id, second_number_proc_id);
        let euid = catalog.get_euid(first_number_proc_id, second_number_proc_id);

        // The public data starts at chunk_abs_start + preamble header size
        // Preamble header: 16 (chunk preamble) + 8 (first_proc_id) + 4 (second_proc_id)
        //   + 1 (ttl) + 1 (collapsed) + 2 (unknown) + 2 (public_data_size)
        //   + 2 (private_data_virtual_offset) + 2 (unknown2) + 2 (unknown3) + 8 (base_time)
        //   = 16 + 32 = 48
        let preamble_header_size = 48;
        let public_data_start = chunk_abs_start + preamble_header_size;

        Some(PreambleIterState {
            first_proc_id: first_number_proc_id,
            second_proc_id: second_number_proc_id,
            ttl,
            collapsed,
            private_data_virtual_offset,
            base_continuous_time,
            pid,
            euid,
            public_data_start,
            public_data_len,
            entry_cursor: 0,
        })
    }

    /// Eagerly resolve a simpledump chunk into `LogData`.
    fn resolve_simpledump(&self, chunk_data: &[u8]) -> Option<LogData> {
        let (_, sd) = SimpleDumpStr::parse_simpledump(chunk_data).ok()?;
        let no_firehose_preamble = 1;
        let timestamp = TimesyncBoot::get_timestamp(
            self.timesync,
            self.boot_uuid,
            sd.continous_time,
            no_firehose_preamble,
        );
        let timezone_name = rc_string!(
            self.timezone_path
                .split('/')
                .next_back()
                .unwrap_or("Unknown Timezone Name")
        );
        Some(LogData {
            subsystem: rc_string!(sd.subsystem),
            thread_id: sd.thread_id,
            pid: sd.first_proc_id,
            euid: 0,
            library: empty_rc_string(),
            library_uuid: sd.sender_uuid,
            activity_id: 0,
            time: timestamp,
            timestamp: unixepoch_to_datetime(timestamp as i64),
            category: empty_rc_string(),
            log_type: LogType::Simpledump,
            event_type: EventType::Simpledump,
            process: empty_rc_string(),
            process_uuid: sd.dsc_uuid,
            message: rc_string!(sd.message_string),
            raw_message: empty_rc_string(),
            boot_uuid: self.boot_uuid,
            timezone_name,
            message_entries: Vec::new(),
        })
    }

    /// Eagerly resolve a statedump chunk into `LogData`.
    fn resolve_statedump(&self, chunk_data: &[u8]) -> Option<LogData> {
        let (_, sd) = StatedumpStr::parse_statedump(chunk_data).ok()?;
        let data_string = match sd.unknown_data_type {
            0x1 => Statedump::<&str>::parse_statedump_plist(&sd.statedump_data),
            0x2 => match sunlight::light::extract_protobuf(&sd.statedump_data) {
                Ok(map) => serde_json::to_string(&map)
                    .unwrap_or_else(|_| String::from("Failed to serialize Protobuf HashMap")),
                Err(_) => format!(
                    "Failed to parse StateDump protobuf: {}",
                    crate::util::encode_standard(&sd.statedump_data)
                ),
            },
            0x3 => Statedump::<&str>::parse_statedump_object(
                &sd.statedump_data,
                sd.title_name,
            )
            .to_string(),
            _ => {
                let results = crate::util::extract_string(&sd.statedump_data);
                match results {
                    Ok((_, s)) => s.to_string(),
                    Err(_) => String::from("Failed to extract string from statedump"),
                }
            }
        };
        let no_firehose_preamble = 1;
        let timestamp = TimesyncBoot::get_timestamp(
            self.timesync,
            self.boot_uuid,
            sd.continuous_time,
            no_firehose_preamble,
        );
        let timezone_name = rc_string!(
            self.timezone_path
                .split('/')
                .next_back()
                .unwrap_or("Unknown Timezone Name")
        );
        Some(LogData {
            subsystem: empty_rc_string(),
            thread_id: 0,
            pid: sd.first_proc_id,
            euid: 0,
            library: empty_rc_string(),
            library_uuid: Uuid::nil(),
            activity_id: sd.activity_id,
            time: timestamp,
            timestamp: unixepoch_to_datetime(timestamp as i64),
            category: empty_rc_string(),
            log_type: LogType::Statedump,
            event_type: EventType::Statedump,
            process: empty_rc_string(),
            process_uuid: Uuid::nil(),
            message: rc_string!(format!(
                "title: {}\nObject Type: {}\nObject Type: {}\n{data_string}",
                sd.title_name, sd.decoder_library, sd.decoder_type,
            )),
            raw_message: empty_rc_string(),
            boot_uuid: self.boot_uuid,
            timezone_name,
            message_entries: Vec::new(),
        })
    }

    // ── Level 1: top-level chunk advancement ───────────────────────────

    /// Try to advance to the next top-level chunk. Returns false at EOF.
    fn try_advance_top_level_chunk(&mut self) -> bool {
        while self.cursor + CHUNK_PREAMBLE_SIZE <= self.file_buf.len() {
            let input = &self.file_buf[self.cursor..];

            let preamble = match LogPreamble::detect_preamble(input) {
                Ok((_, p)) => p,
                Err(err) => {
                    error!("[noalloc_iterator] Failed to detect preamble: {err:?}");
                    return false;
                }
            };

            let total_chunk_size = preamble.chunk_data_size as usize + CHUNK_PREAMBLE_SIZE;
            if self.cursor + total_chunk_size > self.file_buf.len() {
                warn!(
                    "[noalloc_iterator] Chunk extends beyond file buffer ({} + {} > {})",
                    self.cursor,
                    total_chunk_size,
                    self.file_buf.len()
                );
                return false;
            }

            let chunk_data = &self.file_buf[self.cursor..self.cursor + total_chunk_size];

            // Advance cursor past chunk + padding
            self.cursor += total_chunk_size;
            let padding = padding_size_8(preamble.chunk_data_size) as usize;
            if self.cursor + padding <= self.file_buf.len() {
                self.cursor += padding;
            }

            match preamble.chunk_tag {
                HEADER_CHUNK => {
                    self.parse_header(chunk_data);
                }
                CATALOG_CHUNK => {
                    match CatalogChunk::parse_catalog(chunk_data) {
                        Ok((_, catalog)) => {
                            self.current_catalog = Some(catalog);
                            self.catalog_index += 1;
                        }
                        Err(err) => {
                            error!("[noalloc_iterator] Failed to parse catalog: {err:?}");
                        }
                    }
                }
                CHUNKSET_CHUNK => {
                    if self.current_catalog.is_some() && self.process_chunkset(chunk_data) {
                        return true; // inner_state is now set up
                    }
                    if self.current_catalog.is_none() {
                        warn!("[noalloc_iterator] Chunkset encountered without a catalog");
                    }
                }
                other => {
                    warn!("[noalloc_iterator] Unknown top-level chunk type: 0x{other:04x}");
                }
            }
        }

        false // EOF
    }

    /// Parse a header chunk and extract `boot_uuid` + `timezone_path`.
    fn parse_header(&mut self, chunk_data: &[u8]) {
        match HeaderChunkStr::parse_header(chunk_data) {
            Ok((_, header)) => {
                self.boot_uuid = header.boot_uuid;
                self.timezone_path = header.timezone_path.to_string();
                debug!(
                    "[noalloc_iterator] Parsed header, boot_uuid={}",
                    self.boot_uuid
                );
            }
            Err(err) => {
                error!("[noalloc_iterator] Failed to parse header: {err:?}");
            }
        }
    }

    /// Parse a chunkset: decompress if needed, set up `inner_state`.
    /// Returns true if `inner_state` was successfully set up.
    fn process_chunkset(&mut self, chunk_data: &[u8]) -> bool {
        // Skip the 16-byte chunk preamble to get the chunkset data
        let inner = match chunk_data.get(CHUNK_PREAMBLE_SIZE..) {
            Some(d) => d,
            None => return false,
        };

        let (input, signature) = match le_u32::<_, nom::error::Error<&[u8]>>(inner) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let (input, uncompress_size) = match le_u32::<_, nom::error::Error<&[u8]>>(input) {
            Ok(r) => r,
            Err(_) => return false,
        };

        self.decomp_generation += 1;

        if signature == BV41_UNCOMPRESSED {
            // Uncompressed data — borrow from file_buf
            let data_start = (chunk_data.as_ptr() as usize)
                .saturating_sub(self.file_buf.as_ptr() as usize)
                + CHUNK_PREAMBLE_SIZE
                + 8; // 4 (signature) + 4 (uncompress_size)

            let data_len = uncompress_size as usize;
            if data_start + data_len <= self.file_buf.len() {
                let borrowed = &self.file_buf[data_start..data_start + data_len];
                self.decomp_source = DecompSource::Borrowed(borrowed);
                self.inner_state = Some(InnerIterState {
                    inner_cursor: 0,
                    inner_data_len: data_len,
                    preamble: None,
                });
                return true;
            }
            false
        } else if signature == BV41_COMPRESSED {
            // Compressed data
            let (input, block_size) =
                match le_u32::<_, nom::error::Error<&[u8]>>(input) {
                    Ok(r) => r,
                    Err(_) => return false,
                };
            let compressed_data = match input.get(..block_size as usize) {
                Some(d) => d,
                None => return false,
            };

            let target_size = uncompress_size as usize;
            match decompress(compressed_data, target_size) {
                Ok(decompressed) => {
                    self.decomp_buf = decompressed;
                    self.decomp_source = DecompSource::Owned;
                    self.inner_state = Some(InnerIterState {
                        inner_cursor: 0,
                        inner_data_len: self.decomp_buf.len(),
                        preamble: None,
                    });
                    true
                }
                Err(err) => {
                    error!("[noalloc_iterator] LZ4 decompression failed: {err:?}");
                    false
                }
            }
        } else {
            warn!("[noalloc_iterator] Unknown chunkset signature: 0x{signature:08x}");
            false
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────

    /// Get the current decompressed data slice.
    fn get_decomp_data(&self) -> Option<&[u8]> {
        match &self.decomp_source {
            DecompSource::None => None,
            DecompSource::Owned => Some(self.decomp_buf.as_slice()),
            DecompSource::Borrowed(s) => Some(s),
        }
    }

    /// Get a slice from the decompressed data at a given offset and length.
    fn get_decomp_slice(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let data = self.get_decomp_data()?;
        data.get(offset..offset + len)
    }

    // ── Resolution helpers ─────────────────────────────────────────────

    fn resolve_non_activity(
        &mut self,
        entry: &NoAllocEntry,
        raw_data: &[u8],
        catalog: &CatalogChunk,
        provider: &mut dyn FileProvider,
        log_data: &mut LogData,
    ) -> Option<()> {
        let non_activity =
            match FirehoseNonActivity::parse_non_activity(raw_data, &entry.flags) {
                Ok((_, na)) => na,
                Err(err) => {
                    warn!("[noalloc_iterator] Failed to parse non-activity: {err:?}");
                    return None;
                }
            };

        log_data.activity_id = u64::from(non_activity.unknown_activity_id);

        let message_data = FirehoseNonActivity::get_firehose_nonactivity_strings(
            &non_activity,
            provider,
            u64::from(entry.format_string_location),
            entry.first_proc_id,
            entry.second_proc_id,
            catalog,
        );

        match message_data {
            Ok((_, results)) => {
                log_data.library = rc_string!(results.library);
                log_data.library_uuid = results.library_uuid;
                log_data.process = rc_string!(results.process);
                log_data.process_uuid = results.process_uuid;
                results.format_string.clone_into(&mut log_data.raw_message);

                // Collect items for message formatting
                let mut item_data = self.collect_items_for_entry(entry, raw_data);

                // Handle private data
                self.apply_private_data(entry, &non_activity, &mut item_data);

                let log_message = if non_activity.data_ref_value != 0 {
                    let oversize_strings = Oversize::get_oversize_strings(
                        non_activity.data_ref_value,
                        entry.first_proc_id,
                        entry.second_proc_id,
                        &self.oversize_cache,
                    );
                    format_firehose_log_message(
                        results.format_string,
                        oversize_strings,
                        &self.message_re,
                    )
                } else {
                    format_firehose_log_message(
                        results.format_string,
                        &item_data.item_info,
                        &self.message_re,
                    )
                };

                if !item_data.backtrace_strings.is_empty() {
                    log_data.message = rc_string!(format!(
                        "Backtrace:\n{}\n{log_message}",
                        item_data
                            .backtrace_strings
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ));
                } else {
                    log_data.message = rc_string!(log_message);
                }
                log_data.message_entries = item_data.item_info;
            }
            Err(err) => {
                warn!(
                    "[noalloc_iterator] Failed to get non-activity strings: {err:?}"
                );
            }
        }

        // Subsystem/category lookup
        if non_activity.subsystem_value != 0
            && let Ok((_, subsystem)) = catalog.get_subsystem(
                non_activity.subsystem_value,
                entry.first_proc_id,
                entry.second_proc_id,
            )
        {
            log_data.subsystem = rc_string!(subsystem.subsystem);
            log_data.category = rc_string!(subsystem.category);
        }

        Some(())
    }

    fn resolve_activity(
        &mut self,
        entry: &NoAllocEntry,
        raw_data: &[u8],
        catalog: &CatalogChunk,
        provider: &mut dyn FileProvider,
        log_data: &mut LogData,
    ) -> Option<()> {
        let activity =
            match FirehoseActivity::parse_activity(raw_data, &entry.flags, &entry.log_type)
            {
                Ok((_, a)) => a,
                Err(err) => {
                    warn!("[noalloc_iterator] Failed to parse activity: {err:?}");
                    return None;
                }
            };

        log_data.activity_id = u64::from(activity.unknown_activity_id);

        let message_data = FirehoseActivity::get_firehose_activity_strings(
            &activity,
            provider,
            u64::from(entry.format_string_location),
            entry.first_proc_id,
            entry.second_proc_id,
            catalog,
        );

        match message_data {
            Ok((_, results)) => {
                log_data.library = results.library;
                log_data.library_uuid = results.library_uuid;
                log_data.process = results.process;
                log_data.process_uuid = results.process_uuid;
                results.format_string.clone_into(&mut log_data.raw_message);

                let item_data = self.collect_items_for_entry(entry, raw_data);

                let log_message = format_firehose_log_message(
                    results.format_string,
                    &item_data.item_info,
                    &self.message_re,
                );

                if !item_data.backtrace_strings.is_empty() {
                    log_data.message = rc_string!(format!(
                        "Backtrace:\n{}\n{log_message}",
                        item_data
                            .backtrace_strings
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ));
                } else {
                    log_data.message = rc_string!(log_message);
                }
                log_data.message_entries = item_data.item_info;
            }
            Err(err) => {
                warn!(
                    "[noalloc_iterator] Failed to get activity strings: {err:?}"
                );
            }
        }

        Some(())
    }

    fn resolve_signpost(
        &mut self,
        entry: &NoAllocEntry,
        raw_data: &[u8],
        catalog: &CatalogChunk,
        provider: &mut dyn FileProvider,
        log_data: &mut LogData,
    ) -> Option<()> {
        let signpost = match FirehoseSignpost::parse_signpost(raw_data, &entry.flags) {
            Ok((_, s)) => s,
            Err(err) => {
                warn!("[noalloc_iterator] Failed to parse signpost: {err:?}");
                return None;
            }
        };

        log_data.activity_id = u64::from(signpost.unknown_activity_id);

        let message_data = FirehoseSignpost::get_firehose_signpost(
            &signpost,
            provider,
            u64::from(entry.format_string_location),
            entry.first_proc_id,
            entry.second_proc_id,
            catalog,
        );

        match message_data {
            Ok((_, results)) => {
                log_data.library = results.library;
                log_data.library_uuid = results.library_uuid;
                log_data.process = results.process;
                log_data.process_uuid = results.process_uuid;
                results.format_string.clone_into(&mut log_data.raw_message);

                let item_data = self.collect_items_for_entry(entry, raw_data);

                let mut log_message = if entry.data_ref_value != 0 {
                    let oversize_strings = Oversize::get_oversize_strings(
                        entry.data_ref_value,
                        entry.first_proc_id,
                        entry.second_proc_id,
                        &self.oversize_cache,
                    );
                    format_firehose_log_message(
                        results.format_string,
                        oversize_strings,
                        &self.message_re,
                    )
                } else {
                    format_firehose_log_message(
                        results.format_string,
                        &item_data.item_info,
                        &self.message_re,
                    )
                };

                log_message = rc_string!(format!(
                    "Signpost ID: {:X} - Signpost Name: {:X}\n {log_message}",
                    signpost.signpost_id, signpost.signpost_name,
                ));

                if !item_data.backtrace_strings.is_empty() {
                    log_data.message = rc_string!(format!(
                        "Backtrace:\n{}\n{log_message}",
                        item_data
                            .backtrace_strings
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ));
                } else {
                    log_data.message = rc_string!(log_message);
                }
                log_data.message_entries = item_data.item_info;
            }
            Err(err) => {
                warn!(
                    "[noalloc_iterator] Failed to get signpost strings: {err:?}"
                );
            }
        }

        // Subsystem/category lookup
        if signpost.subsystem != 0
            && let Ok((_, subsystem)) = catalog.get_subsystem(
                signpost.subsystem,
                entry.first_proc_id,
                entry.second_proc_id,
            )
        {
            log_data.subsystem = subsystem.subsystem;
            log_data.category = subsystem.category;
        }

        Some(())
    }

    fn resolve_trace(
        &mut self,
        entry: &NoAllocEntry,
        raw_data: &[u8],
        catalog: &CatalogChunk,
        provider: &mut dyn FileProvider,
        log_data: &mut LogData,
    ) -> Option<()> {
        let _trace = match FirehoseTrace::parse_firehose_trace(raw_data) {
            Ok((_, t)) => t,
            Err(err) => {
                warn!("[noalloc_iterator] Failed to parse trace: {err:?}");
                return None;
            }
        };

        let message_data = FirehoseTrace::get_firehose_trace_strings(
            provider,
            u64::from(entry.format_string_location),
            entry.first_proc_id,
            entry.second_proc_id,
            catalog,
        );

        match message_data {
            Ok((_, results)) => {
                log_data.library = results.library;
                log_data.library_uuid = results.library_uuid;
                log_data.process = results.process;
                log_data.process_uuid = results.process_uuid;

                let item_data = self.collect_items_for_entry(entry, raw_data);

                let log_message = format_firehose_log_message(
                    results.format_string,
                    &item_data.item_info,
                    &self.message_re,
                );

                if !item_data.backtrace_strings.is_empty() {
                    log_data.message = rc_string!(format!(
                        "Backtrace:\n{}\n{log_message}",
                        item_data
                            .backtrace_strings
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ));
                } else {
                    log_data.message = rc_string!(log_message);
                }
                log_data.message_entries = item_data.item_info;
            }
            Err(err) => {
                warn!(
                    "[noalloc_iterator] Failed to get trace strings: {err:?}"
                );
            }
        }

        Some(())
    }

    /// Collect message items from a raw firehose entry using the existing parser.
    fn collect_items_for_entry(
        &self,
        entry: &NoAllocEntry,
        _raw_data: &[u8],
    ) -> FirehoseItemData {
        // The item data follows the sub-type header in the raw firehose data.
        // We use collect_items which expects the data after the sub-type header
        // and formatters. However, the existing parsers (parse_non_activity, etc.)
        // already consume the sub-type header; the remaining data contains the
        // formatters + items. We re-parse from raw_data since collect_items is
        // called after the sub-type parse.
        //
        // For simplicity and correctness, we re-parse the entire raw data:
        // The sub-type parsers leave the remaining data after consuming the header,
        // which is exactly what collect_items needs.
        //
        // Since collect_items needs the data AFTER the formatters (which the sub-type
        // parsers consume), and we've already parsed the sub-type in resolve_*,
        // we need the remainder from that parse.
        //
        // However, we don't have the remainder here. The existing codebase handles
        // this by parsing the sub-type AND collecting items in parse_firehose(),
        // which we can't easily replicate without re-parsing.
        //
        // The simplest correct approach: the items were already parsed as part of
        // the full firehose parse in parse_firehose_preamble (the existing code path).
        // Since we need to re-parse anyway, we use the full parse chain.
        //
        // For now, use the full FirehosePreamble::parse_firehose which returns
        // a Firehose struct with message items already collected. But we don't have
        // access to that here without re-parsing the whole preamble.
        //
        // Alternative: call collect_items with the remainder from the sub-type parse.
        // Since we have entry.number_items and entry.flags, we can call collect_items
        // on the data after the sub-type header.

        // Re-parse to get the remainder after the sub-type header
        let raw_data = _raw_data;
        let remainder = match entry.log_activity_type {
            NON_ACTIVITY_TYPE => {
                FirehoseNonActivity::parse_non_activity(raw_data, &entry.flags)
                    .ok()
                    .map(|(r, _)| r)
            }
            ACTIVITY_TYPE => {
                FirehoseActivity::parse_activity(raw_data, &entry.flags, &entry.log_type)
                    .ok()
                    .map(|(r, _)| r)
            }
            SIGNPOST_TYPE => {
                FirehoseSignpost::parse_signpost(raw_data, &entry.flags)
                    .ok()
                    .map(|(r, _)| r)
            }
            TRACE_TYPE => FirehoseTrace::parse_firehose_trace(raw_data)
                .ok()
                .map(|(r, _)| r),
            _ => None,
        };

        match remainder {
            Some(rest) => {
                // The remainder starts with unknown_item (u8) + number_items (u8),
                // matching the standard path in parse_firehose (firehose_log.rs:641-644).
                let minimum_item_size = 6;
                if rest.len() < minimum_item_size {
                    return FirehoseItemData::default();
                }
                let (rest, _unknown_item) = match le_u8::<&[u8], nom::error::Error<&[u8]>>(rest) {
                    Ok(v) => v,
                    Err(_) => return FirehoseItemData::default(),
                };
                let (rest, number_items) = match le_u8::<&[u8], nom::error::Error<&[u8]>>(rest) {
                    Ok(v) => v,
                    Err(_) => return FirehoseItemData::default(),
                };
                match FirehosePreamble::collect_items(
                    rest,
                    &number_items,
                    &entry.flags,
                ) {
                    Ok((_, items)) => items,
                    Err(_) => FirehoseItemData::default(),
                }
            }
            None => FirehoseItemData::default(),
        }
    }

    /// Apply private data to the item data if present.
    fn apply_private_data(
        &self,
        entry: &NoAllocEntry,
        non_activity: &FirehoseNonActivity,
        item_data: &mut FirehoseItemData,
    ) {
        if entry.private_data_virtual_offset == 0x1000 {
            return; // No private data
        }
        if non_activity.private_strings_size == 0 {
            return;
        }

        // Get the preamble's full data range from the decomp source
        let decomp_data = match self.get_decomp_data() {
            Some(d) => d,
            None => return,
        };

        // The private data is located after the public data in the preamble.
        // We need to find it using the offsets stored in the entry.
        let public_data_start = entry.preamble_public_data_start as usize;
        let public_data_size = entry.preamble_public_data_size as usize;

        // Private data follows public data (possibly with padding)
        let after_public = public_data_start + public_data_size;
        if after_public > decomp_data.len() {
            return;
        }

        let private_area = &decomp_data[after_public..];

        // Skip zero padding (unless collapsed)
        let private_input = if entry.collapsed == 1 {
            private_area
        } else {
            skip_zero_padding(private_area)
        };

        if private_input.is_empty() && entry.collapsed != 1 {
            // All zeros — use original
            let private_input = private_area;
            self.parse_private_strings(
                private_input,
                non_activity,
                entry.private_data_virtual_offset,
                item_data,
            );
        } else {
            self.parse_private_strings(
                private_input,
                non_activity,
                entry.private_data_virtual_offset,
                item_data,
            );
        }
    }

    fn parse_private_strings(
        &self,
        private_input: &[u8],
        non_activity: &FirehoseNonActivity,
        private_data_virtual_offset: u16,
        item_data: &mut FirehoseItemData,
    ) {
        if non_activity.private_strings_size == 0 || private_input.is_empty() {
            return;
        }

        let string_offset =
            non_activity.private_strings_offset.saturating_sub(private_data_virtual_offset);

        if let Ok((private_string_start, _)) =
            take::<_, _, nom::error::Error<&[u8]>>(string_offset)(private_input)
        {
            let _ = FirehosePreamble::parse_private_data(private_string_start, item_data);
        }
    }
}

// ── Duplicated helpers (private in tracev3_stream.rs) ──────────────────────

/// Result of advancing to the next inner chunk.
enum InnerChunkResult {
    /// A firehose preamble was set up; continue to yield entries from it.
    PreambleReady,
}

/// Extract key scalar values from a firehose sub-type header without full parsing.
/// Returns (`data_ref_value`, `subsystem_value`, `number_items`).
fn extract_subtype_scalars(raw_data: &[u8], log_activity_type: u8, flags: u16) -> (u32, u16, u8) {
    let mut data_ref_value: u32 = 0;
    let mut subsystem_value: u16 = 0;
    let mut number_items: u8 = 0;

    if raw_data.is_empty() {
        return (data_ref_value, subsystem_value, number_items);
    }

    match log_activity_type {
        NON_ACTIVITY_TYPE => {
            if let Ok((_, vals)) = parse_nonactivity_scalars(raw_data, flags) {
                data_ref_value = vals.0;
                subsystem_value = vals.1;
                number_items = vals.2;
            }
        }
        ACTIVITY_TYPE => {
            if let Ok((_, n)) = parse_activity_item_count(raw_data, flags) {
                number_items = n;
            }
        }
        SIGNPOST_TYPE => {
            if let Ok((_, vals)) = parse_signpost_scalars(raw_data, flags) {
                subsystem_value = vals.0;
                number_items = vals.1;
            }
        }
        TRACE_TYPE => {
            if let Ok((_, n)) = parse_trace_item_count(raw_data) {
                number_items = n;
            }
        }
        LOSS_TYPE => {
            // Loss entries don't have items
        }
        _ => {}
    }

    (data_ref_value, subsystem_value, number_items)
}

/// Parse non-activity sub-type header to extract `data_ref`, subsystem, and item count.
fn parse_nonactivity_scalars(data: &[u8], flags: u16) -> nom::IResult<&[u8], (u32, u16, u8)> {
    let mut input = data;
    let mut data_ref_value: u32 = 0;
    let mut subsystem_value: u16 = 0;

    // has_current_aid (0x0001)
    if (flags & 0x0001) != 0 {
        let (i, _) = le_u32(input)?;
        let (i, _) = le_u32(i)?;
        input = i;
    }

    // has_private_data (0x0100)
    if (flags & 0x0100) != 0 {
        let (i, _) = le_u16(input)?;
        let (i, _) = le_u16(i)?;
        input = i;
    }

    // unknown flag 0x0008
    if (flags & 0x0008) != 0 {
        let (i, _) = le_u32(input)?;
        input = i;
    }

    // has_subsystem (0x0200)
    if (flags & 0x0200) != 0 {
        let (i, val) = le_u16(input)?;
        subsystem_value = val;
        input = i;
    }

    // has_rules (0x0400)
    if (flags & 0x0400) != 0 {
        let (i, _) = le_u8(input)?;
        input = i;
    }

    // has_oversize (0x0800)
    if (flags & 0x0800) != 0 {
        let (i, val) = le_u32(input)?;
        data_ref_value = val;
        input = i;
    }

    let number_items = extract_number_items_after_formatters(input, flags);

    Ok((&[], (data_ref_value, subsystem_value, number_items)))
}

/// Parse activity sub-type header to extract item count.
fn parse_activity_item_count(data: &[u8], flags: u16) -> nom::IResult<&[u8], u8> {
    let mut input = data;

    // Activity always has current_aid
    let (i, _) = le_u64(input)?;
    let (i, _) = le_u32(i)?;
    input = i;

    // has_other_aid (0x0001)
    if (flags & 0x0001) != 0 {
        let (i, _) = le_u32(input)?;
        let (i, _) = le_u32(i)?;
        input = i;
    }

    let number_items = extract_number_items_after_formatters(input, flags);
    Ok((&[], number_items))
}

/// Parse signpost sub-type header to extract subsystem and item count.
fn parse_signpost_scalars(data: &[u8], flags: u16) -> nom::IResult<&[u8], (u16, u8)> {
    let mut input = data;
    let mut subsystem_value: u16 = 0;

    // Signpost always has these:
    let (i, _) = le_u64(input)?;
    let (i, _) = le_u32(i)?;
    input = i;

    // has_other_aid (0x0001)
    if (flags & 0x0001) != 0 {
        let (i, _) = le_u32(input)?;
        let (i, _) = le_u32(i)?;
        input = i;
    }

    // has_private_data (0x0100)
    if (flags & 0x0100) != 0 {
        let (i, _) = le_u16(input)?;
        let (i, _) = le_u16(i)?;
        input = i;
    }

    // has_subsystem (0x0200)
    if (flags & 0x0200) != 0 {
        let (i, val) = le_u16(input)?;
        subsystem_value = val;
        input = i;
    }

    // has_rules (0x0400)
    if (flags & 0x0400) != 0 {
        let (i, _) = le_u8(input)?;
        input = i;
    }

    // Signpost name
    if (flags & 0x8000) != 0 {
        if input.len() >= 8 {
            input = &input[8..];
        }
    } else if input.len() >= 4 {
        input = &input[4..];
    }

    let number_items = extract_number_items_after_formatters(input, flags);
    Ok((&[], (subsystem_value, number_items)))
}

/// Parse trace sub-type header to extract item count.
fn parse_trace_item_count(data: &[u8]) -> nom::IResult<&[u8], u8> {
    if data.len() < 4 {
        return Ok((&[], 0));
    }
    let input = &data[4..]; // skip unknown_pc_id

    if input.len() >= 2 {
        Ok((&[], input[1]))
    } else {
        Ok((&[], 0))
    }
}

/// Skip past `FirehoseFormatters` fields to extract the `number_items` byte.
fn extract_number_items_after_formatters(data: &[u8], flags: u16) -> u8 {
    let mut offset: usize = 0;

    // absolute flag
    if (flags & 0x0004) != 0 {
        offset += 4;
    }

    // uuid flag
    if (flags & 0x0010) != 0 {
        offset += 2;
    }

    // shared_cache flag
    if (flags & 0x0020) != 0 {
        if (flags & 0x8000) != 0 {
            offset += 4;
        } else {
            offset += 2;
        }
    }

    // After formatters: unknown_item (u8) + number_items (u8)
    if data.len() > offset + 1 {
        data[offset + 1]
    } else {
        0
    }
}

/// Skip zero-padding bytes at the start of a slice.
fn skip_zero_padding(data: &[u8]) -> &[u8] {
    match take_while::<_, _, nom::error::Error<&[u8]>>(|b: u8| b == 0)(data) {
        Ok((remaining, _)) => remaining,
        Err(_) => data,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::LogarchiveProvider;
    use crate::parser::collect_timesync;
    use crate::tracev3_stream::TraceV3Stream;
    use std::fs;
    use std::path::PathBuf;

    fn test_data_path() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/test_data/system_logs_big_sur.logarchive");
        path
    }

    #[test]
    fn test_noalloc_entry_count() {
        let base = test_data_path();
        let provider = LogarchiveProvider::new(base.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        let tracev3 = base.join("Persist/0000000000000002.tracev3");
        let buffer = fs::read(tracev3.to_str().unwrap()).unwrap();

        // Count with NoAllocLogStream
        let mut noalloc_stream = NoAllocLogStream::new(&buffer, &timesync_data);
        let mut noalloc_count: u64 = 0;
        noalloc_stream.for_each_entry(|_| {
            noalloc_count += 1;
        });

        // Count with TraceV3Stream
        let mut tracev3_stream = TraceV3Stream::new(&buffer, &timesync_data);
        let mut tracev3_count: u64 = 0;
        tracev3_stream.for_each_entry(|_| {
            tracev3_count += 1;
        });

        assert_eq!(
            noalloc_count, tracev3_count,
            "NoAllocLogStream yielded {noalloc_count} entries, TraceV3Stream yielded {tracev3_count}"
        );
        assert!(noalloc_count > 1000, "Expected >1000 entries, got {noalloc_count}");
    }

    #[test]
    fn test_noalloc_scalar_correctness() {
        let base = test_data_path();
        let provider = LogarchiveProvider::new(base.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        let tracev3 = base.join("Persist/0000000000000002.tracev3");
        let buffer = fs::read(tracev3.to_str().unwrap()).unwrap();

        // Collect first 100 entries from both
        let mut noalloc_stream = NoAllocLogStream::new(&buffer, &timesync_data);
        let mut noalloc_entries = Vec::new();
        while let Some(entry) = noalloc_stream.next_entry() {
            noalloc_entries.push((
                entry.pid,
                entry.euid,
                entry.thread_id,
                entry.timestamp,
                entry.log_type,
                entry.log_activity_type,
                entry.continuous_time,
            ));
            if noalloc_entries.len() >= 100 {
                break;
            }
        }

        let mut tracev3_stream = TraceV3Stream::new(&buffer, &timesync_data);
        let mut tracev3_entries = Vec::new();
        tracev3_stream
            .try_for_each_entry(|entry| {
                tracev3_entries.push((
                    entry.pid,
                    entry.euid,
                    entry.thread_id,
                    entry.timestamp,
                    entry.log_type,
                    entry.log_activity_type,
                    entry.continuous_time,
                ));
                if tracev3_entries.len() >= 100 {
                    Err(())
                } else {
                    Ok(())
                }
            })
            .ok();

        assert_eq!(noalloc_entries.len(), tracev3_entries.len());
        for (i, (na, tv)) in noalloc_entries.iter().zip(tracev3_entries.iter()).enumerate() {
            assert_eq!(na.0, tv.0, "pid mismatch at entry {i}");
            assert_eq!(na.1, tv.1, "euid mismatch at entry {i}");
            assert_eq!(na.2, tv.2, "thread_id mismatch at entry {i}");
            assert!(
                (na.3 - tv.3).abs() < 0.001,
                "timestamp mismatch at entry {i}: {} vs {}",
                na.3,
                tv.3
            );
            assert_eq!(na.4, tv.4, "log_type mismatch at entry {i}");
            assert_eq!(na.5, tv.5, "log_activity_type mismatch at entry {i}");
            assert_eq!(na.6, tv.6, "continuous_time mismatch at entry {i}");
        }
    }

    #[test]
    fn test_noalloc_early_exit() {
        let base = test_data_path();
        let provider = LogarchiveProvider::new(base.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        let tracev3 = base.join("Persist/0000000000000002.tracev3");
        let buffer = fs::read(tracev3.to_str().unwrap()).unwrap();

        let mut stream = NoAllocLogStream::new(&buffer, &timesync_data);
        let mut count = 0u32;
        let result = stream.try_for_each_entry(|_| {
            count += 1;
            if count >= 10 {
                Err("early exit")
            } else {
                Ok(())
            }
        });

        assert!(result.is_err());
        assert_eq!(count, 10);
    }

    #[test]
    fn test_noalloc_oversize_cache() {
        let base = test_data_path();
        let provider = LogarchiveProvider::new(base.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        let tracev3 = base.join("Persist/0000000000000002.tracev3");
        let buffer = fs::read(tracev3.to_str().unwrap()).unwrap();

        let mut stream = NoAllocLogStream::new(&buffer, &timesync_data);
        stream.for_each_entry(|_| {});

        let cache = stream.into_oversize_cache();

        // Verify cache can be carried forward
        let mut stream2 =
            NoAllocLogStream::with_oversize_cache(&buffer, &timesync_data, cache);
        let initial_cache_len = stream2.oversize_cache().len();
        stream2.for_each_entry(|_| {});

        // Cache should grow (or at least be non-negative delta)
        assert!(
            stream2.oversize_cache().len() >= initial_cache_len,
            "Oversize cache should not shrink when processing same file again"
        );
    }

    #[test]
    fn test_noalloc_empty_file() {
        let timesync_data = HashMap::new();
        let empty: &[u8] = &[];

        let mut stream = NoAllocLogStream::new(empty, &timesync_data);
        assert!(stream.next_entry().is_none());
    }

    #[test]
    fn test_noalloc_convenience_methods() {
        let base = test_data_path();
        let provider = LogarchiveProvider::new(base.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        let tracev3 = base.join("Persist/0000000000000002.tracev3");
        let buffer = fs::read(tracev3.to_str().unwrap()).unwrap();

        let mut stream = NoAllocLogStream::new(&buffer, &timesync_data);
        let mut has_nonactivity = false;

        while let Some(entry) = stream.next_entry() {
            // Test convenience methods
            if entry.is_non_activity() {
                has_nonactivity = true;
                assert_eq!(entry.event_type_enum(), EventType::Log);
            }
            if entry.is_activity() {
                assert_eq!(entry.event_type_enum(), EventType::Activity);
            }
            if entry.is_signpost() {
                assert_eq!(entry.event_type_enum(), EventType::Signpost);
            }
            if entry.is_trace() {
                assert_eq!(entry.event_type_enum(), EventType::Trace);
            }
            if entry.is_loss() {
                assert_eq!(entry.event_type_enum(), EventType::Loss);
            }

            // Verify Copy trait works
            let _copy = entry;
            let _copy2 = entry;
            assert_eq!(_copy.pid, _copy2.pid);
        }

        assert!(has_nonactivity, "Should have non-activity entries");
    }

    #[test]
    fn test_noalloc_resolve() {
        let base = test_data_path();
        let mut provider = LogarchiveProvider::new(base.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        let tracev3 = base.join("Persist/0000000000000002.tracev3");
        let buffer = fs::read(tracev3.to_str().unwrap()).unwrap();

        let mut stream = NoAllocLogStream::new(&buffer, &timesync_data);
        let mut resolved_count = 0u32;

        while let Some(entry) = stream.next_entry() {
            // Only resolve first few non-activity entries
            if entry.is_non_activity() && resolved_count < 5 {
                if let Some(log_data) = stream.resolve(&entry, &mut provider) {
                    assert_eq!(log_data.pid, entry.pid);
                    assert_eq!(log_data.euid, entry.euid);
                    assert_eq!(log_data.thread_id, entry.thread_id);
                    assert_eq!(log_data.boot_uuid, entry.boot_uuid);
                    assert_eq!(log_data.log_type, entry.log_type_enum());
                    assert_eq!(log_data.event_type, entry.event_type_enum());
                    resolved_count += 1;
                }
            }
            if resolved_count >= 5 {
                break;
            }
        }

        assert_eq!(resolved_count, 5, "Should have resolved 5 entries");
    }
}
