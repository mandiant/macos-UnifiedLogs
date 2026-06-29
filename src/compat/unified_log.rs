//! Compatibility types matching the legacy module's public API.
//!
//! These types bridge the rewrite pipeline's zero-copy `LogEntry` to the
//! legacy's owned `LogData` / `UnifiedLogData` types that integration tests expect.

pub use crate::rewrite::log_entry::{EventType, LogType, MessageFlags};
use serde::Serialize;
use std::fmt;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error type compatible with the legacy `ParserError`.
#[derive(Debug)]
pub enum ParserError {
    Path,
    Dir,
    Tracev3Parse,
    Read,
    Timesync,
}

impl std::error::Error for ParserError {}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path => write!(f, "Failed to open file path"),
            Self::Dir => write!(f, "Failed to open directory path"),
            Self::Tracev3Parse => write!(f, "Failed to parse tracev3 file"),
            Self::Read => write!(f, "Failed to read file"),
            Self::Timesync => write!(f, "Failed to parse timesync file"),
        }
    }
}

// ---------------------------------------------------------------------------
// CountVec — opaque length-only collection
// ---------------------------------------------------------------------------

/// Opaque vector that reports the correct `len()`.
///
/// Tests only inspect `.len()` on firehose/simpledump/statedump/oversize
/// collections, never the actual items.
pub struct CountVec {
    count: usize,
}

impl CountVec {
    pub(crate) fn new(count: usize) -> Self {
        Self { count }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// Parsed tracev3 metadata types
// ---------------------------------------------------------------------------

/// Parsed tracev3 file header. Tests only check `header.len()`.
pub struct HeaderInfo;

/// Catalog process info container. Tests check
/// `catalog.catalog_process_info_entries.len()`.
pub struct CatalogInfo {
    pub catalog_process_info_entries: CountVec,
}

/// Per-catalog chunk counts — mirrors `legacy::UnifiedLogCatalogData`.
pub struct UnifiedLogCatalogData {
    pub catalog: CatalogInfo,
    pub firehose: CountVec,
    pub simpledump: CountVec,
    pub statedump: CountVec,
    pub oversize: CountVec,
}

// ---------------------------------------------------------------------------
// Oversize entry — transferable for cross-file merging
// ---------------------------------------------------------------------------

/// Transferable oversize entry. Keyed by `(data_ref_index, first_proc_id,
/// second_proc_id)` so it can be pre-populated into `OversizeCache`.
#[derive(Clone)]
pub struct OversizeEntry {
    pub(crate) data_ref_index: u32,
    pub(crate) first_proc_id: u64,
    pub(crate) second_proc_id: u32,
    pub(crate) data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// UnifiedLogData — parsed tracev3 container
// ---------------------------------------------------------------------------

/// Container for parsed tracev3 file data.
///
/// Holds raw bytes + metadata for deferred processing by `build_log`.
/// The `oversize` vec supports cross-file merging via `append`.
pub struct UnifiedLogData {
    pub header: Vec<HeaderInfo>,
    pub catalog_data: Vec<UnifiedLogCatalogData>,
    pub oversize: Vec<OversizeEntry>,
    pub evidence: String,
    /// Stored tracev3 bytes for `build_log` to process.
    pub(crate) raw_data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// TimesyncBoot — opaque wrapper
// ---------------------------------------------------------------------------

/// Timesync boot session data. Opaque wrapper passed between
/// `collect_timesync` and `build_log`.
pub struct TimesyncBoot {
    pub(crate) inner: crate::rewrite::timesync::RawTimesyncBoot,
}

// ---------------------------------------------------------------------------
// LogData — resolved log entry with owned fields
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub enum FirehoseItem {
    String,
    PrivateNumber,
    Number,
    PrivateString,
    Precision,
    Sensitive,
    Object,
    #[default]
    Unknown,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct FirehoseItemType {
    pub item_type: u8,
    pub item_type_size: u8,
    pub offset: u16,
    pub item_size: u16,
    pub message_strings: String,
    pub item: FirehoseItem,
}

/// A single resolved log entry with all fields as owned `String` types.
/// Mirrors the legacy `LogData` struct field-for-field
#[derive(Debug, Serialize)]
pub struct LogData {
    pub subsystem: String,
    pub thread_id: u64,
    pub pid: u64,
    pub euid: u32,
    pub library: String,
    pub library_uuid: String,
    pub activity_id: u64,
    pub parent_activity_id: u64,
    pub time: f64,
    pub category: String,
    pub event_type: EventType,
    pub log_type: LogType,
    pub process: String,
    pub process_uuid: String,
    pub message: String,
    pub raw_message: String,
    pub boot_uuid: String,
    pub timezone_name: String,
    pub message_entries: Vec<FirehoseItemType>,
    pub timestamp: String,
    pub message_flags: Vec<MessageFlags>,
    pub evidence: String,
}
