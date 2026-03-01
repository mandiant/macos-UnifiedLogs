//! Centralized constants for the macOS Unified Log binary format.

// ── Chunk Tags (tracev3 preamble) ──

pub(crate) const HEADER_CHUNK: u32 = 0x1000;
pub(crate) const CATALOG_CHUNK: u32 = 0x600b;
pub(crate) const CHUNKSET_CHUNK: u32 = 0x600d;
pub(crate) const FIREHOSE_CHUNK: u32 = 0x6001;
pub(crate) const OVERSIZE_CHUNK: u32 = 0x6002;
pub(crate) const STATEDUMP_CHUNK: u32 = 0x6003;
pub(crate) const SIMPLEDUMP_CHUNK: u32 = 0x6004;

// ── BV41 Compression Signatures ──

pub(crate) const BV41_COMPRESSED: u32 = 825_521_762; // "bv41"
pub(crate) const BV41_UNCOMPRESSED: u32 = 758_412_898; // "bv4-"

// ── Firehose Log Activity Types (u8) ──

pub(crate) const ACTIVITY_TYPE: u8 = 0x2;
pub(crate) const TRACE_TYPE: u8 = 0x3;
pub(crate) const NON_ACTIVITY_TYPE: u8 = 0x4;
pub(crate) const SIGNPOST_TYPE: u8 = 0x6;
pub(crate) const LOSS_TYPE: u8 = 0x7;
pub(crate) const REMNANT_DATA: u8 = 0x0;

// Synthetic types (not real chunk tags — used by NoAllocLogStream)
pub(crate) const SIMPLEDUMP_TYPE: u8 = 0xF0;
pub(crate) const STATEDUMP_TYPE: u8 = 0xF1;

// ── Structural Sizes ──

pub(crate) const CHUNK_PREAMBLE_SIZE: usize = 16;
pub(crate) const FIREHOSE_ENTRY_HEADER_SIZE: usize = 24;

// ── File Format Signatures ──

pub(crate) const DSC_SIGNATURE: u32 = 0x6473_6368; // "dsch"
pub(crate) const UUIDTEXT_SIGNATURE: u32 = 0x6677_8899;
pub(crate) const TIMESYNC_SIGNATURE: u32 = 0x0020_7354; // " Ts"
pub(crate) const TIMESYNC_BOOT_SIGNATURE: u16 = 0xbbb0;

// ── Firehose Entry Flags (u16 bitmask) ──
// These flags control which optional fields are present in a firehose entry.

/// Activity ID is present (`activity_id` + sentinel u32 pair)
pub(crate) const FLAG_HAS_CURRENT_AID: u16 = 0x0001;
/// Unknown message string reference field is present
pub(crate) const FLAG_HAS_UNKNOWN_REF: u16 = 0x0008;
/// Has unique PID field (activity entries only)
pub(crate) const FLAG_HAS_UNIQUE_PID: u16 = 0x0010;
/// Private string data follows the public data
pub(crate) const FLAG_HAS_PRIVATE_DATA: u16 = 0x0100;
/// Subsystem value is present (non-activity/signpost); `other_current_aid` (activity)
pub(crate) const FLAG_HAS_SUBSYSTEM: u16 = 0x0200;
/// TTL/rules value is present
pub(crate) const FLAG_HAS_RULES: u16 = 0x0400;
/// Data ref / oversize value is present
pub(crate) const FLAG_HAS_OVERSIZE: u16 = 0x0800;
/// Backtrace / context data follows firehose items
pub(crate) const FLAG_HAS_CONTEXT_DATA: u16 = 0x1000;
/// Signpost name field is present
pub(crate) const FLAG_HAS_NAME: u16 = 0x8000;

// ── Formatter Flags (lower nibble of firehose_flags, masked with 0xe) ──

pub(crate) const FORMATTER_FLAG_MASK: u16 = 0x000e;
/// Format string is in a UUID text file (main executable)
pub(crate) const FORMATTER_MAIN_EXE: u16 = 0x2;
/// Format string is in the shared cache (DSC)
pub(crate) const FORMATTER_SHARED_CACHE: u16 = 0x4;
/// Absolute flag — uses an alternative UUID file index from the Catalog
pub(crate) const FORMATTER_ABSOLUTE: u16 = 0x8;
/// UUID-relative — the UUID is embedded in the log data itself
pub(crate) const FORMATTER_UUID_RELATIVE: u16 = 0xa;
/// Large shared cache offset
pub(crate) const FORMATTER_LARGE_SHARED_CACHE: u16 = 0xc;
/// Large offset flag — offset to format string is larger than normal
pub(crate) const FORMATTER_LARGE_OFFSET: u16 = 0x20;

// ── Log Types (u8, used in get_log_type match) ──

pub(crate) const LOG_TYPE_INFO: u8 = 0x01; // also Create for activity
pub(crate) const LOG_TYPE_DEBUG: u8 = 0x02;
pub(crate) const LOG_TYPE_USERACTION: u8 = 0x03;
pub(crate) const LOG_TYPE_ERROR: u8 = 0x10;
pub(crate) const LOG_TYPE_FAULT: u8 = 0x11;

// Signpost log types
pub(crate) const LOG_TYPE_THREAD_SIGNPOST_EVENT: u8 = 0x40;
pub(crate) const LOG_TYPE_THREAD_SIGNPOST_START: u8 = 0x41;
pub(crate) const LOG_TYPE_THREAD_SIGNPOST_END: u8 = 0x42;
pub(crate) const LOG_TYPE_PROCESS_SIGNPOST_EVENT: u8 = 0x80;
pub(crate) const LOG_TYPE_PROCESS_SIGNPOST_START: u8 = 0x81;
pub(crate) const LOG_TYPE_PROCESS_SIGNPOST_END: u8 = 0x82;
pub(crate) const LOG_TYPE_SYSTEM_SIGNPOST_EVENT: u8 = 0xc0;
pub(crate) const LOG_TYPE_SYSTEM_SIGNPOST_START: u8 = 0xc1;
pub(crate) const LOG_TYPE_SYSTEM_SIGNPOST_END: u8 = 0xc2;

// ── Statedump Data Types (u8) ──

pub(crate) const STATEDUMP_DATA_PLIST: u32 = 0x1;
pub(crate) const STATEDUMP_DATA_PROTOBUF: u32 = 0x2;
pub(crate) const STATEDUMP_DATA_OBJECT: u32 = 0x3;

// ── Format String Offset Sentinels ──

/// MSB set in `format_string_location` means the formatter is "%s" (dynamic)
pub(crate) const DYNAMIC_OFFSET_FLAG: u64 = 0x8000_0000;
/// `private_data_virtual_offset` == 0x1000 means no private data
pub(crate) const NO_PRIVATE_DATA: u16 = 0x1000;
/// Base multiplier for `shared_cache` large offset calculation
pub(crate) const LARGE_OFFSET_BASE: u64 = 0x1000_0000;
/// Private number `item_size` sentinel — marks the number as private
pub(crate) const PRIVATE_NUMBER_SIZE: u16 = 0x8000;

// ── Firehose Item Types (u8) ──
// Item types identify how to decode each firehose data payload entry.

pub(crate) const ITEM_NUMBER: u8 = 0x00;
pub(crate) const ITEM_PRIVATE_NUMBER: u8 = 0x01;
pub(crate) const ITEM_NUMBER_ALT: u8 = 0x02;
/// todo: document this constant
pub(crate) const ITEM_SENSITIVE: u8 = 0x05;
pub(crate) const ITEM_PRECISION: u8 = 0x10;
pub(crate) const ITEM_PRECISION_ALT: u8 = 0x12;
pub(crate) const ITEM_STRING: u8 = 0x20;
pub(crate) const ITEM_PRIVATE_STRING: u8 = 0x21;
pub(crate) const ITEM_STRING_ALT: u8 = 0x22;
/// todo: document this constant
pub(crate) const ITEM_PRIVATE_STRING_25: u8 = 0x25;
pub(crate) const ITEM_ARBITRARY: u8 = 0x30;
pub(crate) const ITEM_PRIVATE_ARBITRARY: u8 = 0x31;
pub(crate) const ITEM_ARBITRARY_ALT: u8 = 0x32;
/// todo: document this constant
pub(crate) const ITEM_PRIVATE_STRING_35: u8 = 0x35;
pub(crate) const ITEM_OBJECT: u8 = 0x40;
pub(crate) const ITEM_PRIVATE_OBJECT: u8 = 0x41;
pub(crate) const ITEM_OBJECT_ALT: u8 = 0x42;
/// todo: document this constant
pub(crate) const ITEM_SENSITIVE_45: u8 = 0x45;
/// Added macOS Sequoia; todo: document this constant
pub(crate) const ITEM_PRIVATE_STRING_81: u8 = 0x81;
/// Added macOS Sequoia; todo: document this constant
pub(crate) const ITEM_SENSITIVE_85: u8 = 0x85;
/// Added macOS Sequoia; todo: document this constant
pub(crate) const ITEM_PRIVATE_STRING_F1: u8 = 0xf1;
pub(crate) const ITEM_BASE64_RAW: u8 = 0xf2;
