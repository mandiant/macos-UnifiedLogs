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
