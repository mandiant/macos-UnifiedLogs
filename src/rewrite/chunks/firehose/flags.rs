use nom::Parser;
use nom::combinator::cond;
use nom::number::complete::{be_u128, le_u16};

// --- Entry-level flags (independent bits) ---

bitflags::bitflags! {
  /// Firehose entry flags — independent bit flags parsed from the entry header.
  ///
  /// Controls which optional fields are present in the entry body.
  /// Bits 1–3 (mask 0x000E) are extracted as [`FormatterType`].
  /// Bit 5 (0x0020) is `HAS_LARGE_OFFSET`, an independent modifier for formatter parsing.
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub struct FirehoseFlags: u16 {
    const HAS_CURRENT_AID   = 0x0001;
    const HAS_LARGE_OFFSET  = 0x0020;
    const HAS_UNIQUE_PID    = 0x0010;
    const HAS_PRIVATE_DATA  = 0x0100;
    const HAS_SUBSYSTEM     = 0x0200;
    const HAS_RULES         = 0x0400;
    const HAS_OVERSIZE      = 0x0800;
    const HAS_CONTEXT_DATA  = 0x1000;
    const HAS_NAME          = 0x8000;
  }
}

// --- Formatter type enum (bits 1–3 of entry flags) ---

/// Mask for extracting [`FormatterType`] from entry flags (bits 1–3).
const FORMATTER_TYPE_MASK: u16 = 0x000E;

/// Formatter type — identifies where the format string is located.
///
/// Extracted from bits 1–3 of the entry flags (mask `0x000E`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
#[repr(u8)]
pub enum FormatterType {
    MainExe = 0x2,
    SharedCache = 0x4,
    Absolute = 0x8,
    UuidRelative = 0xa,
    LargeSharedCache = 0xc,
    #[num_enum(default)]
    Unknown,
}

// --- Formatter flags ---

/// Zero-copy formatter flags — replaces `FirehoseFormatters` without heap allocation.
///
/// `uuid_relative` is stored as raw `[u8; 16]` (big-endian) instead of `Uuid`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawFormatterFlags {
    pub main_exe: bool,
    pub shared_cache: bool,
    pub absolute: bool,
    pub has_large_offset: u16,
    pub large_shared_cache: u16,
    pub alt_index: u16,
    pub uuid_relative: [u8; 16],
}

impl RawFormatterFlags {
    /// Parse formatter flags from entry data.
    ///
    /// Direct translation of `FirehoseFormatters::firehose_formatter_flags`
    /// from `src/chunks/firehose/flags.rs`.
    pub(super) fn parse(input: &[u8], flags: FirehoseFlags) -> nom::IResult<&[u8], Self> {
        let mut result = Self::default();
        let has_large_offset = flags.contains(FirehoseFlags::HAS_LARGE_OFFSET);

        match FormatterType::from((flags.bits() & FORMATTER_TYPE_MASK) as u8) {
            FormatterType::LargeSharedCache => {
                let (input, large_offset) = cond(has_large_offset, le_u16).parse(input)?;
                result.has_large_offset = large_offset.unwrap_or(0);
                let (input, val) = le_u16(input)?;
                result.large_shared_cache = val;
                Ok((input, result))
            }
            FormatterType::Absolute => {
                result.absolute = true;
                let (input, val) = le_u16(input)?;
                result.alt_index = val;
                Ok((input, result))
            }
            FormatterType::MainExe => {
                result.main_exe = true;
                Ok((input, result))
            }
            FormatterType::SharedCache => {
                result.shared_cache = true;
                let (input, large_offset) = cond(has_large_offset, le_u16).parse(input)?;
                result.has_large_offset = large_offset.unwrap_or(0);
                Ok((input, result))
            }
            FormatterType::UuidRelative => {
                let (input, val) = be_u128(input)?;
                result.uuid_relative = val.to_be_bytes();
                Ok((input, result))
            }
            FormatterType::Unknown => Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Switch,
            ))),
        }
    }
}
