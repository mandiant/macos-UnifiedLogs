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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatter_has_large_offset() {
        // From src/chunks/firehose/flags.rs test_firehose_formatter_flags_has_large_offset
        let test_data = [
            1, 0, 2, 0, 14, 0, 34, 2, 0, 4, 135, 16, 0, 0, 34, 4, 0, 0, 5, 0, 100, 101, 110, 121,
            0,
        ];
        let flags = FirehoseFlags::from_bits_retain(557);
        let (_, result) = RawFormatterFlags::parse(&test_data, flags).unwrap();
        assert_eq!(result.has_large_offset, 1);
        assert_eq!(result.large_shared_cache, 2);
        assert!(!result.main_exe);
        assert!(!result.shared_cache);
        assert!(!result.absolute);
        assert_eq!(result.alt_index, 0);
        assert_eq!(result.uuid_relative, [0; 16]);
    }

    #[test]
    fn test_formatter_absolute_alt_index_small() {
        // From test_firehose_formatter_flags_message_strings_uuid_message_alt_index
        let test_data = [8, 0, 17, 166, 251, 2, 128, 255, 0, 0];
        let flags = FirehoseFlags::from_bits_retain(8);
        let (_, result) = RawFormatterFlags::parse(&test_data, flags).unwrap();
        assert!(result.absolute);
        assert_eq!(result.alt_index, 8);
        assert!(!result.main_exe);
        assert!(!result.shared_cache);
        assert_eq!(result.has_large_offset, 0);
        assert_eq!(result.large_shared_cache, 0);
        assert_eq!(result.uuid_relative, [0; 16]);
    }

    #[test]
    fn test_formatter_main_exe() {
        // From test_firehose_formatter_flags_message_strings_uuid
        let test_data = [186, 0, 0, 0];
        let flags = FirehoseFlags::from_bits_retain(514);
        let (_, result) = RawFormatterFlags::parse(&test_data, flags).unwrap();
        assert!(result.main_exe);
        assert!(!result.shared_cache);
        assert!(!result.absolute);
        assert_eq!(result.has_large_offset, 0);
        assert_eq!(result.large_shared_cache, 0);
        assert_eq!(result.alt_index, 0);
        assert_eq!(result.uuid_relative, [0; 16]);
    }

    #[test]
    fn test_formatter_shared_cache() {
        // From test_firehose_formatter_flags_shared_cache_dsc_uuid
        let test_data = [
            23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83,
            116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 52, 54, 58, 32, 101,
            110, 116, 101, 114, 0,
        ];
        let flags = FirehoseFlags::from_bits_retain(516);
        let (_, result) = RawFormatterFlags::parse(&test_data, flags).unwrap();
        assert!(result.shared_cache);
        assert!(!result.main_exe);
        assert!(!result.absolute);
        assert_eq!(result.has_large_offset, 0);
        assert_eq!(result.large_shared_cache, 0);
        assert_eq!(result.alt_index, 0);
        assert_eq!(result.uuid_relative, [0; 16]);
    }

    #[test]
    fn test_formatter_absolute_alt_index_large() {
        // From test_firehose_formatter_flags_absolute_message_alt_uuid
        let test_data = [
            128, 255, 2, 13, 34, 4, 0, 0, 6, 0, 34, 4, 6, 0, 11, 0, 34, 4, 17, 0, 7, 0, 2, 4, 8,
            0, 0, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0,
            0, 34, 4, 24, 0, 3, 0, 34, 4, 27, 0, 3, 0, 2, 8, 156, 17, 7, 98, 0, 0, 0, 0, 2, 8,
            156, 17, 7, 98, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 34, 4, 30, 0, 3, 0, 65, 67, 77, 82, 77,
            0, 95, 108, 111, 103, 80, 111, 108, 105, 99, 121, 0, 83, 65, 86, 73, 78, 71, 0, 78,
            79, 0, 78, 79, 0, 78, 79, 0,
        ];
        let flags = FirehoseFlags::from_bits_retain(8);
        let (_, result) = RawFormatterFlags::parse(&test_data, flags).unwrap();
        assert!(result.absolute);
        assert_eq!(result.alt_index, 65408);
        assert!(!result.main_exe);
        assert!(!result.shared_cache);
        assert_eq!(result.has_large_offset, 0);
        assert_eq!(result.large_shared_cache, 0);
        assert_eq!(result.uuid_relative, [0; 16]);
    }

    #[test]
    fn test_formatter_uuid_relative() {
        // From test_firehose_formatter_flags_uuid_relative
        // Old assertion was the hex string "7B0D3775F1903E21BA130447C41B8743".
        let test_data = [
            123, 13, 55, 117, 241, 144, 62, 33, 186, 19, 4, 71, 196, 27, 135, 67, 0, 0,
        ];
        let flags = FirehoseFlags::from_bits_retain(0xa);
        let (_, result) = RawFormatterFlags::parse(&test_data, flags).unwrap();
        assert_eq!(
            result.uuid_relative,
            [123, 13, 55, 117, 241, 144, 62, 33, 186, 19, 4, 71, 196, 27, 135, 67]
        );
        assert!(!result.main_exe);
        assert!(!result.shared_cache);
        assert!(!result.absolute);
        assert_eq!(result.has_large_offset, 0);
        assert_eq!(result.large_shared_cache, 0);
        assert_eq!(result.alt_index, 0);
    }
}
