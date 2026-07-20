use crate::helpers::utf8_str;
use nom::{
    bytes::complete::take,
    number::complete::{be_u128, le_u16, le_u32, le_u64},
};
use uuid::Uuid;

/// Parsed simpledump chunk — introduced in macOS Monterey (12).
///
/// A "simpler" version of Statedump, containing process IDs, UUIDs,
/// a subsystem string, and a message string.
///
/// This struct represents the data *after* the 16-byte preamble (which is
/// already parsed by `RawChunksReader` into `RawChunk.preamble`).
#[derive(Debug, Clone)]
pub struct RawSimpleDump<'a> {
    pub first_proc_id: u64,
    pub second_proc_id: u64,
    pub continuous_time: u64,
    pub thread_id: u64,
    pub unknown_offset: u32,
    pub unknown_ttl: u16,
    pub unknown_type: u16,
    pub sender_uuid: Uuid,
    pub dsc_uuid: Uuid,
    pub unknown_number_message_strings: u32,
    pub subsystem: &'a str,
    pub message_string: &'a str,
}

impl<'a> RawSimpleDump<'a> {
    /// Parse a simpledump log entry from the chunk data (after preamble).
    pub fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, first_proc_id) = le_u64(input)?;
        let (input, second_proc_id) = le_u64(input)?;
        let (input, continuous_time) = le_u64(input)?;
        let (input, thread_id) = le_u64(input)?;
        let (input, unknown_offset) = le_u32(input)?;
        let (input, unknown_ttl) = le_u16(input)?;
        let (input, unknown_type) = le_u16(input)?;

        let (input, sender_uuid_raw) = be_u128(input)?;
        let sender_uuid = Uuid::from_u128(sender_uuid_raw);
        let (input, dsc_uuid_raw) = be_u128(input)?;
        let dsc_uuid = Uuid::from_u128(dsc_uuid_raw);

        let (input, unknown_number_message_strings) = le_u32(input)?;
        let (input, subsystem_size) = le_u32(input)?;
        let (input, message_size) = le_u32(input)?;

        let (input, subsystem_data) = take(subsystem_size)(input)?;
        let (input, message_data) = take(message_size)(input)?;

        let subsystem = utf8_str(subsystem_data);
        let message_string = utf8_str(message_data);

        Ok((
            input,
            RawSimpleDump {
                first_proc_id,
                second_proc_id,
                continuous_time,
                thread_id,
                unknown_offset,
                unknown_ttl,
                unknown_type,
                sender_uuid,
                dsc_uuid,
                unknown_number_message_strings,
                subsystem,
                message_string,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simpledump() -> anyhow::Result<()> {
        // Full test vector from original src/chunks/simpledump.rs.
        let full_data = [
            4, 96, 0, 0, 0, 0, 0, 0, 219, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 45, 182, 196, 71, 133, 4, 0, 0, 3, 234, 0, 0, 0, 0, 0, 0, 118, 118, 1, 0,
            0, 0, 0, 0, 13, 207, 62, 139, 73, 35, 50, 62, 179, 229, 84, 115, 7, 207, 14, 172, 61,
            5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54, 231, 114, 172, 1, 1, 0, 0, 0, 79, 0, 0,
            0, 56, 0, 0, 0, 117, 115, 101, 114, 47, 53, 48, 49, 47, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 109, 100, 119, 111, 114, 107, 101, 114, 46, 115, 104, 97, 114, 101, 100,
            46, 48, 66, 48, 48, 48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48,
            48, 48, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 32, 91, 52, 50, 50, 57, 93,
            0, 115, 101, 114, 118, 105, 99, 101, 32, 101, 120, 105, 116, 101, 100, 58, 32, 100,
            105, 114, 116, 121, 32, 61, 32, 48, 44, 32, 115, 117, 112, 112, 111, 114, 116, 101,
            100, 32, 112, 114, 101, 115, 115, 117, 114, 101, 100, 45, 101, 120, 105, 116, 32, 61,
            32, 49, 0, 0, 0, 0, 0, 0,
        ];

        // Skip the 16-byte preamble (chunk_tag + chunk_subtag + chunk_data_size)
        let data = &full_data[16..];
        let (remaining, result) = RawSimpleDump::parse(data).unwrap();

        assert_eq!(result.first_proc_id, 1);
        assert_eq!(result.second_proc_id, 1);
        assert_eq!(result.continuous_time, 4_970_481_235_501);
        assert_eq!(result.thread_id, 59907);
        assert_eq!(result.unknown_offset, 95862);
        assert_eq!(result.unknown_ttl, 0);
        assert_eq!(result.unknown_type, 0);
        assert_eq!(
            result.sender_uuid,
            Uuid::parse_str("0DCF3E8B4923323EB3E5547307CF0EAC")?
        );
        assert_eq!(
            result.dsc_uuid,
            Uuid::parse_str("3D05845F3F65358F9EBF2236E772AC01")?
        );
        assert_eq!(result.unknown_number_message_strings, 1);
        assert_eq!(
            result.subsystem,
            "user/501/com.apple.mdworker.shared.0B000000-0000-0000-0000-000000000000 [4229]"
        );
        assert_eq!(
            result.message_string,
            "service exited: dirty = 0, supported pressured-exit = 1"
        );
        // Trailing padding bytes remain
        assert!(remaining.iter().all(|&b| b == 0));
        Ok(())
    }
}
