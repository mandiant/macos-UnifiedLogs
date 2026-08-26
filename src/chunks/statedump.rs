use crate::helpers::utf8_str_from_cstring;
use nom::{
    bytes::complete::take,
    number::complete::{be_u128, le_u8, le_u32, le_u64},
};
use uuid::Uuid;

const STRING_FIELD_SIZE: u8 = 64;
const CUSTOM_DECODER: u32 = 3;

/// Parsed statedump chunk — special log entries containing plist, protobuf, or custom object data.
///
/// This struct represents the data *after* the 16-byte preamble (which is
/// already parsed by `RawChunksReader` into `RawChunk.preamble`).
#[derive(Debug, Clone)]
pub struct RawStatedump<'a> {
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub ttl: u8,
    pub unknown_reserved: [u8; 3],
    pub continuous_time: u64,
    pub activity_id: u64,
    pub uuid: Uuid,
    pub data_type: u32,
    pub decoder_library: &'a str,
    pub decoder_type: &'a str,
    pub title_name: &'a str,
    pub statedump_data: &'a [u8],
}

impl<'a> RawStatedump<'a> {
    /// Parse a statedump log entry from the chunk data (after preamble).
    pub fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, first_proc_id) = le_u64(input)?;
        let (input, second_proc_id) = le_u32(input)?;
        let (input, ttl) = le_u8(input)?;
        let (input, reserved_bytes) = take(3_usize)(input)?;
        let unknown_reserved: [u8; 3] = [reserved_bytes[0], reserved_bytes[1], reserved_bytes[2]];
        let (input, continuous_time) = le_u64(input)?;
        let (input, activity_id) = le_u64(input)?;

        let (input, uuid_raw) = be_u128(input)?;
        let uuid = Uuid::from_u128(uuid_raw);

        let (input, data_type) = le_u32(input)?;
        let (input, data_size) = le_u32(input)?;

        let (input, decoder_library, decoder_type) = if data_type == CUSTOM_DECODER {
            let (input, lib_data) = take(STRING_FIELD_SIZE)(input)?;
            let (input, type_data) = take(STRING_FIELD_SIZE)(input)?;
            let (_, lib_data) = utf8_str_from_cstring(lib_data)?;
            let (_, type_data) = utf8_str_from_cstring(type_data)?;
            (input, lib_data, type_data)
        } else {
            // Consume the 128 bytes but discard them
            let (input, _) = take(STRING_FIELD_SIZE)(input)?;
            let (input, _) = take(STRING_FIELD_SIZE)(input)?;
            (input, "", "")
        };

        let (input, title_data) = take(STRING_FIELD_SIZE)(input)?;
        let (_, title_name) = utf8_str_from_cstring(title_data)?;

        let (input, statedump_data) = take(data_size)(input)?;

        Ok((
            input,
            RawStatedump {
                first_proc_id,
                second_proc_id,
                ttl,
                unknown_reserved,
                continuous_time,
                activity_id,
                uuid,
                data_type,
                decoder_library,
                decoder_type,
                title_name,
                statedump_data,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_statedump() -> anyhow::Result<()> {
        // Test vector from original src/chunks/statedump.rs (data_type=3, custom object).
        let full_data = [
            3, 96, 0, 0, 0, 0, 0, 0, 32, 1, 0, 0, 0, 0, 0, 0, 113, 0, 0, 0, 0, 0, 0, 0, 208, 1, 0,
            0, 14, 0, 0, 0, 13, 179, 213, 232, 0, 0, 0, 0, 118, 4, 0, 0, 0, 0, 0, 128, 92, 216,
            221, 238, 4, 56, 58, 56, 136, 119, 16, 34, 124, 90, 10, 86, 3, 0, 0, 0, 40, 0, 0, 0,
            108, 111, 99, 97, 116, 105, 111, 110, 0, 0, 187, 44, 255, 127, 0, 0, 42, 144, 225, 173,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 78, 41, 126, 255, 127,
            0, 0, 6, 144, 225, 173, 0, 0, 0, 0, 148, 242, 123, 124, 255, 127, 0, 0, 95, 67, 76, 68,
            97, 101, 109, 111, 110, 83, 116, 97, 116, 117, 115, 83, 116, 97, 116, 101, 84, 114, 97,
            99, 107, 101, 114, 83, 116, 97, 116, 101, 0, 144, 225, 173, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 72, 78, 41, 126, 255, 127, 0, 0, 67, 76, 68, 97, 101,
            109, 111, 110, 83, 116, 97, 116, 117, 115, 83, 116, 97, 116, 101, 84, 114, 97, 99, 107,
            101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 191, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Skip the 16-byte preamble
        let data = &full_data[16..];
        let (remaining, result) = RawStatedump::parse(data).unwrap();

        assert_eq!(result.first_proc_id, 113);
        assert_eq!(result.second_proc_id, 464);
        assert_eq!(result.ttl, 14);
        assert_eq!(result.unknown_reserved, [0, 0, 0]);
        assert_eq!(result.continuous_time, 3_906_319_117);
        assert_eq!(result.activity_id, 9_223_372_036_854_776_950);
        assert_eq!(
            result.uuid,
            Uuid::parse_str("5CD8DDEE04383A38887710227C5A0A56")?
        );
        assert_eq!(result.data_type, 3);
        assert_eq!(result.decoder_library, "location");
        assert_eq!(result.decoder_type, "_CLDaemonStatusStateTrackerState");
        assert_eq!(result.title_name, "CLDaemonStatusStateTracker");
        assert_eq!(
            result.statedump_data,
            &[
                0, 0, 0, 0, 0, 0, 240, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0,
                0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert!(remaining.is_empty());
        Ok(())
    }
}
