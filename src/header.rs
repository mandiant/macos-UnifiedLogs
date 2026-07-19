use crate::helpers::utf8_str;
use nom::{
    bytes::complete::take,
    number::complete::{be_u128, le_u32, le_u64},
};
use std::mem::size_of;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RawHeaderChunk<'a> {
    pub mach_time_numerator: u32,
    pub mach_time_denominator: u32,
    pub continous_time: u64,
    pub unknown_time: u64, // possibly start time
    pub unknown: u32,
    pub bias_min: u32,
    pub daylight_savings: u32, // 0 no DST, 1 DST
    pub unknown_flags: u32,
    pub sub_chunk_tag: u32, // 0x6100
    pub sub_chunk_data_size: u32,
    pub sub_chunk_continous_time: u64,
    pub sub_chunk_tag_2: u32, // 0x6101
    pub sub_chunk_tag_data_size_2: u32,
    pub unknown_2: u32,
    pub unknown_3: u32,
    pub build_version_string: &'a str,
    pub hardware_model_string: &'a str,
    pub sub_chunk_tag_3: u32, // 0x6102
    pub sub_chunk_tag_data_size_3: u32,
    pub boot_uuid: Uuid,
    pub logd_pid: u32,
    pub logd_exit_status: u32,
    pub sub_chunk_tag_4: u32, // 0x6103
    pub sub_chunk_tag_data_size_4: u32,
    pub timezone_path: &'a str,
}

impl<'a> RawHeaderChunk<'a> {
    /// Parse the Unified Log tracev3 header data
    pub fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, mach_time_numerator) = le_u32(input)?;
        let (input, mach_time_denominator) = le_u32(input)?;
        let (input, continous_time) = le_u64(input)?;
        let (input, unknown_time) = le_u64(input)?;
        let (input, unknown) = le_u32(input)?;
        let (input, bias_min) = le_u32(input)?;
        let (input, daylight_savings) = le_u32(input)?;
        let (input, unknown_flags) = le_u32(input)?;
        let (input, sub_chunk_tag) = le_u32(input)?;
        let (input, sub_chunk_data_size) = le_u32(input)?;
        let (input, sub_chunk_continous_time) = le_u64(input)?;
        let (input, sub_chunk_tag_2) = le_u32(input)?;
        let (input, sub_chunk_tag_data_size_2) = le_u32(input)?;
        let (input, unknown_2) = le_u32(input)?;
        let (input, unknown_3) = le_u32(input)?;
        let (input, build_version_string) = take(size_of::<u128>())(input)?;
        let build_version_string = utf8_str(build_version_string);

        let hardware_model_size: u8 = 32;
        let (input, hardware_model_string) = take(hardware_model_size)(input)?;

        let hardware_model_string = utf8_str(hardware_model_string);

        let (input, sub_chunk_tag_3) = le_u32(input)?;
        let (input, sub_chunk_tag_data_size_3) = le_u32(input)?;
        let (input, boot_uuid_raw) = be_u128(input)?;
        let boot_uuid = Uuid::from_u128(boot_uuid_raw);
        let (input, logd_pid) = le_u32(input)?;
        let (input, logd_exit_status) = le_u32(input)?;
        let (input, sub_chunk_tag_4) = le_u32(input)?;
        let (input, sub_chunk_tag_data_size_4) = le_u32(input)?;

        let timezone_path_size: u8 = 48;
        let (input, timezone_path) = take(timezone_path_size)(input)?;
        let timezone_path = utf8_str(timezone_path);

        let header_chunk = RawHeaderChunk {
            mach_time_numerator,
            mach_time_denominator,
            continous_time,
            unknown_time,
            unknown,
            bias_min,
            daylight_savings,
            unknown_flags,
            sub_chunk_tag,
            sub_chunk_data_size,
            sub_chunk_continous_time,
            sub_chunk_tag_2,
            sub_chunk_tag_data_size_2,
            unknown_2,
            unknown_3,
            sub_chunk_tag_3,
            sub_chunk_tag_data_size_3,
            logd_pid,
            logd_exit_status,
            sub_chunk_tag_4,
            sub_chunk_tag_data_size_4,
            build_version_string,
            hardware_model_string,
            boot_uuid,
            timezone_path,
        };

        Ok((input, header_chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunks::{ChunkPreamble, ChunkTag};

    #[test]
    fn test_detect_preamble() -> anyhow::Result<()> {
        let input = &[
            0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 15, 105,
            217, 162, 204, 126, 0, 0, 48, 215, 18, 98, 0, 0, 0, 0, 203, 138, 9, 0, 44, 1, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 97, 0, 0, 8, 0, 0, 0, 6, 112, 124, 198, 169, 153, 1, 0, 1, 97,
            0, 0, 56, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 50, 49, 65, 53, 53, 57, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 77, 97, 99, 66, 111, 111, 107, 80, 114, 111, 49, 54, 44, 49, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 97, 0, 0, 24, 0, 0, 0, 195, 32, 184, 206, 151,
            250, 77, 165, 159, 49, 125, 57, 46, 56, 156, 234, 85, 0, 0, 0, 0, 0, 0, 0, 3, 97, 0, 0,
            48, 0, 0, 0, 47, 118, 97, 114, 47, 100, 98, 47, 116, 105, 109, 101, 122, 111, 110, 101,
            47, 122, 111, 110, 101, 105, 110, 102, 111, 47, 65, 109, 101, 114, 105, 99, 97, 47, 78,
            101, 119, 95, 89, 111, 114, 107, 0, 0, 0, 0, 0, 0,
        ];

        let (input, preamble) = ChunkPreamble::parse(input)?;
        let (_, header) = RawHeaderChunk::parse(input)?;

        assert_eq!(preamble.tag, ChunkTag::Header);
        assert_eq!(preamble.sub_tag, 0x11);
        assert_eq!(header.mach_time_numerator, 1);
        assert_eq!(header.mach_time_denominator, 1);
        assert_eq!(header.continous_time, 139417370585359);
        assert_eq!(header.unknown_time, 1645401904);
        assert_eq!(header.unknown, 625355);
        assert_eq!(header.bias_min, 300);
        assert_eq!(header.daylight_savings, 0);
        assert_eq!(header.unknown_flags, 1);
        assert_eq!(header.sub_chunk_tag, 24832);
        assert_eq!(header.sub_chunk_data_size, 8);
        assert_eq!(header.sub_chunk_continous_time, 450429435277318);
        assert_eq!(header.sub_chunk_tag_2, 24833);
        assert_eq!(header.sub_chunk_tag_data_size_2, 56);
        assert_eq!(header.unknown_2, 7);
        assert_eq!(header.unknown_3, 8);
        assert_eq!(header.build_version_string, "21A559");
        assert_eq!(header.hardware_model_string, "MacBookPro16,1");
        assert_eq!(header.sub_chunk_tag_3, 24834);
        assert_eq!(header.sub_chunk_tag_data_size_3, 24);
        assert_eq!(
            header.boot_uuid,
            Uuid::parse_str("C320B8CE97FA4DA59F317D392E389CEA").unwrap()
        );
        assert_eq!(header.logd_pid, 85);
        assert_eq!(header.logd_exit_status, 0);
        assert_eq!(header.sub_chunk_tag_4, 24835);
        assert_eq!(header.sub_chunk_tag_data_size_4, 48);
        assert_eq!(
            header.timezone_path,
            "/var/db/timezone/zoneinfo/America/New_York"
        );
        Ok(())
    }
}
