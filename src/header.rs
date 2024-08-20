// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::*;
use nom::{
    bytes::complete::take,
    combinator::map,
    number::complete::{be_u128, le_u32, le_u64},
    sequence::tuple,
};
use std::mem::size_of;
use util::parstr;

use crate::preamble::LogPreamble;

#[derive(Debug, Clone)]
pub struct HeaderChunk {
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
    pub mach_time_numerator: u32,
    pub mach_time_denominator: u32,
    pub continous_time: u64,
    /// possibly start time
    pub unknown_time: u64,
    pub unknown: u32,
    pub bias_min: u32,
    /// 0 no DST, 1 DST
    pub daylight_savings: u32,
    pub unknown_flags: u32,
    /// 0x6100
    pub sub_chunk_tag: u32,
    pub sub_chunk_data_size: u32,
    pub sub_chunk_continous_time: u64,
    /// 0x6101
    pub sub_chunk_tag_2: u32,
    pub sub_chunk_tag_data_size_2: u32,
    pub unknown_2: u32,
    pub unknown_3: u32,
    pub build_version_string: String,
    pub hardware_model_string: String,
    /// 0x6102
    pub sub_chunk_tag_3: u32,
    pub sub_chunk_tag_data_size_3: u32,
    pub boot_uuid: String,
    pub logd_pid: u32,
    pub logd_exit_status: u32,
    /// 0x6103
    pub sub_chunk_tag_4: u32,
    pub sub_chunk_tag_data_size_4: u32,
    pub timezone_path: String,
}

impl HeaderChunk {
    /// Parse the Unified Log tracev3 header data
    pub fn parse(input: Bytes<'_>, preamble: LogPreamble) -> nom::IResult<Bytes<'_>, Self> {
        const HARDWARE_MODEL_SIZE: u8 = 32;
        const TIMEZONE_PATH_SIZE: u8 = 48;

        let (input, (mach_time_numerator, mach_time_denominator, continous_time)) =
            tuple((le_u32, le_u32, le_u64))(input)?;
        let (input, (unknown_time, unknown, bias_min, daylight_savings)) =
            tuple((le_u64, le_u32, le_u32, le_u32))(input)?;
        let (input, (unknown_flags, sub_chunk_tag, sub_chunk_data_size)) =
            tuple((le_u32, le_u32, le_u32))(input)?;
        let (input, (sub_chunk_continous_time, sub_chunk_tag_2, sub_chunk_tag_data_size_2)) =
            tuple((le_u64, le_u32, le_u32))(input)?;
        let (input, (unknown_2, unknown_3, build_version_string)) = tuple((
            le_u32,
            le_u32,
            map(take(size_of::<u128>()), |s| {
                parstr(s, "build version from header")
            }),
        ))(input)?;
        let (input, (hardware_model_string, sub_chunk_tag_3, sub_chunk_tag_data_size_3)) =
            tuple((
                map(take(HARDWARE_MODEL_SIZE), |s| {
                    parstr(s, "hardware info from header")
                }),
                le_u32,
                le_u32,
            ))(input)?;
        let (input, (boot_uuid, logd_pid, logd_exit_status)) =
            tuple((map(be_u128, |x| format!("{x:X}")), le_u32, le_u32))(input)?;
        let (input, (sub_chunk_tag_4, sub_chunk_tag_data_size_4)) = tuple((le_u32, le_u32))(input)?;
        let (input, timezone_path) = map(take(TIMEZONE_PATH_SIZE), |s| {
            parstr(s, "timezone path from header")
        })(input)?;

        Ok((
            input,
            HeaderChunk {
                chunk_tag: preamble.chunk_tag,
                chunk_sub_tag: preamble.chunk_sub_tag,
                chunk_data_size: preamble.chunk_data_size,
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
                build_version_string,
                hardware_model_string,
                sub_chunk_tag_3,
                sub_chunk_tag_data_size_3,
                boot_uuid,
                logd_pid,
                logd_exit_status,
                sub_chunk_tag_4,
                sub_chunk_tag_data_size_4,
                timezone_path,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_preamble() -> anyhow::Result<()> {
        let test_chunk_header = &[
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

        let (input, preamble) = LogPreamble::parse(test_chunk_header)?;
        let (_, header_data) = HeaderChunk::parse(input, preamble)?;

        assert_eq!(header_data.chunk_tag, 0x1000);
        assert_eq!(header_data.chunk_sub_tag, 0x11);
        assert_eq!(header_data.mach_time_numerator, 1);
        assert_eq!(header_data.mach_time_denominator, 1);
        assert_eq!(header_data.continous_time, 139417370585359);
        assert_eq!(header_data.unknown_time, 1645401904);
        assert_eq!(header_data.unknown, 625355);
        assert_eq!(header_data.bias_min, 300);
        assert_eq!(header_data.daylight_savings, 0);
        assert_eq!(header_data.unknown_flags, 1);
        assert_eq!(header_data.sub_chunk_tag, 24832);
        assert_eq!(header_data.sub_chunk_data_size, 8);
        assert_eq!(header_data.sub_chunk_continous_time, 450429435277318);
        assert_eq!(header_data.sub_chunk_tag_2, 24833);
        assert_eq!(header_data.sub_chunk_tag_data_size_2, 56);
        assert_eq!(header_data.unknown_2, 7);
        assert_eq!(header_data.unknown_3, 8);
        assert_eq!(header_data.build_version_string, "21A559");
        assert_eq!(header_data.hardware_model_string, "MacBookPro16,1");
        assert_eq!(header_data.sub_chunk_tag_3, 24834);
        assert_eq!(header_data.sub_chunk_tag_data_size_3, 24);
        assert_eq!(header_data.boot_uuid, "C320B8CE97FA4DA59F317D392E389CEA");
        assert_eq!(header_data.logd_pid, 85);
        assert_eq!(header_data.logd_exit_status, 0);
        assert_eq!(header_data.sub_chunk_tag_4, 24835);
        assert_eq!(header_data.sub_chunk_tag_data_size_4, 48);
        assert_eq!(
            header_data.timezone_path,
            "/var/db/timezone/zoneinfo/America/New_York"
        );

        Ok(())
    }
}
