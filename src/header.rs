// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::INVALID_UTF8;
use crate::{RcString, rc_string};
use log::warn;
use nom::{
    bytes::complete::take,
    number::complete::{be_u128, le_u32, le_u64},
};
use std::{mem::size_of, str::from_utf8};
use uuid::Uuid;

pub type HeaderChunkStr<'a> = HeaderChunk<&'a str>;
pub type HeaderChunkOwned = HeaderChunk<RcString>;

#[derive(Debug, Clone, Default)]
pub struct HeaderChunk<S>
where
    S: Default + ToString,
{
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
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
    pub build_version_string: S,
    pub hardware_model_string: S,
    pub sub_chunk_tag_3: u32, // 0x6102
    pub sub_chunk_tag_data_size_3: u32,
    pub boot_uuid: Uuid,
    pub logd_pid: u32,
    pub logd_exit_status: u32,
    pub sub_chunk_tag_4: u32, // 0x6103
    pub sub_chunk_tag_data_size_4: u32,
    pub timezone_path: S,
}

impl<'a> HeaderChunkStr<'a> {
    pub fn into_owned(self) -> HeaderChunkOwned {
        HeaderChunkOwned {
            build_version_string: rc_string!(self.build_version_string),
            hardware_model_string: rc_string!(self.hardware_model_string),
            timezone_path: rc_string!(self.timezone_path),
            chunk_tag: self.chunk_tag,
            chunk_sub_tag: self.chunk_sub_tag,
            chunk_data_size: self.chunk_data_size,
            mach_time_numerator: self.mach_time_numerator,
            mach_time_denominator: self.mach_time_denominator,
            continous_time: self.continous_time,
            unknown_time: self.unknown_time,
            unknown: self.unknown,
            bias_min: self.bias_min,
            daylight_savings: self.daylight_savings,
            unknown_flags: self.unknown_flags,
            sub_chunk_tag: self.sub_chunk_tag,
            sub_chunk_data_size: self.sub_chunk_data_size,
            sub_chunk_continous_time: self.sub_chunk_continous_time,
            sub_chunk_tag_2: self.sub_chunk_tag_2,
            sub_chunk_tag_data_size_2: self.sub_chunk_tag_data_size_2,
            unknown_2: self.unknown_2,
            unknown_3: self.unknown_3,
            sub_chunk_tag_3: self.sub_chunk_tag_3,
            sub_chunk_tag_data_size_3: self.sub_chunk_tag_data_size_3,
            boot_uuid: self.boot_uuid,
            logd_pid: self.logd_pid,
            logd_exit_status: self.logd_exit_status,
            sub_chunk_tag_4: self.sub_chunk_tag_4,
            sub_chunk_tag_data_size_4: self.sub_chunk_tag_data_size_4,
        }
    }
}

impl<'a> HeaderChunkStr<'a> {
    /// Parse the Unified Log tracev3 header data
    pub fn parse_header(data: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, chunk_tag) = le_u32(data)?;
        let (input, chunk_sub_tag) = le_u32(input)?;
        let (input, chunk_data_size) = le_u64(input)?;
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
        let build_version_string = from_utf8(build_version_string)
            .inspect_err(|err| {
                warn!("[macos-unifiedlogs] Failed to get build version from header: {err:?}")
            })
            .map(|s| s.trim_end_matches('\0'))
            .unwrap_or(INVALID_UTF8);

        let hardware_model_size: u8 = 32;
        let (input, hardware_model_string) = take(hardware_model_size)(input)?;

        let hardware_model_string = from_utf8(hardware_model_string)
            .inspect_err(|err| {
                warn!("[macos-unifiedlogs] Failed to get hardware info from header: {err:?}")
            })
            .map(|s| s.trim_end_matches('\0'))
            .unwrap_or(INVALID_UTF8);

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
        let timezone_path = from_utf8(timezone_path)
            .inspect_err(|err| {
                warn!("[macos-unifiedlogs] Failed to get timezone path from header: {err:?}")
            })
            .map(|s| s.trim_end_matches('\0'))
            .unwrap_or(INVALID_UTF8);

        let header_chunk = HeaderChunk {
            chunk_tag,
            chunk_sub_tag,
            chunk_data_size,
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

    use uuid::Uuid;

    use super::HeaderChunk;

    #[test]
    fn test_detect_preamble() {
        let test_chunk_header = [
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

        let (_, header_data) = HeaderChunk::parse_header(&test_chunk_header).unwrap();

        assert_eq!(header_data.chunk_tag, crate::constants::HEADER_CHUNK);
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
        assert_eq!(
            header_data.boot_uuid,
            Uuid::parse_str("C320B8CE97FA4DA59F317D392E389CEA").unwrap()
        );
        assert_eq!(header_data.logd_pid, 85);
        assert_eq!(header_data.logd_exit_status, 0);
        assert_eq!(header_data.sub_chunk_tag_4, 24835);
        assert_eq!(header_data.sub_chunk_tag_data_size_4, 48);
        assert_eq!(
            header_data.timezone_path,
            "/var/db/timezone/zoneinfo/America/New_York"
        );
    }
}
