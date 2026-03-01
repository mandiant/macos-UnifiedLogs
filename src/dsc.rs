// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::constants::DSC_SIGNATURE;
use crate::util::extract_string;
use crate::{RcString, rc_string};
use log::error;
use nom::Needed;
use nom::bytes::complete::take;
use nom::number::complete::{be_u128, le_u16, le_u32, le_u64};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type SharedCacheStringsStr<'a> = SharedCacheStrings<&'a str>;
pub type SharedCacheStringsOwned = SharedCacheStrings<RcString>;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SharedCacheStrings<S>
where
    S: Default + ToString,
{
    pub signature: u32,
    pub major_version: u16, // Version 1 up to Big Sur. Monterey has Version 2!
    pub minor_version: u16,
    pub number_ranges: u32,
    pub number_uuids: u32,
    pub ranges: Vec<RangeDescriptor>,
    pub uuids: Vec<UUIDDescriptor<S>>,
    pub dsc_uuid: Uuid,
}

impl<'a> SharedCacheStringsStr<'a> {
    pub fn into_owned(self) -> SharedCacheStringsOwned {
        SharedCacheStringsOwned {
            signature: self.signature,
            major_version: self.major_version,
            minor_version: self.minor_version,
            number_ranges: self.number_ranges,
            number_uuids: self.number_uuids,
            ranges: self.ranges,
            uuids: self.uuids.into_iter().map(|u| u.into_owned()).collect(),
            dsc_uuid: self.dsc_uuid,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RangeDescriptor {
    pub range_offset: u64, // In Major version 2 this is 8 bytes, in version 1 its 4 bytes
    pub data_offset: u32,
    pub range_size: u32,
    pub unknown_uuid_index: u64, // Unknown value, added in Major version: 2. Appears to be UUID index. In version 1 the index is 4 bytes and is at the start of the range descriptor
    pub strings: Vec<u8>,
}

pub type UUIDDescriptorStr<'a> = UUIDDescriptor<&'a str>;
pub type UUIDDescriptorOwned = UUIDDescriptor<RcString>;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UUIDDescriptor<S>
where
    S: Default + ToString,
{
    pub text_offset: u64, // Size appears to be 8 bytes in Major version: 2. 4 bytes in Major Version 1
    pub text_size: u32,
    pub uuid: Uuid,
    pub path_offset: u32,
    pub path_string: S, // Not part of format
}

impl<'a> UUIDDescriptorStr<'a> {
    pub fn into_owned(self) -> UUIDDescriptorOwned {
        UUIDDescriptorOwned {
            text_offset: self.text_offset,
            text_size: self.text_size,
            uuid: self.uuid,
            path_offset: self.path_offset,
            path_string: rc_string!(self.path_string),
        }
    }
}

impl<'a> SharedCacheStringsStr<'a> {
    /// Parse shared strings data (the file(s) in /private/var/db/uuidtext/dsc)
    pub fn parse_dsc(data: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, signature) = le_u32(data)?;

        if DSC_SIGNATURE != signature {
            error!(
                "[macos-unifiedlogs] Incorrect DSC file signature. Expected {DSC_SIGNATURE}. Got: {signature}"
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let (input, major_version) = le_u16(input)?;
        let (input, minor_version) = le_u16(input)?;
        let (input, number_ranges) = le_u32(input)?;
        let (mut input, number_uuids) = le_u32(input)?;

        let mut ranges = Vec::new();
        let mut range_count = 0;
        while range_count < number_ranges {
            let (range_input, range_data) =
                SharedCacheStringsStr::get_ranges(input, major_version)?;
            input = range_input;
            ranges.push(range_data);
            range_count += 1;
        }

        let mut uuids = Vec::new();
        let mut uuid_count = 0;
        while uuid_count < number_uuids {
            let (uuid_input, uuid_data) = SharedCacheStringsStr::get_uuids(input, major_version)?;
            input = uuid_input;
            uuids.push(uuid_data);
            uuid_count += 1;
        }

        for uuid_entry in &mut uuids {
            let (_, path_string) = SharedCacheStrings::get_paths(data, uuid_entry.path_offset)?;
            uuid_entry.path_string = path_string;
        }

        for range in &mut ranges {
            let (_, strings) =
                SharedCacheStrings::get_strings(data, range.data_offset, range.range_size)?;
            range.strings = strings.to_vec();
        }

        Ok((
            input,
            SharedCacheStringsStr {
                signature,
                major_version,
                minor_version,
                number_ranges,
                number_uuids,
                ranges,
                uuids,
                dsc_uuid: Uuid::nil(),
            },
        ))
    }

    // Get range data, used by log entries to determine where the base string entry is located.
    fn get_ranges(data: &'a [u8], version: u16) -> nom::IResult<&'a [u8], RangeDescriptor> {
        let version_number: u16 = 2;
        let mut input = data;

        // Version 2 (Monterey and higher) changed the Range format a bit
        // range offset is now 8 bytes (vs 4 bytes) and starts at beginning
        // The uuid index was moved to end
        let mut unknown_uuid_index: u64 = 0;
        let range_offset = if version == version_number {
            let (data_input, dsc_range_offset) = le_u64(input)?;
            input = data_input;
            dsc_range_offset
        } else {
            // Get data based on version 1
            let (data_input, dsc_uuid_descriptor_index) = le_u32(input)?;
            unknown_uuid_index = u64::from(dsc_uuid_descriptor_index);

            let (data_input, dsc_range_offset) = le_u32(data_input)?;
            input = data_input;
            u64::from(dsc_range_offset)
        };

        let (input, data_offset) = le_u32(input)?;
        let (mut input, range_size) = le_u32(input)?;

        // UUID index is now located at the end of the format (instead of beginning)
        if version == version_number {
            let (version_two_input, dsc_unknown) = le_u64(input)?;
            unknown_uuid_index = dsc_unknown;
            input = version_two_input;
        }

        Ok((
            input,
            RangeDescriptor {
                range_offset,
                data_offset,
                range_size,
                unknown_uuid_index,
                strings: Vec::new(),
            },
        ))
    }

    // Get UUID entries related to ranges
    fn get_uuids(data: &'a [u8], version: u16) -> nom::IResult<&'a [u8], UUIDDescriptorStr<'a>> {
        let version_number: u16 = 2;
        let mut input = data;

        let text_offset = if version == version_number {
            let (version_two_input, dsc_text_offset) = le_u64(input)?;
            input = version_two_input;
            dsc_text_offset
        } else {
            let (version_one_input, dsc_text_offset) = le_u32(input)?;
            input = version_one_input;
            u64::from(dsc_text_offset)
        };

        let (input, text_size) = le_u32(input)?;
        let (input, uuid_val) = be_u128(input)?;
        let (input, path_offset) = le_u32(input)?;

        Ok((
            input,
            UUIDDescriptor {
                text_offset,
                text_size,
                uuid: Uuid::from_u128(uuid_val),
                path_offset,
                path_string: Default::default(),
            },
        ))
    }

    fn get_paths(data: &[u8], path_offset: u32) -> nom::IResult<&[u8], &str> {
        let (nom_path_offset, _) = take(path_offset)(data)?;
        let (_, path) = extract_string(nom_path_offset)?;
        Ok((nom_path_offset, path))
    }

    // After parsing the ranges and UUIDs remaining data are the base log entry strings
    fn get_strings(
        data: &[u8],
        string_offset: u32,
        string_range: u32,
    ) -> nom::IResult<&[u8], &[u8]> {
        let (nom_string_offset, _) = take(string_offset)(data)?;
        let (_, strings) = take(string_range)(nom_string_offset)?;
        Ok((&[], strings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsc::SharedCacheStrings;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_parse_dsc_version_one() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = SharedCacheStrings::parse_dsc(&buffer).unwrap();
        assert_eq!(results.uuids.len(), 532);
        assert_eq!(
            results.uuids[0].uuid,
            Uuid::parse_str("4DF6D8F5D9C23A968DE45E99D6B73DC8").unwrap()
        );
        assert_eq!(results.uuids[0].path_offset, 19919502);
        assert_eq!(results.uuids[0].text_size, 8192);
        assert_eq!(results.uuids[0].text_offset, 73728);
        assert_eq!(
            results.uuids[0].path_string,
            "/usr/lib/system/libsystem_blocks.dylib"
        );

        assert_eq!(results.ranges.len(), 788);
        assert_eq!(results.ranges[0].strings, [0]);
        assert_eq!(results.ranges[0].unknown_uuid_index, 0);
        assert_eq!(results.ranges[0].range_offset, 80296);
        assert_eq!(results.ranges[0].range_size, 1);

        assert_eq!(results.signature, 1685283688); // hcsd
        assert_eq!(results.major_version, 1);
        assert_eq!(results.minor_version, 0);
        assert_eq!(results.dsc_uuid, Uuid::nil());
        assert_eq!(results.number_ranges, 788);
        assert_eq!(results.number_uuids, 532);
    }

    #[test]
    fn test_parse_dsc_version_two() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/DSC Tests/monterey_version_2_3D05845F3F65358F9EBF2236E772AC01");

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = SharedCacheStrings::parse_dsc(&buffer).unwrap();
        assert_eq!(results.uuids.len(), 2250);
        assert_eq!(
            results.uuids[0].uuid,
            Uuid::parse_str("326DD91B4EF83D80B90BF50EB7D7FDB8").unwrap()
        );
        assert_eq!(results.uuids[0].path_offset, 98376932);
        assert_eq!(results.uuids[0].text_size, 8192);
        assert_eq!(results.uuids[0].text_offset, 327680);
        assert_eq!(
            results.uuids[0].path_string,
            "/usr/lib/system/libsystem_blocks.dylib"
        );

        assert_eq!(results.ranges.len(), 3432);
        assert_eq!(results.ranges[0].strings, [0]);
        assert_eq!(results.ranges[0].unknown_uuid_index, 0);
        assert_eq!(results.ranges[0].range_offset, 334248);
        assert_eq!(results.ranges[0].range_size, 1);

        assert_eq!(results.signature, 1685283688); // hcsd
        assert_eq!(results.major_version, 2);
        assert_eq!(results.minor_version, 0);
        assert_eq!(results.dsc_uuid, Uuid::nil());
        assert_eq!(results.number_ranges, 3432);
        assert_eq!(results.number_uuids, 2250);
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_bad_header() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/Bad Data/DSC/bad_header_version_1_522F6217CB113F8FB845C2A1B784C7C2",
        );

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = SharedCacheStrings::parse_dsc(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_content() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/Bad Data/DSC/bad_content_version_1_522F6217CB113F8FB845C2A1B784C7C2",
        );

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = SharedCacheStrings::parse_dsc(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_bad_file() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/DSC/Badfile");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = SharedCacheStrings::parse_dsc(&buffer).unwrap();
    }
}
