// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::extract_string;
use log::error;
use nom::bytes::complete::take;
use nom::number::complete::{be_u128, le_u16, le_u32, le_u64};
use nom::Needed;
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SharedCacheStrings {
    pub signature: u32,
    pub major_version: u16, // Version 1 up to Big Sur. Monterey has Version 2!
    pub minor_version: u16,
    pub number_ranges: u32,
    pub number_uuids: u32,
    pub ranges: Vec<RangeDescriptor>,
    pub uuids: Vec<UUIDDescriptor>,
    pub dsc_uuid: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RangeDescriptor {
    pub range_offset: u64, // In Major version 2 this is 8 bytes, in version 1 its 4 bytes
    pub data_offset: u32,
    pub range_size: u32,
    pub unknown_uuid_index: u64, // Unknown value, added in Major version: 2. Appears to be UUID index. In version 1 the index is 4 bytes and is at the start of the range descriptor
    pub strings: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UUIDDescriptor {
    pub text_offset: u64, // Size appears to be 8 bytes in Major version: 2. 4 bytes in Major Version 1
    pub text_size: u32,
    pub uuid: String,
    pub path_offset: u32,
    pub path_string: String, // Not part of format
}

impl SharedCacheStrings {
    /// Parse shared strings data (the file(s) in /private/var/db/uuidtext/dsc)
    pub fn parse_dsc(data: &[u8]) -> nom::IResult<&[u8], SharedCacheStrings> {
        let (input, sig) = take(size_of::<u32>())(data)?;
        let (_, signature) = le_u32(sig)?;

        let expected_dsc_signature = 0x64736368;
        if expected_dsc_signature != signature {
            error!(
                "[macos-unifiedlogs] Incorrect DSC file signature. Expected {}. Got: {}",
                expected_dsc_signature, signature
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let mut shared_cache_strings = SharedCacheStrings {
            signature,
            ..Default::default()
        };

        let (input, major) = take(size_of::<u16>())(input)?;
        let (input, minor) = take(size_of::<u16>())(input)?;
        let (input, number_ranges) = take(size_of::<u32>())(input)?;
        let (mut input, number_uuids) = take(size_of::<u32>())(input)?;

        let (_, dsc_major) = le_u16(major)?;
        let (_, dsc_minor) = le_u16(minor)?;
        let (_, dsc_number_ranges) = le_u32(number_ranges)?;
        let (_, dsc_number_uuids) = le_u32(number_uuids)?;

        shared_cache_strings.minor_version = dsc_minor;
        shared_cache_strings.major_version = dsc_major;
        shared_cache_strings.number_ranges = dsc_number_ranges;
        shared_cache_strings.number_uuids = dsc_number_uuids;

        let mut range_count = 0;
        while range_count < shared_cache_strings.number_ranges {
            let (range_input, range_data) = SharedCacheStrings::get_ranges(input, &dsc_major)?;
            input = range_input;
            shared_cache_strings.ranges.push(range_data);
            range_count += 1;
        }

        let mut uuid_count = 0;
        while uuid_count < shared_cache_strings.number_uuids {
            let (uuid_input, uuid_data) = SharedCacheStrings::get_uuids(input, &dsc_major)?;
            input = uuid_input;
            shared_cache_strings.uuids.push(uuid_data);
            uuid_count += 1;
        }

        for uuids in &mut shared_cache_strings.uuids {
            let (_, path_string) = SharedCacheStrings::get_paths(data, uuids.path_offset)?;
            uuids.path_string = path_string;
        }

        for range in &mut shared_cache_strings.ranges {
            let (_, strings) =
                SharedCacheStrings::get_strings(data, range.data_offset, range.range_size)?;
            range.strings = strings;
        }

        Ok((input, shared_cache_strings))
    }

    // Get range data, used by log entries to determine where the base string entry is located.
    fn get_ranges<'a>(data: &'a [u8], version: &u16) -> nom::IResult<&'a [u8], RangeDescriptor> {
        let version_number: u16 = 2;
        let mut input = data;
        let mut range_data = RangeDescriptor::default();

        // Version 2 (Monterey and higher) changed the Range format a bit
        // range offset is now 8 bytes (vs 4 bytes) and starts at beginning
        // The uuid index was moved to end
        range_data.range_offset = if version == &version_number {
            let (data_input, value_range_offset) = take(size_of::<u64>())(input)?;
            input = data_input;
            let (_, dsc_range_offset) = le_u64(value_range_offset)?;
            dsc_range_offset
        } else {
            // Get data based on version 1
            let (data_input, uuid_descriptor_index) = take(size_of::<u32>())(input)?;
            let (_, dsc_uuid_descriptor_index) = le_u32(uuid_descriptor_index)?;
            range_data.unknown_uuid_index = u64::from(dsc_uuid_descriptor_index);

            let (data_input, value_range_offset) = take(size_of::<u32>())(data_input)?;
            input = data_input;
            let (_, dsc_range_offset) = le_u32(value_range_offset)?;
            u64::from(dsc_range_offset)
        };

        let (input, data_offset) = take(size_of::<u32>())(input)?;
        let (mut input, range_size) = take(size_of::<u32>())(input)?;

        let (_, dsc_data_offset) = le_u32(data_offset)?;
        let (_, dsc_range_size) = le_u32(range_size)?;

        range_data.data_offset = dsc_data_offset;
        range_data.range_size = dsc_range_size;

        // UUID index is now located at the end of the format (instead of beginning)
        if version == &version_number {
            let (version_two_input, unknown) = take(size_of::<u64>())(input)?;
            let (_, dsc_unknown) = le_u64(unknown)?;
            range_data.unknown_uuid_index = dsc_unknown;
            input = version_two_input;
        }
        Ok((input, range_data))
    }

    // Get UUID entries related to ranges
    fn get_uuids<'a>(data: &'a [u8], version: &u16) -> nom::IResult<&'a [u8], UUIDDescriptor> {
        let mut uuid_data = UUIDDescriptor::default();

        let version_number: u16 = 2;
        let mut input = data;
        if version == &version_number {
            let (version_two_input, text_offset) = take(size_of::<u64>())(input)?;
            let (_, dsc_text_offset) = le_u64(text_offset)?;
            uuid_data.text_offset = dsc_text_offset;
            input = version_two_input;
        } else {
            let (version_one_input, text_offset) = take(size_of::<u32>())(input)?;
            let (_, dsc_text_offset) = le_u32(text_offset)?;
            uuid_data.text_offset = u64::from(dsc_text_offset);
            input = version_one_input;
        }

        let (input, text_size) = take(size_of::<u32>())(input)?;
        let (input, uuid) = take(size_of::<u128>())(input)?;
        let (input, path_offset) = take(size_of::<u32>())(input)?;

        let (_, dsc_text_size) = le_u32(text_size)?;
        let (_, dsc_uuid) = be_u128(uuid)?;
        let (_, dsc_path_offset) = le_u32(path_offset)?;

        uuid_data.text_size = dsc_text_size;
        uuid_data.uuid = format!("{:X}", dsc_uuid);
        uuid_data.path_offset = dsc_path_offset;

        Ok((input, uuid_data))
    }

    fn get_paths(data: &[u8], path_offset: u32) -> nom::IResult<&[u8], String> {
        let (nom_path_offset, _) = take(path_offset)(data)?;
        let (_, path) = extract_string(nom_path_offset)?;
        Ok((nom_path_offset, path))
    }

    // After parsing the ranges and UUIDs remaining data are the base log entry strings
    fn get_strings(
        data: &[u8],
        string_offset: u32,
        string_range: u32,
    ) -> nom::IResult<&[u8], Vec<u8>> {
        let (nom_string_offset, _) = take(string_offset)(data)?;
        let (_, strings) = take(string_range)(nom_string_offset)?;
        Ok((&[], strings.to_vec()))
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(results.uuids[0].uuid, "4DF6D8F5D9C23A968DE45E99D6B73DC8");
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
        assert_eq!(results.dsc_uuid, "");
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
        assert_eq!(results.uuids[0].uuid, "326DD91B4EF83D80B90BF50EB7D7FDB8");
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
        assert_eq!(results.dsc_uuid, "");
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
