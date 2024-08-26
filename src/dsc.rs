// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::extract_string;
use crate::Bytes;
use log::error;
use nom::bytes::complete::take;
use nom::combinator::map;
use nom::multi::many_m_n;
use nom::number::complete::{be_u128, le_u16, le_u32, le_u64};
use nom::sequence::tuple;
use nom::Needed;
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Debug, Serialize, Deserialize)]
pub struct SharedCacheStrings {
    pub signature: u32,
    /// Version 1 up to Big Sur. Monterey has Version 2!
    pub major_version: u16,
    pub minor_version: u16,
    pub number_ranges: u32,
    pub number_uuids: u32,
    pub ranges: Vec<RangeDescriptor>,
    pub uuids: Vec<UUIDDescriptor>,
    pub dsc_uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RangeDescriptor {
    /// In Major version 2 this is 8 bytes, in version 1 its 4 bytes
    pub range_offset: u64,
    pub data_offset: u32,
    pub range_size: u32,
    /// Unknown value, added in Major version: 2. Appears to be UUID index. In version 1 the index is 4 bytes and is at the start of the range descriptor
    pub unknown_uuid_index: u64,
    pub strings: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UUIDDescriptor {
    /// Size appears to be 8 bytes in Major version: 2. 4 bytes in Major Version 1
    pub text_offset: u64,
    pub text_size: u32,
    pub uuid: String,
    pub path_offset: u32,
    /// Not part of format
    pub path_string: String,
}

const VERSION_2: u16 = 2;

impl SharedCacheStrings {
    /// Parse shared strings data (the file(s) in /private/var/db/uuidtext/dsc)
    pub fn parse(full_data: Bytes<'_>) -> nom::IResult<Bytes<'_>, Self> {
        let (input, sig) = take(size_of::<u32>())(full_data)?;
        let (_, signature) = le_u32(sig)?;

        const EXPECTED_DSC_SIGNATURE: u32 = 0x64736368;
        if EXPECTED_DSC_SIGNATURE != signature {
            error!(
                "[macos-unifiedlogs] Incorrect DSC file signature. Expected {}. Got: {}",
                EXPECTED_DSC_SIGNATURE, signature
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let (input, (major_version, minor_version, number_ranges, number_uuids)) =
            tuple((le_u16, le_u16, le_u32, le_u32))(input)?;

        let (input, ranges) = many_m_n(number_ranges as _, number_ranges as _, |s| {
            range(s, major_version, full_data)
        })(input)?;

        let (input, uuids) = many_m_n(number_uuids as _, number_uuids as _, |s| {
            uuid(s, major_version, full_data)
        })(input)?;

        Ok((
            input,
            SharedCacheStrings {
                signature,
                major_version,
                minor_version,
                number_ranges,
                number_uuids,
                ranges,
                uuids,
                dsc_uuid: String::new(),
            },
        ))
    }
}

/// Get range data, used by log entries to determine where the base string entry is located.
fn range<'a>(
    input: Bytes<'a>,
    version: u16,
    full_data: Bytes<'a>,
) -> nom::IResult<Bytes<'a>, RangeDescriptor> {
    let (input, (range_offset, data_offset, range_size, unknown_uuid_index)) =
        if version == VERSION_2 {
            // Version 2 (Monterey and higher) changed the Range format a bit
            // range offset is now 8 bytes (vs 4 bytes) and starts at beginning
            // The uuid index was moved to end

            // UUID index is now located at the end of the format (instead of beginning)

            let (input, (range_offset, data_offset, range_size, unknown_uuid_index)) =
                tuple((le_u64, le_u32, le_u32, le_u64))(input)?;
            (
                input,
                (range_offset, data_offset, range_size, unknown_uuid_index),
            )
        } else {
            let (input, (unknown_uuid_index, range_offset, data_offset, range_size)) =
                tuple((
                    map(le_u32, u64::from),
                    map(le_u32, u64::from),
                    le_u32,
                    le_u32,
                ))(input)?;
            (
                input,
                (range_offset, data_offset, range_size, unknown_uuid_index),
            )
        };

    let (_, strings) = data_string(full_data, data_offset, range_size)?;

    Ok((
        input,
        RangeDescriptor {
            range_offset,
            data_offset,
            range_size,
            unknown_uuid_index,
            strings,
        },
    ))
}

// Get UUID entries related to ranges
fn uuid<'a>(
    input: Bytes<'a>,
    version: u16,
    full_data: Bytes<'a>,
) -> nom::IResult<Bytes<'a>, UUIDDescriptor> {
    let (input, text_offset) = if version == VERSION_2 {
        le_u64(input)?
    } else {
        map(le_u32, u64::from)(input)?
    };

    let (input, (text_size, uuid, path_offset)) = tuple((le_u32, be_u128, le_u32))(input)?;

    let (_, path_string) = path_string(full_data, path_offset)?;

    Ok((
        input,
        UUIDDescriptor {
            text_offset,
            text_size,
            uuid: format!("{:X}", uuid),
            path_offset,
            path_string,
        },
    ))
}

fn path_string(input: Bytes<'_>, path_offset: u32) -> nom::IResult<Bytes<'_>, String> {
    let (input, _) = take(path_offset)(input)?;
    let (_, path) = extract_string(input)?;
    Ok((&[], path))
}

/// After parsing the ranges and UUIDs remaining data are the base log entry strings
fn data_string(
    data: Bytes<'_>,
    string_offset: u32,
    string_range: u32,
) -> nom::IResult<Bytes<'_>, Vec<u8>> {
    let (nom_string_offset, _) = take(string_offset)(data)?;
    let (_, strings) = take(string_range)(nom_string_offset)?;
    Ok((&[], strings.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_parse_dsc_version_one_() -> anyhow::Result<()> {
        let input = &[
            0x68, 0x63, 0x73, 0x64, // Signature
            0x01, 0x00, 0x00, 0x00, // Major - Minor
            0x01, 0x00, 0x00, 0x00, // number of ranges
            0x01, 0x00, 0x00, 0x00, // number of uuids
            0x00, 0x00, 0x00, 0x00, // Unknown UUID index
            0xa8, 0x39, 0x01, 0x00, // Range offset
            0x3c, 0x00, 0x00, 0x00, // Data offset
            0x05, 0x00, 0x00, 0x00, // Range size
            0x00, 0x20, 0x01, 0x00, //  text offset
            0x00, 0x20, 0x00, 0x00, //  text size
            0x4d, 0xf6, 0xd8, 0xf5, 0xd9, 0xc2, 0x3a, 0x96, // UUID part 1
            0x8d, 0xe4, 0x5e, 0x99, 0xd6, 0xb7, 0x3d, 0xc8, // UUID part 2
            0x45, 0x00, 0x00, 0x00, // Path offset
            0x48, 0x65, 0x4c, 0x4c, 0x30, // a string "HeLL0"
            0x00, 0x00, 0x00, 0x00, // null bytes (just for fun)
            0x68, 0xc3, 0xa9, 0x6c, 0x6c, 0x6f, // Path string "héllo"
        ];

        let (rest, results) = SharedCacheStrings::parse(input)?;

        assert_eq!(results.signature, 1685283688); // hcsd
        assert_eq!(results.major_version, 1);
        assert_eq!(results.minor_version, 0);
        assert_eq!(results.dsc_uuid, "");
        assert_eq!(results.number_ranges, 1);
        assert_eq!(results.number_uuids, 1);

        assert_eq!(results.ranges.len(), 1);
        assert_eq!(results.ranges[0].unknown_uuid_index, 0);
        assert_eq!(results.ranges[0].range_offset, 80296);
        assert_eq!(results.ranges[0].data_offset, 60);
        assert_eq!(results.ranges[0].range_size, 5);
        assert_eq!(results.ranges[0].strings, [0x48, 0x65, 0x4c, 0x4c, 0x30]);

        assert_eq!(results.uuids.len(), 1);
        assert_eq!(results.uuids[0].text_offset, 73728);
        assert_eq!(results.uuids[0].text_size, 8192);
        assert_eq!(results.uuids[0].uuid, "4DF6D8F5D9C23A968DE45E99D6B73DC8");
        assert_eq!(results.uuids[0].path_offset, 69);
        assert_eq!(results.uuids[0].path_string, "héllo");

        assert_eq!(
            rest,
            &[
                0x48, 0x65, 0x4c, 0x4c, 0x30, 0x00, 0x00, 0x00, 0x00, 0x68, 0xc3, 0xa9, 0x6c, 0x6c,
                0x6f
            ]
        );

        Ok(())
    }

    #[test]
    fn test_parse_dsc_version_one() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = SharedCacheStrings::parse(&buffer).unwrap();
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

        let (_, results) = SharedCacheStrings::parse(&buffer).unwrap();
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
    fn test_bad_header() -> anyhow::Result<()> {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/Bad Data/DSC/bad_header_version_1_522F6217CB113F8FB845C2A1B784C7C2",
        );

        let buffer = fs::read(test_path)?;
        let result = SharedCacheStrings::parse(&buffer);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_bad_content() -> anyhow::Result<()> {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/Bad Data/DSC/bad_content_version_1_522F6217CB113F8FB845C2A1B784C7C2",
        );

        let buffer = fs::read(test_path)?;
        let result = SharedCacheStrings::parse(&buffer);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_bad_file() -> anyhow::Result<()> {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/DSC/Badfile");

        let buffer = fs::read(test_path)?;
        let result = SharedCacheStrings::parse(&buffer);
        assert!(result.is_err());
        Ok(())
    }
}
