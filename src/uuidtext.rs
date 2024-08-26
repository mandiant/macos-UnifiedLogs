// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::Bytes;
use log::error;
use nom::combinator::map;
use nom::multi::many_m_n;
use nom::number::complete::le_u32;
use nom::Needed;
use nom::{bytes::complete::take, sequence::tuple};
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Debug, Serialize, Deserialize)]
pub struct UUIDText {
    pub uuid: String,
    pub signature: u32,
    pub unknown_major_version: u32,
    pub unknown_minor_version: u32,
    pub number_entries: u32,
    pub entry_descriptors: Vec<UUIDTextEntry>,
    /// Collection of strings containing sender process/library with end of string characters
    pub footer_data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UUIDTextEntry {
    pub range_start_offset: u32,
    pub entry_size: u32,
}

impl UUIDText {
    /// Parse the UUID files in uuidinfo directory. Contains the base log message string
    pub fn parse(input: Bytes<'_>) -> nom::IResult<Bytes<'_>, UUIDText> {
        const EXPECTED_UUIDTEXT_SIGNATURE: u32 = 0x66778899;
        let (input, signature) = le_u32(input)?;

        if EXPECTED_UUIDTEXT_SIGNATURE != signature {
            error!(
                "[macos-unifiedlogs] Incorrect UUIDText header signature. Expected {}. Got: {}",
                EXPECTED_UUIDTEXT_SIGNATURE, signature
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let (input, (unknown_major_version, unknown_minor_version, number_entries)) =
            tuple((le_u32, le_u32, le_u32))(input)?;

        let (input, entry_descriptors) = many_m_n(
            number_entries as _,
            number_entries as _,
            map(
                tuple((le_u32, le_u32)),
                |(range_start_offset, entry_size)| UUIDTextEntry {
                    range_start_offset,
                    entry_size,
                },
            ),
        )(input)?;

        let footer_data = input.to_vec();

        Ok((
            input,
            UUIDText {
                uuid: String::new(),
                signature,
                unknown_major_version,
                unknown_minor_version,
                number_entries,
                entry_descriptors,
                footer_data,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_parse_uuidtext_big_sur_() -> anyhow::Result<()> {
        let input = &[
            0x99, 0x88, 0x77, 0x66, // Signature
            0x02, 0x00, 0x00, 0x00, // Unknown Major Version
            0x01, 0x00, 0x00, 0x00, // Unknown Minor Version
            0x02, 0x00, 0x00, 0x00, // Number of Entries
            0x30, 0x7D, 0x00, 0x00, // Entry 1 Range Start Offset
            0x69, 0x02, 0x00, 0x00, // Entry 1 Size
            0x33, 0x74, 0x00, 0x00, // Entry 2 Range Start Offset
            0xFD, 0x08, 0x00, 0x00, // Entry 2 Size
            0x01, 0x02, 0x03, 0x04, 0x05, // Footer Data
        ];

        let (_, uuidtext_data) = UUIDText::parse(input)?;
        assert_eq!(uuidtext_data.signature, 0x66778899);
        assert_eq!(uuidtext_data.unknown_major_version, 2);
        assert_eq!(uuidtext_data.unknown_minor_version, 1);
        assert_eq!(uuidtext_data.number_entries, 2);
        assert_eq!(uuidtext_data.entry_descriptors[0].range_start_offset, 32048);
        assert_eq!(uuidtext_data.entry_descriptors[0].entry_size, 617);
        assert_eq!(uuidtext_data.entry_descriptors[1].range_start_offset, 29747);
        assert_eq!(uuidtext_data.entry_descriptors[1].entry_size, 2301);
        assert_eq!(uuidtext_data.footer_data.len(), 5);
        assert_eq!(
            uuidtext_data.footer_data,
            vec![0x01, 0x02, 0x03, 0x04, 0x05]
        );

        Ok(())
    }

    #[test]
    fn test_parse_uuidtext_big_sur() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/UUIDText/Big Sur/1FE459BBDC3E19BBF82D58415A2AE9");

        let buffer = fs::read(test_path).unwrap();

        let (_, uuidtext_data) = UUIDText::parse(&buffer).unwrap();
        assert_eq!(uuidtext_data.signature, 0x66778899);
        assert_eq!(uuidtext_data.unknown_major_version, 2);
        assert_eq!(uuidtext_data.unknown_minor_version, 1);
        assert_eq!(uuidtext_data.number_entries, 2);
        assert_eq!(uuidtext_data.entry_descriptors[0].entry_size, 617);
        assert_eq!(uuidtext_data.entry_descriptors[1].entry_size, 2301);

        assert_eq!(uuidtext_data.entry_descriptors[0].range_start_offset, 32048);
        assert_eq!(uuidtext_data.entry_descriptors[1].range_start_offset, 29747);
        assert_eq!(uuidtext_data.footer_data.len(), 2987);
    }

    #[test]
    fn test_parse_uuidtext_high_sierra() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/UUIDText/High Sierra/425A2E5B5531B98918411B4379EE5F");

        let buffer = fs::read(test_path).unwrap();

        let (_, uuidtext_data) = UUIDText::parse(&buffer).unwrap();
        assert_eq!(uuidtext_data.signature, 0x66778899);
        assert_eq!(uuidtext_data.unknown_major_version, 2);
        assert_eq!(uuidtext_data.unknown_minor_version, 1);
        assert_eq!(uuidtext_data.number_entries, 1);
        assert_eq!(uuidtext_data.entry_descriptors[0].entry_size, 2740);
        assert_eq!(uuidtext_data.entry_descriptors[0].range_start_offset, 21132);

        assert_eq!(uuidtext_data.footer_data.len(), 2951);
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_bad_header() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/Bad Data/UUIDText/Bad_Header_1FE459BBDC3E19BBF82D58415A2AE9");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = UUIDText::parse(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_content() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/Bad Data/UUIDText/Bad_Content_1FE459BBDC3E19BBF82D58415A2AE9");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = UUIDText::parse(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_bad_file() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/UUIDText/Badfile.txt");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = UUIDText::parse(&buffer).unwrap();
    }
}
