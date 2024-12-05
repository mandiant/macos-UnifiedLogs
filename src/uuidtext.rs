// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::error;
use nom::bytes::complete::take;
use nom::number::complete::le_u32;
use nom::Needed;
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UUIDText {
    pub uuid: String,
    pub signature: u32,
    pub unknown_major_version: u32,
    pub unknown_minor_version: u32,
    pub number_entries: u32,
    pub entry_descriptors: Vec<UUIDTextEntry>,
    pub footer_data: Vec<u8>, // Collection of strings containing sender process/library with end of string characters
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UUIDTextEntry {
    pub range_start_offset: u32,
    pub entry_size: u32,
}
impl UUIDText {
    /// Parse the UUID files in uuidinfo directory. Contains the base log message string
    pub fn parse_uuidtext(data: &[u8]) -> nom::IResult<&[u8], UUIDText> {
        let mut uuidtext_data = UUIDText::default();

        let expected_uuidtext_signature = 0x66778899;
        let (input, signature) = take(size_of::<u32>())(data)?;
        let (_, uuidtext_signature) = le_u32(signature)?;

        if expected_uuidtext_signature != uuidtext_signature {
            error!(
                "[macos-unifiedlogs] Incorrect UUIDText header signature. Expected {}. Got: {}",
                expected_uuidtext_signature, uuidtext_signature
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let (input, unknown_major_version) = take(size_of::<u32>())(input)?;
        let (input, unknown_minor_version) = take(size_of::<u32>())(input)?;
        let (mut input, number_entries) = take(size_of::<u32>())(input)?;

        let (_, uuidtext_unknown_major_version) = le_u32(unknown_major_version)?;
        let (_, uuidtext_unknown_minor_version) = le_u32(unknown_minor_version)?;
        let (_, uuidtext_number_entries) = le_u32(number_entries)?;

        uuidtext_data.signature = uuidtext_signature;
        uuidtext_data.unknown_major_version = uuidtext_unknown_major_version;
        uuidtext_data.unknown_minor_version = uuidtext_unknown_minor_version;
        uuidtext_data.number_entries = uuidtext_number_entries;

        let mut count = 0;
        while count < uuidtext_number_entries {
            let (entry_input, range_start_offset) = take(size_of::<u32>())(input)?;
            let (entry_input, entry_size) = take(size_of::<u32>())(entry_input)?;

            let (_, uuidtext_range_start_offset) = le_u32(range_start_offset)?;
            let (_, uuidtext_entry_size) = le_u32(entry_size)?;

            let entry_data = UUIDTextEntry {
                range_start_offset: uuidtext_range_start_offset,
                entry_size: uuidtext_entry_size,
            };
            uuidtext_data.entry_descriptors.push(entry_data);

            input = entry_input;
            count += 1;
        }
        uuidtext_data.footer_data = input.to_vec();
        Ok((input, uuidtext_data))
    }
}

#[cfg(test)]
mod tests {
    use crate::uuidtext::UUIDText;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_parse_uuidtext_big_sur() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/UUIDText/Big Sur/1FE459BBDC3E19BBF82D58415A2AE9");

        let buffer = fs::read(test_path).unwrap();

        let (_, uuidtext_data) = UUIDText::parse_uuidtext(&buffer).unwrap();
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

        let (_, uuidtext_data) = UUIDText::parse_uuidtext(&buffer).unwrap();
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
        let (_, _) = UUIDText::parse_uuidtext(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_content() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/Bad Data/UUIDText/Bad_Content_1FE459BBDC3E19BBF82D58415A2AE9");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = UUIDText::parse_uuidtext(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_bad_file() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/UUIDText/Badfile.txt");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = UUIDText::parse_uuidtext(&buffer).unwrap();
    }
}
