// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::{debug, error};
use nom::bytes::complete::take;
use nom::number::complete::{be_u128, le_u16};
use nom::Needed;
use std::mem::size_of;

#[derive(Debug, Clone, Default)]
pub struct FirehoseFormatters {
    pub main_exe: bool,
    pub shared_cache: bool,
    pub has_large_offset: u16,
    pub large_shared_cache: u16,
    pub absolute: bool,
    pub uuid_relative: String,
    pub main_plugin: bool,       // Not seen yet
    pub pc_style: bool,          // Not seen yet
    pub main_exe_alt_index: u16, // If log entry uses an alternative uuid file index (ex: absolute). This value gets prepended to the unknown_pc_id/offset
}

impl FirehoseFormatters {
    /// Identify formatter flags associated with the log entry. Formatter flags determine the file where the base format string is located
    pub fn firehose_formatter_flags<'a>(
        data: &'a [u8],
        firehose_flags: &u16,
    ) -> nom::IResult<&'a [u8], FirehoseFormatters> {
        let mut formatter_flags = FirehoseFormatters::default();

        let message_strings_uuid: u16 = 0x2; // main_exe flag
        let large_shared_cache = 0xc; // large_shared_cache flag
        let large_offset = 0x20; // has_large_offset flag

        let flag_check = 0xe;
        let mut input = data;

        /*
        0x20 - has_large_offset flag. Offset to format string is larger than normal
        0xc - has_large_shared_cache flag. Offset to format string is larger than normal
        0x8 - absolute flag. The log uses an alterantive index number that points to the UUID file name in the Catalog which contains the format string
        0x2 - main_exe flag. A UUID file contains the format string
        0x4 - shared_cache flag. DSC file contains the format string
        0xa - uuid_relative flag. The UUID file name is in the log data (instead of the Catalog)
         */
        match firehose_flags & flag_check {
            0x20 => {
                debug!("[macos-unifiedlogs] Firehose flag: has_large_offset");
                let (firehose_input, large_offset_data) = take(size_of::<u16>())(input)?;
                let (_, firehose_large_offset) = le_u16(large_offset_data)?;
                formatter_flags.has_large_offset = firehose_large_offset;
                input = firehose_input;
                if (firehose_flags & large_shared_cache) != 0 {
                    debug!("[macos-unifiedlogs] Firehose flag: large_shared_cache and has_large_offset");
                    let (firehose_input, large_shared_cache) =
                        take(size_of::<u16>())(firehose_input)?;
                    let (_, firehose_large_shared_cache) = le_u16(large_shared_cache)?;
                    formatter_flags.large_shared_cache = firehose_large_shared_cache;
                    input = firehose_input;
                }
            }
            0xc => {
                debug!("[macos-unifiedlogs] Firehose flag: large_shared_cache");
                if (firehose_flags & large_offset) != 0 {
                    let (firehose_input, large_offset_data) = take(size_of::<u16>())(input)?;
                    let (_, firehose_large_offset) = le_u16(large_offset_data)?;
                    formatter_flags.has_large_offset = firehose_large_offset;
                    input = firehose_input;
                }

                let (firehose_input, large_shared_cache) = take(size_of::<u16>())(input)?;
                let (_, firehose_large_shared_cache) = le_u16(large_shared_cache)?;
                formatter_flags.large_shared_cache = firehose_large_shared_cache;
                input = firehose_input;
            }
            0x8 => {
                debug!("[macos-unifiedlogs] Firehose flag: absolute");
                formatter_flags.absolute = true;
                if (firehose_flags & message_strings_uuid) == 0 {
                    debug!("[macos-unifiedlogs] Firehose flag: alt index absolute flag");
                    let (firehose_input, uuid_file_index) = take(size_of::<u16>())(input)?;
                    let (_, firehose_uuid_file_index) = le_u16(uuid_file_index)?;

                    formatter_flags.main_exe_alt_index = firehose_uuid_file_index;
                    input = firehose_input;
                }
            }
            0x2 => {
                debug!("[macos-unifiedlogs] Firehose flag: main_exe");
                formatter_flags.main_exe = true
            }
            0x4 => {
                debug!("[macos-unifiedlogs] Firehose flag: shared_cache");
                formatter_flags.shared_cache = true;
                if (firehose_flags & large_offset) != 0 {
                    let (firehose_input, large_offset_data) = take(size_of::<u16>())(input)?;
                    let (_, firehose_large_offset) = le_u16(large_offset_data)?;
                    formatter_flags.has_large_offset = firehose_large_offset;
                    input = firehose_input;
                }
            }
            0xa => {
                debug!("[macos-unifiedlogs] Firehose flag: uuid_relative");
                let (firehose_input, uuid_relative) = take(size_of::<u128>())(input)?;
                let (_, firehose_uuid_relative) = be_u128(uuid_relative)?;
                formatter_flags.uuid_relative = format!("{:X}", firehose_uuid_relative);
                input = firehose_input;
            }
            _ => {
                error!(
                    "[macos-unifiedlogs] Unknown Firehose formatter flag: {:?}",
                    firehose_flags
                );
                debug!("[macos-unifiedlogs] Firehose data: {:X?}", data);
                return Err(nom::Err::Incomplete(Needed::Unknown));
            }
        }
        Ok((input, formatter_flags))
    }
}

#[cfg(test)]
mod tests {
    use crate::chunks::firehose::flags::FirehoseFormatters;

    #[test]
    fn test_firehose_formatter_flags_has_large_offset() {
        let test_data = [
            1, 0, 2, 0, 14, 0, 34, 2, 0, 4, 135, 16, 0, 0, 34, 4, 0, 0, 5, 0, 100, 101, 110, 121, 0,
        ];
        let test_flags = 557;
        let (_, results) =
            FirehoseFormatters::firehose_formatter_flags(&test_data, &test_flags).unwrap();
        assert_eq!(results.has_large_offset, 1);
        assert_eq!(results.large_shared_cache, 2);
    }

    #[test]
    fn test_firehose_formatter_flags_message_strings_uuid_message_alt_index() {
        let test_data = [8, 0, 17, 166, 251, 2, 128, 255, 0, 0];
        let test_flags = 8;
        let (_, results) =
            FirehoseFormatters::firehose_formatter_flags(&test_data, &test_flags).unwrap();
        assert_eq!(results.main_exe_alt_index, 8)
    }

    #[test]
    fn test_firehose_formatter_flags_message_strings_uuid() {
        let test_data = [186, 0, 0, 0];
        let test_flags = 514;
        let (_, results) =
            FirehoseFormatters::firehose_formatter_flags(&test_data, &test_flags).unwrap();
        assert_eq!(results.main_exe, true);
    }

    #[test]
    fn test_firehose_formatter_flags_shared_cache_dsc_uuid() {
        let test_data = [
            23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83,
            116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 52, 54, 58, 32, 101,
            110, 116, 101, 114, 0,
        ];
        let test_flags = 516;
        let (_, results) =
            FirehoseFormatters::firehose_formatter_flags(&test_data, &test_flags).unwrap();
        assert_eq!(results.shared_cache, true);
    }

    #[test]
    fn test_firehose_formatter_flags_absolute_message_alt_uuid() {
        let test_data = [
            128, 255, 2, 13, 34, 4, 0, 0, 6, 0, 34, 4, 6, 0, 11, 0, 34, 4, 17, 0, 7, 0, 2, 4, 8, 0,
            0, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 34,
            4, 24, 0, 3, 0, 34, 4, 27, 0, 3, 0, 2, 8, 156, 17, 7, 98, 0, 0, 0, 0, 2, 8, 156, 17, 7,
            98, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 34, 4, 30, 0, 3, 0, 65, 67, 77, 82, 77, 0, 95, 108,
            111, 103, 80, 111, 108, 105, 99, 121, 0, 83, 65, 86, 73, 78, 71, 0, 78, 79, 0, 78, 79,
            0, 78, 79, 0,
        ];
        let test_flags = 8;
        let (_, results) =
            FirehoseFormatters::firehose_formatter_flags(&test_data, &test_flags).unwrap();
        assert_eq!(results.absolute, true);
        assert_eq!(results.main_exe_alt_index, 65408);
    }

    #[test]
    fn test_firehose_formatter_flags_uuid_relative() {
        let test_data = [
            123, 13, 55, 117, 241, 144, 62, 33, 186, 19, 4, 71, 196, 27, 135, 67, 0, 0,
        ];
        let test_flags = 0xa;
        let (_, results) =
            FirehoseFormatters::firehose_formatter_flags(&test_data, &test_flags).unwrap();
        assert_eq!(results.uuid_relative, "7B0D3775F1903E21BA130447C41B8743");
    }
}
