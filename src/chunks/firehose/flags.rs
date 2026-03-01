// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::constants::*;
use log::{debug, error};
use nom::Needed;
use nom::number::complete::{be_u128, le_u16};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct FirehoseFormatters {
    pub main_exe: bool,
    pub shared_cache: bool,
    pub has_large_offset: u16,
    pub large_shared_cache: u16,
    pub absolute: bool,
    pub uuid_relative: Uuid,
    pub main_plugin: bool,       // Not seen yet
    pub pc_style: bool,          // Not seen yet
    pub main_exe_alt_index: u16, // If log entry uses an alternative uuid file index (ex: absolute). This value gets prepended to the unknown_pc_id/offset
}

impl<'a> FirehoseFormatters {
    /// Identify formatter flags associated with the log entry. Formatter flags determine the file where the base format string is located
    pub fn firehose_formatter_flags(
        data: &'a [u8],
        firehose_flags: &u16,
    ) -> nom::IResult<&'a [u8], FirehoseFormatters> {
        let mut input = data;

        let mut main_exe = false;
        let mut shared_cache = false;
        let mut has_large_offset: u16 = 0;
        let mut large_shared_cache: u16 = 0;
        let mut absolute = false;
        let mut uuid_relative = Uuid::nil();
        let mut main_exe_alt_index: u16 = 0;

        match firehose_flags & FORMATTER_FLAG_MASK {
            FORMATTER_LARGE_OFFSET => {
                debug!("[macos-unifiedlogs] Firehose flag: has_large_offset");
                let (firehose_input, val) = le_u16(input)?;
                has_large_offset = val;
                input = firehose_input;
                if (firehose_flags & FORMATTER_LARGE_SHARED_CACHE) != 0 {
                    debug!(
                        "[macos-unifiedlogs] Firehose flag: large_shared_cache and has_large_offset"
                    );
                    let (firehose_input, val) = le_u16(input)?;
                    large_shared_cache = val;
                    input = firehose_input;
                }
            }
            FORMATTER_LARGE_SHARED_CACHE => {
                debug!("[macos-unifiedlogs] Firehose flag: large_shared_cache");
                if (firehose_flags & FORMATTER_LARGE_OFFSET) != 0 {
                    let (firehose_input, val) = le_u16(input)?;
                    has_large_offset = val;
                    input = firehose_input;
                }

                let (firehose_input, val) = le_u16(input)?;
                large_shared_cache = val;
                input = firehose_input;
            }
            FORMATTER_ABSOLUTE => {
                debug!("[macos-unifiedlogs] Firehose flag: absolute");
                absolute = true;
                if (firehose_flags & FORMATTER_MAIN_EXE) == 0 {
                    debug!("[macos-unifiedlogs] Firehose flag: alt index absolute flag");
                    let (firehose_input, val) = le_u16(input)?;
                    main_exe_alt_index = val;
                    input = firehose_input;
                }
            }
            FORMATTER_MAIN_EXE => {
                debug!("[macos-unifiedlogs] Firehose flag: main_exe");
                main_exe = true;
            }
            FORMATTER_SHARED_CACHE => {
                debug!("[macos-unifiedlogs] Firehose flag: shared_cache");
                shared_cache = true;
                if (firehose_flags & FORMATTER_LARGE_OFFSET) != 0 {
                    let (firehose_input, val) = le_u16(input)?;
                    has_large_offset = val;
                    input = firehose_input;
                }
            }
            FORMATTER_UUID_RELATIVE => {
                debug!("[macos-unifiedlogs] Firehose flag: uuid_relative");
                let (firehose_input, val) = be_u128(input)?;
                uuid_relative = Uuid::from_u128(val);
                input = firehose_input;
            }
            _ => {
                error!("[macos-unifiedlogs] Unknown Firehose formatter flag: {firehose_flags:?}");
                debug!("[macos-unifiedlogs] Firehose data: {data:X?}");
                return Err(nom::Err::Incomplete(Needed::Unknown));
            }
        }

        Ok((
            input,
            FirehoseFormatters {
                main_exe,
                shared_cache,
                has_large_offset,
                large_shared_cache,
                absolute,
                uuid_relative,
                main_plugin: false,
                pc_style: false,
                main_exe_alt_index,
            },
        ))
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
        assert!(results.main_exe);
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
        assert!(results.shared_cache);
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
        assert!(results.absolute);
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
        assert_eq!(
            results.uuid_relative,
            uuid::Uuid::parse_str("7B0D3775F1903E21BA130447C41B8743").unwrap()
        );
    }
}
