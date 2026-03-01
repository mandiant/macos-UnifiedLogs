// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::flags::FirehoseFormatters;
use crate::chunks::firehose::message::MessageData;
use crate::constants::*;
use crate::traits::FileProvider;
use log::debug;
use nom::number::complete::{le_u8, le_u16, le_u32};

#[derive(Debug, Clone, Default)]
pub struct FirehoseNonActivity {
    pub unknown_activity_id: u32,        // if flag 0x0001
    pub unknown_sentinal: u32,           // always 0x80000000? if flag 0x0001
    pub private_strings_offset: u16,     // if flag 0x0100
    pub private_strings_size: u16,       // if flag 0x0100
    pub unknown_message_string_ref: u32, // if flag 0x0008
    pub subsystem_value: u16,            // if flag 0x200, has_subsystem
    pub ttl_value: u8,                   // if flag 0x0400, has_rules
    pub data_ref_value: u32,             // if flag 0x0800, has_oversize
    pub unknown_pc_id: u32, // Appears to be used to calculate string offset for firehose events with Absolute flag
    pub firehose_formatters: FirehoseFormatters,
}

impl FirehoseNonActivity {
    /// Parse Non-Activity Type Firehose log entry.
    // Ex: tp 728 + 202: log debug (has_current_aid, main_exe, has_subsystem, has_rules)
    pub fn parse_non_activity<'a>(
        data: &'a [u8],
        firehose_flags: &u16,
    ) -> nom::IResult<&'a [u8], FirehoseNonActivity> {
        let mut input = data;

        let mut unknown_activity_id: u32 = 0;
        let mut unknown_sentinal: u32 = 0;
        if (firehose_flags & FLAG_HAS_CURRENT_AID) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_current_aid flag");
            let (firehose_input, val) = le_u32(input)?;
            let (firehose_input, sval) = le_u32(firehose_input)?;
            unknown_activity_id = val;
            unknown_sentinal = sval;
            input = firehose_input;
        }

        let mut private_strings_offset: u16 = 0;
        let mut private_strings_size: u16 = 0;
        // Entry has private string data. The private data is found after parsing all the public data first
        if (firehose_flags & FLAG_HAS_PRIVATE_DATA) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_private_data flag");
            let (firehose_input, val) = le_u16(input)?;
            let (firehose_input, sval) = le_u16(firehose_input)?;
            // Offset points to private string values found after parsing the public data. Size is the data size
            private_strings_offset = val;
            private_strings_size = sval;
            input = firehose_input;
        }

        let (input, unknown_pc_id) = le_u32(input)?;

        // Check for flags related to base string format location (shared string file (dsc) or UUID file)
        let (mut input, firehose_formatters) =
            FirehoseFormatters::firehose_formatter_flags(input, firehose_flags)?;

        let mut subsystem_value: u16 = 0;
        if (firehose_flags & FLAG_HAS_SUBSYSTEM) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_subsystem flag");
            let (firehose_input, val) = le_u16(input)?;
            subsystem_value = val;
            input = firehose_input;
        }

        let mut ttl_value: u8 = 0;
        if (firehose_flags & FLAG_HAS_RULES) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_rules flag");
            let (firehose_input, val) = le_u8(input)?;
            ttl_value = val;
            input = firehose_input;
        }

        let mut data_ref_value: u32 = 0;
        if (firehose_flags & FLAG_HAS_OVERSIZE) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_oversize flag");
            let (firehose_input, val) = le_u32(input)?;
            data_ref_value = val;
            input = firehose_input;
        }

        Ok((
            input,
            FirehoseNonActivity {
                unknown_activity_id,
                unknown_sentinal,
                private_strings_offset,
                private_strings_size,
                unknown_message_string_ref: 0,
                subsystem_value,
                ttl_value,
                data_ref_value,
                unknown_pc_id,
                firehose_formatters,
            },
        ))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose non-activity log entries (chunks)
    pub fn get_firehose_nonactivity_strings<'a>(
        firehose: &FirehoseNonActivity,
        provider: &'a mut dyn FileProvider,
        string_offset: u64,
        first_proc_id: u64,
        second_proc_id: u32,
        catalogs: &CatalogChunk,
    ) -> nom::IResult<&'a [u8], MessageData> {
        if firehose.firehose_formatters.shared_cache
            || (firehose.firehose_formatters.large_shared_cache != 0)
        {
            if firehose.firehose_formatters.has_large_offset != 0 {
                let mut large_offset = firehose.firehose_formatters.has_large_offset;
                // large_shared_cache should be double the value of has_large_offset
                // Ex: has_large_offset = 1, large_shared_cache = 2
                // If the value do not match then there is an issue with shared string offset
                // Can recover by using large_shared_cache
                // Apple/log records this as an error: "error: ~~> <Invalid shared cache code pointer offset>"
                // But is still able to get string formatter
                let offset;
                if large_offset != firehose.firehose_formatters.large_shared_cache / 2
                    && !firehose.firehose_formatters.shared_cache
                {
                    large_offset = firehose.firehose_formatters.large_shared_cache / 2;
                    // Combine large offset value with current string offset to get the true offset
                    offset = (u64::from(large_offset) << 32) | string_offset;
                } else if firehose.firehose_formatters.shared_cache {
                    // Large offset is 8 if shared_cache flag is set
                    large_offset = 8;
                    offset = LARGE_OFFSET_BASE * u64::from(large_offset) + string_offset;
                } else {
                    offset = (u64::from(large_offset) << 32) | string_offset;
                }

                return MessageData::extract_shared_strings(
                    provider,
                    offset,
                    first_proc_id,
                    second_proc_id,
                    catalogs,
                    string_offset,
                );
            }
            MessageData::extract_shared_strings(
                provider,
                string_offset,
                first_proc_id,
                second_proc_id,
                catalogs,
                string_offset,
            )
        } else {
            if firehose.firehose_formatters.absolute {
                let offset = (u64::from(firehose.firehose_formatters.main_exe_alt_index) << 32)
                    | u64::from(firehose.unknown_pc_id);

                return MessageData::extract_absolute_strings(
                    provider,
                    offset,
                    string_offset,
                    first_proc_id,
                    second_proc_id,
                    catalogs,
                    string_offset,
                );
            }
            if !firehose.firehose_formatters.uuid_relative.is_nil() {
                return MessageData::extract_alt_uuid_strings(
                    provider,
                    string_offset,
                    firehose.firehose_formatters.uuid_relative,
                    first_proc_id,
                    second_proc_id,
                    catalogs,
                    string_offset,
                );
            }
            MessageData::extract_format_strings(
                provider,
                string_offset,
                first_proc_id,
                second_proc_id,
                catalogs,
                string_offset,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::FirehoseNonActivity;
    use crate::{filesystem::LogarchiveProvider, parser::parse_log};
    use std::path::PathBuf;

    #[test]
    fn test_parse_non_activity() {
        let test_data = [
            122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32,
            4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105,
            115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0,
        ];
        let test_flags = 556;
        let (_, nonactivity_results) =
            FirehoseNonActivity::parse_non_activity(&test_data, &test_flags).unwrap();
        assert_eq!(nonactivity_results.unknown_activity_id, 0);
        assert_eq!(nonactivity_results.unknown_sentinal, 0);
        assert_eq!(nonactivity_results.private_strings_offset, 0);
        assert_eq!(nonactivity_results.private_strings_size, 0);
        assert_eq!(nonactivity_results.unknown_message_string_ref, 0);
        assert_eq!(
            nonactivity_results.firehose_formatters.main_exe_alt_index,
            0
        );
        assert_eq!(
            nonactivity_results.firehose_formatters.uuid_relative,
            Uuid::nil()
        );
        assert!(!nonactivity_results.firehose_formatters.main_exe);
        assert!(!nonactivity_results.firehose_formatters.absolute);
        assert_eq!(nonactivity_results.subsystem_value, 41);
        assert_eq!(nonactivity_results.ttl_value, 0);
        assert_eq!(nonactivity_results.data_ref_value, 0);
        assert_eq!(
            nonactivity_results.firehose_formatters.large_shared_cache,
            4
        );
        assert_eq!(nonactivity_results.firehose_formatters.has_large_offset, 2);
        assert_eq!(nonactivity_results.unknown_pc_id, 218936186);
    }

    #[test]
    fn test_get_firehose_non_activity_big_sur() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let mut provider = LogarchiveProvider::new(test_path.as_path());
        test_path.push("Persist/0000000000000004.tracev3");
        let handle = std::fs::File::open(&test_path).unwrap();
        let log_data = parse_log(handle).unwrap();

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.unknown_log_activity_type == crate::constants::NON_ACTIVITY_TYPE {
                        let (_, message_data) =
                            FirehoseNonActivity::get_firehose_nonactivity_strings(
                                &firehose.firehose_non_activity,
                                &mut provider,
                                u64::from(firehose.format_string_location),
                                preamble.first_number_proc_id,
                                preamble.second_number_proc_id,
                                &catalog_data.catalog,
                            )
                            .unwrap();
                        assert_eq!(
                            message_data.format_string.as_str(),
                            "opendirectoryd (build %{public}s) launched..."
                        );
                        assert_eq!(message_data.library.as_str(), "/usr/libexec/opendirectoryd");
                        assert_eq!(message_data.process.as_str(), "/usr/libexec/opendirectoryd");
                        assert_eq!(
                            message_data.process_uuid,
                            Uuid::parse_str("B736DF1625F538248E9527A8CEC4991E").unwrap()
                        );
                        assert_eq!(
                            message_data.library_uuid,
                            Uuid::parse_str("B736DF1625F538248E9527A8CEC4991E").unwrap()
                        );
                        return;
                    }
                }
            }
        }
    }
}
