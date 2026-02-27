// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::flags::FirehoseFormatters;
use crate::chunks::firehose::message::MessageData;
use crate::traits::FileProvider;
use log::debug;
use nom::bytes::complete::take;
use nom::number::complete::{le_u8, le_u16, le_u32, le_u64};
use std::mem::size_of;

#[derive(Debug, Clone, Default)]
pub struct FirehoseSignpost {
    pub unknown_pc_id: u32, // Appears to be used to calculate string offset for firehose events with Absolute flag
    pub unknown_activity_id: u32,
    pub unknown_sentinel: u32,
    pub subsystem: u16,
    pub signpost_id: u64,
    pub signpost_name: u32,
    pub private_strings_offset: u16, // if flag 0x0100
    pub private_strings_size: u16,   // if flag 0x0100
    pub ttl_value: u8,
    pub data_ref_value: u32, // if flag 0x0800, has_oversize
    pub firehose_formatters: FirehoseFormatters,
}

impl FirehoseSignpost {
    /// Parse Signpost Firehose log entry.
    // Ex: tp 2368 + 92: process signpost event (shared_cache, has_name, has_subsystem)
    pub fn parse_signpost<'a>(
        data: &'a [u8],
        firehose_flags: &u16,
    ) -> nom::IResult<&'a [u8], FirehoseSignpost> {
        let mut input = data;

        let mut unknown_activity_id: u32 = 0;
        let mut unknown_sentinel: u32 = 0;
        let activity_id_current: u16 = 0x1; // has_current_aid flag
        if (firehose_flags & activity_id_current) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose has has_current_aid flag");
            let (firehose_input, aid) = take(size_of::<u32>())(input)?;
            let (firehose_input, sent) = take(size_of::<u32>())(firehose_input)?;
            let (_, val) = le_u32(aid)?;
            let (_, sval) = le_u32(sent)?;
            unknown_activity_id = val;
            unknown_sentinel = sval;
            input = firehose_input;
        }

        let mut private_strings_offset: u16 = 0;
        let mut private_strings_size: u16 = 0;
        let private_string_range: u16 = 0x100; // has_private_data flag
        // Entry has private string data. The private data is found after parsing all the public data first
        if (firehose_flags & private_string_range) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose has has_private_data flag");
            let (firehose_input, pso) = take(size_of::<u16>())(input)?;
            let (firehose_input, pss) = take(size_of::<u16>())(firehose_input)?;
            let (_, val) = le_u16(pso)?;
            let (_, sval) = le_u16(pss)?;
            // Offset points to private string values found after parsing the public data. Size is the data size
            private_strings_offset = val;
            private_strings_size = sval;
            input = firehose_input;
        }

        let (input, pc_id_data) = take(size_of::<u32>())(input)?;
        let (_, unknown_pc_id) = le_u32(pc_id_data)?;

        // Check for flags related to base string format location (shared string file (dsc) or UUID file)
        let (mut input, firehose_formatters) =
            FirehoseFormatters::firehose_formatter_flags(input, firehose_flags)?;

        let mut subsystem: u16 = 0;
        let subsystem_flag: u16 = 0x200; // has_subsystem flag. In Signpost log entries this is the subsystem flag
        if (firehose_flags & subsystem_flag) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_subsystem flag");
            let (firehose_input, sub) = take(size_of::<u16>())(input)?;
            let (_, val) = le_u16(sub)?;
            subsystem = val;
            input = firehose_input;
        }

        let (mut input, signpost_id_data) = take(size_of::<u64>())(input)?;
        let (_, signpost_id) = le_u64(signpost_id_data)?;

        let mut ttl_value: u8 = 0;
        let has_rules: u16 = 0x400; // has_rules flag
        if (firehose_flags & has_rules) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_rules flag");
            let (firehose_input, ttl_data) = take(size_of::<u8>())(input)?;
            let (_, val) = le_u8(ttl_data)?;
            ttl_value = val;
            input = firehose_input;
        }

        let mut data_ref_value: u32 = 0;
        let data_ref: u16 = 0x800; // has_oversize flag
        if (firehose_flags & data_ref) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_oversize flag");
            let (firehose_input, dref) = take(size_of::<u32>())(input)?;
            let (_, val) = le_u32(dref)?;
            data_ref_value = val;
            input = firehose_input;
        }

        let mut signpost_name: u32 = 0;
        let has_name = 0x8000;
        if (firehose_flags & has_name) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_name flag");
            let (firehose_input, name_data) = take(size_of::<u32>())(input)?;
            let (_, val) = le_u32(name_data)?;
            signpost_name = val;
            input = firehose_input;
            // If the signpost log has large_shared_cache flag
            // Then the signpost name has the same value after as the large_shared_cache
            if firehose_formatters.large_shared_cache != 0 {
                let (firehose_input, _) = take(size_of::<u16>())(input)?;
                input = firehose_input;
            }
        }

        Ok((
            input,
            FirehoseSignpost {
                unknown_pc_id,
                unknown_activity_id,
                unknown_sentinel,
                subsystem,
                signpost_id,
                signpost_name,
                private_strings_offset,
                private_strings_size,
                ttl_value,
                data_ref_value,
                firehose_formatters,
            },
        ))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose signpost log entries (chunks)
    pub fn get_firehose_signpost<'a>(
        firehose: &FirehoseSignpost,
        provider: &'a mut dyn FileProvider,
        string_offset: u64,
        first_proc_id: u64,
        second_proc_id: u32,
        catalogs: &CatalogChunk,
    ) -> nom::IResult<&'a [u8], MessageData> {
        if firehose.firehose_formatters.shared_cache
            || (firehose.firehose_formatters.large_shared_cache != 0
                && firehose.firehose_formatters.has_large_offset != 0)
        {
            if firehose.firehose_formatters.has_large_offset != 0 {
                let mut large_offset = firehose.firehose_formatters.has_large_offset;
                // large_shared_cache should be double the value of has_large_offset
                // Ex: has_large_offset = 1, large_shared_cache = 2
                // If the value do not match then there is an issue with shared string offset
                // Can recover by using large_shared_cache
                // Apple records this as an error: "error: ~~> <Invalid shared cache code pointer offset>"
                //   But is still able to get string formatter
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
                    offset = (u64::from(large_offset) << 28) | string_offset;
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

    use crate::chunks::firehose::signpost::FirehoseSignpost;
    use crate::filesystem::LogarchiveProvider;
    use crate::parser::parse_log;
    use std::path::PathBuf;

    #[test]
    fn test_parse_signpost() {
        let test_data = [
            225, 244, 2, 0, 1, 0, 238, 238, 178, 178, 181, 176, 238, 238, 176, 63, 27, 0, 0, 0,
        ];
        let test_flags = 33282;
        let (_, results) = FirehoseSignpost::parse_signpost(&test_data, &test_flags).unwrap();
        assert_eq!(results.unknown_pc_id, 193761);
        assert_eq!(results.unknown_activity_id, 0);
        assert_eq!(results.unknown_sentinel, 0);
        assert_eq!(results.subsystem, 1);
        assert_eq!(results.signpost_id, 17216892719917625070);
        assert_eq!(results.signpost_name, 1785776);
        assert_eq!(results.ttl_value, 0);
        assert_eq!(results.data_ref_value, 0);

        assert!(results.firehose_formatters.main_exe);
        assert!(!results.firehose_formatters.shared_cache);
        assert_eq!(results.firehose_formatters.has_large_offset, 0);
        assert_eq!(results.firehose_formatters.large_shared_cache, 0);
        assert!(!results.firehose_formatters.absolute);
        assert_eq!(results.firehose_formatters.uuid_relative, Uuid::nil());
        assert!(!results.firehose_formatters.main_plugin);
        assert!(!results.firehose_formatters.pc_style);
        assert_eq!(results.firehose_formatters.main_exe_alt_index, 0);
    }

    #[test]
    fn test_get_firehose_signpost_big_sur() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let mut provider = LogarchiveProvider::new(test_path.as_path());

        test_path.push("Signpost/0000000000000001.tracev3");

        let handle = std::fs::File::open(&test_path).unwrap();
        let log_data = parse_log(handle).unwrap();

        let activity_type = 0x6;

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.unknown_log_activity_type == activity_type {
                        let (_, message_data) = FirehoseSignpost::get_firehose_signpost(
                            &firehose.firehose_signpost,
                            &mut provider,
                            u64::from(firehose.format_string_location),
                            preamble.first_number_proc_id,
                            preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        )
                        .unwrap();
                        assert_eq!(message_data.format_string.as_str(), "");
                        assert_eq!(message_data.library.as_str(), "/usr/libexec/kernelmanagerd");
                        assert_eq!(message_data.process.as_str(), "/usr/libexec/kernelmanagerd");
                        assert_eq!(
                            message_data.process_uuid,
                            Uuid::parse_str("CCCF30257483376883C824222233386D").unwrap()
                        );
                        assert_eq!(
                            message_data.library_uuid,
                            Uuid::parse_str("CCCF30257483376883C824222233386D").unwrap()
                        );

                        return;
                    }
                }
            }
        }
    }
}
