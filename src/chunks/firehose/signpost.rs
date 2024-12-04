// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::flags::FirehoseFormatters;
use crate::chunks::firehose::message::MessageData;
use crate::dsc::SharedCacheStrings;
use crate::uuidtext::UUIDText;
use log::{debug, error};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u64, le_u8};
use nom::Needed;
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
        let mut firehose_signpost = FirehoseSignpost::default();

        let mut input = data;

        let activity_id_current: u16 = 0x1; // has_current_aid flag
        if (firehose_flags & activity_id_current) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose has has_current_aid flag");
            let (firehose_input, unknown_activity_id) = take(size_of::<u32>())(input)?;
            let (firehose_input, unknown_sentinel) = take(size_of::<u32>())(firehose_input)?;
            let (_, firehose_unknown_activity_id) = le_u32(unknown_activity_id)?;
            let (_, firehose_unknown_sentinel) = le_u32(unknown_sentinel)?;
            firehose_signpost.unknown_activity_id = firehose_unknown_activity_id;
            firehose_signpost.unknown_sentinel = firehose_unknown_sentinel;
            input = firehose_input;
        }

        let private_string_range: u16 = 0x100; // has_private_data flag
                                               // Entry has private string data. The private data is found after parsing all the public data first
        if (firehose_flags & private_string_range) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose has has_private_data flag");
            let (firehose_input, private_strings_offset) = take(size_of::<u16>())(input)?;
            let (firehose_input, private_strings_size) = take(size_of::<u16>())(firehose_input)?;

            let (_, firehose_private_strings_offset) = le_u16(private_strings_offset)?;
            let (_, firehose_private_strings_size) = le_u16(private_strings_size)?;

            // Offset points to private string values found after parsing the public data. Size is the data size
            firehose_signpost.private_strings_offset = firehose_private_strings_offset;
            firehose_signpost.private_strings_size = firehose_private_strings_size;
            input = firehose_input;
        }

        let (input, unknown_pc_id) = take(size_of::<u32>())(input)?;
        let (_, firehose_unknown_pc_id) = le_u32(unknown_pc_id)?;
        firehose_signpost.unknown_pc_id = firehose_unknown_pc_id;

        // Check for flags related to base string format location (shared string file (dsc) or UUID file)
        let (mut input, formatters) =
            FirehoseFormatters::firehose_formatter_flags(input, firehose_flags)?;
        firehose_signpost.firehose_formatters = formatters;

        let subsystem: u16 = 0x200; // has_subsystem flag. In Signpost log entries this is the subsystem flag
        if (firehose_flags & subsystem) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_subsystem flag");
            let (firehose_input, subsystem) = take(size_of::<u16>())(input)?;
            let (_, firehose_subsystem) = le_u16(subsystem)?;
            firehose_signpost.subsystem = firehose_subsystem;
            input = firehose_input;
        }
        let (mut input, signpost_id) = take(size_of::<u64>())(input)?;
        let (_, firehose_signpost_id) = le_u64(signpost_id)?;
        firehose_signpost.signpost_id = firehose_signpost_id;

        let has_rules: u16 = 0x400; // has_rules flag
        if (firehose_flags & has_rules) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_rules flag");
            let (firehose_input, ttl_data) = take(size_of::<u8>())(input)?;
            let (_, firehose_ttl) = le_u8(ttl_data)?;
            firehose_signpost.ttl_value = firehose_ttl;
            input = firehose_input;
        }

        let data_ref: u16 = 0x800; // has_oversize flag
        if (firehose_flags & data_ref) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_oversize flag");
            let (firehose_input, data_ref_value) = take(size_of::<u32>())(input)?;
            let (_, firehose_data_ref) = le_u32(data_ref_value)?;
            firehose_signpost.data_ref_value = firehose_data_ref;
            input = firehose_input;
        }

        let has_name = 0x8000;
        if (firehose_flags & has_name) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_name flag");
            let (firehose_input, signpost_name) = take(size_of::<u32>())(input)?;
            let (_, firehose_signpost_name) = le_u32(signpost_name)?;
            firehose_signpost.signpost_name = firehose_signpost_name;
            input = firehose_input;
            // If the signpost log has large_shared_cache flag
            // Then the signpost name has the same value after as the large_shared_cache
            if firehose_signpost.firehose_formatters.large_shared_cache != 0 {
                let (firehose_input, _) = take(size_of::<u16>())(input)?;
                input = firehose_input;
            }
        }

        Ok((input, firehose_signpost))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose signpost log entries (chunks)
    pub fn get_firehose_signpost<'a>(
        firehose: &FirehoseSignpost,
        strings_data: &'a [UUIDText],
        shared_strings: &'a [SharedCacheStrings],
        string_offset: u64,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
    ) -> nom::IResult<&'a [u8], MessageData> {
        if firehose.firehose_formatters.shared_cache
            || (firehose.firehose_formatters.large_shared_cache != 0
                && firehose.firehose_formatters.has_large_offset != 0)
        {
            if firehose.firehose_formatters.has_large_offset != 0 {
                let mut large_offset = firehose.firehose_formatters.has_large_offset;
                let extra_offset_value;
                // large_shared_cache should be double the value of has_large_offset
                // Ex: has_large_offset = 1, large_shared_cache = 2
                // If the value do not match then there is an issue with shared string offset
                // Can recover by using large_shared_cache
                // Apple records this as an error: "error: ~~> <Invalid shared cache code pointer offset>"
                //   But is still able to get string formatter
                if large_offset != firehose.firehose_formatters.large_shared_cache / 2
                    && !firehose.firehose_formatters.shared_cache
                {
                    large_offset = firehose.firehose_formatters.large_shared_cache / 2;
                    // Combine large offset value with current string offset to get the true offset
                    extra_offset_value = format!("{:X}{:08X}", large_offset, string_offset);
                } else if firehose.firehose_formatters.shared_cache {
                    // Large offset is 8 if shared_cache flag is set
                    large_offset = 8;
                    extra_offset_value = format!("{:X}{:07X}", large_offset, string_offset);
                } else {
                    extra_offset_value = format!("{:X}{:08X}", large_offset, string_offset);
                }

                // Combine large offset value with current string offset to get the true offset
                //let extra_offset_value = format!("{:X}{:07X}", large_offset, string_offset);
                let extra_offset_value_result = u64::from_str_radix(&extra_offset_value, 16);
                match extra_offset_value_result {
                    Ok(offset) => {
                        return MessageData::extract_shared_strings(
                            shared_strings,
                            strings_data,
                            offset,
                            first_proc_id,
                            second_proc_id,
                            catalogs,
                            string_offset,
                        );
                    }
                    Err(err) => {
                        // We should not get errors since we are combining two numbers to create the offset
                        error!(
                            "Failed to get shared string offset to format string for signpost firehose entry: {:?}",
                            err
                        );
                        return Err(nom::Err::Incomplete(Needed::Unknown));
                    }
                }
            }
            MessageData::extract_shared_strings(
                shared_strings,
                strings_data,
                string_offset,
                first_proc_id,
                second_proc_id,
                catalogs,
                string_offset,
            )
        } else {
            if firehose.firehose_formatters.absolute {
                let extra_offset_value = format!(
                    "{:X}{:08X}",
                    firehose.firehose_formatters.main_exe_alt_index, firehose.unknown_pc_id,
                );

                let offset_result = u64::from_str_radix(&extra_offset_value, 16);
                match offset_result {
                    Ok(offset) => {
                        return MessageData::extract_absolute_strings(
                            strings_data,
                            offset,
                            string_offset,
                            first_proc_id,
                            second_proc_id,
                            catalogs,
                            string_offset,
                        );
                    }
                    Err(err) => {
                        // We should not get errors since we are combining two numbers to create the offset
                        error!("Failed to get absolute offset to format string for signpost firehose entry: {:?}", err);
                        return Err(nom::Err::Incomplete(Needed::Unknown));
                    }
                }
            }
            if !firehose.firehose_formatters.uuid_relative.is_empty() {
                return MessageData::extract_alt_uuid_strings(
                    strings_data,
                    string_offset,
                    &firehose.firehose_formatters.uuid_relative,
                    first_proc_id,
                    second_proc_id,
                    catalogs,
                    string_offset,
                );
            }
            MessageData::extract_format_strings(
                strings_data,
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
    use crate::chunks::firehose::signpost::FirehoseSignpost;
    use crate::parser::{collect_shared_strings, collect_strings, parse_log};
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

        assert_eq!(results.firehose_formatters.main_exe, true);
        assert_eq!(results.firehose_formatters.shared_cache, false);
        assert_eq!(results.firehose_formatters.has_large_offset, 0);
        assert_eq!(results.firehose_formatters.large_shared_cache, 0);
        assert_eq!(results.firehose_formatters.absolute, false);
        assert_eq!(results.firehose_formatters.uuid_relative, String::new());
        assert_eq!(results.firehose_formatters.main_plugin, false);
        assert_eq!(results.firehose_formatters.pc_style, false);
        assert_eq!(results.firehose_formatters.main_exe_alt_index, 0);
    }

    #[test]
    fn test_get_firehose_signpost_big_sur() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let string_results = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Signpost/0000000000000001.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let activity_type = 0x6;

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.unknown_log_activity_type == activity_type {
                        let (_, message_data) = FirehoseSignpost::get_firehose_signpost(
                            &firehose.firehose_signpost,
                            &string_results,
                            &shared_strings_results,
                            firehose.format_string_location as u64,
                            &preamble.first_number_proc_id,
                            &preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        )
                        .unwrap();
                        assert_eq!(message_data.format_string, "");
                        assert_eq!(message_data.library, "/usr/libexec/kernelmanagerd");
                        assert_eq!(message_data.process, "/usr/libexec/kernelmanagerd");
                        assert_eq!(
                            message_data.process_uuid,
                            "CCCF30257483376883C824222233386D"
                        );
                        assert_eq!(
                            message_data.library_uuid,
                            "CCCF30257483376883C824222233386D"
                        );

                        return;
                    }
                }
            }
        }
    }
}
