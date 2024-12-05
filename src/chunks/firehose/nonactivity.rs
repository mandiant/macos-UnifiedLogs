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
use nom::Needed;
use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, le_u8},
};
use std::mem::size_of;

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
        let mut non_activity = FirehoseNonActivity::default();

        let mut input = data;
        let activity_id_current: u16 = 0x1; // has_current_aid flag

        if (firehose_flags & activity_id_current) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_current_aid flag");
            let (firehose_input, unknown_activity_id) = take(size_of::<u32>())(input)?;
            let (firehose_input, unknown_sentinel) = take(size_of::<u32>())(firehose_input)?;
            let (_, firehose_unknown_activity_id) = le_u32(unknown_activity_id)?;
            let (_, firehose_unknown_sentinel) = le_u32(unknown_sentinel)?;
            non_activity.unknown_activity_id = firehose_unknown_activity_id;
            non_activity.unknown_sentinal = firehose_unknown_sentinel;
            input = firehose_input;
        }

        let private_string_range: u16 = 0x100; // has_private_data flag
                                               // Entry has private string data. The private data is found after parsing all the public data first
        if (firehose_flags & private_string_range) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_private_data flag");
            let (firehose_input, private_strings_offset) = take(size_of::<u16>())(input)?;
            let (firehose_input, private_strings_size) = take(size_of::<u16>())(firehose_input)?;

            let (_, firehose_private_strings_offset) = le_u16(private_strings_offset)?;
            let (_, firehose_private_strings_size) = le_u16(private_strings_size)?;

            // Offset points to private string values found after parsing the public data. Size is the data size
            non_activity.private_strings_offset = firehose_private_strings_offset;
            non_activity.private_strings_size = firehose_private_strings_size;
            input = firehose_input;
        }

        let (input, unknown_pc_id) = take(size_of::<u32>())(input)?;
        let (_, firehose_unknown_pc_id) = le_u32(unknown_pc_id)?;
        non_activity.unknown_pc_id = firehose_unknown_pc_id;

        // Check for flags related to base string format location (shared string file (dsc) or UUID file)
        let (mut input, formatters) =
            FirehoseFormatters::firehose_formatter_flags(input, firehose_flags)?;
        non_activity.firehose_formatters = formatters;

        let subsystem: u16 = 0x200; // has_subsystem flag. In Non-Activity log entries this is the subsystem flag
        if (firehose_flags & subsystem) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_subsystem flag");
            let (firehose_input, subsystem) = take(size_of::<u16>())(input)?;
            let (_, firehose_subsystem) = le_u16(subsystem)?;
            non_activity.subsystem_value = firehose_subsystem;
            input = firehose_input;
        }

        let ttl: u16 = 0x400; // has_rules flag
        if (firehose_flags & ttl) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_rules flag");
            let (firehose_input, ttl_data) = take(size_of::<u8>())(input)?;
            let (_, firehose_ttl) = le_u8(ttl_data)?;
            non_activity.ttl_value = firehose_ttl;
            input = firehose_input;
        }

        let data_ref: u16 = 0x800; // has_oversize flag
        if (firehose_flags & data_ref) != 0 {
            debug!("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_oversize flag");
            let (firehose_input, data_ref_value) = take(size_of::<u32>())(input)?;
            let (_, firehose_data_ref) = le_u32(data_ref_value)?;
            non_activity.data_ref_value = firehose_data_ref;
            input = firehose_input;
        }

        Ok((input, non_activity))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose non-activity log entries (chunks)
    pub fn get_firehose_nonactivity_strings<'a>(
        firehose: &FirehoseNonActivity,
        strings_data: &'a [UUIDText],
        shared_strings: &'a [SharedCacheStrings],
        string_offset: u64,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
    ) -> nom::IResult<&'a [u8], MessageData> {
        if firehose.firehose_formatters.shared_cache
            || (firehose.firehose_formatters.large_shared_cache != 0)
        {
            if firehose.firehose_formatters.has_large_offset != 0 {
                let mut large_offset = firehose.firehose_formatters.has_large_offset;
                let extra_offset_value;
                // large_shared_cache should be double the value of has_large_offset
                // Ex: has_large_offset = 1, large_shared_cache = 2
                // If the value do not match then there is an issue with shared string offset
                // Can recover by using large_shared_cache
                // Apple/log records this as an error: "error: ~~> <Invalid shared cache code pointer offset>"
                // But is still able to get string formatter
                if large_offset != firehose.firehose_formatters.large_shared_cache / 2
                    && !firehose.firehose_formatters.shared_cache
                {
                    large_offset = firehose.firehose_formatters.large_shared_cache / 2;
                    // Combine large offset value with current string offset to get the true offset
                    extra_offset_value = format!("{:X}{:08X}", large_offset, string_offset);
                } else if firehose.firehose_formatters.shared_cache {
                    // Large offset is 8 if shared_cache flag is set
                    large_offset = 8;
                    let add_offset = 0x10000000 * u64::from(large_offset);
                    extra_offset_value = format!("{:X}", add_offset + string_offset);
                } else {
                    extra_offset_value = format!("{:X}{:08X}", large_offset, string_offset);
                }

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
                            "Failed to get shared string offset to format string for non-activity firehose entry: {:?}",
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
                    firehose.firehose_formatters.main_exe_alt_index, firehose.unknown_pc_id
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
                        error!("Failed to get absolute offset to format string for non-activity firehose entry: {:?}", err);
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
    use super::FirehoseNonActivity;
    use crate::parser::{collect_shared_strings, collect_strings, parse_log};
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
            String::from("")
        );
        assert_eq!(nonactivity_results.firehose_formatters.main_exe, false);
        assert_eq!(nonactivity_results.firehose_formatters.absolute, false);
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
        let string_results = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000004.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let activity_type = 0x4;

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.unknown_log_activity_type == activity_type {
                        let (_, message_data) =
                            FirehoseNonActivity::get_firehose_nonactivity_strings(
                                &firehose.firehose_non_activity,
                                &string_results,
                                &shared_strings_results,
                                firehose.format_string_location as u64,
                                &preamble.first_number_proc_id,
                                &preamble.second_number_proc_id,
                                &catalog_data.catalog,
                            )
                            .unwrap();
                        assert_eq!(
                            message_data.format_string,
                            "opendirectoryd (build %{public}s) launched..."
                        );
                        assert_eq!(message_data.library, "/usr/libexec/opendirectoryd");
                        assert_eq!(message_data.process, "/usr/libexec/opendirectoryd");
                        assert_eq!(
                            message_data.process_uuid,
                            "B736DF1625F538248E9527A8CEC4991E"
                        );
                        assert_eq!(
                            message_data.library_uuid,
                            "B736DF1625F538248E9527A8CEC4991E"
                        );
                        return;
                    }
                }
            }
        }
    }
}
