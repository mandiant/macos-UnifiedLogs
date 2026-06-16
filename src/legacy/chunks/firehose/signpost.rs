// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::firehose_log::MessageFlags;
use crate::chunks::firehose::flags::FirehoseFormatters;
use crate::chunks::firehose::message::{MessageData, MessageParams};
use crate::traits::FileProvider;
use log::debug;
use nom::number::complete::{le_u8, le_u16, le_u32, le_u64};

#[derive(Debug, Clone, Default)]
pub struct FirehoseSignpost {
    pub pc_id: u32, // Appears to be used to calculate string offset for firehose events with Absolute flag
    pub activity_id: u32,
    pub sentinel: u32,
    pub subsystem: u16,
    pub signpost_id: u64,
    pub signpost_name: u32,
    pub private_strings_offset: u16, // if flag 0x0100
    pub private_strings_size: u16,   // if flag 0x0100
    pub ttl_value: u8,
    pub data_ref_value: u32, // if flag 0x0800, has_oversize
    pub firehose_formatters: FirehoseFormatters,
    pub flags: Vec<MessageFlags>,
}

impl FirehoseSignpost {
    /// Parse Signpost Firehose log entry.
    // Ex: tp 2368 + 92: process signpost event (shared_cache, has_name, has_subsystem)
    pub fn parse_signpost(
        data: &[u8],
        firehose_flags: u16,
    ) -> nom::IResult<&[u8], FirehoseSignpost> {
        let mut firehose_signpost = FirehoseSignpost::default();

        let mut input = data;

        let activity_id_current = 0x1; // has_current_aid flag
        if (firehose_flags & activity_id_current) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose has has_current_aid flag");
            let (firehose_input, firehose_activity_id) = le_u32(input)?;
            let (firehose_input, firehose_sentinel) = le_u32(firehose_input)?;
            firehose_signpost.activity_id = firehose_activity_id;
            firehose_signpost.sentinel = firehose_sentinel;
            input = firehose_input;
            firehose_signpost.flags.push(MessageFlags::HasCurrentAid);
        }

        let private_string_range = 0x100; // has_private_data flag
        // Entry has private string data. The private data is found after parsing all the public data first
        if (firehose_flags & private_string_range) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose has has_private_data flag");
            let (firehose_input, firehose_private_strings_offset) = le_u16(input)?;
            let (firehose_input, firehose_private_strings_size) = le_u16(firehose_input)?;

            // Offset points to private string values found after parsing the public data. Size is the data size
            firehose_signpost.private_strings_offset = firehose_private_strings_offset;
            firehose_signpost.private_strings_size = firehose_private_strings_size;
            input = firehose_input;
            firehose_signpost.flags.push(MessageFlags::HasPrivateData);
        }

        let (input, firehose_pc_id) = le_u32(input)?;
        firehose_signpost.pc_id = firehose_pc_id;

        // Check for flags related to base string format location (shared string file (dsc) or UUID file)
        let (mut input, formatters) = FirehoseFormatters::firehose_formatter_flags(
            input,
            firehose_flags,
            &mut firehose_signpost.flags,
        )?;
        firehose_signpost.firehose_formatters = formatters;

        let subsystem = 0x200; // has_subsystem flag. In Signpost log entries this is the subsystem flag
        if (firehose_flags & subsystem) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_subsystem flag");
            let (firehose_input, firehose_subsystem) = le_u16(input)?;
            firehose_signpost.subsystem = firehose_subsystem;
            input = firehose_input;
            firehose_signpost.flags.push(MessageFlags::HasSubsystem);
        }
        let (mut input, firehose_signpost_id) = le_u64(input)?;
        firehose_signpost.signpost_id = firehose_signpost_id;

        let has_rules = 0x400; // has_rules flag
        if (firehose_flags & has_rules) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_rules flag");
            let (firehose_input, firehose_ttl) = le_u8(input)?;
            firehose_signpost.ttl_value = firehose_ttl;
            input = firehose_input;
            firehose_signpost.flags.push(MessageFlags::HasRules);
        }

        let data_ref = 0x800; // has_oversize flag
        if (firehose_flags & data_ref) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_oversize flag");
            let (firehose_input, firehose_data_ref) = le_u32(input)?;
            firehose_signpost.data_ref_value = firehose_data_ref;
            input = firehose_input;
            firehose_signpost.flags.push(MessageFlags::HasOversize);
        }

        let has_name = 0x8000;
        if (firehose_flags & has_name) != 0 {
            debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_name flag");
            let (firehose_input, firehose_signpost_name) = le_u32(input)?;
            firehose_signpost.signpost_name = firehose_signpost_name;
            input = firehose_input;
            // If the signpost log has large_shared_cache or shared_cache flag
            // Then need to add 0x80000000 to signpost name
            if (firehose_signpost.firehose_formatters.shared_cache
                && firehose_signpost.firehose_formatters.has_large_offset != 0)
                || firehose_signpost.firehose_formatters.large_shared_cache != 0
            {
                let (firehose_input, _) = le_u16(input)?;
                input = firehose_input;
                let cache = 0x80000000;
                firehose_signpost.signpost_name += cache;
            }
        }

        Ok((input, firehose_signpost))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose signpost log entries (chunks)
    pub(crate) fn get_firehose_signpost<'a>(
        firehose: &FirehoseSignpost,
        provider: &'a mut dyn FileProvider,
        string_offset: u64,
        first_proc_id: u64,
        second_proc_id: u32,
        catalogs: &CatalogChunk,
    ) -> nom::IResult<&'a [u8], MessageData> {
        let params = MessageParams {
            pc_id: firehose.pc_id,
            string_offset,
            first_proc_id,
            second_proc_id,
            supports_large_offset: true,
        };

        MessageData::get_message(&firehose.firehose_formatters, provider, &params, catalogs)
    }
}

#[cfg(test)]
mod tests {
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
        let (_, results) = FirehoseSignpost::parse_signpost(&test_data, test_flags).unwrap();
        assert_eq!(results.pc_id, 193761);
        assert_eq!(results.activity_id, 0);
        assert_eq!(results.sentinel, 0);
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
        assert_eq!(results.firehose_formatters.uuid_relative, String::new());
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
        let log_data = parse_log(handle, test_path.to_str().unwrap()).unwrap();

        let activity_type = 0x6;

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.log_activity_type == activity_type {
                        let (_, message_data) = FirehoseSignpost::get_firehose_signpost(
                            &firehose.firehose_signpost,
                            &mut provider,
                            u64::from(firehose.format_string_location),
                            preamble.first_number_proc_id,
                            preamble.second_number_proc_id,
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
