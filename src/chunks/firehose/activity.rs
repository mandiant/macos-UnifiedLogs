// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::flags::FirehoseFormatters;
use crate::chunks::firehose::message::{MessageData, MessageParams};
use crate::traits::FileProvider;
use log::debug;
use nom::number::complete::{le_u32, le_u64};

#[derive(Debug, Clone, Default)]
pub struct FirehoseActivity {
    pub activity_id: u32,
    pub sentinal: u32,      // always 0x80000000?
    pub pid: u64,           // if flag 0x0010
    pub activity_id_2: u32, // if flag 0x0001
    pub sentinal_2: u32,    // always 0x80000000? only if flag 0x0001
    pub activity_id_3: u32, // if flag 0x0200
    pub sentinal_3: u32,    // always 0x80000000? only if flag 0x0200
    pub message_string_ref: u32,
    pub pc_id: u32, // Appears to be used to calculate string offset for firehose events with Absolute flag
    pub firehose_formatters: FirehoseFormatters,
}

impl FirehoseActivity {
    /// Parse Activity Type Firehose log entry.
    //  Ex: tp 3536 + 60: activity create (has_current_aid, has_unique_pid, shared_cache, has_other_aid)
    pub fn parse_activity(
        data: &[u8],
        firehose_flags: u16,
        firehose_log_type: u8,
    ) -> nom::IResult<&[u8], FirehoseActivity> {
        let mut activity = FirehoseActivity::default();
        let mut input = data;

        // Useraction activity type does not have first Activity ID or sentinel
        let useraction = 0x3;
        // Get first activity_id (if not useraction type)
        if firehose_log_type != useraction {
            let (firehose_input, firehose_activity_id) = le_u32(data)?;
            let (firehose_input, firehose_sentinel) = le_u32(firehose_input)?;

            activity.activity_id = firehose_activity_id;
            activity.sentinal = firehose_sentinel;
            input = firehose_input;
        }

        let unique_pid = 0x10; // has_unique_pid flag
        if (firehose_flags & unique_pid) != 0 {
            debug!("[macos-unifiedlogs] Activity Firehose log chunk has unique_pid flag");
            let (firehose_input, firehose_unique_pid) = le_u64(input)?;
            activity.pid = firehose_unique_pid;
            input = firehose_input;
        }

        let activity_id_current = 0x1; // has_current_aid flag
        if (firehose_flags & activity_id_current) != 0 {
            debug!("[macos-unifiedlogs] Activity Firehose log chunk has has_current_aid flag");
            let (firehose_input, firehose_activity_id) = le_u32(input)?;
            let (firehose_input, firehose_sentinel) = le_u32(firehose_input)?;

            activity.activity_id_2 = firehose_activity_id;
            activity.sentinal_2 = firehose_sentinel;
            input = firehose_input;
        }

        let activity_id_other = 0x200; // has_other_current_aid flag. In Activity log entries this is another activity id flag
        if (firehose_flags & activity_id_other) != 0 {
            debug!(
                "[macos-unifiedlogs] Activity Firehose log chunk has has_other_current_aid flag"
            );
            let (firehose_input, firehose_activity_id) = le_u32(input)?;
            let (firehose_input, firehose_sentinel) = le_u32(firehose_input)?;

            activity.activity_id_3 = firehose_activity_id;
            activity.sentinal_3 = firehose_sentinel;
            input = firehose_input;
        }
        let (input, firehose_pc_id) = le_u32(input)?;
        activity.pc_id = firehose_pc_id; // Message string reference?

        // Check for flags related to base string format location (shared string file (dsc) or UUID file)
        let (input, formatters) =
            FirehoseFormatters::firehose_formatter_flags(input, firehose_flags)?;
        activity.firehose_formatters = formatters;
        Ok((input, activity))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose activity log entries (chunks)
    pub(crate) fn get_firehose_activity_strings<'a>(
        firehose: &FirehoseActivity,
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
    use super::FirehoseActivity;
    use crate::filesystem::LogarchiveProvider;
    use crate::parser::parse_log;
    use std::path::PathBuf;

    #[test]
    fn test_parse_activity() {
        let test_data = [
            178, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 178, 251, 0, 0, 0, 0, 0, 128,
            179, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0,
        ];
        let test_flags = 573;
        let log_type: u8 = 0x1;
        let (_, results) =
            FirehoseActivity::parse_activity(&test_data, test_flags, log_type).unwrap();
        assert_eq!(results.activity_id, 64434);
        assert_eq!(results.sentinal, 2147483648);
        assert_eq!(results.pid, 236);
        assert_eq!(results.activity_id_2, 64434);
        assert_eq!(results.sentinal_2, 2147483648);
        assert_eq!(results.activity_id_3, 64435);
        assert_eq!(results.sentinal_3, 2147483648);
        assert_eq!(results.message_string_ref, 0);
        assert!(!results.firehose_formatters.main_exe);
        assert!(!results.firehose_formatters.absolute);
        assert!(!results.firehose_formatters.shared_cache);
        assert!(!results.firehose_formatters.main_plugin);
        assert!(!results.firehose_formatters.pc_style);
        assert_eq!(results.firehose_formatters.main_exe_alt_index, 0);
        assert_eq!(results.firehose_formatters.uuid_relative, "");
        assert_eq!(results.pc_id, 303578944);
        assert_eq!(results.firehose_formatters.has_large_offset, 1);
        assert_eq!(results.firehose_formatters.large_shared_cache, 2);
    }

    #[test]
    fn test_get_firehose_activity_big_sur() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let mut provider = LogarchiveProvider::new(test_path.as_path());

        test_path.push("Persist/0000000000000004.tracev3");
        let handle = std::fs::File::open(&test_path).unwrap();
        let log_data = parse_log(handle, test_path.to_str().unwrap()).unwrap();

        let activity_type = 0x2;

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.log_activity_type == activity_type {
                        let (_, message_data) = FirehoseActivity::get_firehose_activity_strings(
                            &firehose.firehose_activity,
                            &mut provider,
                            u64::from(firehose.format_string_location),
                            preamble.first_number_proc_id,
                            preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        )
                        .unwrap();
                        assert_eq!(
                            message_data.format_string,
                            "Internal: Check the state of a node"
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
