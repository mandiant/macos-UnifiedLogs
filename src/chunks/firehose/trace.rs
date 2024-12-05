// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::{error, warn};
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, be_u64, be_u8, le_u32, le_u8};
use std::mem::size_of;

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::firehose_log::{FirehoseItemData, FirehoseItemInfo};
use crate::chunks::firehose::message::MessageData;
use crate::uuidtext::UUIDText;

#[derive(Debug, Clone, Default)]
pub struct FirehoseTrace {
    pub unknown_pc_id: u32, // Appears to be used to calculate string offset for firehose events with Absolute flag
    pub message_data: FirehoseItemData,
}

impl FirehoseTrace {
    /// Parse Trace Firehose log entry.
    //  Ex: tp 504 + 34: trace default (main_exe)
    pub fn parse_firehose_trace(data: &[u8]) -> nom::IResult<&[u8], FirehoseTrace> {
        let mut firehose_trace = FirehoseTrace::default();

        let (input, unknown_pc_id) = take(size_of::<u32>())(data)?;
        let (_, firehose_unknown_pc_id) = le_u32(unknown_pc_id)?;

        // Trace logs only have message values if more than 4 bytes remaining in log entry
        let minimum_message_size = 4;
        if input.len() < minimum_message_size {
            let (_, firehose_unknown_pc_id) = le_u32(unknown_pc_id)?;
            firehose_trace.unknown_pc_id = firehose_unknown_pc_id;
            let (input, _unknown_data) = take(input.len())(input)?;

            return Ok((input, firehose_trace));
        }

        let mut message_data = input.to_vec();
        // The rest of the trace log entry appears to be related to log message values
        // But the data is stored differently from other log entries
        // The data appears to be stored backwards? Ex: Data value, Data size, number of data entries, instead normal: number of data entries, data size, data value
        message_data.reverse();
        let message = FirehoseTrace::get_message(&message_data);
        firehose_trace.message_data = message;
        firehose_trace.unknown_pc_id = firehose_unknown_pc_id;

        Ok((&[], firehose_trace))
    }

    /// Get the Trace message
    fn get_message(data: &[u8]) -> FirehoseItemData {
        let message_result = FirehoseTrace::parse_trace_message(data);
        match message_result {
            Ok((_, result)) => result,
            Err(err) => {
                error!("[macos-unifiedlogs] Could not get Trace message data: {err:?}");
                FirehoseItemData {
                    item_info: Vec::new(),
                    backtrace_strings: Vec::new(),
                }
            }
        }
    }

    /// Parse the data associated with the trace message
    fn parse_trace_message(data: &[u8]) -> nom::IResult<&[u8], FirehoseItemData> {
        let mut item_data = FirehoseItemData {
            item_info: Vec::new(),
            backtrace_strings: Vec::new(),
        };
        let minimum_message_size = 4;
        if data.len() < minimum_message_size {
            return Ok((data, item_data));
        }

        let (mut remaining_input, entries_data) = take(size_of::<u8>())(data)?;
        let (_, entries) = le_u8(entries_data)?;

        let mut count = 0;
        let mut sizes_count = Vec::new();
        // based on number of entries get the size for each entry
        while count < entries {
            let (input, size_data) = take(size_of::<u8>())(remaining_input)?;
            let (_, size) = le_u8(size_data)?;
            sizes_count.push(size);
            count += 1;
            remaining_input = input;
        }

        for entry_size in sizes_count {
            let mut item_info = FirehoseItemInfo {
                message_strings: String::new(),
                item_type: 0,
                item_size: 0,
            };
            // So far all entries appears to be numbers. Using Big Endian because we reversed the data above
            let (input, message_data) = take(entry_size as usize)(remaining_input)?;
            match entry_size {
                1 => {
                    let (_, value) = be_u8(message_data)?;
                    item_info.message_strings = format!("{value}")
                }
                2 => {
                    let (_, value) = be_u16(message_data)?;
                    item_info.message_strings = format!("{value}")
                }
                4 => {
                    let (_, value) = be_u32(message_data)?;
                    item_info.message_strings = format!("{value}")
                }
                8 => {
                    let (_, value) = be_u64(message_data)?;
                    item_info.message_strings = format!("{value}")
                }
                _ => {
                    warn!("[macos-unifiedlogs] Unhandled size of trace data: {entry_size}. Defaulting to size of one");
                    let (_, unknown_size) = le_u8(message_data)?;
                    item_info.message_strings = format!("{unknown_size}")
                }
            }
            remaining_input = input;
            item_data.item_info.push(item_info)
        }
        // Reverse the data back to expected format
        item_data.item_info.reverse();

        Ok((remaining_input, item_data))
    }

    /// Get base log message string formatter from shared cache strings (dsc) or UUID text file for firehose trace log entries (chunks)
    pub fn get_firehose_trace_strings<'a>(
        strings_data: &'a [UUIDText],
        string_offset: u64,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
    ) -> nom::IResult<&'a [u8], MessageData> {
        // Only main_exe flag has been seen for format strings
        MessageData::extract_format_strings(
            strings_data,
            string_offset,
            first_proc_id,
            second_proc_id,
            catalogs,
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        chunks::firehose::trace::FirehoseTrace,
        parser::{collect_strings, parse_log},
    };

    #[test]
    fn test_parse_firehose_trace() {
        let test_data = [106, 139, 3, 0, 0];
        let (_, results) = FirehoseTrace::parse_firehose_trace(&test_data).unwrap();
        assert_eq!(results.unknown_pc_id, 232298);

        let test_data = [248, 145, 3, 0, 200, 0, 0, 0, 0, 0, 0, 0, 8, 1];
        let (_, results) = FirehoseTrace::parse_firehose_trace(&test_data).unwrap();
        assert_eq!(results.unknown_pc_id, 233976);
        assert_eq!(results.message_data.item_info.len(), 1);
    }

    #[test]
    fn test_parse_trace_message() {
        let mut test_message = vec![200, 0, 0, 0, 0, 0, 0, 0, 8, 1];
        test_message.reverse();
        let (_, results) = FirehoseTrace::parse_trace_message(&test_message).unwrap();
        assert_eq!(results.item_info[0].message_strings, "200");
    }

    #[test]
    fn test_parse_trace_message_multiple() {
        let test_message = [
            2, 8, 8, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 127, 251, 75, 225, 96, 176,
        ];
        let (_, results) = FirehoseTrace::parse_trace_message(&test_message).unwrap();

        assert_eq!(results.item_info[0].message_strings, "140717286580400");
        assert_eq!(results.item_info[1].message_strings, "200");
    }

    #[test]
    fn test_get_message() {
        let mut test_message = vec![200, 0, 0, 0, 0, 0, 0, 0, 8, 1];
        test_message.reverse();
        let results = FirehoseTrace::get_message(&test_message);
        assert_eq!(results.item_info[0].message_strings, "200");
    }

    #[test]
    fn test_get_firehose_trace_strings() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_high_sierra.logarchive");
        let string_results = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("logdata.LiveData.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let activity_type = 0x3;

        for catalog_data in log_data.catalog_data {
            for preamble in catalog_data.firehose {
                for firehose in preamble.public_data {
                    if firehose.unknown_log_activity_type == activity_type {
                        let (_, message_data) = FirehoseTrace::get_firehose_trace_strings(
                            &string_results,
                            firehose.format_string_location as u64,
                            &preamble.first_number_proc_id,
                            &preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        )
                        .unwrap();
                        assert_eq!(message_data.format_string, "starting metadata download");
                        assert_eq!(message_data.library, "/usr/libexec/mobileassetd");
                        assert_eq!(message_data.process, "/usr/libexec/mobileassetd");
                        assert_eq!(
                            message_data.process_uuid,
                            "CC6C867B44D63D0ABAA7598659629484"
                        );
                        assert_eq!(
                            message_data.library_uuid,
                            "CC6C867B44D63D0ABAA7598659629484"
                        );
                        return;
                    }
                }
            }
        }
    }
}
