use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32};
use std::mem::size_of;

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::firehose_log::{FirehoseItemData, FirehoseItemInfo};
use crate::chunks::firehose::message::MessageData;
use crate::uuidtext::UUIDText;

#[derive(Debug, Clone)]
pub struct FirehoseTrace {
    pub unknown_pc_id: u32, // Appears to be used to calculate string offset for firehose events with Absolute flag
    pub message_value: u16,
    pub unknown_data: Vec<u8>,
}

impl FirehoseTrace {
    /// Parse Trace Firehose log entry.
    //  Ex: tp 504 + 34: trace default (main_exe)
    pub fn parse_firehose_trace(data: &[u8]) -> nom::IResult<&[u8], FirehoseTrace> {
        let mut firehose_trace = FirehoseTrace {
            unknown_pc_id: 0,
            message_value: 0,
            unknown_data: Vec::new(),
        };
        let (input, unknown_pc_id) = take(size_of::<u32>())(data)?;

        // Trace logs only have message values if more than 4 bytes remaining in log entry
        let minimum_message_size = 4;
        if input.len() < minimum_message_size {
            let (_, firehose_unknown_pc_id) = le_u32(unknown_pc_id)?;
            firehose_trace.unknown_pc_id = firehose_unknown_pc_id;
            let (input, unknown_data) = take(input.len())(input)?;
            firehose_trace.unknown_data = unknown_data.to_vec();

            return Ok((input, firehose_trace));
        }
        let (input, message_value) = take(size_of::<u16>())(input)?;
        let (input, unknown_data) = take(input.len())(input)?;

        let (_, firehose_unknown_pc_id) = le_u32(unknown_pc_id)?;
        let (_, fireshose_message_value) = le_u16(message_value)?;

        firehose_trace.unknown_pc_id = firehose_unknown_pc_id;
        // The rest of the trace log entry appears to be related to log message values
        // But the data is stored differently from other log entries
        // The data appears to be stored backwards? Ex: Data value, Data size, number of data entries, instead normal: number of data entries, data size, data value
        firehose_trace.message_value = fireshose_message_value;
        firehose_trace.unknown_data = unknown_data.to_vec();

        Ok((input, firehose_trace))
    }

    /// Format the trace message data to make consistent with other log entries
    pub fn get_trace_message_string(message: u16) -> FirehoseItemData {
        let mut item_data = FirehoseItemData {
            item_info: Vec::new(),
            backtrace_strings: Vec::new(),
        };

        let item_info = FirehoseItemInfo {
            message_strings: format!("{}", message),
            item_type: 0,
            item_size: 0,
        };

        item_data.item_info.push(item_info);
        item_data
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
        assert_eq!(results.message_value, 0);
        assert_eq!(results.unknown_data.len(), 1);

        let test_data = [248, 145, 3, 0, 200, 0, 0, 0, 0, 0, 0, 0, 8, 1];
        let (_, results) = FirehoseTrace::parse_firehose_trace(&test_data).unwrap();
        assert_eq!(results.unknown_pc_id, 233976);
        assert_eq!(results.message_value, 200);
        assert_eq!(results.unknown_data.len(), 8);
    }

    #[test]
    fn test_get_trace_message_string() {
        let test_message = 0;
        let results = FirehoseTrace::get_trace_message_string(test_message);
        assert_eq!(results.item_info[0].message_strings, "0");
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
