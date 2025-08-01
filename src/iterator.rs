use crate::{
    header::HeaderChunk,
    preamble::LogPreamble,
    unified_log::{LogData, UnifiedLogCatalogData, UnifiedLogData},
    util::padding_size_8,
};
use log::{error, warn};
use nom::bytes::complete::take;

#[derive(Debug, Clone)]
/// Iterator to loop through Chunks in the tracev3 file
pub struct UnifiedLogIterator {
    pub data: Vec<u8>,
    pub header: Vec<HeaderChunk>,
}

impl Iterator for UnifiedLogIterator {
    type Item = UnifiedLogData;
    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let mut unified_log_data_true = UnifiedLogData {
            header: self.header.clone(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        let mut catalog_data = UnifiedLogCatalogData::default();

        let mut input = self.data.as_slice();
        let chunk_preamble_size = 16; // Include preamble size in total chunk size

        let header_chunk = 0x1000;
        let catalog_chunk = 0x600b;
        let chunkset_chunk = 0x600d;

        loop {
            let preamble_result = LogPreamble::detect_preamble(input);
            let preamble = match preamble_result {
                Ok((_, result)) => result,
                Err(_err) => {
                    error!("Failed to determine preamble chunk");
                    return None;
                }
            };
            let chunk_size = preamble.chunk_data_size;

            // Grab all data associated with Unified Log entry (chunk)
            let chunk_result = nom_bytes(input, &(chunk_size + chunk_preamble_size));

            let (data, chunk_data) = match chunk_result {
                Ok(result) => result,
                Err(_err) => {
                    error!("Failed to nom chunk bytes");
                    return None;
                }
            };

            if preamble.chunk_tag == header_chunk {
                LogData::get_header_data(chunk_data, &mut unified_log_data_true);
            } else if preamble.chunk_tag == catalog_chunk {
                if catalog_data.catalog.chunk_tag != 0 {
                    self.data = input.to_vec();
                    break;
                }

                LogData::get_catalog_data(chunk_data, &mut catalog_data);
            } else if preamble.chunk_tag == chunkset_chunk {
                LogData::get_chunkset_data(
                    chunk_data,
                    &mut catalog_data,
                    &mut unified_log_data_true,
                );
            } else {
                error!(
                    "[macos-unifiedlogs] Unknown chunk type: {}",
                    preamble.chunk_tag
                );
            }

            let padding_size = padding_size_8(preamble.chunk_data_size);
            if self.data.len() < padding_size as usize {
                self.data = Vec::new();
                break;
            }
            let data_result = nom_bytes(data, &padding_size);
            let data = match data_result {
                Ok((result, _)) => result,
                Err(_err) => {
                    error!("Failed to nom log end padding");
                    return None;
                }
            };
            if data.is_empty() {
                self.data = Vec::new();
                break;
            }
            input = data;
            if input.len() < chunk_preamble_size as usize {
                warn!(
                    "Not enough data for preamble header, needed 16 bytes. Got: {}",
                    input.len()
                );
                self.data = Vec::new();
                break;
            }
        }

        // Make sure to get the last catalog
        if catalog_data.catalog.chunk_tag != 0 {
            unified_log_data_true.catalog_data.push(catalog_data);
        }
        self.header = unified_log_data_true.header.clone();
        Some(unified_log_data_true)
    }
}

/// Nom bytes of the log chunk
fn nom_bytes<'a>(data: &'a [u8], size: &u64) -> nom::IResult<&'a [u8], &'a [u8]> {
    let size = match usize::try_from(*size).ok() {
        Some(s) => s,
        None => {
            error!("[macos-unifiedlogs] u64 is bigger than system usize");
            return Err(nom::Err::Error(nom::error::Error::new(
                data,
                nom::error::ErrorKind::TooLarge,
            )));
        }
    };
    take(size)(data)
}

#[cfg(test)]
mod tests {
    use super::UnifiedLogIterator;
    use crate::{
        filesystem::LogarchiveProvider,
        iterator::nom_bytes,
        parser::{build_log, collect_timesync},
        unified_log::{EventType, LogType},
    };
    use std::{fs, path::PathBuf};

    #[test]
    fn test_unified_log_iterator() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        test_path.push("Persist/0000000000000002.tracev3");
        let buffer_results = fs::read(test_path.to_str().unwrap()).unwrap();

        let log_iterator = UnifiedLogIterator {
            data: buffer_results,
            header: Vec::new(),
        };

        let mut total = 0;
        for chunk in log_iterator {
            if chunk.catalog_data[0].firehose.len() == 99 {
                assert_eq!(chunk.catalog_data[0].firehose.len(), 99);
                assert_eq!(chunk.catalog_data[0].simpledump.len(), 0);
                assert_eq!(chunk.header.len(), 1);
                assert!(
                    chunk.catalog_data[0]
                        .catalog
                        .catalog_process_info_entries
                        .len()
                        > 40
                );
                assert_eq!(chunk.catalog_data[0].statedump.len(), 0);
            }

            total += chunk.catalog_data.len();
        }

        assert_eq!(total, 56);
    }

    #[test]
    fn test_unified_log_iterator_build_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let mut provider = LogarchiveProvider::new(test_path.as_path());
        let timesync_data = collect_timesync(&provider).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let buffer_results = fs::read(test_path.to_str().unwrap()).unwrap();

        let log_iterator = UnifiedLogIterator {
            data: buffer_results,
            header: Vec::new(),
        };

        let mut total = 0;
        for chunk in log_iterator {
            let exclude_missing = false;
            let (results, _) = build_log(&chunk, &mut provider, &timesync_data, exclude_missing);

            if results[10].time == 1642302327364384800.0 {
                assert_eq!(results.len(), 3805);
                assert_eq!(results[10].process, "/usr/libexec/lightsoutmanagementd");
                assert_eq!(results[10].subsystem, "com.apple.lom");
                assert_eq!(results[10].time, 1642302327364384800.0);
                assert_eq!(results[10].activity_id, 0);
                assert_eq!(
                    results[10].library,
                    "/System/Library/PrivateFrameworks/AppleLOM.framework/Versions/A/AppleLOM"
                );
                assert_eq!(results[10].message, "<private> LOM isSupported : No");
                assert_eq!(results[10].pid, 45);
                assert_eq!(results[10].thread_id, 588);
                assert_eq!(results[10].category, "device");
                assert_eq!(results[10].log_type, LogType::Default);
                assert_eq!(results[10].event_type, EventType::Log);
                assert_eq!(results[10].euid, 0);
                assert_eq!(results[10].boot_uuid, "80D194AF56A34C54867449D2130D41BB");
                assert_eq!(results[10].timezone_name, "Pacific");
                assert_eq!(results[10].library_uuid, "D8E5AF1CAF4F3CEB8731E6F240E8EA7D");
                assert_eq!(results[10].process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
                assert_eq!(results[10].raw_message, "%@ LOM isSupported : %s");
            }

            total += results.len();
        }

        assert_eq!(total, 207366);
    }

    #[test]
    fn test_nom_bytes() {
        let test = [1, 0, 0, 0];
        let (left, _) = nom_bytes(&test, &1).unwrap();
        assert_eq!(left.len(), 3);
    }
}
