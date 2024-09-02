// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::{error, info};

use crate::dsc::SharedCacheStrings;
use crate::error::ParserError;
use crate::timesync::TimesyncBoot;
use crate::unified_log::{LogData, UnifiedLogData};
use crate::uuidtext::UUIDText;
use std::fs;

/// Parse the UUID files on a live system
pub fn collect_strings_system() -> Result<Vec<UUIDText>, ParserError> {
    let uuidtext_path = String::from("/private/var/db/uuidtext");
    collect_strings(&uuidtext_path)
}

/// Parse the dsc (shared cache strings) files on a live system
pub fn collect_shared_strings_system() -> Result<Vec<SharedCacheStrings>, ParserError> {
    let dsc_path = String::from("/private/var/db/uuidtext/dsc");
    collect_shared_strings(&dsc_path)
}

/// Parse the timesync files on a live system
pub fn collect_timesync_system() -> Result<Vec<TimesyncBoot>, ParserError> {
    let timesync = String::from("/private/var/db/diagnostics/timesync");
    collect_timesync(&timesync)
}

/// Parse a tracev3 file and return the deconstructed log data
pub fn parse_log(full_path: &str) -> Result<UnifiedLogData, ParserError> {
    let buffer_results = fs::read(full_path);

    let buffer = match buffer_results {
        Ok(results) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to read the tracev3 file {}: {:?}",
                full_path, err
            );
            return Err(ParserError::Read);
        }
    };
    info!("Read {} bytes for file {}", buffer.len(), full_path);

    let log_data_results = LogData::parse_unified_log(&buffer);
    match log_data_results {
        Ok((_, log_data)) => Ok(log_data),
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse the tracev3 file: {:?}",
                err
            );
            Err(ParserError::Tracev3Parse)
        }
    }
}

pub fn iter_log<'a>(
    unified_log_data: &'a UnifiedLogData,
    strings_data: &'a [UUIDText],
    shared_strings: &'a [SharedCacheStrings],
    timesync_data: &'a [TimesyncBoot],
    exclude_missing: bool,
) -> Result<impl Iterator<Item = (Vec<LogData>, UnifiedLogData)> + 'a, regex::Error> {
    LogData::iter_log(
        unified_log_data,
        strings_data,
        shared_strings,
        timesync_data,
        exclude_missing,
    )
}

/// Reconstruct Unified Log entries using the strings data, cached strings data, timesync data, and unified log. Provide bool to ignore log entries that are not able to be recontructed (additional tracev3 files needed)
/// Return a reconstructed log entries and any leftover Unified Log entries that could not be reconstructed (data may be stored in other tracev3 files)
// Log entries with Oversize string entries may have the data in a different tracev3 file.
pub fn build_log(
    unified_data: &UnifiedLogData,
    strings_data: &[UUIDText],
    shared_strings: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    exclude_missing: bool,
) -> (Vec<LogData>, UnifiedLogData) {
    LogData::build_log(
        unified_data,
        strings_data,
        shared_strings,
        timesync_data,
        exclude_missing,
    )
}

/// Parse all UUID files in provided directory. The directory should follow the same layout as the live system (ex: path/to/files/<two character UUID>/<remaining UUID name>)
pub fn collect_strings(path: &str) -> Result<Vec<UUIDText>, ParserError> {
    let paths_results = fs::read_dir(path);

    let paths = match paths_results {
        Ok(path) => path,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to read directory path: {:?}",
                err
            );
            return Err(ParserError::Dir);
        }
    };

    let mut uuidtext_vec: Vec<UUIDText> = Vec::new();
    // Start process to read a directory containing subdirectories that contain the uuidtext files
    for path in paths {
        let dir_entry = match path {
            Ok(entry) => entry,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to get directory entry: {:?}",
                    err
                );
                continue;
            }
        };

        let type_results = dir_entry.file_type();
        let entry_type = match type_results {
            Ok(dir_type) => dir_type,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to get directory entry type: {:?}",
                    err
                );
                continue;
            }
        };

        if entry_type.is_file() {
            continue;
        }

        let directory_results = dir_entry.file_name().into_string();
        let directory = match directory_results {
            Ok(directory_path) => directory_path,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to convert path {:?} to string",
                    err
                );
                continue;
            }
        };

        // Currently expect the subdirectories to be structured like a live system (or .logarchive)
        // they should be /private/var/db/uuidtext/<2 char values>/<rest of uuid> (/private/var/db/uuidtext/1F/470CAE74D83AA1A6637FD0C5B1D365)
        let first_two_uuid_chars = 2;
        if directory.len() != first_two_uuid_chars {
            continue;
        }

        let dir_path = dir_entry.path();
        let uuidtext_path_results = fs::read_dir(dir_path);
        let uuidtext_path = match uuidtext_path_results {
            Ok(uuid_path) => uuid_path,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to read directory path for UUID files: {:?}",
                    err
                );
                continue;
            }
        };

        // Read all uuidtext files in directory
        for uuid_data in uuidtext_path {
            let uuidtext_full_path = match uuid_data {
                Ok(uuid_entry) => uuid_entry,
                Err(err) => {
                    error!(
                        "[macos-unifiedlogs] Failed to get directory uuid entry: {:?}",
                        err
                    );
                    continue;
                }
            };

            let full_path = uuidtext_full_path.path();
            let buffer_results = fs::read(&full_path);
            let buffer = match buffer_results {
                Ok(results) => results,
                Err(err) => {
                    error!("[macos-unifiedlogs] Failed to read UUID file: {:?}", err);
                    continue;
                }
            };
            info!(
                "Read {} bytes for file {}",
                buffer.len(),
                full_path.display().to_string()
            );

            let uuid_results = UUIDText::parse_uuidtext(&buffer);
            let mut uuidtext_data = match uuid_results {
                Ok((_, results)) => results,
                Err(err) => {
                    error!(
                        "[macos-unifiedlogs] Failed to parse UUID file {}: {:?}",
                        full_path.display().to_string(),
                        err
                    );
                    continue;
                }
            };

            // Track the uuidtext filename, this will be referenced by log entries via the Catalog (or log entry)
            let uuid_file_name = uuidtext_full_path.file_name().into_string();
            match uuid_file_name {
                // Only the last 14 characters of the UUID name are saved here. Limited chance of UUID collisions on a real system
                Ok(uuid_file_string) => uuidtext_data.uuid = uuid_file_string,
                Err(err) => {
                    error!("[macos-unifiedlogs] Failed to convert UUID filename {:?} to string. Unable to do base format string lookups", err);
                    continue;
                }
            }

            uuidtext_vec.push(uuidtext_data)
        }
    }
    Ok(uuidtext_vec)
}

/// Parse all dsc uuid files in provided directory
pub fn collect_shared_strings(path: &str) -> Result<Vec<SharedCacheStrings>, ParserError> {
    let paths_results = fs::read_dir(path);

    let paths = match paths_results {
        Ok(results) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to read dsc directory {}: {:?}",
                path, err
            );
            return Err(ParserError::Path);
        }
    };

    let mut shared_strings_vec: Vec<SharedCacheStrings> = Vec::new();
    // Start process to read and parse uuid files related to dsc
    for path in paths {
        let data = match path {
            Ok(path_results) => path_results,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to get dsc directory entry: {:?}",
                    err
                );
                continue;
            }
        };

        let full_path = data.path();
        let buffer_results = fs::read(&full_path);
        let buffer = match buffer_results {
            Ok(results) => results,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to read dsc file {}: {:?}",
                    full_path.display().to_string(),
                    err
                );
                continue;
            }
        };

        let shared_strings_data_results = SharedCacheStrings::parse_dsc(&buffer);
        let mut shared_strings_data = match shared_strings_data_results {
            Ok((_, results)) => results,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to parse dsc file {}: {:?}",
                    full_path.display().to_string(),
                    err
                );
                continue;
            }
        };

        // Track the uuid filename, this will be referenced by log entries via the Catalog (or log entry)
        let dsc_filename = data.file_name().into_string();
        match dsc_filename {
            Ok(dsc_file_string) => shared_strings_data.dsc_uuid = dsc_file_string,
            Err(err) => {
                error!("[macos-unifiedlogs] Failed to convert dsc filename {:?} to string. Unable to do base format string lookups", err);
                continue;
            }
        }
        shared_strings_vec.push(shared_strings_data);
    }
    Ok(shared_strings_vec)
}

/// Parse all timesync files in provided directory
pub fn collect_timesync(path: &str) -> Result<Vec<TimesyncBoot>, ParserError> {
    let paths_results = fs::read_dir(path);

    let paths = match paths_results {
        Ok(results) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to read timesync directory {}: {:?}",
                path, err
            );
            return Err(ParserError::Path);
        }
    };

    let mut timesync_data_vec: Vec<TimesyncBoot> = Vec::new();
    // Start process to read and parse all timesync files
    for path in paths {
        let data = match path {
            Ok(path_results) => path_results,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to get timesync directory entry: {:?}",
                    err
                );
                continue;
            }
        };

        let full_path = data.path();
        let buffer_results = fs::read(&full_path);
        let buffer = match buffer_results {
            Ok(results) => results,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to read timesync file {}: {:?}",
                    full_path.display().to_string(),
                    err
                );
                continue;
            }
        };
        info!(
            "Read {} bytes from timesync file {}",
            buffer.len(),
            full_path.display().to_string()
        );

        let timesync_results = TimesyncBoot::parse_timesync_data(&buffer);
        match timesync_results {
            Ok((_, mut timesync)) => timesync_data_vec.append(&mut timesync),
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to parse timesync file {}: {:?}",
                    full_path.display().to_string(),
                    err
                );
                continue;
            }
        }
    }
    Ok(timesync_data_vec)
}

#[cfg(test)]
mod tests {
    use crate::parser::{
        build_log, collect_shared_strings, collect_shared_strings_system, collect_strings,
        collect_strings_system, collect_timesync, collect_timesync_system, parse_log,
    };

    use std::path::PathBuf;

    #[test]
    fn test_collect_strings_system() {
        let uuidtext_results = collect_strings_system().unwrap();
        assert!(uuidtext_results.len() > 100);
    }

    #[test]
    fn test_collect_timesync_system() {
        let timesync_results = collect_timesync_system().unwrap();
        assert!(timesync_results.len() > 1);
    }

    #[test]
    fn test_collect_timesync_archive() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive/timesync");

        let timesync_data = collect_timesync(&test_path.display().to_string()).unwrap();
        assert_eq!(timesync_data.len(), 5);
        assert_eq!(timesync_data[0].signature, 48048);
        assert_eq!(timesync_data[0].unknown, 0);
        assert_eq!(
            timesync_data[0].boot_uuid,
            "9A6A3124274A44B29ABF2BC9E4599B3B"
        );
        assert_eq!(timesync_data[0].timesync.len(), 5);
        assert_eq!(timesync_data[0].daylight_savings, 0);
        assert_eq!(timesync_data[0].boot_time, 1642302206000000000);
        assert_eq!(timesync_data[0].header_size, 48);
        assert_eq!(timesync_data[0].timebase_denominator, 1);
        assert_eq!(timesync_data[0].timebase_numerator, 1);
        assert_eq!(timesync_data[0].timezone_offset_mins, 0);
    }

    #[test]
    fn test_collect_shared_strings_system() {
        let shared_strings_results = collect_shared_strings_system().unwrap();
        assert!(shared_strings_results[0].ranges.len() > 1);
        assert!(shared_strings_results[0].uuids.len() > 1);
        assert!(shared_strings_results[0].number_ranges > 1);
        assert!(shared_strings_results[0].number_uuids > 1);
    }

    #[test]
    fn test_shared_strings_archive() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive/dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        assert_eq!(shared_strings_results.len(), 2);
        assert_eq!(shared_strings_results[0].number_uuids, 1976);
        assert_eq!(shared_strings_results[0].number_ranges, 2993);
        assert_eq!(
            shared_strings_results[0].dsc_uuid,
            "80896B329EB13A10A7C5449B15305DE2"
        );
        assert_eq!(shared_strings_results[0].minor_version, 0);
        assert_eq!(shared_strings_results[0].major_version, 1);
        assert_eq!(shared_strings_results[0].ranges.len(), 2993);
        assert_eq!(shared_strings_results[0].uuids.len(), 1976);
    }

    #[test]
    fn test_collect_strings_archive() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let strings_results = collect_strings(&test_path.display().to_string()).unwrap();
        assert_eq!(strings_results.len(), 536);
        assert_eq!(strings_results[0].signature, 1719109785);
        assert_eq!(strings_results[0].uuid, "5283D7FC2531558F2C1ACE9AF26A0F");
        assert_eq!(strings_results[0].entry_descriptors.len(), 2);
        assert_eq!(strings_results[0].footer_data.len(), 48096);
        assert_eq!(strings_results[0].number_entries, 2);
        assert_eq!(strings_results[0].unknown_minor_version, 1);
        assert_eq!(strings_results[0].unknown_major_version, 2);
    }

    #[test]
    fn test_parse_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        assert_eq!(log_data.catalog_data[0].firehose.len(), 99);
        assert_eq!(log_data.catalog_data[0].simpledump.len(), 0);
        assert_eq!(log_data.header.len(), 1);
        assert_eq!(
            log_data.catalog_data[0]
                .catalog
                .catalog_process_info_entries
                .len(),
            46
        );
        assert_eq!(log_data.catalog_data[0].statedump.len(), 0);
    }

    #[test]
    fn test_build_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let string_results = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("timesync");
        let timesync_data = collect_timesync(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let exclude_missing = false;
        let (results, _) = build_log(
            &log_data,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            exclude_missing,
        );
        assert_eq!(results.len(), 207366);
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
        assert_eq!(results[10].log_type, "Default");
        assert_eq!(results[10].event_type, "Log");
        assert_eq!(results[10].euid, 0);
        assert_eq!(results[10].boot_uuid, "80D194AF56A34C54867449D2130D41BB");
        assert_eq!(results[10].timezone_name, "Pacific");
        assert_eq!(results[10].library_uuid, "D8E5AF1CAF4F3CEB8731E6F240E8EA7D");
        assert_eq!(results[10].process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
        assert_eq!(results[10].raw_message, "%@ LOM isSupported : %s");
    }
}
