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
use crate::traits::FileProvider;
use crate::unified_log::{LogData, UnifiedLogData};
use crate::uuidtext::UUIDText;
use std::io::Read;
use std::path::PathBuf;

/// Parse a tracev3 file and return the deconstructed log data
pub fn parse_log(mut reader: impl Read) -> Result<UnifiedLogData, ParserError> {
    let mut buf = Vec::new();
    if let Err(e) = reader.read_to_end(&mut buf) {
        error!(
            "[macos-unifiedlogs] Failed to read the tracev3 file: {:?}",
            e
        );
        return Err(ParserError::Read);
    }

    info!("Read {} bytes from tracev3 file", buf.len());

    let log_data_results = LogData::parse_unified_log(&buf);
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

/// Returns an iterator that parses through the log entries
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

/// Reconstruct Unified Log entries using the strings data, cached strings data, timesync data, and unified log. Provide bool to ignore log entries that are not able to be recontructed (additional tracev3 files needed)
/// Return a reconstructed log entries and any leftover Unified Log entries that could not be reconstructed (data may be stored in other tracev3 files)
// Log entries with Oversize string entries may have the data in a different tracev3 file.
pub fn build_logv2(
    unified_data: &UnifiedLogData,
    provider: &mut dyn FileProvider,
    timesync_data: &[TimesyncBoot],
    exclude_missing: bool,
) -> (Vec<LogData>, UnifiedLogData) {
    LogData::build_logv2(unified_data, provider, timesync_data, exclude_missing)
}

/// Parse all UUID files in provided directory. The directory should follow the same layout as the live system (ex: path/to/files/<two character UUID>/<remaining UUID name>)
pub fn collect_strings(provider: &dyn FileProvider) -> Result<Vec<UUIDText>, ParserError> {
    let mut uuidtext_vec: Vec<UUIDText> = Vec::new();
    // Start process to read a directory containing subdirectories that contain the uuidtext files
    for mut source in provider.uuidtext_files() {
        let mut buf = Vec::new();
        let path = source.source_path().to_owned();
        if let Err(e) = source.reader().read_to_end(&mut buf) {
            error!(
                "[macos-unifiedlogs] Failed to read uuidfile {}: {:?}",
                path, e
            );
            continue;
        };

        info!("Read {} bytes for file {}", buf.len(), path);

        let uuid_results = UUIDText::parse_uuidtext(&buf);
        let mut uuidtext_data = match uuid_results {
            Ok((_, results)) => results,
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to parse UUID file {}: {:?}",
                    path, err
                );
                continue;
            }
        };

        uuidtext_data.uuid = PathBuf::from(path)
            .file_name()
            .map(|f| f.to_string_lossy())
            .unwrap_or_default()
            .to_string();
        uuidtext_vec.push(uuidtext_data)
    }
    Ok(uuidtext_vec)
}

/// Parse all dsc uuid files in provided directory
pub fn collect_shared_strings(
    provider: &dyn FileProvider,
) -> Result<Vec<SharedCacheStrings>, ParserError> {
    let mut shared_strings_vec: Vec<SharedCacheStrings> = Vec::new();
    // Start process to read and parse uuid files related to dsc
    for mut source in provider.dsc_files() {
        let mut buf = Vec::new();
        if let Err(e) = source.reader().read_to_end(&mut buf) {
            error!("[macos-unifiedlogs] Failed to read dsc file: {:?}", e);
            continue;
        }

        match SharedCacheStrings::parse_dsc(&buf) {
            Ok((_, mut results)) => {
                results.dsc_uuid = PathBuf::from(source.source_path())
                    .file_name()
                    .map(|fname| fname.to_string_lossy())
                    .unwrap_or_default()
                    .to_string();
                shared_strings_vec.push(results);
            }
            Err(err) => {
                error!("[macos-unifiedlogs] Failed to parse dsc file: {:?}", err);
            }
        };
    }
    Ok(shared_strings_vec)
}

/// Parse all timesync files in provided directory
pub fn collect_timesync(provider: &dyn FileProvider) -> Result<Vec<TimesyncBoot>, ParserError> {
    let mut timesync_data_vec: Vec<TimesyncBoot> = Vec::new();
    // Start process to read and parse all timesync files
    for mut source in provider.timesync_files() {
        let mut buffer = Vec::new();
        if let Err(e) = source.reader().read_to_end(&mut buffer) {
            error!("[macos-unifiedlogs] Failed to read timesync file: {:?}", e);
            continue;
        }

        let timesync_results = TimesyncBoot::parse_timesync_data(&buffer);
        match timesync_results {
            Ok((_, mut timesync)) => timesync_data_vec.append(&mut timesync),
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to parse timesync file: {:?}",
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
    use crate::filesystem::LogarchiveProvider;
    use crate::parser::{
        build_log, collect_shared_strings, collect_strings, collect_timesync, parse_log,
    };
    use crate::unified_log::{EventType, LogType};
    use std::path::PathBuf;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_collect_strings_system() {
        use crate::filesystem::LiveSystemProvider;
        let system_provider = LiveSystemProvider::default();
        let uuidtext_results = collect_strings(&system_provider).unwrap();
        assert!(uuidtext_results.len() > 100);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_collect_timesync_system() {
        use crate::filesystem::LiveSystemProvider;
        let system_provider = LiveSystemProvider::default();
        let timesync_results = collect_timesync(&system_provider).unwrap();
        assert!(timesync_results.len() > 1);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_collect_timesync_archive() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let provider = LogarchiveProvider::new(test_path.as_path());

        let timesync_data = collect_timesync(&provider).unwrap();
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
    #[cfg(target_os = "macos")]
    fn test_collect_shared_strings_system() {
        use crate::filesystem::LiveSystemProvider;
        let system_provider = LiveSystemProvider::default();
        let shared_strings_results = collect_shared_strings(&system_provider).unwrap();
        assert!(shared_strings_results[0].ranges.len() > 1);
        assert!(shared_strings_results[0].uuids.len() > 1);
        assert!(shared_strings_results[0].number_ranges > 1);
        assert!(shared_strings_results[0].number_uuids > 1);
    }

    #[test]
    fn test_shared_strings_archive() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(test_path.as_path());
        let shared_strings_results = collect_shared_strings(&provider).unwrap();
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
        let provider = LogarchiveProvider::new(test_path.as_path());

        let mut strings_results = collect_strings(&provider).unwrap();
        assert_eq!(strings_results.len(), 536);

        strings_results.sort_by(|a, b| a.uuid.cmp(&b.uuid));

        assert_eq!(strings_results[0].signature, 1719109785);
        assert_eq!(strings_results[0].uuid, "004EAF1C2B310DA0383BE3D60B80E8");
        assert_eq!(strings_results[0].entry_descriptors.len(), 1);
        assert_eq!(strings_results[0].footer_data.len(), 2847);
        assert_eq!(strings_results[0].number_entries, 1);
        assert_eq!(strings_results[0].unknown_minor_version, 1);
        assert_eq!(strings_results[0].unknown_major_version, 2);

        assert_eq!(strings_results[1].uuid, "00B3D870FB3AE8BDC1BA3A60D0B9A0");
        assert_eq!(strings_results[1].footer_data.len(), 2164);

        assert_eq!(strings_results[2].uuid, "014C44534A3A748476ABD88D376918");
        assert_eq!(strings_results[2].footer_data.len(), 19011);
    }

    #[test]
    fn test_parse_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        test_path.push("Persist/0000000000000002.tracev3");
        let handle = std::fs::File::open(test_path).unwrap();
        let log_data = parse_log(handle).unwrap();

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
        let provider = LogarchiveProvider::new(test_path.as_path());

        let string_results = collect_strings(&provider).unwrap();
        let shared_strings_results = collect_shared_strings(&provider).unwrap();
        let timesync_data = collect_timesync(&provider).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let handle = std::fs::File::open(&test_path).unwrap();
        let log_data = parse_log(handle).unwrap();

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
        assert_eq!(results[10].log_type, LogType::Default);
        assert_eq!(results[10].event_type, EventType::Log);
        assert_eq!(results[10].euid, 0);
        assert_eq!(results[10].boot_uuid, "80D194AF56A34C54867449D2130D41BB");
        assert_eq!(results[10].timezone_name, "Pacific");
        assert_eq!(results[10].library_uuid, "D8E5AF1CAF4F3CEB8731E6F240E8EA7D");
        assert_eq!(results[10].process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
        assert_eq!(results[10].raw_message, "%@ LOM isSupported : %s");
    }
}
