// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::{fs::File, path::PathBuf};

use macos_unifiedlogs::{
    filesystem::LogarchiveProvider,
    parser::{build_log, collect_timesync, parse_log},
    traits::FileProvider,
    unified_log::{EventType, LogData, LogType, UnifiedLogData},
};
use regex::Regex;

fn collect_logs(provider: &dyn FileProvider) -> Vec<UnifiedLogData> {
    provider
        .tracev3_files()
        .map(|mut file| parse_log(file.reader()).unwrap())
        .collect()
}

#[test]
fn test_parse_log_monterey() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_monterey.logarchive");

    test_path.push("Persist/000000000000000a.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();

    assert_eq!(log_data.catalog_data[0].firehose.len(), 17);
    assert_eq!(log_data.catalog_data[0].simpledump.len(), 383);
    assert_eq!(log_data.header.len(), 1);
    assert_eq!(
        log_data.catalog_data[0]
            .catalog
            .catalog_process_info_entries
            .len(),
        17
    );
    assert_eq!(log_data.catalog_data[0].statedump.len(), 0);
}

#[test]
fn test_build_log_monterey() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_monterey.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/000000000000000a.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();
    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(&log_data, &mut provider, &timesync_data, exclude_missing);
    assert_eq!(results.len(), 322859);
    assert_eq!(results[0].process, "/kernel");
    assert_eq!(results[0].subsystem, "");
    assert_eq!(results[0].time, 1651345928766719209.0);
    assert_eq!(results[0].activity_id, 0);
    assert_eq!(
        results[0].library,
        "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox"
    );
    assert_eq!(
        results[0].message,
        "2 duplicate reports for Sandbox: MTLCompilerServi(187) deny(1) file-read-metadata /private"
    );
    assert_eq!(results[0].pid, 0);
    assert_eq!(results[0].thread_id, 2241);
    assert_eq!(results[0].category, "");
    assert_eq!(results[0].log_type, LogType::Error);
    assert_eq!(results[0].event_type, EventType::Log);
    assert_eq!(results[0].euid, 0);
    assert_eq!(results[0].boot_uuid, "17AB576950394796B7F3CD2C157F4A2F");
    assert_eq!(results[0].timezone_name, "New_York");
    assert_eq!(results[0].library_uuid, "7EFAFB8B6CA63090957FC68A6230BC38");
    assert_eq!(results[0].process_uuid, "C342869FFFB93CCEA5A3EA711C1E87F6");
    assert_eq!(results[0].raw_message, "%s");
}

#[test]
fn test_parse_all_logs_monterey() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_monterey.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());

    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);

    let mut log_data_vec: Vec<LogData> = Vec::new();
    let exclude_missing = false;
    let message_re = Regex::new(r"^[\s]*%s\s*$").unwrap();

    for logs in &log_data {
        let (mut data, _) = build_log(&logs, &mut provider, &timesync_data, exclude_missing);
        log_data_vec.append(&mut data);
    }
    assert_eq!(log_data_vec.len(), 2397109);

    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;
    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;
    let mut string_count = 0;

    let mut mutilities_worldclock = 0;
    let mut mutililties_return = 0;
    let mut location_tracker = 0;
    let mut pauses_tracker = 0;
    let mut dns_counts = 0;

    for logs in &log_data_vec {
        if logs.message.contains("Failed to get string message from ")
            || logs.message.contains("Unknown shared string message")
        {
            unknown_strings += 1;
        }

        if logs.message.contains("Error: Invalid offset ") {
            invalid_offsets += 1;
        }

        if logs.message.contains("Error: Invalid shared string offset") {
            invalid_shared_string_offsets += 1;
        }

        if logs.message.contains("Unsupported Statedump object") {
            statedump_custom_objects += 1;
        }
        if logs.message.contains("Failed to parse StateDump protobuf")
            || logs
                .message
                .contains("Failed to serialize Protobuf HashMap")
        {
            statedump_protocol_buffer += 1;
        }

        if message_re.is_match(&logs.raw_message) {
            string_count += 1;
        }

        if logs.message.contains("MTUtilities: WorldClockWidget:")
            && logs.log_type == LogType::Default
        {
            mutilities_worldclock += 1;
        }
        if logs.message.contains("MTUtilities: Returning widget") {
            mutililties_return += 1;
        }
        if logs.message.contains("allowsMapCorrection") {
            location_tracker += 1;
        }
        if logs
            .message
            .contains("\"pausesLocationUpdatesAutomatically\":1,")
        {
            pauses_tracker += 1;
        }
        if logs.message.contains("Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0") {
            dns_counts += 1;
        }
    }
    assert_eq!(unknown_strings, 531);
    assert_eq!(invalid_offsets, 60);
    assert_eq!(invalid_shared_string_offsets, 309);
    assert_eq!(statedump_custom_objects, 1);
    assert_eq!(statedump_protocol_buffer, 0);
    assert_eq!(string_count, 28196); // Accurate count based on log raw-dump -a <monterey.logarchive> | grep "format:\s*%s$" | sort | uniq -c | sort -n
    assert_eq!(mutilities_worldclock, 57);
    assert_eq!(mutililties_return, 71);
    assert_eq!(dns_counts, 3196);

    assert_eq!(location_tracker, 298);
    assert_eq!(pauses_tracker, 118);
}
