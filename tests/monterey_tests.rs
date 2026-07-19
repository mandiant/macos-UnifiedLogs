// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use macos_unifiedlogs::{
    chunk::{Chunk, ChunksReader},
    log_entry::{EventType, LogType},
    logarchive::{visit_logarchive, visit_logarchive_tracev3_file},
};
use regex::Regex;
use std::path::PathBuf;
use uuid::uuid;

#[test]
fn test_parse_log_monterey() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_monterey.logarchive");
    test_path.push("Persist/000000000000000a.tracev3");

    let data = std::fs::read(&test_path).unwrap();

    let mut firehose = Vec::new();
    let mut simpledump = Vec::new();
    let mut headers_count = 0;
    let mut catalog_process_info_entries = Vec::new();
    let mut statedump = Vec::new();

    let mut reader = ChunksReader::new(&data);
    reader
        .visit(|chunk| match chunk {
            Chunk::Header(_) => headers_count += 1,
            Chunk::Catalog(catalog) => {
                firehose.push(0);
                simpledump.push(0);
                catalog_process_info_entries.push(catalog.catalog_process_info_entries.len());
                statedump.push(0);
            }
            Chunk::Firehose(_) => {
                *firehose.last_mut().unwrap() += 1;
            }
            Chunk::Simpledump(_) => {
                *simpledump.last_mut().unwrap() += 1;
            }
            Chunk::Statedump(_) => {
                *statedump.last_mut().unwrap() += 1;
            }
            _ => {}
        })
        .unwrap();

    assert_eq!(firehose[0], 17);
    assert_eq!(simpledump[0], 383);
    assert_eq!(headers_count, 1);
    assert_eq!(catalog_process_info_entries[0], 17);
    assert_eq!(statedump[0], 0);
}

#[test]
fn test_build_log_monterey() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_monterey.logarchive");

    let mut count = 0;
    visit_logarchive_tracev3_file(&test_path, "Persist/000000000000000a.tracev3", |results| {
        if count == 0 {
            assert_eq!(results.process, Some("/kernel"));
            assert_eq!(results.subsystem, None);
            assert_eq!(results.time, 1651345928766719209.0);
            assert_eq!(results.activity_id, 0);
            assert_eq!(
                results.library,
                Some("/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox")
            );
            assert_eq!(
                results.message().as_str(),
                "2 duplicate reports for Sandbox: MTLCompilerServi(187) deny(1) file-read-metadata /private"
            );
            assert_eq!(results.pid, 0);
            assert_eq!(results.thread_id, 2241);
            assert_eq!(results.category, None);
            assert_eq!(results.log_type, LogType::Error);
            assert_eq!(results.event_type, EventType::Log);
            assert_eq!(results.euid, 0);
            assert_eq!(results.boot_uuid, uuid!("17AB576950394796B7F3CD2C157F4A2F"));
            assert_eq!(results.timezone_name, "New_York");
            assert_eq!(
                results.library_uuid,
                uuid!("7EFAFB8B6CA63090957FC68A6230BC38")
            );
            assert_eq!(
                results.process_uuid,
                uuid!("C342869FFFB93CCEA5A3EA711C1E87F6")
            );
            assert_eq!(results.raw_message(), "%s");
        }
        count += 1;
    })
    .unwrap();

    assert_eq!(count, 322859);
}

#[test]
fn test_parse_all_logs_monterey() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_monterey.logarchive");

    let mut log_data_vec_len = 0;
    let message_re = Regex::new(r"^[\s]*%s\s*$").unwrap();

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

    visit_logarchive(&test_path, |logs| {
        log_data_vec_len += 1;
        let message = logs.message();
        let raw_message = logs.raw_message();

        if message.contains("Failed to get string message from ")
            || message.contains("Unknown shared string message")
        {
            unknown_strings += 1;
        }

        if message.contains("Error: Invalid offset ") {
            invalid_offsets += 1;
        }

        if message.contains("Error: Invalid shared string offset") {
            invalid_shared_string_offsets += 1;
        }

        if message.contains("Unsupported Statedump object") {
            statedump_custom_objects += 1;
        }
        if message.contains("Failed to parse StateDump protobuf")
            || message.contains("Failed to serialize Protobuf HashMap")
        {
            statedump_protocol_buffer += 1;
        }

        if message_re.is_match(raw_message) {
            string_count += 1;
        }

        if message.contains("MTUtilities: WorldClockWidget:")
            && logs.log_type == LogType::Default
        {
            mutilities_worldclock += 1;
        }
        if message.contains("MTUtilities: Returning widget") {
            mutililties_return += 1;
        }
        if message.contains("allowsMapCorrection") {
            location_tracker += 1;
        }
        if message.contains("\"pausesLocationUpdatesAutomatically\":1,") {
            pauses_tracker += 1;
        }
        if message.contains("Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0") {
            dns_counts += 1;
        }
    })
    .unwrap();

    assert_eq!(log_data_vec_len, 2397109);
    assert_eq!(unknown_strings, 531);
    assert_eq!(invalid_offsets, 60);
    assert_eq!(invalid_shared_string_offsets, 309);
    assert_eq!(statedump_custom_objects, 0);
    assert_eq!(statedump_protocol_buffer, 0);
    assert_eq!(string_count, 28196); // Accurate count based on log raw-dump -a <monterey.logarchive> | grep "format:\s*%s$" | sort | uniq -c | sort -n
    // Compat keeps legacy per-file build semantics in src/compat/parser.rs:227-249:
    // build_log creates a fresh OversizeCache for one UnifiedLogData and seeds it only
    // from that file's oversize entries before calling visit_tracev3. The direct rewrite
    // logarchive visitor carries one OversizeCache across the archive, so it resolves two
    // additional WorldClockWidget messages whose oversize payloads are outside their tracev3 file.
    assert_eq!(mutilities_worldclock, 59);
    assert_eq!(mutililties_return, 71);
    assert_eq!(dns_counts, 3196);

    assert_eq!(location_tracker, 298);
    assert_eq!(pauses_tracker, 180); // Accurate count based on log raw-dump -A tests/test_data/system_logs_monterey.logarchive | grep -c pausesLocationUpdatesAutomatically
}
