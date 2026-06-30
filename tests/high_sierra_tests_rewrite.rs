// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
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
fn test_parse_log_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    test_path.push("Persist/0000000000000001.tracev3");
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

    assert_eq!(firehose[0], 172);
    assert_eq!(simpledump[0], 0);
    assert_eq!(headers_count, 1);
    assert_eq!(catalog_process_info_entries[0], 30);
    assert_eq!(statedump[0], 0);
}

#[test]
fn test_build_log_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut count = 0;
    visit_logarchive_tracev3_file(&test_path, "Persist/0000000000000001.tracev3", |results| {
        if count == 0 {
            assert_eq!(results.process, Some("/usr/libexec/opendirectoryd"));
            assert_eq!(results.subsystem, Some("com.apple.opendirectoryd"));
            assert_eq!(results.time, 1624134811546060433.0);
            assert_eq!(results.activity_id, 0);
            assert_eq!(results.library, Some("/usr/libexec/opendirectoryd"));
            assert_eq!(
                results.message().as_str(),
                "opendirectoryd (build 483.700) launched..."
            );
            assert_eq!(results.pid, 59);
            assert_eq!(results.thread_id, 622);
            assert_eq!(results.category, Some("default"));
            assert_eq!(results.log_type, LogType::Default);
            assert_eq!(results.event_type, EventType::Log);
            assert_eq!(results.euid, 0);
            assert_eq!(results.boot_uuid, uuid!("30774817CF1549B0920E1A8E17D47AB5"));
            assert_eq!(results.timezone_name, "Pacific");
            assert_eq!(
                results.process_uuid,
                uuid!("AD43C574A9F73311A4E995237667082A")
            );
            assert_eq!(
                results.library_uuid,
                uuid!("AD43C574A9F73311A4E995237667082A")
            );
            assert_eq!(
                results.raw_message(),
                "opendirectoryd (build %{public}s) launched..."
            );
            assert!(results.evidence.ends_with("0000000000000001.tracev3"));
        }
        count += 1;
    })
    .unwrap();

    assert_eq!(count, 162402);
}

#[test]
fn test_build_log_complex_format_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut count = 0;
    let mut found = false;
    visit_logarchive_tracev3_file(&test_path, "Persist/0000000000000001.tracev3", |result| {
        count += 1;
        let message = result.message();
        if message.as_str()
            == "<PCPersistentTimer: 0x7f8b72c722f0> Calculated minimum fire date [2021-06-19 19:47:59 -0700] (75%) with fire date [2021-06-19 21:51:14 -0700], start date [2021-06-19 13:38:14 -0700], minimum early fire proportion 0.75, power state detection supported: no, in high power state: no, early fire constant interval 0"
            && result.time == 1624135094694359040.0
        {
            assert_eq!(
                result.process,
                Some(
                    "/System/Library/PrivateFrameworks/CalendarNotification.framework/Versions/A/XPCServices/CalNCService.xpc/Contents/MacOS/CalNCService"
                )
            );
            assert_eq!(result.subsystem, Some("com.apple.PersistentConnection"));
            assert_eq!(result.time, 1624135094694359040.0);
            assert_eq!(result.activity_id, 0);
            assert_eq!(
                result.library,
                Some(
                    "/System/Library/PrivateFrameworks/PersistentConnection.framework/Versions/A/PersistentConnection"
                )
            );
            assert_eq!(
                message.as_str(),
                "<PCPersistentTimer: 0x7f8b72c722f0> Calculated minimum fire date [2021-06-19 19:47:59 -0700] (75%) with fire date [2021-06-19 21:51:14 -0700], start date [2021-06-19 13:38:14 -0700], minimum early fire proportion 0.75, power state detection supported: no, in high power state: no, early fire constant interval 0"
            );
            assert_eq!(result.pid, 580);
            assert_eq!(result.thread_id, 8759);
            assert_eq!(
                result.category,
                Some(
                    "persistentTimer.com.apple.CalendarNotification.EKTravelEngine.periodicRefreshTimer"
                )
            );
            assert_eq!(result.log_type, LogType::Default);
            assert_eq!(result.event_type, EventType::Log);
            assert_eq!(result.euid, 501);
            assert_eq!(result.boot_uuid, uuid!("30774817CF1549B0920E1A8E17D47AB5"));
            assert_eq!(result.timezone_name, "Pacific");
            assert_eq!(
                result.process_uuid,
                uuid!("3E78A65047873F8AAFB10EA606B84B5D")
            );
            assert_eq!(
                result.library_uuid,
                uuid!("761AF71A7FBE3374A4A48A38E0D59B6B")
            );
            assert_eq!(
                result.raw_message(),
                "%{public}@ Calculated minimum fire date [%{public}@] (%g%%) with fire date [%{public}@], start date [%{public}@], minimum early fire proportion %g, power state detection supported: %{public}s, in high power state: %{public}s, early fire constant interval %f"
            );
            found = true;
        }
    })
    .unwrap();

    assert_eq!(count, 162402);
    assert!(found, "Did not find message match");
}

#[test]
fn test_build_log_negative_number_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut count = 0;
    let mut found = false;
    visit_logarchive_tracev3_file(&test_path, "Special/0000000000000003.tracev3", |result| {
        count += 1;
        if result.message().as_str()
            == "[BTUserEventAgentController messageTracerEventDriven] PowerSource -2 -2\n"
        {
            assert_eq!(
                result.raw_message(),
                "[BTUserEventAgentController messageTracerEventDriven] PowerSource %f %f\n"
            );
            found = true;
        }
    })
    .unwrap();

    assert_eq!(count, 12058);
    assert!(found, "Did not find negative message match");
}

#[test]
fn test_parse_all_logs_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut log_data_vec_len = 0;
    let mut empty_counter = 0;
    let mut empty_identityservicesd = 0;
    let mut empty_callservicesd = 0;
    let mut empty_configd = 0;
    let mut empty_coreduetd = 0;
    let mut private_entries = 0;
    let mut kernel_entries = 0;
    let mut string_count = 0;

    let message_re = Regex::new(r"^[\s]*%s\s*$").unwrap();

    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;
    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;
    visit_logarchive(&test_path, |logs| {
        log_data_vec_len += 1;
        let message = logs.message();

        if message.is_empty() {
            empty_counter += 1;

            if logs.process == Some("/System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd") {
                empty_callservicesd += 1;
            } else if logs.process == Some("/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd") {
                empty_identityservicesd += 1;
            } else if logs.process == Some("/usr/libexec/configd") {
                empty_configd += 1;
            } else if logs.process == Some("/usr/libexec/coreduetd") {
                empty_coreduetd += 1;
            }
        } else if message.contains("<private>") {
            private_entries += message.matches("<private>").count();
        }
        if message.contains("bytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2") {
            assert_eq!(message.as_str(), "[11 <private> stream, pid: 344] cancelled\n\t[11.1 334B42D96E654481B31C3A452BFB96B7 <private>.49154<-><private>]\n\tConnected Path: satisfied (Path is satisfied), interface: en0, ipv4, dns\n\tDuration: 0.115s, DNS @0.000s took 0.002s, TCP @0.002s took 0.014s\n\tbytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2");
            assert_eq!(logs.raw_message(), "[%{public}s %{private}@ %{public}@] cancelled\n\t[%s %{uuid_t}.16P %{private,network:in_addr}d.%d<->%{private,network:sockaddr}.*P]\n\tConnected Path: %@\n\tDuration: %u.%03us, DNS @%u.%03us took %u.%03us, %{public}s @%u.%03us took %u.%03us\n\tbytes in/out: %llu/%llu, packets in/out: %llu/%llu, rtt: %u.%03us, retransmitted packets: %llu, out-of-order packets: %u");
        }
        if logs.process == Some("/kernel") && logs.library == Some("/kernel") {
            kernel_entries += 1;
        }

        if message_re.is_match(logs.raw_message()) {
            string_count += 1;
        }

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
    })
    .unwrap();

    assert_eq!(log_data_vec_len, 569796);

    // Opening system_logs_high_sierra.logarchive in Console.app and searching for the processes (configd, coreduetd, identityservicesd, callservicesd) above should return the exact same number of empty entries as below
    assert_eq!(empty_counter, 107);
    assert_eq!(empty_identityservicesd, 24);
    assert_eq!(empty_configd, 64);
    assert_eq!(empty_coreduetd, 1);
    assert_eq!(empty_callservicesd, 18);
    assert_eq!(private_entries, 88352);
    assert_eq!(kernel_entries, 389);
    assert_eq!(string_count, 23982);

    assert_eq!(unknown_strings, 0);
    assert_eq!(invalid_offsets, 3);
    assert_eq!(invalid_shared_string_offsets, 0);
    assert_eq!(statedump_custom_objects, 0);
    assert_eq!(statedump_protocol_buffer, 0);
}
