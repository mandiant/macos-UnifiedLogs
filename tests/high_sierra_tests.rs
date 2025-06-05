// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::{fs::File, path::PathBuf};

use macos_unifiedlogs::{
    filesystem::LogarchiveProvider,
    parser::{build_log, collect_timesync, parse_log},
    traits::FileProvider,
    unified_log::{EventType, LogType, UnifiedLogData},
};
use regex::Regex;

fn collect_logs(provider: &dyn FileProvider) -> Vec<UnifiedLogData> {
    provider
        .tracev3_files()
        .map(|mut file| parse_log(file.reader()).unwrap())
        .collect()
}

#[test]
fn test_parse_log_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    test_path.push("Persist/0000000000000001.tracev3");
    let handle = File::open(test_path).unwrap();
    let log_data = parse_log(handle).unwrap();

    assert_eq!(log_data.catalog_data[0].firehose.len(), 172);
    assert_eq!(log_data.catalog_data[0].simpledump.len(), 0);
    assert_eq!(log_data.header.len(), 1);
    assert_eq!(
        log_data.catalog_data[0]
            .catalog
            .catalog_process_info_entries
            .len(),
        30
    );
    assert_eq!(log_data.catalog_data[0].statedump.len(), 0);
}

#[test]
fn test_build_log_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/0000000000000001.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();
    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(&log_data, &mut provider, &timesync_data, exclude_missing);
    assert_eq!(results.len(), 162402);
    assert_eq!(results[0].process, "/usr/libexec/opendirectoryd");
    assert_eq!(results[0].subsystem, "com.apple.opendirectoryd");
    assert_eq!(results[0].time, 1624134811546060433.0);
    assert_eq!(results[0].activity_id, 0);
    assert_eq!(results[0].library, "/usr/libexec/opendirectoryd");
    assert_eq!(
        results[0].message,
        "opendirectoryd (build 483.700) launched..."
    );
    assert_eq!(results[0].pid, 59);
    assert_eq!(results[0].thread_id, 622);
    assert_eq!(results[0].category, "default");
    assert_eq!(results[0].log_type, LogType::Default);
    assert_eq!(results[0].event_type, EventType::Log);
    assert_eq!(results[0].euid, 0);
    assert_eq!(results[0].boot_uuid, "30774817CF1549B0920E1A8E17D47AB5");
    assert_eq!(results[0].timezone_name, "Pacific");
    assert_eq!(results[0].process_uuid, "AD43C574A9F73311A4E995237667082A");
    assert_eq!(results[0].library_uuid, "AD43C574A9F73311A4E995237667082A");
    assert_eq!(
        results[0].raw_message,
        "opendirectoryd (build %{public}s) launched..."
    );
}

#[test]
fn test_build_log_complex_format_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/0000000000000001.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();
    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(&log_data, &mut provider, &timesync_data, exclude_missing);
    assert_eq!(results.len(), 162402);

    for result in &results {
        if result.message
            == "<PCPersistentTimer: 0x7f8b72c722f0> Calculated minimum fire date [2021-06-19 19:47:59 -0700] (75%) with fire date [2021-06-19 21:51:14 -0700], start date [2021-06-19 13:38:14 -0700], minimum early fire proportion 0.75, power state detection supported: no, in high power state: no, early fire constant interval 0"
        {
            assert_eq!(
                result.process,
                "/System/Library/PrivateFrameworks/CalendarNotification.framework/Versions/A/XPCServices/CalNCService.xpc/Contents/MacOS/CalNCService"
            );
            assert_eq!(result.subsystem, "com.apple.PersistentConnection");
            assert_eq!(result.time, 1624135094694359040.0);
            assert_eq!(result.activity_id, 0);
            assert_eq!(
                result.library,
                "/System/Library/PrivateFrameworks/PersistentConnection.framework/Versions/A/PersistentConnection"
            );
            assert_eq!(
                result.message,
                "<PCPersistentTimer: 0x7f8b72c722f0> Calculated minimum fire date [2021-06-19 19:47:59 -0700] (75%) with fire date [2021-06-19 21:51:14 -0700], start date [2021-06-19 13:38:14 -0700], minimum early fire proportion 0.75, power state detection supported: no, in high power state: no, early fire constant interval 0"
            );
            assert_eq!(result.pid, 580);
            assert_eq!(result.thread_id, 8759);
            assert_eq!(
                result.category,
                "persistentTimer.com.apple.CalendarNotification.EKTravelEngine.periodicRefreshTimer"
            );
            assert_eq!(result.log_type, LogType::Default);
            assert_eq!(result.event_type, EventType::Log);
            assert_eq!(result.euid, 501);
            assert_eq!(result.boot_uuid, "30774817CF1549B0920E1A8E17D47AB5");
            assert_eq!(result.timezone_name, "Pacific");
            assert_eq!(result.process_uuid, "3E78A65047873F8AAFB10EA606B84B5D");
            assert_eq!(result.library_uuid, "761AF71A7FBE3374A4A48A38E0D59B6B");
            assert_eq!(
                result.raw_message,
                "%{public}@ Calculated minimum fire date [%{public}@] (%g%%) with fire date [%{public}@], start date [%{public}@], minimum early fire proportion %g, power state detection supported: %{public}s, in high power state: %{public}s, early fire constant interval %f"
            );
            return;
        }
    }
    panic!("Did not find message match")
}

#[test]
fn test_build_log_negative_number_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Special/0000000000000003.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(&log_data, &mut provider, &timesync_data, exclude_missing);
    assert_eq!(results.len(), 12058);

    for result in &results {
        if result.message
            == "[BTUserEventAgentController messageTracerEventDriven] PowerSource -2 -2\n"
        {
            assert_eq!(
                result.raw_message,
                "[BTUserEventAgentController messageTracerEventDriven] PowerSource %f %f\n"
            );
            return;
        }
    }
    panic!("Did not find negative message match")
}

#[test]
fn test_parse_all_logs_high_sierra() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_high_sierra.logarchive");
    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);
    let mut log_data_vec = Vec::new();

    let exclude_missing = false;
    for logs in &log_data {
        let (mut data, _) = build_log(&logs, &mut provider, &timesync_data, exclude_missing);
        log_data_vec.append(&mut data);
    }
    assert_eq!(log_data_vec.len(), 569796);

    let mut empty_counter = 0;
    let mut empty_identityservicesd = 0;
    let mut empty_callservicesd = 0;
    let mut empty_configd = 0;
    let mut empty_coreduetd = 0;
    let mut private_entries = 0;
    let mut kernel_entries = 0;
    let mut string_count = 0;

    let message_re = Regex::new(r"^[\s]*%s\s*$").unwrap();

    for logs in &log_data_vec {
        if logs.message == "" {
            empty_counter += 1;

            if logs.process
                == "/System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd"
            {
                empty_callservicesd += 1;
            } else if logs.process
                == "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd"
            {
                empty_identityservicesd += 1;
            } else if logs.process == "/usr/libexec/configd" {
                empty_configd += 1;
            } else if logs.process == "/usr/libexec/coreduetd" {
                empty_coreduetd += 1;
            }
        } else if logs.message.contains("<private>") {
            private_entries += logs.message.matches("<private>").count();
        }
        if logs.message.contains("bytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2") {
            assert_eq!(logs.message, "[11 <private> stream, pid: 344] cancelled\n\t[11.1 334B42D96E654481B31C3A452BFB96B7 <private>.49154<-><private>]\n\tConnected Path: satisfied (Path is satisfied), interface: en0, ipv4, dns\n\tDuration: 0.115s, DNS @0.000s took 0.002s, TCP @0.002s took 0.014s\n\tbytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2");
            assert_eq!(logs.raw_message, "[%{public}s %{private}@ %{public}@] cancelled\n\t[%s %{uuid_t}.16P %{private,network:in_addr}d.%d<->%{private,network:sockaddr}.*P]\n\tConnected Path: %@\n\tDuration: %u.%03us, DNS @%u.%03us took %u.%03us, %{public}s @%u.%03us took %u.%03us\n\tbytes in/out: %llu/%llu, packets in/out: %llu/%llu, rtt: %u.%03us, retransmitted packets: %llu, out-of-order packets: %u");
        }
        if logs.process == "/kernel" && logs.library == "/kernel" {
            kernel_entries += 1;
        }

        if message_re.is_match(&logs.raw_message) {
            string_count += 1;
        }
    }
    // Opening system_logs_high_sierra.logarchive in Console.app and searching for the processes (configd, coreduetd, identityservicesd, callservicesd) above should return the exact same number of empty entries as below
    assert_eq!(empty_counter, 107);
    assert_eq!(empty_identityservicesd, 24);
    assert_eq!(empty_configd, 64);
    assert_eq!(empty_coreduetd, 1);
    assert_eq!(empty_callservicesd, 18);
    assert_eq!(private_entries, 88352);
    assert_eq!(kernel_entries, 389);
    assert_eq!(string_count, 23982);

    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;
    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;
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
    }
    assert_eq!(unknown_strings, 0);
    assert_eq!(invalid_offsets, 3);
    assert_eq!(invalid_shared_string_offsets, 0);
    assert_eq!(statedump_custom_objects, 0);
    assert_eq!(statedump_protocol_buffer, 0);
}
