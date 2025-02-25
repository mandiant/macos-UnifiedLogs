// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::{fs::File, path::PathBuf};

use macos_unifiedlogs::{
    filesystem::LogarchiveProvider,
    parser::{build_log, collect_shared_strings, collect_strings, collect_timesync, parse_log},
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

fn is_signpost(log_type: LogType) -> bool {
    match log_type {
        LogType::ProcessSignpostEvent
        | LogType::ProcessSignpostStart
        | LogType::ProcessSignpostEnd
        | LogType::SystemSignpostEvent
        | LogType::SystemSignpostStart
        | LogType::SystemSignpostEnd
        | LogType::ThreadSignpostEvent
        | LogType::ThreadSignpostStart
        | LogType::ThreadSignpostEnd => true,
        LogType::Debug
        | LogType::Info
        | LogType::Default
        | LogType::Error
        | LogType::Fault
        | LogType::Create
        | LogType::Useraction
        | LogType::Simpledump
        | LogType::Statedump
        | LogType::Loss => false,
    }
}

#[test]
fn test_parse_log_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");
    test_path.push("Persist/0000000000000004.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();
    let log_data = parse_log(handle).unwrap();

    assert_eq!(log_data.catalog_data[0].firehose.len(), 82);
    assert_eq!(log_data.catalog_data[0].simpledump.len(), 0);
    assert_eq!(log_data.header.len(), 1);
    assert_eq!(
        log_data.catalog_data[0]
            .catalog
            .catalog_process_info_entries
            .len(),
        45
    );
    assert_eq!(log_data.catalog_data[0].statedump.len(), 0);
}

#[test]
fn test_big_sur_livedata() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("logdata.LiveData.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();
    let results = parse_log(handle).unwrap();
    test_path.pop();

    let exclude_missing = false;
    let (data, _) = build_log(
        &results,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    assert_eq!(data.len(), 101566);

    for results in data {
        // Test for a log message that uses a firehose_header_timestamp with a value of zero
        if results.message == "TimeSyncTime is mach_absolute_time nanoseconds\n" {
            assert_eq!(
                results.message,
                "TimeSyncTime is mach_absolute_time nanoseconds\n"
            );
            assert_eq!(results.activity_id, 0);
            assert_eq!(results.thread_id, 116);
            assert_eq!(results.euid, 0);
            assert_eq!(results.pid, 0);
            assert_eq!(
                results.library,
                "/System/Library/Extensions/IOTimeSyncFamily.kext/Contents/MacOS/IOTimeSyncFamily"
            );
            assert_eq!(results.subsystem, String::new());
            assert_eq!(results.category, String::new());
            assert_eq!(results.event_type, EventType::Log);
            assert_eq!(results.log_type, LogType::Info);
            assert_eq!(results.process, "/kernel");
            assert_eq!(results.time, 1642304801596413351.0);
            assert_eq!(results.boot_uuid, "A2A9017676CF421C84DC9BBD6263FEE7");
            assert_eq!(results.timezone_name, "Pacific");
        }
    }
}

#[test]
fn test_build_log_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/0000000000000004.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(
        &log_data,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    assert_eq!(results.len(), 110953);
    assert_eq!(results[0].process, "/usr/libexec/opendirectoryd");
    assert_eq!(results[0].subsystem, "com.apple.opendirectoryd");
    assert_eq!(results[0].time, 1642303933964503310.0);
    assert_eq!(results[0].activity_id, 0);
    assert_eq!(results[0].library, "/usr/libexec/opendirectoryd");
    assert_eq!(
        results[0].message,
        "opendirectoryd (build 796.100) launched..."
    );
    assert_eq!(results[0].pid, 105);
    assert_eq!(results[0].thread_id, 670);
    assert_eq!(results[0].category, "default");
    assert_eq!(results[0].log_type, LogType::Default);
    assert_eq!(results[0].event_type, EventType::Log);
    assert_eq!(results[0].euid, 0);
    assert_eq!(results[0].boot_uuid, "AACFB573E87545CE98B893D132766A46");
    assert_eq!(results[0].timezone_name, "Pacific");
    assert_eq!(results[0].library_uuid, "B736DF1625F538248E9527A8CEC4991E");
    assert_eq!(results[0].process_uuid, "B736DF1625F538248E9527A8CEC4991E");
    assert_eq!(
        results[0].raw_message,
        "opendirectoryd (build %{public}s) launched..."
    );
}

#[test]
fn test_parse_all_logs_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);

    let mut log_data_vec: Vec<LogData> = Vec::new();
    let exclude_missing = false;
    for logs in &log_data {
        let (mut data, _) = build_log(
            &logs,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            exclude_missing,
        );
        log_data_vec.append(&mut data);
    }
    // Run: "log raw-dump -a macos-unifiedlogs/tests/test_data/system_logs_big_sur.logarchive"
    // total log entries: 747,294
    // Add Statedump log entries: 322
    // Total log entries: 747,616
    assert_eq!(log_data_vec.len(), 747616);

    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;
    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;

    let mut found_precision_string = false;
    let mut statedump_count = 0;
    let mut signpost_count = 0;

    let mut default_type = 0;
    let mut info_type = 0;
    let mut error_type = 0;
    let mut create_type = 0;
    let mut debug_type = 0;
    let mut useraction_type = 0;
    let mut fault_type = 0;
    let mut loss_type = 0;

    let mut string_count = 0;
    let message_re = Regex::new(r"^[\s]*%s\s*$").unwrap();
    let mut empty_format_count = 0;
    let mut sock_count = 0;

    // Breakdown log entries by smaller types to ensure count is accurate
    for logs in &log_data_vec {
        if logs.message.contains("Failed to get string message from ")
            || logs.message.contains("Unknown shared string message")
        {
            unknown_strings += 1;
        } else if logs.message.contains("Error: Invalid offset ") {
            invalid_offsets += 1;
        } else if logs.message.contains("Error: Invalid shared string offset") {
            invalid_shared_string_offsets += 1;
        } else if logs.message.contains("Unsupported Statedump object") {
            statedump_custom_objects += 1;
        } else if logs.message.contains("Failed to parse StateDump protobuf")
            || logs
                .message
                .contains("Failed to serialize Protobuf HashMap")
        {
            statedump_protocol_buffer += 1;
        } else if logs.message
            == r##"#32EC4B64 [AssetCacheLocatorService.queue] sending POST [327]{"locator-tag":"#32ec4b64","local-addresses":["192.168.101.144"],"ranked-results":true,"locator-software":[{"build":"20G224","type":"system","name":"macOS","version":"11.6.1"},{"id":"com.apple.AssetCacheLocatorService","executable":"AssetCacheLocatorService","type":"bundle","name":"AssetCacheLocatorService","version":"118"}]} to https://lcdn-locator.apple.com/lcdn/locate"##
        {
            found_precision_string = true;
        }

        if logs.event_type == EventType::Statedump {
            statedump_count += 1;
        } else if logs.event_type == EventType::Signpost {
            signpost_count += 1;
        } else if logs.log_type == LogType::Default {
            default_type += 1;
        } else if logs.log_type == LogType::Info {
            info_type += 1;
        } else if logs.log_type == LogType::Error {
            error_type += 1
        } else if logs.log_type == LogType::Create {
            create_type += 1;
        } else if logs.log_type == LogType::Debug {
            debug_type += 1;
        } else if logs.log_type == LogType::Useraction {
            useraction_type += 1;
        } else if logs.log_type == LogType::Fault {
            fault_type += 1;
        } else if logs.event_type == EventType::Loss {
            loss_type += 1;
        }

        if message_re.is_match(&logs.raw_message) {
            string_count += 1;
        }

        if logs.raw_message.is_empty()
            && logs.message.is_empty()
            && logs.event_type != EventType::Loss
        {
            empty_format_count += 1
        }

        if logs.message.contains("nw_resolver_create_dns_getaddrinfo_locked_block_invoke [C1] Got DNS result type NoAddress ifindex=0 configuration.ls.apple.com configuration.ls.apple.com. ::") {
            sock_count += 1;
        }
    }

    assert_eq!(unknown_strings, 0);
    assert_eq!(invalid_offsets, 54);
    assert_eq!(invalid_shared_string_offsets, 0);
    assert_eq!(statedump_custom_objects, 2);
    assert_eq!(statedump_protocol_buffer, 0);
    assert_eq!(found_precision_string, true);

    assert_eq!(statedump_count, 322);
    assert_eq!(signpost_count, 50665);
    assert_eq!(string_count, 11764);
    assert_eq!(empty_format_count, 56);
    assert_eq!(default_type, 462518);
    assert_eq!(info_type, 114540);
    assert_eq!(error_type, 29132);
    assert_eq!(create_type, 87831);
    assert_eq!(debug_type, 1908);
    assert_eq!(useraction_type, 15);
    assert_eq!(fault_type, 680);
    assert_eq!(loss_type, 5);
    assert_eq!(sock_count, 2);
}

#[test]
fn test_parse_all_persist_logs_with_network_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);

    let mut log_data_vec: Vec<LogData> = Vec::new();
    let exclude_missing = false;

    for logs in &log_data {
        let (mut data, _) = build_log(
            &logs,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            exclude_missing,
        );
        log_data_vec.append(&mut data);
    }

    let mut messages_containing_network = 0;
    let mut default_type = 0;
    let mut info_type = 0;
    let mut error_type = 0;
    let mut create_type = 0;
    let mut state_simple_dump = 0;
    let mut signpost = 0;

    let mut network_message_uuid = false;

    // Check all logs that contain the word "network"
    for logs in &log_data_vec {
        if logs.message.to_lowercase().contains("network") {
            if logs.log_type == LogType::Default {
                default_type += 1;
                if logs
                    .message
                    .contains("7C10C1EF-1B86-494F-800D-C769A89172C1")
                {
                    // The Console.app does not show the following network message. This might be a bug in the app?
                    // But the log command shows it correctly
                    // This is the only message that contains the UUID 7C10C1EF-1B86-494F-800D-C769A89172C1
                    /*
                    tp 2264 + 286:      log default (has_current_aid, shared_cache, has_subsystem)
                    thread:         00000000000036ea
                    time:           +95.856s
                    walltime:       1648611808 - 2022-03-29 20:43:28 (Tuesday)
                    cur_aid:        8000000000007840
                    location:       pc:0x405faf5 fmt:0x4613cd0
                    image uuid:     6D702F3B-34C0-3809-8CEC-1D59D58CF8BB
                    image path:     /usr/lib/libnetwork.dylib
                    format:         [C%u %{public,uuid_t}.16P %{public}s %{public}s] start
                    subsystem:      50 com.apple.network.connection
                    [C6 527C4884-E24B-425C-B3AB-AA91DCD23FCE configuration.ls.apple.com:443 tcp, url hash: 8feb6d24, tls, context: com.apple.CFNetwork.NSURLSession.{7C10C1EF-1B86-494F-800D-C769A89172C1}{(null)}{Y}{1}, proc: 21B380F4-D50C-3463-9CAF-46BB2178258B] start
                     */
                    network_message_uuid = true;
                }
            } else if logs.log_type == LogType::Info {
                info_type += 1;
            } else if logs.log_type == LogType::Error {
                error_type += 1
            } else if logs.log_type == LogType::Create {
                create_type += 1;
                // We are basing these counts on the Cosole.app tool
                // Console.app skips Activity event logs
                continue;
            } else if logs.event_type == EventType::Simpledump
                || logs.event_type == EventType::Statedump
            {
                // We are basing these counts on the Cosole.app tool
                // Console.app skips Simple and State dump event logs
                state_simple_dump += 1;
                continue;
            } else if is_signpost(logs.log_type) {
                // We are basing these counts on the Cosole.app tool
                // Console.app skips Signpost event logs
                signpost += 1;
                continue;
            }
            messages_containing_network += 1;
        }
    }
    assert_eq!(messages_containing_network, 9173);
    // Console.app is missing a log entry. The log command shows the entry
    assert_eq!(default_type, 8320);
    assert_eq!(network_message_uuid, true);

    assert_eq!(info_type, 638);
    assert_eq!(error_type, 215);
    assert_eq!(create_type, 687);
    assert_eq!(state_simple_dump, 34);
    assert_eq!(signpost, 62);
}

#[test]
fn test_parse_all_logs_private_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur_private_enabled.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);

    let mut log_data_vec: Vec<LogData> = Vec::new();
    let exclude_missing = false;
    for logs in &log_data {
        let (mut data, _) = build_log(
            &logs,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            exclude_missing,
        );
        log_data_vec.append(&mut data);
    }
    assert_eq!(log_data_vec.len(), 887890);

    let mut empty_counter = 0;
    let mut not_found = 0;
    let mut staff_count = 0;
    for logs in log_data_vec {
        if logs.message == "" {
            empty_counter += 1;
        }
        if logs.message.contains("<not found>") {
            println!("{}", logs.message);
            not_found += 1;
        }
        if logs.message.contains("group: staff@/Local/Default") {
            staff_count += 1;
        }
    }
    assert_eq!(not_found, 0);
    assert_eq!(staff_count, 4);
    assert_eq!(empty_counter, 596);
}

// Test for logs that have same public data in private
#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);

    let mut log_data_vec: Vec<LogData> = Vec::new();
    let exclude_missing = false;

    for logs in &log_data {
        let (mut data, _) = build_log(
            &logs,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            exclude_missing,
        );
        log_data_vec.append(&mut data);
    }
    assert_eq!(log_data_vec.len(), 1287628);

    let mut not_found = 0;
    let mut user_not_found = 0;
    let mut mobile_not_found = 0;
    let mut bssid_count = 0;
    let mut dns_query_count = 0;
    let mut bofa_count = 0;

    for logs in log_data_vec {
        if logs.message.contains("<not found>") {
            not_found += 1;
        }
        if logs.message.contains("user: -1 <not found>") {
            user_not_found += 1;
        }

        if logs
            .message
            .contains("refreshing: details, reason: expired, user: mobile <not found>")
        {
            mobile_not_found += 1;
        }

        if logs.message.contains("BSSID 00:00:00:00:00:00") {
            bssid_count += 1;
        }

        if logs.message.contains("https://doh.dns.apple.com/dns-query") {
            dns_query_count += 1;
        }

        if logs.message.contains("bankofamerica") {
            bofa_count += 1;
        }
    }
    assert_eq!(not_found, 5);
    assert_eq!(user_not_found, 2);
    assert_eq!(mobile_not_found, 1);
    assert_eq!(bssid_count, 39);
    assert_eq!(dns_query_count, 41);
    assert_eq!(bofa_count, 573);
}

#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur_single_file() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/0000000000000009.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(
        &log_data,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    assert_eq!(results.len(), 91567);

    let mut hex_count = 0;
    let mut dns = 0;
    let mut public_private_mixture = false;
    for result in results {
        if result.message.contains("7FAE25804F50") {
            hex_count += 1;
        }
        if result.subsystem.contains(".mdns") {
            dns += 1;
        }
        // 7FAE25B0E420 is half public and half private
        // B0E420 exists in public data but is copied/prepended to the private data.
        // 7FAE25 only exists in private data
        if result.message
            == "os_transaction created: (7FAE25B0E420) CLLS:0x7fae23628160.LocationFine"
        {
            public_private_mixture = true
        }
    }

    assert_eq!(hex_count, 4);
    assert_eq!(dns, 801);
    assert_eq!(public_private_mixture, true);
}

// We are able to get 2238 entries from this special tracev3 file. But log command only gets 231
#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur_special_file() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Special/0000000000000008.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(
        &log_data,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    assert_eq!(results.len(), 2238);

    let mut statedump = 0;
    let mut default = 0;
    let mut fault = 0;
    let mut info = 0;
    let mut error = 0;

    for result in results {
        if result.event_type == EventType::Statedump {
            statedump += 1;
        } else if result.log_type == LogType::Default {
            default += 1;
        } else if result.log_type == LogType::Fault {
            fault += 1;
        } else if result.log_type == LogType::Info {
            info += 1;
        } else if result.log_type == LogType::Error {
            error += 1;
        }
    }

    assert_eq!(statedump, 1);
    assert_eq!(default, 1972);
    assert_eq!(fault, 32);
    assert_eq!(info, 41);
    assert_eq!(error, 192);
}

#[test]
fn test_big_sur_missing_oversize_strings() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    // livedata may have oversize string data in other tracev3 on disk
    test_path.push("logdata.LiveData.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();
    test_path.pop();

    let exclude_missing = false;
    let (data, _) = build_log(
        &log_data,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    assert_eq!(data.len(), 101566);

    let mut missing_strings = 0;
    for results in data {
        if results.message.contains("<Missing message data>") {
            missing_strings = missing_strings + 1;
        }
    }
    // There should be only 29 entries that have actual missing data
    // 23 strings are in other trave3 files. 23 + 29 = 52
    assert_eq!(missing_strings, 52);
}

#[test]
fn test_big_sur_oversize_strings_in_another_file() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let provider = LogarchiveProvider::new(test_path.as_path());
    let string_results = collect_strings(&provider).unwrap();
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    // Get most recent Persist tracev3 file could contain oversize log entries
    test_path.push("Persist/0000000000000005.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();

    let mut log_data = parse_log(handle).unwrap();
    test_path.pop();
    test_path.pop();

    // Get most recent Special tracev3 file that could contain oversize log entries
    test_path.push("Special/0000000000000005.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();
    let mut special_data = parse_log(handle).unwrap();
    test_path.pop();
    test_path.pop();

    test_path.push("logdata.LiveData.tracev3");
    let handle = File::open(test_path.as_path()).unwrap();
    let mut results = parse_log(handle).unwrap();
    test_path.pop();

    results.oversize.append(&mut log_data.oversize);
    results.oversize.append(&mut special_data.oversize);

    let exclude_missing = false;
    let (data, _) = build_log(
        &results,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    assert_eq!(data.len(), 101566);

    let mut missing_strings = 0;
    for results in data {
        if results.message.contains("<Missing message data>") {
            missing_strings = missing_strings + 1;
        }
    }
    // 29 log entries actually have missing data
    // Apple displays as: <decode: missing data>
    assert_eq!(missing_strings, 29);
}
