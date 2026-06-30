// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use macos_unifiedlogs::{
    chunk::{Chunk, ChunksReader},
    log_entry::{EventType, LogType},
    logarchive::{visit_logarchive, visit_logarchive_tracev3_file, visit_logarchive_tracev3_files},
};
use regex::Regex;
use std::path::PathBuf;
use uuid::uuid;

#[test]
fn test_parse_log_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");
    test_path.push("Persist/0000000000000004.tracev3");

    let data = std::fs::read(&test_path).unwrap();

    let mut firehose = Vec::new();
    let mut simpledump = Vec::new();
    let mut headers_count = 0;
    let mut catalog_process_info_entries = Vec::new();
    let mut statedump = Vec::new();
    let mut chunks_count = 0;

    let mut reader = ChunksReader::new(&data);
    reader
        .visit(|chunk| {
            match chunk {
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
            };
            chunks_count += 1;
        })
        .unwrap();

    assert_eq!(chunks_count, 3446);
    assert_eq!(firehose[0], 82);
    assert_eq!(simpledump[0], 0);
    assert_eq!(headers_count, 1);
    assert_eq!(catalog_process_info_entries[0], 45);
    assert_eq!(statedump[0], 0);
}

#[test]
fn test_big_sur_livedata() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut count = 0;
    visit_logarchive_tracev3_file(&test_path, "logdata.LiveData.tracev3", |results| {
        count += 1;

        let message = results.message();
        if message.as_str() == "TimeSyncTime is mach_absolute_time nanoseconds\n" {
            assert_eq!(
                message.as_str(),
                "TimeSyncTime is mach_absolute_time nanoseconds\n"
            );
            assert_eq!(results.activity_id, 0);
            assert_eq!(results.thread_id, 116);
            assert_eq!(results.euid, 0);
            assert_eq!(results.pid, 0);
            assert_eq!(
                results.library,
                Some(
                    "/System/Library/Extensions/IOTimeSyncFamily.kext/Contents/MacOS/IOTimeSyncFamily"
                )
            );
            assert_eq!(results.subsystem, None);
            assert_eq!(results.category, None);
            assert_eq!(results.event_type, EventType::Log);
            assert_eq!(results.log_type, LogType::Info);
            assert_eq!(results.process, Some("/kernel"));
            assert_eq!(results.time, 1642304801596413351.0);
            assert_eq!(results.boot_uuid, uuid!("A2A9017676CF421C84DC9BBD6263FEE7"));
            assert_eq!(results.timezone_name, "Pacific");
        }
    })
    .unwrap();

    assert_eq!(count, 101566);
}

#[test]
fn test_build_log_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut count = 0;
    visit_logarchive_tracev3_file(&test_path, "Persist/0000000000000004.tracev3", |results| {
        if count == 0 {
            assert_eq!(results.process, Some("/usr/libexec/opendirectoryd"));
            assert_eq!(results.subsystem, Some("com.apple.opendirectoryd"));
            assert_eq!(results.time, 1642303933964503310.0);
            assert_eq!(results.activity_id, 0);
            assert_eq!(results.library, Some("/usr/libexec/opendirectoryd"));
            assert_eq!(
                results.message().as_str(),
                "opendirectoryd (build 796.100) launched..."
            );
            assert_eq!(results.pid, 105);
            assert_eq!(results.thread_id, 670);
            assert_eq!(results.category, Some("default"));
            assert_eq!(results.log_type, LogType::Default);
            assert_eq!(results.event_type, EventType::Log);
            assert_eq!(results.euid, 0);
            assert_eq!(results.boot_uuid, uuid!("AACFB573E87545CE98B893D132766A46"));
            assert_eq!(results.timezone_name, "Pacific");
            assert_eq!(
                results.library_uuid,
                uuid!("B736DF1625F538248E9527A8CEC4991E")
            );
            assert_eq!(
                results.process_uuid,
                uuid!("B736DF1625F538248E9527A8CEC4991E")
            );
            assert_eq!(
                results.raw_message(),
                "opendirectoryd (build %{public}s) launched..."
            );
        }
        count += 1;
    })
    .unwrap();

    assert_eq!(count, 110953);
}

#[test]
fn test_parse_all_logs_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut log_data_vec_len = 0;
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
    let mut location_harvest_count = 0;
    let mut parent_activity = 0;
    let mut no_such_file_or_directory = 0;

    // Breakdown log entries by smaller types to ensure count is accurate
    visit_logarchive(&test_path, |logs| {
        log_data_vec_len += 1;
        let message = logs.message();
        let raw_message = logs.raw_message();

        if message.contains("Failed to get string message from ")
            || message.contains("Unknown shared string message")
        {
            unknown_strings += 1;
        } else if message.contains("Error: Invalid offset ") {
            invalid_offsets += 1;
        } else if message.contains("Error: Invalid shared string offset") {
            invalid_shared_string_offsets += 1;
        } else if message.contains("Unsupported Statedump object") {
            statedump_custom_objects += 1;
        } else if message.contains("Failed to parse StateDump protobuf")
            || message.contains("Failed to serialize Protobuf HashMap")
        {
            statedump_protocol_buffer += 1;
        } else if message.as_str()
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

        if message.contains("\"subHarvester\":\"Trace\"") {
            location_harvest_count += 1;
        }

        if message_re.is_match(raw_message) {
            string_count += 1;
        }

        if raw_message.is_empty() && message.is_empty() && logs.event_type != EventType::Loss {
            empty_format_count += 1
        }

        if message.contains("nw_resolver_create_dns_getaddrinfo_locked_block_invoke [C1] Got DNS result type NoAddress ifindex=0 configuration.ls.apple.com configuration.ls.apple.com. ::") {
            sock_count += 1;
        }

        if logs.parent_activity_id == Some(208) {
            parent_activity += 1;
        }

        if message.contains("No such file or directory") {
            no_such_file_or_directory += 1;
        }
    })
    .unwrap();

    // Run: "log raw-dump -a macos-unifiedlogs/tests/test_data/system_logs_big_sur.logarchive"
    // total log entries: 747,294
    // Add Statedump log entries: 322
    // Total log entries: 747,616
    assert_eq!(log_data_vec_len, 747616);
    assert_eq!(unknown_strings, 0);
    assert_eq!(invalid_offsets, 54);
    assert_eq!(invalid_shared_string_offsets, 0);
    assert_eq!(statedump_custom_objects, 0);
    assert_eq!(statedump_protocol_buffer, 0);
    assert!(found_precision_string);

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
    assert_eq!(location_harvest_count, 11);
    assert_eq!(parent_activity, 5);
    assert_eq!(no_such_file_or_directory, 1728)
}

#[test]
fn test_parse_all_persist_logs_with_network_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut messages_containing_network = 0;
    let mut default_type = 0;
    let mut info_type = 0;
    let mut error_type = 0;
    let mut create_type = 0;
    let mut state_simple_dump = 0;
    let mut signpost = 0;

    let mut network_message_uuid = false;

    // Check all logs that contain the word "network"
    visit_logarchive(&test_path, |logs| {
        let message = logs.message();
        if message.to_lowercase().contains("network") {
            if logs.log_type == LogType::Default {
                default_type += 1;
                if message.contains("7C10C1EF-1B86-494F-800D-C769A89172C1") {
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
                return;
            } else if logs.event_type == EventType::Simpledump
                || logs.event_type == EventType::Statedump
            {
                state_simple_dump += 1;
                // We are basing these counts on the Cosole.app tool
                // Console.app skips Simple and State dump event logs
                return;
            } else if logs.log_type.is_signpost() {
                signpost += 1;
                // We are basing these counts on the Cosole.app tool
                // Console.app skips Signpost event logs
                return;
            }
            messages_containing_network += 1;
        }
    })
    .unwrap();

    assert_eq!(messages_containing_network, 9173);
    // Console.app is missing a log entry. The log command shows the entry
    assert_eq!(default_type, 8320);
    assert!(network_message_uuid);

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

    let mut log_data_vec_len = 0;
    let mut empty_counter = 0;
    let mut not_found = 0;
    let mut staff_count = 0;
    visit_logarchive(&test_path, |logs| {
        log_data_vec_len += 1;
        let message = logs.message();
        if message.is_empty() {
            empty_counter += 1;
        }
        if message.contains("<not found>") {
            not_found += 1;
        }
        if message.contains("group: staff@/Local/Default") {
            staff_count += 1;
        }
    })
    .unwrap();

    assert_eq!(log_data_vec_len, 887890);
    assert_eq!(not_found, 0);
    assert_eq!(staff_count, 4);
    assert_eq!(empty_counter, 596);
}

// Test for logs that have same public data in private
#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive");

    let mut log_data_vec_len = 0;
    let mut not_found = 0;
    let mut user_not_found = 0;
    let mut mobile_not_found = 0;
    let mut bssid_count = 0;
    let mut dns_query_count = 0;
    let mut bofa_count = 0;

    visit_logarchive(&test_path, |logs| {
        log_data_vec_len += 1;
        let message = logs.message();
        if message.contains("<not found>") {
            not_found += 1;
        }
        if message.contains("user: -1 <not found>") {
            user_not_found += 1;
        }

        if message.contains("refreshing: details, reason: expired, user: mobile <not found>") {
            mobile_not_found += 1;
        }

        if message.contains("BSSID 00:00:00:00:00:00") {
            bssid_count += 1;
        }

        if message.contains("https://doh.dns.apple.com/dns-query") {
            dns_query_count += 1;
        }

        if message.contains("bankofamerica") {
            bofa_count += 1;
        }
    })
    .unwrap();

    assert_eq!(log_data_vec_len, 1287628);
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

    let mut results_len = 0;
    let mut hex_count = 0;
    let mut dns = 0;
    let mut public_private_mixture = false;
    visit_logarchive_tracev3_file(&test_path, "Persist/0000000000000009.tracev3", |result| {
        results_len += 1;
        let message = result.message();
        if message.contains("7FAE25804F50") {
            hex_count += 1;
        }
        if result.subsystem.unwrap_or("").contains(".mdns") {
            dns += 1;
        }
        // 7FAE25B0E420 is half public and half private
        // B0E420 exists in public data but is copied/prepended to the private data.
        // 7FAE25 only exists in private data
        if message.as_str()
            == "os_transaction created: (7FAE25B0E420) CLLS:0x7fae23628160.LocationFine"
        {
            public_private_mixture = true
        }
    })
    .unwrap();

    assert_eq!(results_len, 91567);
    assert_eq!(hex_count, 4);
    assert_eq!(dns, 801);
    assert!(public_private_mixture);
}

// We are able to get 2238 entries from this special tracev3 file. But log command only gets 231
#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur_special_file() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur_public_private_data_mix.logarchive");

    let mut results_len = 0;
    let mut statedump = 0;
    let mut default = 0;
    let mut fault = 0;
    let mut info = 0;
    let mut error = 0;

    visit_logarchive_tracev3_file(&test_path, "Special/0000000000000008.tracev3", |result| {
        results_len += 1;
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
    })
    .unwrap();

    assert_eq!(results_len, 2238);
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

    let mut data_len = 0;
    let mut missing_strings = 0;
    // livedata may have oversize string data in other tracev3 on disk
    visit_logarchive_tracev3_file(&test_path, "logdata.LiveData.tracev3", |results| {
        data_len += 1;
        if results.message().contains("<Missing message data>") {
            missing_strings += 1;
        }
    })
    .unwrap();

    assert_eq!(data_len, 101566);
    // There should be only 29 entries that have actual missing data
    // 23 strings are in other trave3 files. 23 + 29 = 52
    assert_eq!(missing_strings, 52);
}

#[test]
fn test_big_sur_oversize_strings_in_another_file() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut data_len = 0;
    let mut missing_strings = 0;
    visit_logarchive_tracev3_files(
        &test_path,
        &[
            "Persist/0000000000000005.tracev3",
            "Special/0000000000000005.tracev3",
            "logdata.LiveData.tracev3",
        ],
        |index, results| {
            if index != 2 {
                return;
            }
            data_len += 1;
            if results.message().contains("<Missing message data>") {
                missing_strings += 1;
            }
        },
    )
    .unwrap();

    assert_eq!(data_len, 101566);
    // 29 log entries actually have missing data
    // Apple displays as: <decode: missing data>
    assert_eq!(missing_strings, 29);
}
