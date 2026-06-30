// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use macos_unifiedlogs::{
    chunk::{Chunk, ChunksReader},
    log_entry::{EventType, LogEntry, LogType},
    logarchive::{
        load_file_buffers_by_uuid, load_timesync_data, load_uuidtext_buffers, parse_dsc_buffers,
        parse_uuidtext_buffers, visit_logarchive,
    },
    timesync::TimestampResolver,
    tracev3::{OversizeCache, visit_tracev3},
};
use std::path::PathBuf;
use uuid::uuid;
use regex::Regex;

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
    visit_trace_file(&test_path, "logdata.LiveData.tracev3", |results| {
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
    });

    assert_eq!(count, 101566);
}

#[test]
fn test_build_log_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut count = 0;
    visit_trace_file(&test_path, "Persist/0000000000000004.tracev3", |results| {
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
    });

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

fn visit_trace_file(
    logarchive_path: &PathBuf,
    trace_relative_path: &str,
    callback: impl for<'a, 'b> FnMut(LogEntry<'a, 'b>),
) {
    let timesync_data = load_timesync_data(&logarchive_path.join("timesync")).unwrap();
    let resolver = TimestampResolver::new(timesync_data);
    let dsc_buffers = load_file_buffers_by_uuid(&logarchive_path.join("dsc"));
    let dsc_files = parse_dsc_buffers(&dsc_buffers);
    let uuidtext_buffers = load_uuidtext_buffers(logarchive_path);
    let uuidtext_files = parse_uuidtext_buffers(&uuidtext_buffers);
    let data = std::fs::read(logarchive_path.join(trace_relative_path)).unwrap();

    visit_tracev3(
        &data,
        &resolver,
        &dsc_files,
        &uuidtext_files,
        &mut OversizeCache::new(),
        callback,
    )
    .unwrap();
}
