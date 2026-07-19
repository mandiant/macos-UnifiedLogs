// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use macos_unifiedlogs::{
    chunk::{Chunk, ChunksReader},
    chunks::firehose::item::{RawItemKind, parse_items_data, parse_trace_items},
    log_entry::{EventType, ItemsData, LogEntry, LogType},
    logarchive::{visit_logarchive, visit_logarchive_tracev3_file},
};
use std::path::PathBuf;
use uuid::uuid;

fn item_kind_counts(entry: &LogEntry<'_, '_>) -> (usize, usize, usize, usize) {
    let raw_items = match entry.items() {
        ItemsData::Regular { data, flags, .. } => {
            let Ok((_, parsed)) = parse_items_data(data, *flags) else {
                return (0, 0, 0, 0);
            };
            parsed.items
        }
        ItemsData::Trace { data } => parse_trace_items(data),
        _ => return (0, 0, 0, 0),
    };

    let mut string_count = 0;
    let mut number_count = 0;
    let mut precision_count = 0;
    let mut private_number_count = 0;

    for item in raw_items {
        match item.item_type {
            RawItemKind::String | RawItemKind::Object | RawItemKind::BaseRaw => string_count += 1,
            RawItemKind::Number => number_count += 1,
            RawItemKind::Precision => precision_count += 1,
            RawItemKind::PrivateNumber => private_number_count += 1,
            _ => {}
        }
    }

    (
        string_count,
        number_count,
        precision_count,
        private_number_count,
    )
}

#[test]
fn test_parse_log_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

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

    assert_eq!(firehose.len(), 121);
    assert_eq!(firehose[78], 112);
    assert_eq!(simpledump[12], 78);
    assert_eq!(headers_count, 1);
    assert_eq!(catalog_process_info_entries[0], 10);
    assert_eq!(statedump[0], 0);
}

#[test]
fn test_build_log_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    let mut count = 0;
    let mut midnight = 0;

    let mut string_count = 0;
    let mut precision_count = 0;
    let mut number_count = 0;
    let mut private_number_count = 0;
    visit_logarchive_tracev3_file(&test_path, "Persist/000000000000000a.tracev3", |results| {
        if count == 103032 {
            assert_eq!(
                results.process,
                Some(
                    "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd"
                )
            );
            assert_eq!(results.subsystem, None);
            assert_eq!(results.time, 1.7766457650551785e18);
            assert_eq!(results.activity_id, 25562);
            assert_eq!(results.parent_activity_id.unwrap_or(0), 0);
            assert_eq!(
                results.library,
                Some("/System/Library/Frameworks/Security.framework/Versions/A/Security")
            );
            assert_eq!(results.message().as_str(), "SecKeyCreateWithData");
            assert_eq!(results.pid, 412);
            assert_eq!(results.thread_id, 2701);
            assert_eq!(results.category, None);
            assert_eq!(results.log_type, LogType::Create);
            assert_eq!(results.event_type, EventType::Activity);
            assert_eq!(results.euid, 501);
            assert_eq!(results.boot_uuid, uuid!("78EDF02104B6458E9EFAAAC1FB21CCF7"));
            assert_eq!(results.timezone_name, "Pacific");
            assert_eq!(
                results.library_uuid,
                uuid!("22A9E9D9308633AAB1B36C0FA75D3797")
            );
            assert_eq!(
                results.process_uuid,
                uuid!("338D916F98A033EBB68B80C74C6C41C8")
            );
            assert_eq!(results.raw_message(), "SecKeyCreateWithData");
            assert!(results.evidence.ends_with("000000000000000a.tracev3"));
            assert_eq!(
                results
                    .timestamp()
                    .format("%Y-%m-%dT%H:%M:%S%.9fZ")
                    .to_string(),
                "2026-04-20T00:42:45.055178496Z"
            );
        }

        if count == 45 {
            assert_eq!(results.process, Some("/usr/libexec/opendirectoryd"));
            assert_eq!(results.subsystem, Some("com.apple.CFBundle"));
            assert_eq!(results.time, 1.7766457511717076e18);
            assert_eq!(results.activity_id, 192);
            assert_eq!(results.parent_activity_id.unwrap_or(0), 0);
            assert_eq!(
                results.library,
                Some("/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation")
            );
            assert_eq!(
                results.message().as_str(),
                "dlsym cannot find symbol odm_RecordRemoveValue in CFBundle 0x102ed4970 </System/Library/OpenDirectory/Modules/SystemCache.bundle> (bundle, loaded): <private>"
            );
            assert_eq!(results.pid, 131);
            assert_eq!(results.thread_id, 790);
            assert_eq!(results.category, Some("loading"));
            assert_eq!(results.log_type, LogType::Error);
            assert_eq!(results.event_type, EventType::Log);
            assert_eq!(results.euid, 0);
            assert_eq!(results.boot_uuid, uuid!("78EDF02104B6458E9EFAAAC1FB21CCF7"));
            assert_eq!(results.timezone_name, "Pacific");
            assert_eq!(
                results.library_uuid,
                uuid!("61AFC7A8FF8D3F8F8B0F42CAFB667E76")
            );
            assert_eq!(
                results.process_uuid,
                uuid!("751A0472343930F7B421E36891337A30")
            );
            assert_eq!(
                results.raw_message(),
                "dlsym cannot find symbol %{public}@ in %{public}@: %s"
            );
            assert!(results.evidence.ends_with("000000000000000a.tracev3"));
            assert_eq!(
                results
                    .timestamp()
                    .format("%Y-%m-%dT%H:%M:%S%.9fZ")
                    .to_string(),
                "2026-04-20T00:42:31.171707648Z"
            );
        }

        let timestamp = results
            .timestamp()
            .format("%Y-%m-%dT%H:%M:%S%.9fZ")
            .to_string();
        assert!(timestamp.contains("2026-04-20T"));
        if timestamp.contains("2026-04-20T00:42") {
            midnight += 1;
        }

        let (strings, numbers, precisions, private_numbers) = item_kind_counts(&results);
        string_count += strings;
        number_count += numbers;
        precision_count += precisions;
        private_number_count += private_numbers;

        count += 1;
    })
    .unwrap();

    assert_eq!(count, 305785);
    assert_eq!(string_count, 370565);
    assert_eq!(number_count, 382513);
    assert_eq!(precision_count, 13077);
    assert_eq!(private_number_count, 711);

    assert_eq!(midnight, 209452);
}

#[test]
fn test_check_log_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    let mut invalid_shared_string_offsets = 0;

    visit_logarchive_tracev3_file(&test_path, "Persist/0000000000000002.tracev3", |logs| {
        if logs
            .message()
            .contains("Error: Invalid shared string offset")
        {
            invalid_shared_string_offsets += 1;
        }
    })
    .unwrap();

    assert_eq!(invalid_shared_string_offsets, 97); // Can validate with log raw-dump -f 0000000000000002.tracev3 | grep "~~> <Invalid shared cache " | wc -l
}

#[test]
fn test_parse_all_logs_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    let mut log_data_vec_len = 0;
    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;
    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;

    let mut syncthing = 0;
    let mut brew = 0;

    visit_logarchive(&test_path, |logs| {
        log_data_vec_len += 1;
        let message = logs.message();

        if message.contains("Failed to get string message from ")
            || message.contains("Unknown shared string message")
        {
            unknown_strings += 1;

            let evidence = logs.evidence.to_string_lossy();
            if !evidence.ends_with("4.tracev3") && !evidence.ends_with("5.tracev3") {
                panic!("Got unspected missing strings for: {logs:?}");
            }
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

        if message.contains("syncthing") {
            syncthing += 1;
        }

        if message.contains("brew") {
            brew += 1;
        }
    })
    .unwrap();

    assert_eq!(log_data_vec_len, 4288584);
    assert_eq!(unknown_strings, 2); // Can validate with log raw-dump -A system_logs_tahoe.logarchive | grep "~~> Invalid image "
    assert_eq!(invalid_offsets, 268); // Can validate with log raw-dump -A system_logs_tahoe.logarchive | grep "~~> Invalid bounds " | wc -l
    assert_eq!(invalid_shared_string_offsets, 647); // Can validate with log raw-dump -A system_logs_tahoe.logarchive | grep "~~> <Invalid shared cache " | wc -l
    assert_eq!(statedump_custom_objects, 0);
    assert_eq!(statedump_protocol_buffer, 0);
    assert_eq!(syncthing, 1146);
    assert_eq!(brew, 97);
}
