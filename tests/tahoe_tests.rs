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

fn collect_logs(provider: &dyn FileProvider) -> Vec<UnifiedLogData> {
    provider
        .tracev3_files()
        .map(|mut file| {
            let path = file.source_path().to_string();
            parse_log(file.reader(), &path).unwrap()
        })
        .collect()
}

#[test]
fn test_parse_log_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    test_path.push("Persist/000000000000000a.tracev3");
    let handle = File::open(&test_path.as_path()).unwrap();

    let log_data = parse_log(handle, test_path.to_str().unwrap()).unwrap();
    assert_eq!(log_data.catalog_data.len(), 121);

    assert_eq!(log_data.catalog_data[78].firehose.len(), 112);
    assert_eq!(log_data.catalog_data[12].simpledump.len(), 78);
    assert_eq!(log_data.header.len(), 1);
    assert_eq!(
        log_data.catalog_data[0]
            .catalog
            .catalog_process_info_entries
            .len(),
        10
    );
    assert_eq!(log_data.catalog_data[0].statedump.len(), 0);
}

#[test]
fn test_build_log_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/000000000000000a.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();
    let log_data = parse_log(handle, test_path.to_str().unwrap()).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(&log_data, &mut provider, &timesync_data, exclude_missing);
    assert_eq!(results.len(), 305785);

    assert_eq!(
        results[103032].process,
        "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd"
    );
    assert_eq!(results[103032].subsystem, "");
    assert_eq!(results[103032].time, 1.7766457650551785e18);
    assert_eq!(results[103032].activity_id, 25562);
    assert_eq!(results[103032].parent_activity_id, 0);
    assert_eq!(
        results[103032].library,
        "/System/Library/Frameworks/Security.framework/Versions/A/Security"
    );
    assert_eq!(results[103032].message, "SecKeyCreateWithData");
    assert_eq!(results[103032].pid, 412);
    assert_eq!(results[103032].thread_id, 2701);
    assert_eq!(results[103032].category, "");
    assert_eq!(results[103032].log_type, LogType::Create);
    assert_eq!(results[103032].event_type, EventType::Activity);
    assert_eq!(results[103032].euid, 501);
    assert_eq!(
        results[103032].boot_uuid,
        "78EDF02104B6458E9EFAAAC1FB21CCF7"
    );
    assert_eq!(results[103032].timezone_name, "Pacific");
    assert_eq!(
        results[103032].library_uuid,
        "22A9E9D9308633AAB1B36C0FA75D3797"
    );
    assert_eq!(
        results[103032].process_uuid,
        "338D916F98A033EBB68B80C74C6C41C8"
    );
    assert_eq!(results[103032].raw_message, "SecKeyCreateWithData");
    assert!(results[103032].message_entries.is_empty());
    assert!(
        results[103032]
            .evidence
            .ends_with("000000000000000a.tracev3")
    );
    assert_eq!(results[103032].timestamp, "2026-04-20T00:42:45.055178496Z");

    assert_eq!(results[45].process, "/usr/libexec/opendirectoryd");
    assert_eq!(results[45].subsystem, "com.apple.CFBundle");
    assert_eq!(results[45].time, 1.7766457511717076e18);
    assert_eq!(results[45].activity_id, 192);
    assert_eq!(results[45].parent_activity_id, 0);
    assert_eq!(
        results[45].library,
        "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
    );
    assert_eq!(
        results[45].message,
        "dlsym cannot find symbol odm_RecordRemoveValue in CFBundle 0x102ed4970 </System/Library/OpenDirectory/Modules/SystemCache.bundle> (bundle, loaded): <private>"
    );
    assert_eq!(results[45].pid, 131);
    assert_eq!(results[45].thread_id, 790);
    assert_eq!(results[45].category, "loading");
    assert_eq!(results[45].log_type, LogType::Error);
    assert_eq!(results[45].event_type, EventType::Log);
    assert_eq!(results[45].euid, 0);
    assert_eq!(results[45].boot_uuid, "78EDF02104B6458E9EFAAAC1FB21CCF7");
    assert_eq!(results[45].timezone_name, "Pacific");
    assert_eq!(results[45].library_uuid, "61AFC7A8FF8D3F8F8B0F42CAFB667E76");
    assert_eq!(results[45].process_uuid, "751A0472343930F7B421E36891337A30");
    assert_eq!(
        results[45].raw_message,
        "dlsym cannot find symbol %{public}@ in %{public}@: %s"
    );
    assert_eq!(
        results[45].message_entries[0].message_strings,
        "odm_RecordRemoveValue"
    );
    assert!(results[45].evidence.ends_with("000000000000000a.tracev3"));
    assert_eq!(results[45].timestamp, "2026-04-20T00:42:31.171707648Z");

    let mut midnight = 0;

    let mut string_count = 0;
    let mut precision_count = 0;
    let mut number_count = 0;
    let mut private_number_count = 0;
    for entry in results {
        assert!(entry.timestamp.contains("2026-04-20T"));
        if entry.timestamp.contains("2026-04-20T00:42") {
            midnight += 1;
        }

        for value in entry.message_entries {
            assert_ne!(format!("{:?}", value.item), "Unknown");

            if format!("{:?}", value.item) == "String" {
                string_count += 1;
            } else if format!("{:?}", value.item) == "Number" {
                number_count += 1;
            } else if format!("{:?}", value.item) == "Precision" {
                precision_count += 1;
            } else if format!("{:?}", value.item) == "PrivateNumber" {
                private_number_count += 1;
            }
        }
    }
    assert_eq!(string_count, 369927);
    assert_eq!(number_count, 382427);
    assert_eq!(precision_count, 13077);
    assert_eq!(private_number_count, 711);

    assert_eq!(midnight, 209452);
}

#[test]
fn test_check_log_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/0000000000000002.tracev3");

    let handle = File::open(test_path.as_path()).unwrap();
    let log_data = parse_log(handle, test_path.to_str().unwrap()).unwrap();

    let exclude_missing = false;
    let (results, _) = build_log(&log_data, &mut provider, &timesync_data, exclude_missing);

    let mut invalid_shared_string_offsets = 0;

    for logs in &results {
        if logs.message.contains("Error: Invalid shared string offset") {
            invalid_shared_string_offsets += 1;
        }
    }
    assert_eq!(invalid_shared_string_offsets, 97); // Can validate with log raw-dump -f 0000000000000002.tracev3 | grep "~~> <Invalid shared cache " | wc -l
}

#[test]
fn test_parse_all_logs_tahoe() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_tahoe.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());

    let timesync_data = collect_timesync(&provider).unwrap();
    let log_data = collect_logs(&provider);

    let mut log_data_vec: Vec<LogData> = Vec::new();
    let exclude_missing = false;

    for logs in &log_data {
        let (mut data, _) = build_log(logs, &mut provider, &timesync_data, exclude_missing);
        log_data_vec.append(&mut data);
    }
    assert_eq!(log_data_vec.len(), 4288584);

    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;
    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;

    let mut syncthing = 0;
    let mut brew = 0;

    for logs in &log_data_vec {
        if logs.message.contains("Failed to get string message from ")
            || logs.message.contains("Unknown shared string message")
        {
            unknown_strings += 1;

            if !logs.evidence.ends_with("4.tracev3") && !logs.evidence.ends_with("5.tracev3") {
                panic!("Got unspected missing strings for: {logs:?}");
            }
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

        if logs.message.contains("syncthing") {
            syncthing += 1;
        }

        if logs.message.contains("brew") {
            brew += 1;
        }
    }
    assert_eq!(unknown_strings, 2); // Can validate with log raw-dump -A system_logs_tahoe.logarchive | grep "~~> Invalid image "
    assert_eq!(invalid_offsets, 268); // Can validate with log raw-dump -A system_logs_tahoe.logarchive | grep "~~> Invalid bounds " | wc -l
    assert_eq!(invalid_shared_string_offsets, 647); // Can validate with log raw-dump -A system_logs_tahoe.logarchive | grep "~~> <Invalid shared cache " | wc -l
    assert_eq!(statedump_custom_objects, 0);
    assert_eq!(statedump_protocol_buffer, 0);
    assert_eq!(syncthing, 1146);
    assert_eq!(brew, 97);
}
