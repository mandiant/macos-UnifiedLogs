use macos_unifiedlogs::{
    log_entry::{LogEntry, MessageFlags},
    logarchive::{visit_logarchive, visit_logarchive_tracev3_file},
};
use std::{collections::HashMap, path::PathBuf};

fn log_flag_counts(entry: &LogEntry<'_, '_>, flags: &mut HashMap<MessageFlags, u64>) {
    for flag in &entry.message_flags {
        if let Some(count) = flags.get_mut(flag) {
            *count += 1;
            continue;
        }
        flags.insert(*flag, 1);
    }
}

#[test]
fn test_parse_log_gg() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/tart_goldengate.logarchive");

    let mut flags = HashMap::new();
    visit_logarchive_tracev3_file(&test_path, "Persist/0000000000000001.tracev3", |results| {
        log_flag_counts(&results, &mut flags);
    })
    .unwrap();

    // Command below returns same counts
    // log raw-dump -f tart_goldengate.logarchive/Persist/0000000000000001.tracev3 | grep "tp " | grep " + " | grep ":  " | cut -d ":" -f 2 | awk -F'[()]' '{print $2}' | tr -d ' ' | tr ',' '\n' | sort | uniq -c | sort -n
    assert_eq!(flags[&MessageFlags::MainExe], 22863);
    assert_eq!(flags[&MessageFlags::HasUniquePid], 8651);
    assert_eq!(flags[&MessageFlags::Absolute], 4943);
    assert_eq!(flags[&MessageFlags::HasCurrentAid], 27706);
    assert_eq!(flags[&MessageFlags::HasOversize], 2);
    assert_eq!(flags[&MessageFlags::LargeSharedCache], 148);
    assert_eq!(flags[&MessageFlags::HasSubsystem], 1024385);
    assert_eq!(flags[&MessageFlags::HasPrivateData], 528);
    assert_eq!(flags[&MessageFlags::HasOtherAid], 8608);
    assert_eq!(flags[&MessageFlags::SharedCache], 1019703);
    assert_eq!(flags[&MessageFlags::UuidRelative], 1113);
    assert_eq!(flags[&MessageFlags::HasLargeOffset], 1290);
    assert_eq!(flags[&MessageFlags::AltIndex], 4943);
}

#[test]
fn test_parse_all_logs_gg() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/tart_goldengate.logarchive");

    let mut person_flags = 0;
    let mut network_message = 0;

    let mut unknown_strings = 0;
    let mut invalid_offsets = 0;
    let mut invalid_shared_string_offsets = 0;

    let mut statedump_custom_objects = 0;
    let mut statedump_protocol_buffer = 0;
    let mut log_count = 0;
    visit_logarchive(&test_path, |logs| {
        log_count += 1;
        let message = logs.message();

        if message.to_ascii_lowercase().contains("network") {
            network_message += 1;
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

        if logs.message_flags.contains(&MessageFlags::HasPersona) {
            person_flags += 1;
        }
    })
    .unwrap();

    assert_eq!(person_flags, 69577);
    assert_eq!(network_message, 36099);

    assert_eq!(log_count, 4754401);
    assert_eq!(unknown_strings, 3); // Can validate with log raw-dump -A tart_goldengate.logarchive | grep "~~> Invalid image "
    assert_eq!(invalid_offsets, 157); // Can validate with log raw-dump -A tart_goldengate.logarchive | grep "~~> Invalid bounds " | wc -l
    assert_eq!(invalid_shared_string_offsets, 489); // Can validate with log raw-dump -A tart_goldengate.logarchive | grep "~~> <Invalid shared cache " | wc -l
}
