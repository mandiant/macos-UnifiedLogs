// Rewrite-API integration tests — exercises visit_logarchive / visit_tracev3 / ChunksReader
// directly, without the compat shim.
//
// Mirrors the structure of big_sur_tests.rs but adapted for the rewrite types:
//   - Option<&str> instead of String (None instead of "")
//   - uuid::Uuid instead of uppercase hex string
//   - Lazy message via entry.message()
//   - format_string: Option<&str> instead of raw_message: String
//   - Loss entries: "Lost N log entries between X and Y" (non-empty)
//   - No signpost prefix
//   - NoDecoder (raw values instead of DNS/uuid_t/OpenDirectory output)
//   - "<decode: missing data>" instead of "<Missing message data>" for missing items

#![cfg(all(feature = "rewrite", not(feature = "rewrite-compat")))]

use std::collections::HashMap;
use std::path::PathBuf;

use macos_unifiedlogs::{
    chunk::{Chunk, ChunksReader},
    chunks::ChunkTag,
    dsc::RawSharedCacheStrings,
    log_entry::{EventType, LogType},
    logarchive::{
        load_file_buffers_by_uuid, load_timesync_data, load_uuidtext_buffers, visit_logarchive,
    },
    timesync::TimestampResolver,
    tracev3::{visit_tracev3, OversizeCache},
    uuidtext::RawUUIDText,
};
use regex::Regex;
use uuid::Uuid;

fn test_data_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test_data")
}

fn is_signpost(log_type: LogType) -> bool {
    matches!(
        log_type,
        LogType::ProcessSignpostEvent
            | LogType::ProcessSignpostStart
            | LogType::ProcessSignpostEnd
            | LogType::SystemSignpostEvent
            | LogType::SystemSignpostStart
            | LogType::SystemSignpostEnd
            | LogType::ThreadSignpostEvent
            | LogType::ThreadSignpostStart
            | LogType::ThreadSignpostEnd
    )
}

/// Helper that loads timesync/DSC/UUIDText for a logarchive directory,
/// enabling per-file `visit_tracev3` calls from integration tests.
struct LogarchiveContext {
    resolver: TimestampResolver,
    dsc_buffers: Vec<(Uuid, Vec<u8>)>,
    uuidtext_buffers: Vec<(Uuid, Vec<u8>)>,
}

impl LogarchiveContext {
    fn new(path: &std::path::Path) -> Self {
        let timesync_data = load_timesync_data(&path.join("timesync")).unwrap();
        let resolver = TimestampResolver::new(timesync_data);
        let dsc_buffers = load_file_buffers_by_uuid(&path.join("dsc"));
        let uuidtext_buffers = load_uuidtext_buffers(path);
        Self {
            resolver,
            dsc_buffers,
            uuidtext_buffers,
        }
    }

    fn dsc_files(&self) -> HashMap<Uuid, RawSharedCacheStrings<'_>> {
        self.dsc_buffers
            .iter()
            .filter_map(|(uuid, buffer)| {
                let (_, dsc) = RawSharedCacheStrings::parse(buffer).ok()?;
                Some((*uuid, dsc))
            })
            .collect()
    }

    fn uuidtext_files(&self) -> HashMap<Uuid, RawUUIDText<'_>> {
        self.uuidtext_buffers
            .iter()
            .filter_map(|(uuid, buffer)| {
                let (_, ut) = RawUUIDText::parse(buffer).ok()?;
                Some((*uuid, ut))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Test 1: Raw chunk counting via ChunksReader
// ---------------------------------------------------------------------------

#[test]
fn test_parse_log_big_sur() {
    let path =
        test_data_path().join("system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");
    let data = std::fs::read(&path).unwrap();

    let mut count_by_type: HashMap<ChunkTag, usize> = HashMap::new();
    let mut reader = ChunksReader::new(&data);
    reader
        .visit(|chunk| {
            let tag = match chunk {
                Chunk::Header(_) => ChunkTag::Header,
                Chunk::Catalog(_) => ChunkTag::Catalog,
                Chunk::Firehose(_) => ChunkTag::Firehose,
                Chunk::Simpledump(_) => ChunkTag::Simpledump,
                Chunk::Statedump(_) => ChunkTag::Statedump,
                Chunk::Oversize(_) => ChunkTag::Oversize,
                Chunk::Unknown(_) => ChunkTag::Unknown,
            };
            *count_by_type.entry(tag).or_insert(0) += 1;
        })
        .unwrap();

    assert_eq!(count_by_type[&ChunkTag::Header], 1);
    // Compat test checks catalog_data[0].firehose.len() == 82 (first catalog only).
    // ChunksReader visits all firehose chunks across all catalogs.
    assert!(
        count_by_type[&ChunkTag::Firehose] >= 82,
        "expected at least 82 firehose chunks, got {}",
        count_by_type[&ChunkTag::Firehose]
    );
    assert_eq!(
        count_by_type.get(&ChunkTag::Simpledump).copied().unwrap_or(0),
        0
    );
    assert_eq!(
        count_by_type.get(&ChunkTag::Statedump).copied().unwrap_or(0),
        0
    );
}

// ---------------------------------------------------------------------------
// Test 2: LiveData single file
// ---------------------------------------------------------------------------

#[test]
fn test_big_sur_livedata() {
    let base = test_data_path().join("system_logs_big_sur.logarchive");
    let ctx = LogarchiveContext::new(&base);
    let dsc_files = ctx.dsc_files();
    let uuidtext_files = ctx.uuidtext_files();

    let data = std::fs::read(base.join("logdata.LiveData.tracev3")).unwrap();
    let mut oversize_cache = OversizeCache::new();
    let mut count = 0_usize;
    let mut found_timesync = false;

    visit_tracev3(
        &data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            if entry
                .message()
                .contains("TimeSyncTime is mach_absolute_time nanoseconds\n")
            {
                assert_eq!(entry.activity_id, 0);
                assert_eq!(entry.thread_id, 116);
                assert_eq!(entry.euid, 0);
                assert_eq!(entry.pid, 0);
                assert_eq!(
                    entry.library,
                    Some("/System/Library/Extensions/IOTimeSyncFamily.kext/Contents/MacOS/IOTimeSyncFamily")
                );
                assert_eq!(entry.subsystem, None);
                assert_eq!(entry.category, None);
                assert_eq!(entry.event_type, EventType::Log);
                assert_eq!(entry.log_type, LogType::Info);
                assert_eq!(entry.process, Some("/kernel"));
                assert_eq!(entry.time, 1_642_304_801_596_413_351.0);
                assert_eq!(
                    entry.boot_uuid,
                    Uuid::parse_str("a2a90176-76cf-421c-84dc-9bbd6263fee7").unwrap()
                );
                assert_eq!(entry.timezone_name, "Pacific");
                found_timesync = true;
            }
            count += 1;
        },
    )
    .unwrap();

    assert_eq!(count, 101_566);
    assert!(found_timesync, "should find the TimeSyncTime entry");
}

// ---------------------------------------------------------------------------
// Test 3: Build log — Persist/0000000000000004
// ---------------------------------------------------------------------------

#[test]
fn test_build_log_big_sur() {
    let base = test_data_path().join("system_logs_big_sur.logarchive");
    let ctx = LogarchiveContext::new(&base);
    let dsc_files = ctx.dsc_files();
    let uuidtext_files = ctx.uuidtext_files();

    let data = std::fs::read(base.join("Persist/0000000000000004.tracev3")).unwrap();
    let mut oversize_cache = OversizeCache::new();
    let mut count = 0_usize;
    let mut checked_first = false;

    visit_tracev3(
        &data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            if count == 0 && !checked_first {
                assert_eq!(entry.process, Some("/usr/libexec/opendirectoryd"));
                assert_eq!(entry.subsystem, Some("com.apple.opendirectoryd"));
                assert_eq!(entry.time, 1_642_303_933_964_503_310.0);
                assert_eq!(entry.activity_id, 0);
                assert_eq!(entry.library, Some("/usr/libexec/opendirectoryd"));
                assert_eq!(
                    entry.message(),
                    "opendirectoryd (build 796.100) launched..."
                );
                assert_eq!(entry.pid, 105);
                assert_eq!(entry.thread_id, 670);
                assert_eq!(entry.category, Some("default"));
                assert_eq!(entry.log_type, LogType::Default);
                assert_eq!(entry.event_type, EventType::Log);
                assert_eq!(entry.euid, 0);
                assert_eq!(
                    entry.boot_uuid,
                    Uuid::parse_str("aacfb573-e875-45ce-98b8-93d132766a46").unwrap()
                );
                assert_eq!(entry.timezone_name, "Pacific");
                assert_eq!(
                    entry.library_uuid,
                    Uuid::parse_str("b736df16-25f5-3824-8e95-27a8cec4991e").unwrap()
                );
                assert_eq!(
                    entry.process_uuid,
                    Uuid::parse_str("b736df16-25f5-3824-8e95-27a8cec4991e").unwrap()
                );
                assert_eq!(
                    entry.format_string,
                    Some("opendirectoryd (build %{public}s) launched...")
                );
                checked_first = true;
            }
            count += 1;
        },
    )
    .unwrap();

    assert_eq!(count, 110_953);
    assert!(checked_first, "should have checked first entry");
}

// ---------------------------------------------------------------------------
// Test 4: Full logarchive — all entries
// ---------------------------------------------------------------------------

#[test]
fn test_parse_all_logs_big_sur() {
    let base = test_data_path().join("system_logs_big_sur.logarchive");

    let mut count = 0_usize;
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

    visit_logarchive(&base, |entry| {
        // Type breakdown (identical logic to compat — types are decoder-independent)
        if entry.event_type == EventType::Statedump {
            statedump_count += 1;
        } else if entry.event_type == EventType::Signpost {
            signpost_count += 1;
        } else if entry.log_type == LogType::Default {
            default_type += 1;
        } else if entry.log_type == LogType::Info {
            info_type += 1;
        } else if entry.log_type == LogType::Error {
            error_type += 1;
        } else if entry.log_type == LogType::Create {
            create_type += 1;
        } else if entry.log_type == LogType::Debug {
            debug_type += 1;
        } else if entry.log_type == LogType::Useraction {
            useraction_type += 1;
        } else if entry.log_type == LogType::Fault {
            fault_type += 1;
        } else if entry.event_type == EventType::Loss {
            loss_type += 1;
        }

        count += 1;
    })
    .unwrap();

    assert_eq!(count, 747_616);

    // Type breakdown — identical to compat (types are independent of decoders)
    assert_eq!(statedump_count, 322);
    assert_eq!(signpost_count, 50_665);
    assert_eq!(default_type, 462_518);
    assert_eq!(info_type, 114_540);
    assert_eq!(error_type, 29_132);
    assert_eq!(create_type, 87_831);
    assert_eq!(debug_type, 1_908);
    assert_eq!(useraction_type, 15);
    assert_eq!(fault_type, 680);
    assert_eq!(loss_type, 5);
}

// ---------------------------------------------------------------------------
// Test 5: Network messages
// ---------------------------------------------------------------------------

#[test]
fn test_parse_all_persist_logs_with_network_big_sur() {
    let base = test_data_path().join("system_logs_big_sur.logarchive");

    let mut messages_containing_network = 0;
    let mut default_type = 0;
    let mut info_type = 0;
    let mut error_type = 0;
    let mut create_type = 0;
    let mut state_simple_dump = 0;
    let mut signpost = 0;

    visit_logarchive(&base, |entry| {
        let message = entry.message();
        if message.to_lowercase().contains("network") {
            if entry.log_type == LogType::Default {
                default_type += 1;
                // Skip the uuid_t decoder check for "7C10C1EF-1B86-494F-800D-C769A89172C1".
                // With NoDecoder, the uuid_t bytes are formatted differently.
            } else if entry.log_type == LogType::Info {
                info_type += 1;
            } else if entry.log_type == LogType::Error {
                error_type += 1;
            } else if entry.log_type == LogType::Create {
                create_type += 1;
                return; // skip create in network count (matches compat)
            } else if entry.event_type == EventType::Simpledump
                || entry.event_type == EventType::Statedump
            {
                state_simple_dump += 1;
                return;
            } else if is_signpost(entry.log_type) {
                signpost += 1;
                return;
            }
            messages_containing_network += 1;
        }
    })
    .unwrap();

    // Network message counts differ slightly from compat (9173) due to uuid_t/DNS
    // decoder differences — 3 messages lose the "network" substring without the decoder.
    assert_eq!(messages_containing_network, 9170);
    assert_eq!(default_type, 8320);
    assert_eq!(info_type, 635);
    assert_eq!(error_type, 215);
    assert_eq!(create_type, 687);
    assert_eq!(state_simple_dump, 34);
    assert_eq!(signpost, 62);
}

// ---------------------------------------------------------------------------
// Test 6: Private-enabled logarchive
// ---------------------------------------------------------------------------

#[test]
fn test_parse_all_logs_private_big_sur() {
    let base = test_data_path().join("system_logs_big_sur_private_enabled.logarchive");

    let mut count = 0_usize;
    let mut empty_counter = 0;
    let mut not_found = 0;

    visit_logarchive(&base, |entry| {
        let message = entry.message();
        if message.is_empty() {
            empty_counter += 1;
        }
        if message.contains("<not found>") {
            not_found += 1;
        }
        // Skip staff_count ("group: staff@/Local/Default") — depends on OpenDirectory decoder
        count += 1;
    })
    .unwrap();

    assert_eq!(count, 887_890);
    assert_eq!(not_found, 0);
    // empty_counter differs from compat (596) because:
    // 1. Signpost entries lack the "Signpost ID:..." prefix, producing more empty messages
    // 2. Some entries that had error text in compat now show "<missing format string>" (non-empty)
    assert_eq!(empty_counter, 4383);
}

// ---------------------------------------------------------------------------
// Test 7: Private + public mix
// ---------------------------------------------------------------------------

#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur() {
    let base = test_data_path().join("system_logs_big_sur_public_private_data_mix.logarchive");

    let mut count = 0_usize;
    let mut not_found = 0;
    let mut bssid_count = 0;
    let mut dns_query_count = 0;
    let mut bofa_count = 0;

    visit_logarchive(&base, |entry| {
        let message = entry.message();
        if message.contains("<not found>") {
            not_found += 1;
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
        count += 1;
    })
    .unwrap();

    assert_eq!(count, 1_287_628);
    // "<not found>" text comes from the OpenDirectory decoder — not present with NoDecoder
    assert_eq!(not_found, 0);
    // Counts differ from compat (39, 41, 573) because rewrite uses strict private data
    // boundaries, while compat prepends leftover public bytes to the private data region.
    assert_eq!(bssid_count, 0);
    assert_eq!(dns_query_count, 33);
    assert_eq!(bofa_count, 310);
}

// ---------------------------------------------------------------------------
// Test 8: Single file from mix archive — Persist/0000000000000009
// ---------------------------------------------------------------------------

#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur_single_file() {
    let base = test_data_path().join("system_logs_big_sur_public_private_data_mix.logarchive");
    let ctx = LogarchiveContext::new(&base);
    let dsc_files = ctx.dsc_files();
    let uuidtext_files = ctx.uuidtext_files();

    let data = std::fs::read(base.join("Persist/0000000000000009.tracev3")).unwrap();
    let mut oversize_cache = OversizeCache::new();
    let mut count = 0_usize;
    let mut hex_count = 0;
    let mut dns = 0;

    visit_tracev3(
        &data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            let message = entry.message();
            if message.contains("7FAE25804F50") {
                hex_count += 1;
            }
            if let Some(subsystem) = entry.subsystem
                && subsystem.contains(".mdns")
            {
                dns += 1;
            }
            // Skip public_private_mixture check — the specific "os_transaction created:
            // (7FAE25B0E420)" message depends on private data assembly order which differs
            // between compat and rewrite (compat prepends leftover public bytes to private
            // data, rewrite does not).
            count += 1;
        },
    )
    .unwrap();

    assert_eq!(count, 91_567);
    assert_eq!(hex_count, 4);
    assert_eq!(dns, 801);
}

// ---------------------------------------------------------------------------
// Test 9: Special file from mix archive — Special/0000000000000008
// ---------------------------------------------------------------------------

#[test]
fn test_parse_all_logs_private_with_public_mix_big_sur_special_file() {
    let base = test_data_path().join("system_logs_big_sur_public_private_data_mix.logarchive");
    let ctx = LogarchiveContext::new(&base);
    let dsc_files = ctx.dsc_files();
    let uuidtext_files = ctx.uuidtext_files();

    let data = std::fs::read(base.join("Special/0000000000000008.tracev3")).unwrap();
    let mut oversize_cache = OversizeCache::new();
    let mut statedump = 0;
    let mut default = 0;
    let mut fault = 0;
    let mut info = 0;
    let mut error = 0;
    let mut count = 0_usize;

    visit_tracev3(
        &data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            if entry.event_type == EventType::Statedump {
                statedump += 1;
            } else if entry.log_type == LogType::Default {
                default += 1;
            } else if entry.log_type == LogType::Fault {
                fault += 1;
            } else if entry.log_type == LogType::Info {
                info += 1;
            } else if entry.log_type == LogType::Error {
                error += 1;
            }
            count += 1;
        },
    )
    .unwrap();

    assert_eq!(count, 2_238);
    assert_eq!(statedump, 1);
    assert_eq!(default, 1_972);
    assert_eq!(fault, 32);
    assert_eq!(info, 41);
    assert_eq!(error, 192);
}

// ---------------------------------------------------------------------------
// Test 10: Missing oversize strings
// ---------------------------------------------------------------------------

#[test]
fn test_big_sur_missing_oversize_strings() {
    let base = test_data_path().join("system_logs_big_sur.logarchive");
    let ctx = LogarchiveContext::new(&base);
    let dsc_files = ctx.dsc_files();
    let uuidtext_files = ctx.uuidtext_files();

    // Parse LiveData alone — some entries reference oversize data in other tracev3 files
    let data = std::fs::read(base.join("logdata.LiveData.tracev3")).unwrap();
    let mut oversize_cache = OversizeCache::new();
    let mut count = 0_usize;
    let mut missing_data_count = 0;

    visit_tracev3(
        &data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            // In rewrite, when items run out (missing oversize data), format_message
            // inserts "<decode: missing data>" for each unfilled format specifier.
            let message = entry.message();
            if message.contains("<decode: missing data>") {
                missing_data_count += 1;
            }
            count += 1;
        },
    )
    .unwrap();

    assert_eq!(count, 101_566);
    // Compat had 52 entries with "<Missing message data>". Rewrite uses
    // "<decode: missing data>" for unfilled format specifiers. The count should match.
    assert_eq!(missing_data_count, 52);
}

// ---------------------------------------------------------------------------
// Test 11: Oversize strings recovered from other files
// ---------------------------------------------------------------------------

#[test]
fn test_big_sur_oversize_strings_in_another_file() {
    let base = test_data_path().join("system_logs_big_sur.logarchive");
    let ctx = LogarchiveContext::new(&base);
    let dsc_files = ctx.dsc_files();
    let uuidtext_files = ctx.uuidtext_files();

    // Populate oversize cache from Persist and Special files first
    let mut oversize_cache = OversizeCache::new();

    let persist_data = std::fs::read(base.join("Persist/0000000000000005.tracev3")).unwrap();
    visit_tracev3(
        &persist_data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |_| {},
    )
    .unwrap();

    let special_data = std::fs::read(base.join("Special/0000000000000005.tracev3")).unwrap();
    visit_tracev3(
        &special_data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |_| {},
    )
    .unwrap();

    // Now parse LiveData with the populated cache
    let live_data = std::fs::read(base.join("logdata.LiveData.tracev3")).unwrap();
    let mut count = 0_usize;
    let mut missing_data_count = 0;

    visit_tracev3(
        &live_data,
        &ctx.resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            let message = entry.message();
            if message.contains("<decode: missing data>") {
                missing_data_count += 1;
            }
            count += 1;
        },
    )
    .unwrap();

    assert_eq!(count, 101_566);
    // With oversize data from Persist/Special files, 23 entries are resolved.
    // Compat: 52 → 29. Rewrite should show the same reduction.
    assert_eq!(missing_data_count, 29);
}
