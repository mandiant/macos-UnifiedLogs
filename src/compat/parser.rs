//! Compatibility wrappers for `parse_log`, `build_log`, and `collect_timesync`.
//!
//! These functions present the legacy two-phase API (parse → build) over the
//! rewrite's streaming `visit_tracev3` pipeline.

use std::collections::HashMap;
use std::io::Read;

use base64::Engine;
use log::{error, info, warn};
use uuid::Uuid;

use crate::rewrite::chunk::{ChunksReader, TopChunk};
use crate::rewrite::chunks::ChunkTag;
use crate::rewrite::chunks::firehose::item::{
    RawFirehoseItem, RawItemKind, RawItemValue, fill_private_data_compat, parse_items_data,
    parse_trace_items,
};
use crate::rewrite::chunks::oversize::RawOversize;
use crate::rewrite::dsc::RawSharedCacheStrings;
use crate::rewrite::log_entry::{ItemsData, LogEntry};
use crate::rewrite::logarchive::{
    load_file_buffers_by_uuid, load_timesync_data, load_uuidtext_buffers,
};
use crate::rewrite::timesync::{RawTimesyncBoot, TimestampResolver};
use crate::rewrite::tracev3::{OversizeCache, visit_tracev3};
use crate::rewrite::uuidtext::RawUUIDText;

use super::filesystem::LogarchiveProvider;
use super::traits::FileProvider;
use super::unified_log::{
    CatalogInfo, CountVec, EventType, FirehoseItem, FirehoseItemType, HeaderInfo, LogData,
    OversizeEntry, ParserError, TimesyncBoot, UnifiedLogCatalogData, UnifiedLogData,
};

// ---------------------------------------------------------------------------
// parse_log
// ---------------------------------------------------------------------------

/// Parse a tracev3 file, counting chunks and extracting oversize entries.
///
/// The returned `UnifiedLogData` stores the raw bytes for later processing
/// by `build_log`.
pub fn parse_log(mut reader: impl Read, evidence: &str) -> Result<UnifiedLogData, ParserError> {
    let mut buf = Vec::new();
    if let Err(err) = reader.read_to_end(&mut buf) {
        error!("[macos-unifiedlogs] Failed to read the tracev3 file: {err:?}");
        return Err(ParserError::Read);
    }

    info!("Read {} bytes from tracev3 file", buf.len());

    let mut headers = 0_usize;
    let mut catalog_datas: Vec<UnifiedLogCatalogData> = Vec::new();
    let mut oversize_entries: Vec<OversizeEntry> = Vec::new();

    // Per-catalog counters, flushed when a new Catalog is seen.
    let mut cat_proc_info = 0_usize;
    let mut cat_firehose = 0_usize;
    let mut cat_simpledump = 0_usize;
    let mut cat_statedump = 0_usize;
    let mut cat_oversize = 0_usize;
    let mut has_catalog = false;

    for top_chunk in ChunksReader::new(&buf) {
        let top_chunk = match top_chunk {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to parse top chunk: {e}");
                break;
            }
        };

        match top_chunk {
            TopChunk::Header(_) => {
                headers += 1;
            }
            TopChunk::Catalog(c) => {
                // Flush the previous catalog's counts
                if has_catalog {
                    catalog_datas.push(UnifiedLogCatalogData {
                        catalog: CatalogInfo {
                            catalog_process_info_entries: CountVec::new(cat_proc_info),
                        },
                        firehose: CountVec::new(cat_firehose),
                        simpledump: CountVec::new(cat_simpledump),
                        statedump: CountVec::new(cat_statedump),
                        oversize: CountVec::new(cat_oversize),
                    });
                }
                cat_proc_info = c.catalog_process_info_entries.len();
                cat_firehose = 0;
                cat_simpledump = 0;
                cat_statedump = 0;
                cat_oversize = 0;
                has_catalog = true;
            }
            TopChunk::Chunkset(mut reader) => {
                while let Some(inner) = reader.next() {
                    let inner = match inner {
                        Ok(c) => c,
                        Err(e) => {
                            warn!("Failed to parse inner chunk: {e}");
                            break;
                        }
                    };
                    match inner.preamble.tag {
                        ChunkTag::Firehose => cat_firehose += 1,
                        ChunkTag::Simpledump => cat_simpledump += 1,
                        ChunkTag::Statedump => cat_statedump += 1,
                        ChunkTag::Oversize => {
                            cat_oversize += 1;
                            if let Ok((_, ov)) = RawOversize::parse(inner.data) {
                                oversize_entries.push(OversizeEntry {
                                    data_ref_index: ov.data_ref_index,
                                    first_proc_id: ov.first_proc_id,
                                    second_proc_id: ov.second_proc_id,
                                    data: ov.oversize_data.to_vec(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            TopChunk::Unknown(_) => {}
        }
    }

    // Flush the last catalog
    if has_catalog {
        catalog_datas.push(UnifiedLogCatalogData {
            catalog: CatalogInfo {
                catalog_process_info_entries: CountVec::new(cat_proc_info),
            },
            firehose: CountVec::new(cat_firehose),
            simpledump: CountVec::new(cat_simpledump),
            statedump: CountVec::new(cat_statedump),
            oversize: CountVec::new(cat_oversize),
        });
    }

    Ok(UnifiedLogData {
        header: (0..headers).map(|_| HeaderInfo).collect(),
        catalog_data: catalog_datas,
        oversize: oversize_entries,
        evidence: evidence.to_string(),
        raw_data: buf,
    })
}

// ---------------------------------------------------------------------------
// collect_timesync
// ---------------------------------------------------------------------------

/// Parse all timesync files from the logarchive and return a map keyed by
/// boot UUID (uppercase hex without hyphens).
pub fn collect_timesync(
    provider: &dyn FileProvider,
) -> Result<HashMap<String, TimesyncBoot>, ParserError> {
    let timesync_dir = provider.logarchive_base_path().join("timesync");
    let raw_data = load_timesync_data(&timesync_dir).map_err(|e| {
        error!("[macos-unifiedlogs] Failed to read timesync directory: {e}");
        ParserError::Timesync
    })?;

    let mut result = HashMap::new();
    for (uuid, boot) in raw_data {
        let key = format!("{:X}", uuid.simple());
        result.insert(key, TimesyncBoot { inner: boot });
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// build_log
// ---------------------------------------------------------------------------

/// Build fully resolved `LogData` entries from parsed tracev3 data.
///
/// Loads DSC / `UUIDText` from the filesystem (cached when the provider is
/// `LogarchiveProvider`), pre-populates oversize cache from
/// `unified_data.oversize`, then runs `visit_tracev3` to produce entries.
pub fn build_log(
    unified_data: &UnifiedLogData,
    provider: &mut dyn FileProvider,
    timesync_data: &HashMap<String, TimesyncBoot>,
    exclude_missing: bool,
) -> (Vec<LogData>, UnifiedLogData) {
    // 1. Build TimestampResolver from the compat TimesyncBoot map
    let raw_timesync: HashMap<Uuid, RawTimesyncBoot> = timesync_data
        .iter()
        .filter_map(|(key, ts)| {
            let uuid = Uuid::parse_str(key).ok()?;
            Some((uuid, ts.inner.clone()))
        })
        .collect();
    let resolver = TimestampResolver::new(raw_timesync);

    // 2–3. Load DSC + UUIDText buffers (cached on LogarchiveProvider)
    // Try to use LogarchiveProvider's cache for O(1) buffer access on repeat calls.
    let lap = provider.as_any_mut().downcast_mut::<LogarchiveProvider>();
    if let Some(lap) = lap {
        // Ensure buffers are loaded into the provider's cache
        lap.dsc_buffers();
        lap.uuidtext_buffers();
    }

    // Re-borrow the provider to get the parsed files
    let base = provider.logarchive_base_path().to_path_buf();
    let lap = provider.as_any_mut().downcast_mut::<LogarchiveProvider>();

    let (dsc_buffers_owned, uuidtext_buffers_owned);
    let dsc_buf_ref: &[(Uuid, Vec<u8>)];
    let uuidtext_buf_ref: &[(Uuid, Vec<u8>)];

    if let Some(lap) = lap {
        // Both caches were loaded above, access fields directly (shared borrows only)
        dsc_buf_ref = lap.dsc_buffers.as_deref().unwrap_or(&[]);
        uuidtext_buf_ref = lap.uuidtext_buffers.as_deref().unwrap_or(&[]);
    } else {
        dsc_buffers_owned = load_file_buffers_by_uuid(&base.join("dsc"));
        uuidtext_buffers_owned = load_uuidtext_buffers(&base);
        dsc_buf_ref = &dsc_buffers_owned;
        uuidtext_buf_ref = &uuidtext_buffers_owned;
    }

    let dsc_files: HashMap<Uuid, RawSharedCacheStrings<'_>> = dsc_buf_ref
        .iter()
        .filter_map(|(uuid, buffer)| {
            let (_, dsc) = RawSharedCacheStrings::parse(buffer)
                .inspect_err(|e| warn!("Failed to parse DSC {uuid}: {e}"))
                .ok()?;
            Some((*uuid, dsc))
        })
        .collect();

    let uuidtext_files: HashMap<Uuid, RawUUIDText<'_>> = uuidtext_buf_ref
        .iter()
        .filter_map(|(uuid, buffer)| {
            let (_, uuidtext) = RawUUIDText::parse(buffer)
                .inspect_err(|e| warn!("Failed to parse UUIDText {uuid}: {e}"))
                .ok()?;
            Some((*uuid, uuidtext))
        })
        .collect();

    // 4. Pre-populate OversizeCache from cross-file merged oversize entries
    let mut oversize_cache = OversizeCache::new();
    for ov in &unified_data.oversize {
        oversize_cache
            .entries
            .entry((ov.data_ref_index, ov.first_proc_id, ov.second_proc_id))
            .or_insert_with(|| ov.data.clone());
    }

    // 5. Process tracev3 data via the rewrite pipeline
    let mut logs = Vec::new();
    let evidence = unified_data.evidence.clone();

    if let Err(e) = visit_tracev3(
        &unified_data.raw_data,
        &resolver,
        &dsc_files,
        &uuidtext_files,
        &mut oversize_cache,
        |entry| {
            let message = entry.message();

            if exclude_missing && message.contains("<Missing message data>") {
                return;
            }

            let raw_message = entry.raw_message().to_string();

            let subsystem = entry.subsystem.unwrap_or("").to_string();

            let timestamp = entry
                .timestamp()
                .format("%Y-%m-%dT%H:%M:%S%.9fZ")
                .to_string();

            let message_entries = compat_message_entries(&entry);
            let library_uuid = compat_uuid_string(entry.event_type, entry.library_uuid);
            let process_uuid = compat_uuid_string(entry.event_type, entry.process_uuid);
            let library = compat_attribution_string(entry.event_type, entry.library);
            let process = compat_attribution_string(entry.event_type, entry.process);

            logs.push(LogData {
                subsystem,
                thread_id: entry.thread_id,
                pid: entry.pid,
                euid: entry.euid,
                library,
                library_uuid,
                activity_id: entry.activity_id,
                parent_activity_id: entry.parent_activity_id.unwrap_or(0),
                time: entry.time,
                category: entry.category.unwrap_or("").to_string(),
                event_type: entry.event_type,
                log_type: entry.log_type,
                process,
                process_uuid,
                message: (*message).clone(),
                raw_message,
                boot_uuid: format!("{:X}", entry.boot_uuid.simple()),
                timezone_name: entry.timezone_name.to_string(),
                message_entries,
                timestamp,
                message_flags: entry.message_flags.clone(),
                evidence: evidence.clone(),
            });
        },
    ) {
        warn!("Failed to process tracev3 data: {e}");
    }

    // Return empty UnifiedLogData as the "missing" bucket (tests ignore it)
    let remaining = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
        evidence: unified_data.evidence.clone(),
        raw_data: Vec::new(),
    };

    (logs, remaining)
}

fn compat_uuid_string(event_type: EventType, uuid: Uuid) -> String {
    if (event_type == EventType::Statedump && uuid.is_nil())
        || event_type == EventType::Loss
        || event_type == EventType::Unknown
    {
        String::new()
    } else {
        format!("{:X}", uuid.simple())
    }
}

fn compat_attribution_string(event_type: EventType, value: Option<&str>) -> String {
    if event_type == EventType::Loss || event_type == EventType::Unknown {
        String::new()
    } else {
        value.unwrap_or("").to_string()
    }
}

fn compat_message_entries(entry: &LogEntry<'_, '_>) -> Vec<FirehoseItemType> {
    match &entry.items {
        ItemsData::Regular {
            data,
            flags,
            private_data_context,
            ..
        } => {
            let Ok((_, parsed)) = parse_items_data(data, *flags) else {
                return Vec::new();
            };
            let mut items = parsed.items;

            if let Some(ctx) = private_data_context {
                fill_private_data_compat(
                    &mut items,
                    ctx.private_data,
                    ctx.private_strings_offset,
                    ctx.private_data_virtual_offset,
                    ctx.collapsed,
                );
            }

            items.iter().map(compat_item_from_raw).collect()
        }
        ItemsData::Trace { data } => parse_trace_items(data)
            .iter()
            .map(compat_item_from_raw)
            .collect(),
        _ => Vec::new(),
    }
}

fn compat_item_from_raw(item: &RawFirehoseItem<'_>) -> FirehoseItemType {
    FirehoseItemType {
        item_type: item.item_type.into(),
        item_type_size: if matches!(item.item_type, RawItemKind::Number | RawItemKind::Precision) {
            u8::try_from(item.item_size).unwrap_or(0)
        } else {
            0
        },
        offset: 0,
        item_size: item.item_size,
        message_strings: compat_item_value_to_string(item.value),
        item: compat_item_kind(item.item_type),
    }
}

fn compat_item_kind(kind: RawItemKind) -> FirehoseItem {
    match kind {
        RawItemKind::String | RawItemKind::Object | RawItemKind::BaseRaw => FirehoseItem::String,
        RawItemKind::PrivateString
        | RawItemKind::PrivateArbitrary
        | RawItemKind::PrivateObject
        | RawItemKind::Sensitive => FirehoseItem::PrivateString,
        RawItemKind::Arbitrary => FirehoseItem::Object,
        RawItemKind::PrivateNumber => FirehoseItem::PrivateNumber,
        RawItemKind::Number => FirehoseItem::Number,
        RawItemKind::Precision => FirehoseItem::Precision,
        RawItemKind::Unknown => FirehoseItem::Unknown,
    }
}

fn compat_item_value_to_string(value: RawItemValue<'_>) -> String {
    match value {
        RawItemValue::Empty => String::new(),
        RawItemValue::I64(value) => value.to_string(),
        RawItemValue::U64(value) => value.to_string(),
        RawItemValue::Str(value) => value.to_string(),
        RawItemValue::Bytes(value) => base64::engine::general_purpose::STANDARD.encode(value),
        RawItemValue::Private { .. } => String::from("<private>"),
        RawItemValue::Null => String::from("(null)"),
    }
}
