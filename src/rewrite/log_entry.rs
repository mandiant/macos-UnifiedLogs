//! Output types for the rewrite pipeline.
//!
//! `LogEntry<'a, 'b>` is the zero-copy replacement for `LogData` + `RcString`.
//! All fields borrow from source data buffers. The `message` is formatted
//! on demand via `.message()` — no heap allocation until explicitly requested.

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use uuid::Uuid;

use super::decoders::{config, location};

use super::chunkset::firehose::flags::FirehoseFlags;
#[cfg(feature = "rewrite-compat")]
use super::chunkset::firehose::item::fill_private_data_compat;
#[cfg(not(feature = "rewrite-compat"))]
use super::chunkset::firehose::item::fill_private_data;
use super::chunkset::firehose::item::{parse_items_data, parse_trace_items};
#[cfg(not(feature = "rewrite-compat"))]
use super::format::NoDecoder;
#[cfg(feature = "rewrite-compat")]
use super::format::OldAppleDecoder;
use super::format::{AppleDecoder, format_message};

/// Event type classification for a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EventType {
  Unknown,
  Log,
  Activity,
  Trace,
  Signpost,
  Simpledump,
  Statedump,
  Loss,
}

/// Log severity/subtype for a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LogType {
  Debug,
  Info,
  Default,
  Error,
  Fault,
  Create,
  Useraction,
  ProcessSignpostEvent,
  ProcessSignpostStart,
  ProcessSignpostEnd,
  SystemSignpostEvent,
  SystemSignpostStart,
  SystemSignpostEnd,
  ThreadSignpostEvent,
  ThreadSignpostStart,
  ThreadSignpostEnd,
  Simpledump,
  Statedump,
  Loss,
}

/// Context for filling private item values from the firehose private data section.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PrivateDataContext<'b> {
  pub private_data: &'b [u8],
  pub private_strings_offset: u16,
  pub private_data_virtual_offset: u16,
  pub collapsed: u8,
  /// Extended private data region for compat mode — extends to end of chunkset buffer.
  /// The old pipeline had access to subsequent chunks' data when parsing private items,
  /// producing different results (e.g., "Could not find path string") for oversized items.
  #[cfg(feature = "rewrite-compat")]
  pub extended_private_data: Option<&'b [u8]>,
}

/// Raw data needed to format a message on demand.
/// Not public — callers use `LogEntry::message()`.
///
/// Borrows raw item bytes with lifetime `'b` from the tracev3 chunk data
/// or oversize cache — zero-copy. The `'b` lifetime is scoped to a single
/// iteration of the chunkset reader, which outlives the callback invocation.
#[derive(Debug)]
pub(crate) enum ItemsData<'b> {
  /// Activity/NonActivity/Signpost: raw item bytes.
  Regular {
    data: &'b [u8],
    flags: FirehoseFlags,
    private_data_context: Option<PrivateDataContext<'b>>,
  },
  /// Trace: raw item bytes (parsed differently — reversed big-endian).
  Trace { data: &'b [u8] },
  /// Loss entry: formatted lazily from count + time range.
  Loss { count: u64, start_time: u64, end_time: u64 },
  /// SimpleDump: message is pre-formatted in the chunk data.
  Simpledump { subsystem: &'b str, message: &'b str },
  /// StateDump: raw data to be decoded based on data_type.
  Statedump {
    title_name: &'b str,
    decoder_library: &'b str,
    decoder_type: &'b str,
    statedump_data: &'b [u8],
    data_type: u32,
  },
  /// No items (Unknown, or genuinely empty).
  None,
}

/// Zero-copy log entry — borrows strings from source data buffers.
///
/// All `&'a str` fields borrow from the tracev3 file buffer, DSC files,
/// or `UUIDText` files passed to [`super::tracev3::process_tracev3`].
/// The `'b` lifetime covers raw item bytes borrowed from chunk data or
/// the oversize cache — scoped to a single chunkset iteration.
///
/// The log message is **not** eagerly formatted. Call `.message()` to format
/// the message string on demand. This is the only allocation point.
#[derive(Debug)]
pub struct LogEntry<'a, 'b> {
  pub subsystem: Option<&'a str>,
  pub category: Option<&'a str>,
  pub thread_id: u64,
  pub pid: u64,
  pub euid: u32,
  pub library: Option<&'a str>,
  pub library_uuid: Uuid,
  pub activity_id: u64,
  pub time: f64,
  pub event_type: EventType,
  pub log_type: LogType,
  pub process: Option<&'a str>,
  pub process_uuid: Uuid,
  pub format_string: Option<&'a str>,
  pub boot_uuid: Uuid,
  pub timezone_name: &'a str,
  // Private: deferred message data
  pub(crate) items: ItemsData<'b>,
  // Signpost fields — populated only for Signpost entries, 0 otherwise.
  #[cfg_attr(not(feature = "rewrite-compat"), allow(dead_code))]
  pub(crate) signpost_id: u64,
  #[cfg_attr(not(feature = "rewrite-compat"), allow(dead_code))]
  pub(crate) signpost_name: u32,
  /// Error message for invalid format string offsets (old pipeline parity).
  /// When `format_string` is None, this replaces `<missing format string>`.
  #[cfg(feature = "rewrite-compat")]
  pub(crate) format_string_error: Option<String>,
}

impl<'a, 'b> LogEntry<'a, 'b> {
  /// Return the effective subsystem — simpledump entries carry it in `ItemsData`.
  pub fn effective_subsystem(&self) -> Option<&str> {
    match &self.items {
      ItemsData::Simpledump { subsystem, .. } => Some(subsystem),
      _ => self.subsystem,
    }
  }

  /// Format the log message on demand. This is the only allocation point.
  pub fn message(&self) -> String {
    #[cfg(feature = "rewrite-compat")]
    {
      self.message_with_decoder(&OldAppleDecoder)
    }
    #[cfg(not(feature = "rewrite-compat"))]
    {
      self.message_with_decoder(&NoDecoder)
    }
  }

  /// Effective format string — falls back to error string for parity with old pipeline.
  fn effective_format_string(&self) -> Option<&str> {
    if self.format_string.is_some() {
      return self.format_string;
    }
    #[cfg(feature = "rewrite-compat")]
    {
      self.format_string_error.as_deref()
    }
    #[cfg(not(feature = "rewrite-compat"))]
    {
      None
    }
  }

  /// Format with a custom Apple decoder.
  pub fn message_with_decoder(&self, decoder: &dyn AppleDecoder) -> String {
    let fmt_str = self.effective_format_string();
    match &self.items {
      ItemsData::Regular { data, flags, .. } => {
        let (mut items, backtrace) = match parse_items_data(data, *flags) {
          Ok((_, d)) => (d.items, d.backtrace_data),
          Err(_) => (Vec::new(), None),
        };
        if let ItemsData::Regular {
          private_data_context: Some(ctx),
          ..
        } = &self.items
        {
          #[cfg(not(feature = "rewrite-compat"))]
          fill_private_data(
            &mut items,
            ctx.private_data,
            ctx.private_strings_offset,
            ctx.private_data_virtual_offset,
            ctx.collapsed,
          );
          #[cfg(feature = "rewrite-compat")]
          fill_private_data_compat(
            &mut items,
            ctx.private_data,
            ctx.private_strings_offset,
            ctx.private_data_virtual_offset,
            ctx.collapsed,
          );
        }
        let msg = format_message(fmt_str, &items, decoder);
        self.apply_parity_prefix(msg, backtrace)
      }
      ItemsData::Trace { data } => {
        let items = parse_trace_items(data);
        format_message(fmt_str, &items, decoder)
      }
      ItemsData::Loss {
        count,
        start_time,
        end_time,
      } => {
        #[cfg(feature = "rewrite-compat")]
        {
          let _ = (count, start_time, end_time);
          String::new()
        }
        #[cfg(not(feature = "rewrite-compat"))]
        {
          format!("Lost {} log entries between {} and {}", count, start_time, end_time)
        }
      }
      ItemsData::Simpledump { message, .. } => message.to_string(),
      ItemsData::Statedump {
        title_name,
        decoder_library,
        decoder_type,
        statedump_data,
        data_type,
      } => {
        let data_string = format_statedump_data(*data_type, statedump_data, title_name);
        format!(
          "title: {title_name}\nObject Type: {decoder_library}\nObject Type: {decoder_type}\n{data_string}"
        )
      }
      ItemsData::None => format_message(fmt_str, &[], decoder),
    }
  }

  /// Compute wall-clock timestamp on demand from `time` (nanoseconds since UNIX epoch).
  pub fn timestamp(&self) -> DateTime<Utc> {
    DateTime::from_timestamp_nanos(self.time as i64)
  }

  /// Apply signpost prefix and backtrace prefix for parity with the old pipeline.
  /// Without the feature flag, returns the message unchanged.
  fn apply_parity_prefix(&self, msg: String, _backtrace: Option<&[u8]>) -> String {
    #[cfg(feature = "rewrite-compat")]
    {
      let mut result = msg;

      // Signpost entries get "Signpost ID: XX - Signpost Name: XX\n " prefix
      if self.event_type == EventType::Signpost {
        result = format!(
          "Signpost ID: {:X} - Signpost Name: {:X}\n {result}",
          self.signpost_id, self.signpost_name,
        );
      }

      // Backtrace data gets "Backtrace:\n{lines}\n" prefix
      if let Some(bt_data) = _backtrace {
        let bt_str = format_backtrace(bt_data);
        if !bt_str.is_empty() {
          result = format!("Backtrace:\n{bt_str}\n{result}");
        }
      }

      result
    }
    #[cfg(not(feature = "rewrite-compat"))]
    {
      msg
    }
  }
}

/// Format raw backtrace bytes into the old pipeline's string format.
///
/// Layout: 3 unknown bytes, uuid_count (u8), offset_count (u16 LE),
/// UUIDs (uuid_count × 16, big-endian u128), offsets (offset_count × 4, LE u32),
/// indexes (offset_count × 1).
///
/// Output: one line per offset: `"UUID_HEX" +0xOFFSET_DECIMAL` joined by newlines.
/// Matches old pipeline's `FirehosePreamble::get_backtrace_data()`.
#[cfg(feature = "rewrite-compat")]
fn format_backtrace(data: &[u8]) -> String {
  if data.len() < 6 {
    return String::new();
  }

  let uuid_count = data[3] as usize;
  let offset_count = u16::from_le_bytes([data[4], data[5]]) as usize;

  let uuid_start = 6;
  let uuid_end = uuid_start + uuid_count * 16;
  let offsets_end = uuid_end + offset_count * 4;
  let indexes_end = offsets_end + offset_count;

  if data.len() < indexes_end {
    return String::new();
  }

  let uuids: Vec<u128> = (0..uuid_count)
    .map(|i| {
      let s = uuid_start + i * 16;
      u128::from_be_bytes(data[s..s + 16].try_into().unwrap())
    })
    .collect();

  let offsets: Vec<u32> = (0..offset_count)
    .map(|i| {
      let s = uuid_end + i * 4;
      u32::from_le_bytes(data[s..s + 4].try_into().unwrap())
    })
    .collect();

  let indexes = &data[offsets_end..indexes_end];

  let lines: Vec<String> = indexes
    .iter()
    .enumerate()
    .map(|(i, &idx)| {
      let uuid = uuids.get(idx as usize).copied().unwrap_or(0);
      let offset = offsets.get(i).copied().unwrap_or(0);
      // Old pipeline uses: format!("\"{:X}\" +0x{:?}", uuid, offset)
      // {:?} on u32 gives decimal, so +0x prefix is cosmetic (matches old behavior)
      format!("\"{uuid:X}\" +0x{offset:?}")
    })
    .collect();

  lines.join("\n")
}

// Statedump data type constants (matches src/constants.rs)
const STATEDUMP_DATA_PLIST: u32 = 1;
const STATEDUMP_DATA_PROTOBUF: u32 = 2;
const STATEDUMP_DATA_OBJECT: u32 = 3;

/// Format statedump data based on its type (plist, protobuf, custom object, or raw string).
fn format_statedump_data(data_type: u32, data: &[u8], title_name: &str) -> String {
  match data_type {
    STATEDUMP_DATA_PLIST => {
      if data.is_empty() {
        return String::from("Empty plist data");
      }
      match plist::from_bytes::<plist::Value>(data) {
        Ok(value) => serde_json::to_string(&value)
          .unwrap_or_else(|_| String::from("Failed to convert plist data to json")),
        Err(_) => String::from("Failed to get plist data"),
      }
    }
    STATEDUMP_DATA_PROTOBUF => match sunlight::light::extract_protobuf(data) {
      Ok(map) => {
        #[cfg(feature = "rewrite-compat")]
        let map: std::collections::BTreeMap<_, _> = map.into_iter().collect();
        serde_json::to_string(&map)
          .unwrap_or_else(|_| String::from("Failed to serialize Protobuf HashMap"))
      }
      Err(_) => format!(
        "Failed to parse StateDump protobuf: {}",
        base64::engine::general_purpose::STANDARD.encode(data)
      ),
    },
    STATEDUMP_DATA_OBJECT => format_statedump_object(data, title_name),
    _ => std::str::from_utf8(data)
      .map(|s| s.to_string())
      .unwrap_or_else(|_| String::from("Failed to extract statedump data")),
  }
}

/// Decode a statedump custom object (data_type=3) using the appropriate decoder.
fn format_statedump_object(data: &[u8], title_name: &str) -> String {
  let result = match title_name {
    "CLDaemonStatusStateTracker" => location::get_daemon_status_tracker(data).map(|(_, r)| r.to_string()),
    "CLClientManagerStateTracker" => location::get_state_tracker_data(data).map(|(_, r)| r.to_string()),
    "CLLocationManagerStateTracker" => {
      location::get_location_tracker_state(data).map(|(_, r)| r.to_string())
    }
    "DNS Configuration" => config::get_dns_config(data).map(|(_, r)| r.to_string()),
    "Network information" => config::get_network_interface(data).map(|(_, r)| r.to_string()),
    _ => {
      return format!(
        "Unsupported Statedump object: {title_name}-{}",
        base64::engine::general_purpose::STANDARD.encode(data)
      );
    }
  };
  match result {
    Ok(s) => s,
    Err(_) => format!("Failed to parse statedump object: {title_name}"),
  }
}

impl Serialize for LogEntry<'_, '_> {
  fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    let mut state = serializer.serialize_struct("LogEntry", 17)?;
    state.serialize_field("subsystem", &self.effective_subsystem())?;
    state.serialize_field("category", &self.category)?;
    state.serialize_field("thread_id", &self.thread_id)?;
    state.serialize_field("pid", &self.pid)?;
    state.serialize_field("euid", &self.euid)?;
    state.serialize_field("library", &self.library)?;
    state.serialize_field("library_uuid", &self.library_uuid)?;
    state.serialize_field("activity_id", &self.activity_id)?;
    state.serialize_field("time", &self.time)?;
    state.serialize_field("event_type", &self.event_type)?;
    state.serialize_field("log_type", &self.log_type)?;
    state.serialize_field("process", &self.process)?;
    state.serialize_field("process_uuid", &self.process_uuid)?;
    let message = self.message();
    state.serialize_field("message", &message)?;
    state.serialize_field("format_string", &self.effective_format_string())?;
    state.serialize_field("boot_uuid", &self.boot_uuid)?;
    state.serialize_field("timezone_name", self.timezone_name)?;
    state.end()
  }
}
