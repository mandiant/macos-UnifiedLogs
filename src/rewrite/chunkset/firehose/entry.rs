use nom::number::complete::{le_u8, le_u16, le_u32, le_u64};

use super::super::super::helpers::padding_size_8;
use super::body::RawFirehoseBody;
use super::flags::FirehoseFlags;
use super::item::RawFirehoseItemData;

const ENTRY_HEADER_SIZE: usize = 24;
const REMNANT_DATA: u8 = 0x0;

/// Firehose entry activity type — identifies the kind of log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
#[repr(u8)]
pub enum FirehoseActivityType {
  Activity = 0x2,
  Trace = 0x3,
  NonActivity = 0x4,
  Signpost = 0x6,
  Loss = 0x7,
  #[num_enum(default)]
  Unknown,
}

/// Firehose entry log type — the raw wire value for severity/subtype.
///
/// Note: `Info` (0x01) is also used as `Create` for activity entries.
/// The semantic interpretation depends on `FirehoseActivityType` and belongs
/// in a higher-level layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
#[repr(u8)]
pub enum FirehoseLogType {
  /// Info (0x01) — also "Create" for activity entries.
  Info = 0x01,
  Debug = 0x02,
  Useraction = 0x03,
  Error = 0x10,
  Fault = 0x11,
  ThreadSignpostEvent = 0x40,
  ThreadSignpostStart = 0x41,
  ThreadSignpostEnd = 0x42,
  ProcessSignpostEvent = 0x80,
  ProcessSignpostStart = 0x81,
  ProcessSignpostEnd = 0x82,
  SystemSignpostEvent = 0xc0,
  SystemSignpostStart = 0xc1,
  SystemSignpostEnd = 0xc2,
  #[num_enum(default)]
  Default,
}

/// A single firehose log entry header with its raw body (zero-copy).
///
/// The 24-byte header is fully parsed; the type-specific body (`entry_data`)
/// is kept as raw `&[u8]` for later dispatch (activity / nonactivity / signpost / trace / loss).
#[derive(Debug, Clone, Copy)]
pub struct RawFirehoseEntry<'a> {
  pub log_activity_type: FirehoseActivityType,
  pub log_type: FirehoseLogType,
  pub flags: FirehoseFlags,
  pub format_string_location: u32,
  pub thread_id: u64,
  pub continuous_time_delta: u32,
  pub continuous_time_delta_upper: u16,
  pub data_size: u16,
  pub entry_data: &'a [u8],
}

impl<'a> RawFirehoseEntry<'a> {
  /// Reconstruct the 48-bit continuous time delta from its split fields.
  pub fn continuous_time_delta_combined(&self) -> u64 {
    u64::from(self.continuous_time_delta) | (u64::from(self.continuous_time_delta_upper) << 32)
  }

  /// Compute the absolute continuous time given the firehose chunk's base time.
  pub fn absolute_continuous_time(&self, base_continuous_time: u64) -> u64 {
    base_continuous_time + self.continuous_time_delta_combined()
  }

  /// Parse the type-specific body by dispatching on `log_activity_type`.
  ///
  /// Returns a `RawFirehoseBody` variant matching the entry type, with the
  /// remaining unparsed bytes captured as `items_data` in each body struct.
  pub fn parse_body(&self) -> Result<RawFirehoseBody<'a>, nom::Err<nom::error::Error<&'a [u8]>>> {
    RawFirehoseBody::parse(self.entry_data, self.log_activity_type, self.flags, self.log_type)
  }

  /// Parse items from this entry — dispatches to the right parser based on body type.
  pub fn parse_items(&self) -> Option<RawFirehoseItemData<'a>> {
    self.parse_body().ok()?.parse_items(self.flags)
  }

  fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
    let (input, log_activity_type_raw) = le_u8(input)?;
    let (input, log_type_raw) = le_u8(input)?;
    let log_activity_type = FirehoseActivityType::from(log_activity_type_raw);
    let log_type = FirehoseLogType::from(log_type_raw);
    let (input, flags_raw) = le_u16(input)?;
    let flags = FirehoseFlags::from_bits_retain(flags_raw);
    let (input, format_string_location) = le_u32(input)?;
    let (input, thread_id) = le_u64(input)?;
    let (input, continuous_time_delta) = le_u32(input)?;
    let (input, continuous_time_delta_upper) = le_u16(input)?;
    let (input, data_size) = le_u16(input)?;

    let data_len = data_size as usize;
    if input.len() < data_len {
      return Err(nom::Err::Incomplete(nom::Needed::new(data_len - input.len())));
    }
    let entry_data = &input[..data_len];
    let input = &input[data_len..];

    Ok((
      input,
      RawFirehoseEntry {
        log_activity_type,
        log_type,
        flags,
        format_string_location,
        thread_id,
        continuous_time_delta,
        continuous_time_delta_upper,
        data_size,
        entry_data,
      },
    ))
  }
}

/// Iterator over individual firehose entries within the public data region.
///
/// Stops when:
/// - remaining bytes < 24 (entry header size)
/// - `log_activity_type == 0x0` (remnant/sentinel)
/// - `data_size` exceeds remaining bytes (malformed)
pub struct RawFirehoseEntryReader<'a> {
  data: &'a [u8],
}

impl<'a> RawFirehoseEntryReader<'a> {
  pub fn new(data: &'a [u8]) -> Self {
    Self { data }
  }

  /// Remaining unconsumed bytes after iteration completes.
  pub fn remaining(&self) -> &'a [u8] {
    self.data
  }
}

impl<'a> Iterator for RawFirehoseEntryReader<'a> {
  type Item = RawFirehoseEntry<'a>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.data.len() < ENTRY_HEADER_SIZE {
      return None;
    }

    // Peek at raw log_activity_type byte — 0x0 means end of entries
    if self.data[0] == REMNANT_DATA {
      return None;
    }

    let entry = match RawFirehoseEntry::parse(self.data) {
      Ok((remaining, entry)) => {
        let padding = padding_size_8(u64::from(entry.data_size)) as usize;

        // In compat mode, match the legacy's padding behavior: if the calculated
        // 8-byte alignment padding extends into non-zero bytes, skip only the
        // leading zeros instead. The legacy code eats zeros via `take_while`,
        // then falls back when `padding > leading_zeros`.
        #[cfg(feature = "rewrite-compat")]
        {
          let leading_zeros = remaining.iter().take_while(|&&b| b == 0).count();
          let skip = if padding > leading_zeros { leading_zeros } else { padding };
          self.data = &remaining[skip..];
        }
        #[cfg(not(feature = "rewrite-compat"))]
        {
          if remaining.len() >= padding {
            self.data = &remaining[padding..];
          } else {
            self.data = &[];
          }
        }
        entry
      }
      Err(_) => return None,
    };

    Some(entry)
  }
}

#[cfg(test)]
mod tests {
  use super::super::RawFirehose;
  use super::*;

  /// Same test data as `test_parse_raw_firehose` in mod.rs.
  /// 16-byte preamble + 32-byte header + 120 bytes of entry data (3 entries).
  const TEST_DATA: &[u8] = &[
    1, 96, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 133, 16, 0, 0, 0, 0, 0, 0, 157, 38, 0, 0, 0, 0, 0, 0, 136, 0, 0, 16, 0, 0, 0, 2, 42,
    188, 25, 14, 104, 4, 0, 0, 2, 1, 4, 0, 240, 243, 53, 0, 176, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 12, 0, 176, 249, 0, 0, 0, 0, 0,
    128, 163, 133, 51, 0, 0, 0, 0, 0, 2, 1, 4, 0, 32, 250, 53, 0, 177, 232, 0, 0, 0, 0, 0, 0, 209, 67, 85, 0, 16, 0, 12, 0, 177, 249, 0, 0,
    0, 0, 0, 128, 237, 115, 51, 0, 0, 0, 0, 0, 2, 1, 4, 0, 48, 57, 126, 0, 179, 232, 0, 0, 0, 0, 0, 0, 40, 101, 197, 1, 16, 0, 12, 0, 178,
    249, 0, 0, 0, 0, 0, 128, 105, 67, 61, 0, 0, 0, 0, 0,
  ];

  #[test]
  fn test_iterate_entries() -> anyhow::Result<()> {
    let data = &TEST_DATA[16..]; // skip preamble
    let (_, fh) = RawFirehose::parse(data).unwrap();
    let entries: Vec<_> = fh.entries().collect();

    assert_eq!(entries.len(), 3);

    for entry in &entries {
      assert_eq!(entry.log_activity_type, FirehoseActivityType::Activity);
      assert_eq!(entry.log_type, FirehoseLogType::Info);
      assert_eq!(entry.flags.bits(), 4);
      assert_eq!(entry.data_size, 12);
      assert_eq!(entry.entry_data.len(), 12);
    }

    // thread_id should differ between entries
    assert_ne!(entries[0].thread_id, entries[1].thread_id);
    assert_ne!(entries[1].thread_id, entries[2].thread_id);

    // continuous_time_delta should differ
    assert_ne!(entries[0].continuous_time_delta, entries[1].continuous_time_delta);
    Ok(())
  }

  #[test]
  fn test_continuous_time_methods() -> anyhow::Result<()> {
    let data = &TEST_DATA[16..]; // skip preamble
    let (_, fh) = RawFirehose::parse(data).unwrap();
    let entries: Vec<_> = fh.entries().collect();

    let entry = &entries[0];

    // combined delta must equal lower | (upper << 32)
    let expected_combined = u64::from(entry.continuous_time_delta) | (u64::from(entry.continuous_time_delta_upper) << 32);
    assert_eq!(entry.continuous_time_delta_combined(), expected_combined);

    // absolute = base + combined
    let base = fh.base_continuous_time;
    assert_eq!(entry.absolute_continuous_time(base), base + expected_combined);

    // zero base should return just the combined delta
    assert_eq!(entry.absolute_continuous_time(0), expected_combined);
    Ok(())
  }
}
