use nom::Parser;
use nom::bytes::complete::take;
use nom::number::complete::{be_u128, le_u16, le_u32, le_u64};
use uuid::Uuid;

use super::helpers::utf8_str_from_cstring;

const DSC_SIGNATURE: u32 = 0x6473_6368; // "dsch"

#[derive(Debug, Clone, Copy)]
pub struct RawRangeDescriptor<'a> {
  pub range_offset: u64,
  pub data_offset: u32,
  pub range_size: u32,
  pub uuid_index: u64,
  pub strings: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct RawUuidDescriptor<'a> {
  pub text_offset: u64,
  pub text_size: u32,
  pub uuid: Uuid,
  pub path_offset: u32,
  pub path_string: &'a str,
}

#[derive(Debug, Clone)]
pub struct RawSharedCacheStrings<'a> {
  pub major_version: u16,
  pub minor_version: u16,
  pub ranges: Vec<RawRangeDescriptor<'a>>,
  pub uuids: Vec<RawUuidDescriptor<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct DscStringResult<'a> {
  pub format_string: &'a str,
  pub library_path: &'a str,
  pub library_uuid: Uuid,
}

impl<'a> RawSharedCacheStrings<'a> {
  /// Find the range containing `string_offset`, extract the null-terminated
  /// format string, and return it with the associated library path/UUID.
  pub fn format_string(&self, string_offset: u64) -> Option<DscStringResult<'a>> {
    for range in &self.ranges {
      if string_offset >= range.range_offset && string_offset < (range.range_offset + u64::from(range.range_size)) {
        let local_offset = (string_offset - range.range_offset) as usize;

        // Edge case: offset at exact boundary means the string is in the next range
        if local_offset == range.strings.len() {
          continue;
        }

        if local_offset > range.strings.len() {
          continue;
        }

        let (_, s) = utf8_str_from_cstring(&range.strings[local_offset..]).ok()?;
        let uuid_entry = self.uuids.get(range.uuid_index as usize)?;
        return Some(DscStringResult {
          format_string: s,
          library_path: uuid_entry.path_string,
          library_uuid: uuid_entry.uuid,
        });
      }
    }
    None
  }

  /// Fallback: library info from the first range (used when offset is invalid).
  pub fn fallback_library_info(&self) -> Option<(&'a str, Uuid)> {
    let range = self.ranges.first()?;
    let uuid_entry = self.uuids.get(range.uuid_index as usize)?;
    Some((uuid_entry.path_string, uuid_entry.uuid))
  }

  pub fn parse(data: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
    let (input, signature) = le_u32(data)?;
    if signature != DSC_SIGNATURE {
      return Err(nom::Err::Error(nom::error::Error::new(data, nom::error::ErrorKind::Tag)));
    }

    let (input, major_version) = le_u16(input)?;
    let (input, minor_version) = le_u16(input)?;
    let (input, number_ranges) = le_u32(input)?;
    let (mut input, number_uuids) = le_u32(input)?;

    let mut ranges = Vec::with_capacity(number_ranges as usize);
    for _ in 0..number_ranges {
      let (next, range) = parse_range(input, major_version)?;
      input = next;
      ranges.push(range);
    }

    let mut uuids = Vec::with_capacity(number_uuids as usize);
    for _ in 0..number_uuids {
      let (next, uuid) = parse_uuid(input, major_version)?;
      input = next;
      uuids.push(uuid);
    }

    // Resolve path strings from original data
    for uuid_entry in &mut uuids {
      let (path_data, _) = take(uuid_entry.path_offset).parse(data)?;
      let (_, path) = utf8_str_from_cstring(path_data)?;
      uuid_entry.path_string = path;
    }

    // Resolve string slices from original data
    for range in &mut ranges {
      let (string_data, _) = take(range.data_offset).parse(data)?;
      let (_, strings) = take(range.range_size).parse(string_data)?;
      range.strings = strings;
    }

    Ok((
      input,
      RawSharedCacheStrings {
        major_version,
        minor_version,
        ranges,
        uuids,
      },
    ))
  }
}

fn parse_range<'a>(input: &'a [u8], major_version: u16) -> nom::IResult<&'a [u8], RawRangeDescriptor<'a>> {
  if major_version >= 2 {
    // v2: range_offset(u64), data_offset(u32), range_size(u32), uuid_index(u64)
    let (input, range_offset) = le_u64(input)?;
    let (input, data_offset) = le_u32(input)?;
    let (input, range_size) = le_u32(input)?;
    let (input, uuid_index) = le_u64(input)?;
    Ok((
      input,
      RawRangeDescriptor {
        range_offset,
        data_offset,
        range_size,
        uuid_index,
        strings: &[],
      },
    ))
  } else {
    // v1: uuid_index(u32), range_offset(u32), data_offset(u32), range_size(u32)
    let (input, uuid_index) = le_u32(input)?;
    let (input, range_offset) = le_u32(input)?;
    let (input, data_offset) = le_u32(input)?;
    let (input, range_size) = le_u32(input)?;
    Ok((
      input,
      RawRangeDescriptor {
        range_offset: u64::from(range_offset),
        data_offset,
        range_size,
        uuid_index: u64::from(uuid_index),
        strings: &[],
      },
    ))
  }
}

fn parse_uuid<'a>(input: &'a [u8], major_version: u16) -> nom::IResult<&'a [u8], RawUuidDescriptor<'a>> {
  let (input, text_offset) = if major_version >= 2 {
    le_u64(input)?
  } else {
    let (i, v) = le_u32(input)?;
    (i, u64::from(v))
  };
  let (input, text_size) = le_u32(input)?;
  let (input, uuid_val) = be_u128(input)?;
  let (input, path_offset) = le_u32(input)?;

  Ok((
    input,
    RawUuidDescriptor {
      text_offset,
      text_size,
      uuid: Uuid::from_u128(uuid_val),
      path_offset,
      path_string: "",
    },
  ))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rewrite::helpers::tests::test_data_path;

  #[test]
  fn test_parse_dsc_v1() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");
    let buffer = std::fs::read(path)?;

    let (_, results) = RawSharedCacheStrings::parse(&buffer).unwrap();

    assert_eq!(results.major_version, 1);
    assert_eq!(results.minor_version, 0);
    assert_eq!(results.ranges.len(), 788);
    assert_eq!(results.uuids.len(), 532);

    assert_eq!(results.uuids.len(), 532);
    assert_eq!(results.uuids[0].uuid, Uuid::parse_str("4DF6D8F5D9C23A968DE45E99D6B73DC8")?);
    assert_eq!(results.uuids[0].path_string, "/usr/lib/system/libsystem_blocks.dylib");
    assert_eq!(results.uuids[0].text_offset, 73728);
    assert_eq!(results.uuids[0].text_size, 8192);
    assert_eq!(results.uuids[0].path_offset, 19919502);

    assert_eq!(results.ranges.len(), 788);
    assert_eq!(results.ranges[0].strings, [0]);
    assert_eq!(results.ranges[0].uuid_index, 0);
    assert_eq!(results.ranges[0].range_offset, 80296);
    assert_eq!(results.ranges[0].range_size, 1);
    Ok(())
  }

  #[test]
  fn test_parse_dsc_v2() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/monterey_version_2_3D05845F3F65358F9EBF2236E772AC01");
    let buffer = std::fs::read(path)?;

    let (_, results) = RawSharedCacheStrings::parse(&buffer).unwrap();

    assert_eq!(results.major_version, 2);
    assert_eq!(results.minor_version, 0);
    assert_eq!(results.ranges.len(), 3432);
    assert_eq!(results.uuids.len(), 2250);

    assert_eq!(results.uuids.len(), 2250);
    assert_eq!(results.uuids[0].uuid, Uuid::parse_str("326DD91B4EF83D80B90BF50EB7D7FDB8")?);
    assert_eq!(results.uuids[0].path_string, "/usr/lib/system/libsystem_blocks.dylib");
    assert_eq!(results.uuids[0].text_offset, 327680);
    assert_eq!(results.uuids[0].text_size, 8192);
    assert_eq!(results.uuids[0].path_offset, 98376932);

    assert_eq!(results.ranges.len(), 3432);
    assert_eq!(results.ranges[0].strings, [0]);
    assert_eq!(results.ranges[0].uuid_index, 0);
    assert_eq!(results.ranges[0].range_offset, 334248);
    assert_eq!(results.ranges[0].range_size, 1);
    Ok(())
  }

  #[test]
  fn test_dsc_format_string_v1() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");
    let buffer = std::fs::read(path)?;
    let (_, dsc) = RawSharedCacheStrings::parse(&buffer).unwrap();

    // Use a known range's offset
    let offset = dsc.ranges[1].range_offset;
    let result = dsc.format_string(offset);
    assert!(result.is_some(), "Expected format string at offset {offset}");
    let result = result.unwrap();
    assert!(!result.format_string.is_empty());
    assert!(!result.library_path.is_empty());
    assert!(!result.library_uuid.is_nil());
    Ok(())
  }

  #[test]
  fn test_dsc_format_string_v2() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/monterey_version_2_3D05845F3F65358F9EBF2236E772AC01");
    let buffer = std::fs::read(path)?;
    let (_, dsc) = RawSharedCacheStrings::parse(&buffer).unwrap();

    let offset = dsc.ranges[1].range_offset;
    let result = dsc.format_string(offset);
    assert!(result.is_some(), "Expected format string at offset {offset}");
    let result = result.unwrap();
    assert!(!result.format_string.is_empty());
    assert!(!result.library_path.is_empty());
    assert!(!result.library_uuid.is_nil());
    Ok(())
  }

  #[test]
  fn test_dsc_format_string_not_found() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");
    let buffer = std::fs::read(path)?;
    let (_, dsc) = RawSharedCacheStrings::parse(&buffer).unwrap();

    // Use an offset that's way out of range
    let result = dsc.format_string(0xFFFF_FFFF_FFFF);
    assert!(result.is_none());
    Ok(())
  }

  #[test]
  fn test_dsc_format_string_boundary() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");
    let buffer = std::fs::read(path)?;
    let (_, dsc) = RawSharedCacheStrings::parse(&buffer).unwrap();

    // Offset at exact range boundary (range_offset + range_size) should skip to next range
    let range = &dsc.ranges[0];
    let boundary_offset = range.range_offset + u64::from(range.range_size);
    // This should either find the next range or return None — not panic
    let _ = dsc.format_string(boundary_offset);
    Ok(())
  }

  #[test]
  fn test_dsc_fallback_library_info() -> anyhow::Result<()> {
    let path = test_data_path().join("DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2");
    let buffer = std::fs::read(path)?;
    let (_, dsc) = RawSharedCacheStrings::parse(&buffer).unwrap();

    let (lib_path, lib_uuid) = dsc.fallback_library_info().unwrap();
    assert!(!lib_path.is_empty());
    assert!(!lib_uuid.is_nil());
    // Should match the first range's UUID entry
    assert_eq!(lib_uuid, dsc.uuids[dsc.ranges[0].uuid_index as usize].uuid);
    Ok(())
  }

  #[test]
  fn test_bad_signature() -> anyhow::Result<()> {
    let data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let result = RawSharedCacheStrings::parse(&data);
    assert!(result.is_err());
    match result.unwrap_err() {
      nom::Err::Error(e) => assert_eq!(e.code, nom::error::ErrorKind::Tag),
      other => panic!("Expected Error(Tag), got: {other:?}"),
    }
    Ok(())
  }
}
