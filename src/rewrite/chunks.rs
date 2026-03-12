use super::*;
use nom::number::complete::{le_u32, le_u64};

/// Typed chunk tag — identifies the kind of chunk in a tracev3 file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, num_enum::IntoPrimitive, num_enum::FromPrimitive)]
#[repr(u32)]
pub enum ChunkTag {
  /// File header (0x1000) — appears once at the start of a tracev3 file.
  Header = 0x1000,
  /// Catalog (0x600b) — metadata: process info, subsystems, subchunk descriptors.
  Catalog = 0x600b,
  /// Chunkset (0x600d) — compressed (bv41) or uncompressed (bv4-) container.
  Chunkset = 0x600d,
  /// Firehose (0x6001) — log entries, found inside decompressed chunksets.
  Firehose = 0x6001,
  /// Oversize (0x6002) — oversize string data, found inside chunksets.
  Oversize = 0x6002,
  /// Statedump (0x6003) — state dump, found inside chunksets.
  Statedump = 0x6003,
  /// Simpledump (0x6004) — simple dump, found inside chunksets.
  Simpledump = 0x6004,
  #[num_enum(default)]
  Unknown,
}

impl ChunkTag {
  /// Whether this tag appears at the top level of a tracev3 file.
  pub fn is_top_level(self) -> bool {
    matches!(self, Self::Header | Self::Catalog | Self::Chunkset)
  }
}

/// Size of the preamble in bytes: `tag`(4) + `sub_tag`(4) + `data_size`(8) = 16.
pub const PREAMBLE_SIZE: usize = 16;

/// Parsed chunk preamble — the 16-byte header that prefixes every chunk.
#[derive(Debug, Clone, Copy)]
pub struct ChunkPreamble {
  pub tag: ChunkTag,
  pub sub_tag: u32,
  /// Size of the chunk body in bytes, *excluding* the 16-byte preamble.
  pub data_size: u64,
}

impl ChunkPreamble {
  /// Get the preamble (first 16 bytes of all Unified Log entries (chunks)) to detect the log (chunk) type. Ex: Firehose, Statedump, Simpledump, Catalog, etc
  /// Do not consume the input
  pub fn detect_preamble(input: &[u8]) -> IResult<&[u8], Self> {
    let (_, preamble) = Self::parse(input)?;
    Ok((input, preamble))
  }

  /// Get the preamble (first 16 bytes of all Unified Log entries (chunks)) to detect the log (chunk) type. Ex: Firehose, Statedump, Simpledump, Catalog, etc
  /// And consume the input
  pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
    let (input, (tag, sub_tag, data_size)) = (le_u32, le_u32, le_u64).parse(input)?;
    let tag = ChunkTag::from(tag);
    Ok((input, ChunkPreamble { tag, sub_tag, data_size }))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn round_trip() -> anyhow::Result<()> {
    for tag in [
      ChunkTag::Header,
      ChunkTag::Catalog,
      ChunkTag::Chunkset,
      ChunkTag::Firehose,
      ChunkTag::Oversize,
      ChunkTag::Statedump,
      ChunkTag::Simpledump,
    ] {
      assert_eq!(ChunkTag::from(tag as u32), tag);
    }

    assert_eq!(ChunkTag::from(42_u32), ChunkTag::Unknown);
    Ok(())
  }

  #[test]
  fn parse_header_preamble() -> anyhow::Result<()> {
    // tag=0x1000, sub_tag=0x11, data_size=0xD0
    let bytes = &[
      0x00, 0x10, 0x00, 0x00, // tag
      0x11, 0x00, 0x00, 0x00, // sub_tag
      0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data_size
    ];

    let (i, p) = ChunkPreamble::parse(bytes)?;
    assert_eq!(p.tag, ChunkTag::Header);
    assert_eq!(p.sub_tag, 0x11);
    assert_eq!(p.data_size, 0xD0);
    assert!(i.is_empty());
    Ok(())
  }

  #[test]
  fn parse_catalog_preamble() -> anyhow::Result<()> {
    let bytes = &[
      0x0b, 0x60, 0x00, 0x00, // tag = 0x600b
      0x11, 0x00, 0x00, 0x00, // sub_tag
      0xB0, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data_size = 0x1FB0
    ];
    let (i, p) = ChunkPreamble::parse(bytes)?;
    assert_eq!(p.tag, ChunkTag::Catalog);
    assert_eq!(p.data_size, 0x1FB0);
    assert!(i.is_empty());
    Ok(())
  }

  #[test]
  fn test_detect_preamble() -> anyhow::Result<()> {
    let test_preamble_header = &[0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0];

    let (output, preamble_data) = ChunkPreamble::detect_preamble(test_preamble_header)?;

    assert_eq!(output, test_preamble_header);
    assert_eq!(preamble_data.tag, ChunkTag::Header);
    assert_eq!(preamble_data.sub_tag, 0x11);
    assert_eq!(preamble_data.data_size, 0xd0);

    let test_catalog_chunk = &[11, 96, 0, 0, 17, 0, 0, 0, 176, 31, 0, 0, 0, 0, 0, 0];
    let (output, preamble_data) = ChunkPreamble::parse(test_catalog_chunk)?;

    assert_eq!(output.len(), 0);
    assert_eq!(preamble_data.tag, ChunkTag::Catalog);
    assert_eq!(preamble_data.sub_tag, 0x11);
    assert_eq!(preamble_data.data_size, 0x1fb0);

    Ok(())
  }
}
