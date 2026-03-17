use super::{chunks_reader::*, *};
use nom::number::complete::{le_u32, le_u64};
use std::rc::Rc;

pub mod firehose;
pub mod oversize;
pub mod simpledump;
pub mod statedump;

const BV41_COMPRESSED: u32 = 825_521_762; // "bv41"
const BV41_UNCOMPRESSED: u32 = 758_412_898; // "bv4-"

/// Typed chunk tag — identifies the kind of chunk in a tracev3 file.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, num_enum::IntoPrimitive, num_enum::FromPrimitive,
)]
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
        Ok((
            input,
            ChunkPreamble {
                tag,
                sub_tag,
                data_size,
            },
        ))
    }
}

/// Decompressed chunkset payload — either borrowed (uncompressed) or owned (was compressed).
pub enum ChunksetPayload<'a> {
    /// `bv4-`: data is borrowed directly from the input buffer.
    Uncompressed(&'a [u8]),
    /// `bv41`: data was LZ4-decompressed into an owned buffer.
    Decompressed(Rc<Vec<u8>>),
}

impl std::fmt::Debug for ChunksetPayload<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uncompressed(data) => f.debug_tuple("Uncompressed").field(&data.len()).finish(),
            Self::Decompressed(vec) => f.debug_tuple("Decompressed").field(&vec.len()).finish(),
        }
    }
}

impl<'a> ChunksetPayload<'a> {
    /// Get the inner chunk data as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Uncompressed(data) => data,
            Self::Decompressed(vec) => vec.as_ref(),
        }
    }

    /// Iterate over the inner chunks using `RawChunksReader` with 8-byte padding.
    pub fn inner_chunks(&self) -> RawChunksReader<'_> {
        RawChunksReader::new_chunckset(self.as_bytes())
    }
}

impl<'a> ChunksetPayload<'a> {
    /// Parse chunkset body (after preamble) into decompressed payload.
    /// `data` is `RawChunk.data` for a `ChunkTag::Chunkset` chunk.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let (input, signature) =
            le_u32::<_, nom::error::Error<&[u8]>>(data).map_err(|e| e.to_parse_error())?;
        let (input, uncompressed_size) =
            le_u32::<_, nom::error::Error<&[u8]>>(input).map_err(|e| e.to_parse_error())?;

        match signature {
            BV41_UNCOMPRESSED => {
                let size = uncompressed_size as usize;
                if input.len() < size {
                    return Err(ParseError::unexpected_eof(
                        8,
                        size,
                        input.len(),
                        Some("chunkset uncompressed payload"),
                    ));
                }
                Ok(ChunksetPayload::Uncompressed(&input[..size]))
            }
            BV41_COMPRESSED => {
                let (input, compressed_size) =
                    le_u32::<_, nom::error::Error<&[u8]>>(input).map_err(|e| e.to_parse_error())?;
                let size = compressed_size as usize;
                if input.len() < size {
                    return Err(ParseError::unexpected_eof(
                        12,
                        size,
                        input.len(),
                        Some("chunkset compressed payload"),
                    ));
                }
                let decompressed = lz4_flex::decompress(&input[..size], uncompressed_size as usize)
                    .map_err(|e| {
                        ParseError::decompress_error(
                            0,
                            e.to_string(),
                            Some("chunkset LZ4 decompress"),
                        )
                    })?;
                Ok(ChunksetPayload::Decompressed(Rc::new(decompressed)))
            }
            _ => Err(ParseError::unknown_chunk_tag(
                0,
                signature,
                Some("chunkset signature (expected bv41 or bv4-)"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::tests::test_data_path;

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
        let test_preamble_header = &[
            0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        ];

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

    #[test]
    fn decompress_big_sur_chunkset() -> anyhow::Result<()> {
        let test_data = test_data_path();
        let data = std::fs::read(test_data.join("Chunkset Tests/big_sur_chunkset.raw"))?;

        // This file is raw inner chunk data — test RawChunksReader on it directly
        // to confirm our inner_chunks() method would work the same way.
        let reader = RawChunksReader::new_top_level(&data);
        let chunks: Vec<_> = reader.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(chunks.len(), 26);

        // Verify all chunks have valid inner-chunk tags
        for chunk in &chunks {
            assert!(matches!(
                chunk.preamble.tag,
                ChunkTag::Firehose
                    | ChunkTag::Oversize
                    | ChunkTag::Statedump
                    | ChunkTag::Simpledump
            ));
        }
        Ok(())
    }

    #[test]
    fn parse_real_tracev3_chunksets() -> anyhow::Result<()> {
        let test_data = test_data_path();
        let tracev3_path =
            test_data.join("system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");
        let file_data = std::fs::read(tracev3_path)?;
        let reader = RawChunksReader::new_top_level(&file_data);

        let mut total_inner = 0;
        for chunk in reader {
            let chunk = chunk?;
            if chunk.preamble.tag == ChunkTag::Chunkset {
                let payload = ChunksetPayload::parse(chunk.data)?;
                for inner in payload.inner_chunks() {
                    let inner = inner?;
                    assert!(matches!(
                        inner.preamble.tag,
                        ChunkTag::Firehose
                            | ChunkTag::Oversize
                            | ChunkTag::Statedump
                            | ChunkTag::Simpledump
                    ));
                    total_inner += 1;
                }
            }
        }

        assert_eq!(total_inner, 3411);
        Ok(())
    }
}
