use super::{chunks_reader::*, *};
use nom::number::complete::le_u32;
use std::rc::Rc;

pub mod firehose;
pub mod oversize;
pub mod simpledump;
pub mod statedump;

const BV41_COMPRESSED: u32 = 825_521_762; // "bv41"
const BV41_UNCOMPRESSED: u32 = 758_412_898; // "bv4-"

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
    let (input, signature) = le_u32::<_, nom::error::Error<&[u8]>>(data).map_err(|e| e.to_parse_error())?;
    let (input, uncompressed_size) = le_u32::<_, nom::error::Error<&[u8]>>(input).map_err(|e| e.to_parse_error())?;

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
        let (input, compressed_size) = le_u32::<_, nom::error::Error<&[u8]>>(input).map_err(|e| e.to_parse_error())?;
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
          .map_err(|e| ParseError::decompress_error(0, e.to_string(), Some("chunkset LZ4 decompress")))?;
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
  use super::super::{chunks::*, helpers::tests::test_data_path};
  use super::*;

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
        ChunkTag::Firehose | ChunkTag::Oversize | ChunkTag::Statedump | ChunkTag::Simpledump
      ));
    }
    Ok(())
  }

  #[test]
  fn parse_real_tracev3_chunksets() -> anyhow::Result<()> {
    let test_data = test_data_path();
    let tracev3_path = test_data.join("system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");
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
            ChunkTag::Firehose | ChunkTag::Oversize | ChunkTag::Statedump | ChunkTag::Simpledump
          ));
          total_inner += 1;
        }
      }
    }

    assert_eq!(total_inner, 3411);
    Ok(())
  }
}
