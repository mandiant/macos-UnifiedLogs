use super::{chunks::*, *};
use nom::bytes::complete::take;

/// A parsed top-level chunk reference: preamble + borrowed payload.
#[derive(Debug)]
pub struct RawChunk<'a> {
  pub preamble: ChunkPreamble,
  pub data: &'a [u8],
  /// Everything from the start of this chunk's data to the end of the buffer.
  /// Only used in compat mode to replicate the old pipeline's extended private data access.
  #[cfg(feature = "rewrite-compat")]
  pub data_and_tail: &'a [u8],
}

#[derive(Debug)]
pub struct RawChunksReader<'a> {
  data: &'a [u8],
  input: &'a [u8],
  padding: usize,
}

impl<'a> RawChunksReader<'a> {
  /// Create a reader over the entire contents of a tracev3 file, assuming 8-byte alignment.
  pub fn new_top_level(input: &'a [u8]) -> Self {
    Self::new(input, 8)
  }
  /// Create a reader over the entire contents of a tracev3 file, assuming no padding.
  pub fn new_chunckset(input: &'a [u8]) -> Self {
    Self::new(input, 8)
  }
  fn new(input: &'a [u8], padding: usize) -> Self {
    assert!(padding != 0, "Padding must be non-zero");
    Self {
      data: input,
      input,
      padding,
    }
  }
  pub fn current_offset(&self) -> usize {
    self.data.len() - self.input.len()
  }
}

impl<'a> Iterator for RawChunksReader<'a> {
  type Item = Result<RawChunk<'a>, ParseError>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.input.is_empty() {
      return None;
    }

    let (input, preamble) = match ChunkPreamble::parse(self.input) {
      Ok(ok) => ok,
      Err(e) => return Some(Err(e.to_parse_error())),
    };

    // Capture data_and_tail BEFORE scoping — everything from data start to end of buffer.
    // The old pipeline's firehose parser had access to this entire region for private data.
    #[cfg(feature = "rewrite-compat")]
    let data_and_tail = input;

    let (input, data) = match take(preamble.data_size)(input) {
      Ok(ok) => ok,
      Err(e) => return Some(Err(e.to_parse_error())),
    };

    let consumed = self.input.len() - input.len();
    let missing_to_pad = (self.padding - (consumed % self.padding)) % self.padding;
    let (input, _pad) = match take(missing_to_pad)(input) {
      Ok(ok) => ok,
      Err(e) => return Some(Err(e.to_parse_error())),
    };

    self.input = input;
    Some(Ok(RawChunk {
      preamble,
      data,
      #[cfg(feature = "rewrite-compat")]
      data_and_tail,
    }))
  }
}

#[cfg(test)]
mod tests {
  use super::super::helpers::tests::test_data_path;
  use super::*;

  #[test]
  fn read_big_sur_catalog() -> anyhow::Result<()> {
    let test_data = test_data_path();
    let data = std::fs::read(test_data.join("Catalog Tests/big_sur_catalog.raw"))?;
    let reader = RawChunksReader::new(&data, 8);

    let chunks = reader.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(chunks.len(), 1);
    let chunk = &chunks[0];
    assert_eq!(chunk.preamble.tag, ChunkTag::Catalog);
    Ok(())
  }

  #[test]
  fn read_big_sur_chunkset() -> anyhow::Result<()> {
    let test_data = test_data_path();
    let data = std::fs::read(test_data.join("Chunkset Tests/big_sur_chunkset.raw"))?;
    let reader = RawChunksReader::new(&data, 8);

    let chunks = reader.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(chunks.len(), 26);

    for chunk in &chunks {
      assert_ne!(chunk.preamble.tag, ChunkTag::Unknown);
    }

    Ok(())
  }

  #[test]
  fn read_not_a_tracev3() -> anyhow::Result<()> {
    // todo: why does this work ?
    let test_data = test_data_path();
    let data = std::fs::read(test_data.join("Bad Data/TraceV3/00.tracev3"))?;
    let reader = RawChunksReader::new(&data, 8);
    let chunks = reader.collect::<Result<Vec<_>, _>>();
    assert!(chunks.is_err());
    Ok(())
  }

  #[test]
  fn read_bad_header() -> anyhow::Result<()> {
    // todo: why does this work ?
    let test_data = test_data_path();
    let data = std::fs::read(test_data.join("Bad Data/TraceV3/Bad_header_0000000000000005.tracev3"))?;

    let reader = RawChunksReader::new(&data, 8);
    let chunks = reader.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(chunks.len(), 251);

    Ok(())
  }
}
