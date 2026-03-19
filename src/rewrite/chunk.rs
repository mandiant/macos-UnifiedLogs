use nom::bytes::complete::take;

use super::{
    catalog::RawCatalogChunk,
    chunks::{ChunkPreamble, ChunkTag},
    chunks::{
        ChunksetPayload, firehose::RawFirehose, oversize::RawOversize, simpledump::RawSimpleDump,
        statedump::RawStatedump,
    },
    chunks_reader::{RawChunk, RawChunksReader},
    error::{NomExt, ParseError},
    header::RawHeaderChunk,
};

#[derive(Debug)]
pub enum Chunk<'a> {
    Header(super::header::RawHeaderChunk<'a>),
    Catalog(RawCatalogChunk<'a>),
    Firehose(RawFirehose<'a>),
    Simpledump(RawSimpleDump<'a>),
    Statedump(RawStatedump<'a>),
    Oversize(RawOversize<'a>),
    Unknown(RawChunk<'a>),
}

/// A top-level chunk from a tracev3 file.
///
/// Covers only the three top-level container types (Header, Catalog, Chunkset).
/// Inner chunkset types (Firehose, Oversize, etc.) are dispatched inside
/// `ChunkSetReader` and represented by the [`Chunk`] enum.
#[derive(Debug)]
pub enum TopChunk<'a> {
    Header(super::header::RawHeaderChunk<'a>),
    Catalog(RawCatalogChunk<'a>),
    Chunkset(ChunkSetReader<'a>),
    Unknown(RawChunk<'a>),
}

#[derive(Debug)]
pub struct ChunksReader<'a> {
    inner: RawChunksReader<'a>,
}

impl<'a> ChunksReader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            inner: RawChunksReader::new_top_level(input),
        }
    }
}

#[derive(Debug)]
pub struct ChunkSetReader<'a> {
    payload: ChunksetPayload<'a>,
    current_offset: usize,
}

impl<'a> ChunkSetReader<'a> {
    pub fn new(payload: ChunksetPayload<'a>) -> Self {
        Self {
            payload,
            current_offset: 0,
        }
    }

    /// Reset the reader to the beginning of the chunkset data.
    /// Used for multi-pass iteration (e.g. firehose first, then simpledump, then statedump).
    pub fn reset(&mut self) {
        self.current_offset = 0;
    }

    pub fn next(&mut self) -> Option<Result<RawChunk<'_>, ParseError>> {
        let data = self.payload.as_bytes();

        // Skip zero-padding between inner chunks, matching the legacy parser's
        // `take_while(|b| b == 0)` behavior. Inner chunks may have variable
        // zero-padding that doesn't match fixed 8-byte alignment.
        while self.current_offset < data.len() && data[self.current_offset] == 0 {
            self.current_offset += 1;
        }

        if self.current_offset >= data.len() {
            return None;
        }

        if data.len() - self.current_offset < super::chunks::PREAMBLE_SIZE {
            return None;
        }

        // Parse preamble + data directly (no alignment padding).
        let input = &data[self.current_offset..];
        let (remaining, preamble) = match ChunkPreamble::parse(input) {
            Ok(ok) => ok,
            Err(e) => {
                self.current_offset = data.len(); // prevent retry on same bad data
                return Some(Err(e.to_parse_error()));
            }
        };

        #[cfg(feature = "rewrite-compat")]
        let data_and_tail = remaining;

        let (remaining, chunk_data) =
            match take::<u64, &[u8], nom::error::Error<&[u8]>>(preamble.data_size)(remaining) {
                Ok(ok) => ok,
                Err(e) => {
                    self.current_offset = data.len();
                    return Some(Err(e.to_parse_error()));
                }
            };

        self.current_offset = data.len() - remaining.len();

        Some(Ok(RawChunk {
            preamble,
            data: chunk_data,
            #[cfg(feature = "rewrite-compat")]
            data_and_tail,
        }))
    }
}

impl<'a> Iterator for ChunksReader<'a> {
    type Item = Result<TopChunk<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = match self.inner.next()? {
            Ok(raw) => raw,
            Err(e) => return Some(Err(e)),
        };

        Some(match raw.preamble.tag {
            ChunkTag::Header => RawHeaderChunk::parse(raw.data)
                .map_err(|e| e.to_parse_error())
                .map(|(_, c)| TopChunk::Header(c)),
            ChunkTag::Catalog => RawCatalogChunk::parse(raw.data)
                .map_err(|e| e.to_parse_error())
                .map(|(_, c)| TopChunk::Catalog(c)),
            ChunkTag::Chunkset => {
                let payload = match ChunksetPayload::parse(raw.data) {
                    Ok(p) => p,
                    Err(e) => return Some(Err(e)),
                };
                let reader = ChunkSetReader::new(payload);
                Ok(TopChunk::Chunkset(reader))
            }
            _ => Ok(TopChunk::Unknown(raw)),
        })
    }
}

impl ChunksReader<'_> {
    pub fn visit(&mut self, mut f: impl FnMut(Chunk<'_>) -> ()) -> Result<(), ParseError> {
        for chunk in self {
            let chunk = chunk?;
            match chunk {
                TopChunk::Header(c) => f(Chunk::Header(c)),
                TopChunk::Catalog(c) => f(Chunk::Catalog(c)),
                TopChunk::Chunkset(mut reader) => {
                    while let Some(inner) = reader.next() {
                        let inner = inner?;
                        match inner.preamble.tag {
                            ChunkTag::Firehose => {
                                let (_, fh) = RawFirehose::parse(inner.data)
                                    .map_err(|e| e.to_parse_error())?;
                                f(Chunk::Firehose(fh));
                            }
                            ChunkTag::Simpledump => {
                                let (_, sd) = RawSimpleDump::parse(inner.data)
                                    .map_err(|e| e.to_parse_error())?;
                                f(Chunk::Simpledump(sd));
                            }
                            ChunkTag::Statedump => {
                                let (_, sd) = RawStatedump::parse(inner.data)
                                    .map_err(|e| e.to_parse_error())?;
                                f(Chunk::Statedump(sd));
                            }
                            ChunkTag::Oversize => {
                                let (_, ov) = RawOversize::parse(inner.data)
                                    .map_err(|e| e.to_parse_error())?;
                                f(Chunk::Oversize(ov));
                            }
                            _ => f(Chunk::Unknown(inner)),
                        }
                    }
                }
                TopChunk::Unknown(raw) => f(Chunk::Unknown(raw)),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::helpers::tests::test_data_path;
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_catalog_chunk() -> anyhow::Result<()> {
        let data = std::fs::read(test_data_path().join("Catalog Tests/big_sur_catalog.raw"))?;
        let reader = ChunksReader::new(&data);

        let chunks = reader.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(chunks.len(), 1);
        assert!(matches!(chunks[0], TopChunk::Catalog(_)));
        Ok(())
    }

    #[test]
    fn parse() -> anyhow::Result<()> {
        let data = std::fs::read(
            test_data_path().join("Bad Data/TraceV3/Bad_header_0000000000000005.tracev3"),
        )?;

        let reader = ChunksReader::new(&data);
        let chunks = reader.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(chunks.len(), 251);

        Ok(())
    }

    #[test]
    fn visit() -> anyhow::Result<()> {
        let data = std::fs::read(
            test_data_path().join("Bad Data/TraceV3/Bad_header_0000000000000005.tracev3"),
        )?;

        let mut reader = ChunksReader::new(&data);
        let mut count = 0;
        let mut count_by_type = HashMap::new();
        reader.visit(|chunk| {
            count += 1;
            match chunk {
                Chunk::Header(_) => {
                    *count_by_type.entry(ChunkTag::Header).or_insert(0) += 1;
                }
                Chunk::Catalog(_) => {
                    *count_by_type.entry(ChunkTag::Catalog).or_insert(0) += 1;
                }
                Chunk::Firehose(_) => {
                    *count_by_type.entry(ChunkTag::Firehose).or_insert(0) += 1;
                }
                Chunk::Simpledump(_) => {
                    *count_by_type.entry(ChunkTag::Simpledump).or_insert(0) += 1;
                }
                Chunk::Statedump(_) => {
                    *count_by_type.entry(ChunkTag::Statedump).or_insert(0) += 1;
                }
                Chunk::Oversize(_) => {
                    *count_by_type.entry(ChunkTag::Oversize).or_insert(0) += 1;
                }
                Chunk::Unknown(_) => {
                    *count_by_type.entry(ChunkTag::Unknown).or_insert(0) += 1;
                }
            }
        })?;
        assert_eq!(count, 4082);
        // dbg!(&count_by_type);
        assert_eq!(count_by_type.get(&ChunkTag::Catalog), Some(&36));
        assert_eq!(count_by_type.get(&ChunkTag::Firehose), Some(&4017));
        assert_eq!(count_by_type.get(&ChunkTag::Simpledump), None);
        assert_eq!(count_by_type.get(&ChunkTag::Statedump), None);
        assert_eq!(count_by_type.get(&ChunkTag::Oversize), Some(&28));
        // 1 truly unrecognized inner chunk remains
        assert_eq!(count_by_type.get(&ChunkTag::Unknown), Some(&1));

        Ok(())
    }

    #[test]
    fn visit_firehose_entries() -> anyhow::Result<()> {
        let data = std::fs::read(
            test_data_path().join("Bad Data/TraceV3/Bad_header_0000000000000005.tracev3"),
        )?;

        let mut reader = ChunksReader::new(&data);
        let mut total_entries = 0_usize;
        reader.visit(|chunk| {
            if let Chunk::Firehose(fh) = chunk {
                total_entries += fh.entries().count();
            }
        })?;

        // 4017 firehose chunks yield exactly 129617 individual log entries
        assert_eq!(total_entries, 129_617);

        Ok(())
    }

    #[test]
    fn visit_firehose_entry_bodies() -> anyhow::Result<()> {
        use super::super::chunks::firehose::entry::FirehoseActivityType;

        let data = std::fs::read(
            test_data_path().join("Bad Data/TraceV3/Bad_header_0000000000000005.tracev3"),
        )?;

        let mut reader = ChunksReader::new(&data);
        let mut total = 0_usize;
        let mut failures = 0_usize;
        let mut counts: HashMap<_, usize> = HashMap::new();

        reader.visit(|chunk| {
            if let Chunk::Firehose(fh) = chunk {
                for entry in fh.entries() {
                    total += 1;
                    match entry.parse_body() {
                        Ok(_) => {
                            *counts.entry(entry.log_activity_type).or_insert(0) += 1;
                        }
                        Err(_) => {
                            failures += 1;
                        }
                    }
                }
            }
        })?;

        assert_eq!(total, 129_617);
        assert_eq!(failures, 0, "all entry bodies should parse successfully");
        assert!(
            counts
                .get(&FirehoseActivityType::Activity)
                .copied()
                .unwrap_or(0)
                > 0,
            "should have Activity entries"
        );
        assert!(
            counts
                .get(&FirehoseActivityType::NonActivity)
                .copied()
                .unwrap_or(0)
                > 0,
            "should have NonActivity entries"
        );

        eprintln!("Body type distribution: {counts:?}");

        Ok(())
    }
}
