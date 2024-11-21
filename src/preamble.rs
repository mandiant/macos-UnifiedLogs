// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use nom::{
    number::complete::{le_u32, le_u64},
    sequence::tuple,
    IResult,
};

#[derive(Debug, Clone, Copy)]
pub struct LogPreamble {
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
}

impl LogPreamble {
    /// Get the preamble (first 16 bytes of all Unified Log entries (chunks)) to detect the log (chunk) type. Ex: Firehose, Statedump, Simpledump, Catalog, etc
    /// Do not consume the input
    pub fn detect_preamble(input: &[u8]) -> IResult<&[u8], Self> {
        let (_, preamble) = Self::parse(input)?;
        Ok((input, preamble))
    }

    /// Get the preamble (first 16 bytes of all Unified Log entries (chunks)) to detect the log (chunk) type. Ex: Firehose, Statedump, Simpledump, Catalog, etc
    /// And consume the input
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, (chunk_tag, chunk_sub_tag, chunk_data_size)) =
            tuple((le_u32, le_u32, le_u64))(input)?;
        Ok((
            input,
            LogPreamble {
                chunk_tag,
                chunk_sub_tag,
                chunk_data_size,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::LogPreamble;

    #[test]
    fn test_detect_preamble() -> anyhow::Result<()> {
        let test_preamble_header = &[
            0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        ];

        let (output, preamble_data) = LogPreamble::detect_preamble(test_preamble_header)?;

        assert_eq!(output, test_preamble_header);
        assert_eq!(preamble_data.chunk_tag, 0x1000);
        assert_eq!(preamble_data.chunk_sub_tag, 0x11);
        assert_eq!(preamble_data.chunk_data_size, 0xd0);

        let test_catalog_chunk = &[11, 96, 0, 0, 17, 0, 0, 0, 176, 31, 0, 0, 0, 0, 0, 0];
        let (output, preamble_data) = LogPreamble::parse(test_catalog_chunk)?;

        assert_eq!(output.len(), 0);
        assert_eq!(preamble_data.chunk_tag, 0x600b);
        assert_eq!(preamble_data.chunk_sub_tag, 0x11);
        assert_eq!(preamble_data.chunk_data_size, 0x1fb0);

        Ok(())
    }
}
