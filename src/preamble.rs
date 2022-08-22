// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::mem::size_of;

use nom::{
    bytes::complete::take,
    number::complete::{le_u32, le_u64},
};

#[derive(Debug)]
pub struct LogPreamble {
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
}
impl LogPreamble {
    /// Get the preamble (first 16 bytes of all Unified Log entries (chunks)) to detect the log (chunk) type. Ex: Firehose, Statedump, Simpledump, Catalog, etc
    pub fn detect_preamble(data: &[u8]) -> nom::IResult<&[u8], LogPreamble> {
        let mut preamble = LogPreamble {
            chunk_tag: 0,
            chunk_sub_tag: 0,
            chunk_data_size: 0,
        };

        let (input, tag) = take(size_of::<u32>())(data)?;
        let (input, sub_tag) = take(size_of::<u32>())(input)?;
        let (input, data_size) = take(size_of::<u64>())(input)?;

        let (_, trace_tag) = le_u32(tag)?;
        let (_, trace_sub_tag) = le_u32(sub_tag)?;
        let (_, trace_data_size) = le_u64(data_size)?;

        preamble.chunk_tag = trace_tag;
        preamble.chunk_sub_tag = trace_sub_tag;
        preamble.chunk_data_size = trace_data_size;
        Ok((input, preamble))
    }
}

#[cfg(test)]
mod tests {
    use super::LogPreamble;

    #[test]
    fn test_detect_preamble() {
        let test_preamble_header = [
            0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        ];

        let (_, preamble_data) = LogPreamble::detect_preamble(&test_preamble_header).unwrap();

        assert_eq!(preamble_data.chunk_tag, 0x1000);
        assert_eq!(preamble_data.chunk_sub_tag, 0x11);
        assert_eq!(preamble_data.chunk_data_size, 0xd0);

        let test_catalog_chunk = [11, 96, 0, 0, 17, 0, 0, 0, 176, 31, 0, 0, 0, 0, 0, 0];
        let (_, preamble_data) = LogPreamble::detect_preamble(&test_catalog_chunk).unwrap();

        assert_eq!(preamble_data.chunk_tag, 0x600b);
        assert_eq!(preamble_data.chunk_sub_tag, 0x11);
        assert_eq!(preamble_data.chunk_data_size, 0x1fb0);
    }
}
