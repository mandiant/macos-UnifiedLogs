pub mod activity;
pub mod body;
pub mod entry;
pub mod flags;
pub mod item;
pub mod loss;
pub mod nonactivity;
pub mod signpost;
pub mod trace;

use nom::{
    bytes::complete::take,
    number::complete::{le_u8, le_u16, le_u32, le_u64},
};

use entry::RawFirehoseEntryReader;

/// Parsed firehose chunk header — the 32-byte header after the preamble.
///
/// Individual log entries within `firehose_data` are parsed on demand via
/// [`RawFirehoseEntryReader`] (see `entries()` method).
///
/// Field names match the original `FirehosePreamble` (with typo fixes:
/// `base_continous_time` → `base_continuous_time`, `unkonwn2` → `unknown2`).
#[derive(Debug, Clone)]
pub struct RawFirehose<'a> {
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub ttl: u8,
    pub collapsed: u8,
    pub unknown: [u8; 2],
    /// Size includes itself and the 8 bytes below and the public data.
    pub public_data_size: u16,
    /// 0x1000 (4096) if there is NO private data.
    pub private_data_virtual_offset: u16,
    pub unknown2: u16,
    pub unknown3: u16,
    pub base_continuous_time: u64,
    /// All remaining bytes after the 32-byte header (public + private data), zero-copy.
    pub firehose_data: &'a [u8],
}

impl<'a> RawFirehose<'a> {
    /// Parse a firehose chunk from the chunk data (after preamble).
    pub fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, first_proc_id) = le_u64(input)?;
        let (input, second_proc_id) = le_u32(input)?;
        let (input, ttl) = le_u8(input)?;
        let (input, collapsed) = le_u8(input)?;
        let (input, unknown_bytes) = take(2_usize)(input)?;
        let unknown: [u8; 2] = [unknown_bytes[0], unknown_bytes[1]];
        let (input, public_data_size) = le_u16(input)?;
        let (input, private_data_virtual_offset) = le_u16(input)?;
        let (input, unknown2) = le_u16(input)?;
        let (input, unknown3) = le_u16(input)?;
        let (input, base_continuous_time) = le_u64(input)?;

        // Everything remaining is the firehose entry data (public + private).
        let firehose_data = input;

        Ok((
            &[],
            RawFirehose {
                first_proc_id,
                second_proc_id,
                ttl,
                collapsed,
                unknown,
                public_data_size,
                private_data_virtual_offset,
                unknown2,
                unknown3,
                base_continuous_time,
                firehose_data,
            },
        ))
    }

    /// Length of the public data region within `firehose_data`.
    ///
    /// `public_data_size` includes 16 bytes of the header itself
    /// (from `public_data_size` through `base_continuous_time`),
    /// so the actual public data length is `public_data_size - 16`.
    pub fn public_data_len(&self) -> usize {
        (self.public_data_size.saturating_sub(16) as usize).min(self.firehose_data.len())
    }

    /// Public data slice (contains the firehose entries).
    pub fn public_data(&self) -> &'a [u8] {
        &self.firehose_data[..self.public_data_len()]
    }

    /// Private data slice, or `None` if `private_data_virtual_offset == 0x1000`.
    pub fn private_data(&self) -> Option<&'a [u8]> {
        const NO_PRIVATE_DATA: u16 = 0x1000;
        if self.private_data_virtual_offset == NO_PRIVATE_DATA {
            return None;
        }
        let public_len = self.public_data_len();
        if public_len >= self.firehose_data.len() {
            return None;
        }
        Some(&self.firehose_data[public_len..])
    }

    /// Iterate over individual firehose entries in the public data region.
    pub fn entries(&self) -> RawFirehoseEntryReader<'a> {
        RawFirehoseEntryReader::new(self.public_data())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_raw_firehose() -> anyhow::Result<()> {
        // Second (smaller) firehose chunk from original test at
        // src/chunks/firehose/firehose_log.rs (test_parse_firehose_preamble, line ~2928).
        // First 16 bytes are the preamble (tag=0x6001, subtag=0, data_size=152).
        let test_data: &[u8] = &[
            1, 96, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 133, 16, 0, 0, 0, 0, 0, 0, 157, 38,
            0, 0, 0, 0, 0, 0, 136, 0, 0, 16, 0, 0, 0, 2, 42, 188, 25, 14, 104, 4, 0, 0, 2, 1, 4, 0,
            240, 243, 53, 0, 176, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 12, 0, 176, 249, 0, 0,
            0, 0, 0, 128, 163, 133, 51, 0, 0, 0, 0, 0, 2, 1, 4, 0, 32, 250, 53, 0, 177, 232, 0, 0,
            0, 0, 0, 0, 209, 67, 85, 0, 16, 0, 12, 0, 177, 249, 0, 0, 0, 0, 0, 128, 237, 115, 51,
            0, 0, 0, 0, 0, 2, 1, 4, 0, 48, 57, 126, 0, 179, 232, 0, 0, 0, 0, 0, 0, 40, 101, 197, 1,
            16, 0, 12, 0, 178, 249, 0, 0, 0, 0, 0, 128, 105, 67, 61, 0, 0, 0, 0, 0,
        ];

        // Skip the 16-byte preamble
        let data = &test_data[16..];
        let (remaining, result) = RawFirehose::parse(data).unwrap();

        assert_eq!(result.first_proc_id, 4229);
        assert_eq!(result.second_proc_id, 9885);
        assert_eq!(result.ttl, 0);
        assert_eq!(result.collapsed, 0);
        assert_eq!(result.unknown, [0, 0]);
        assert_eq!(result.public_data_size, 136);
        assert_eq!(result.private_data_virtual_offset, 4096);
        assert_eq!(result.unknown2, 0);
        assert_eq!(result.unknown3, 512);
        assert_eq!(result.base_continuous_time, 4_844_959_677_482);
        // firehose_data = data_size(152) - header(32) = 120 bytes
        assert_eq!(result.firehose_data.len(), 152 - 32);
        assert!(remaining.is_empty());
        Ok(())
    }
}
