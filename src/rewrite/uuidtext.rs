use nom::number::complete::le_u32;

use super::helpers::utf8_str_from_cstring;

const UUIDTEXT_SIGNATURE: u32 = 0x6677_8899;

#[derive(Debug, Clone, Copy)]
pub struct RawUUIDTextEntry {
    pub range_start_offset: u32,
    pub entry_size: u32,
}

#[derive(Debug, Clone)]
pub struct RawUUIDText<'a> {
    pub major_version: u32,
    pub minor_version: u32,
    pub entries: Vec<RawUUIDTextEntry>,
    pub footer_data: &'a [u8],
}

impl<'a> RawUUIDText<'a> {
    pub fn parse(data: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, signature) = le_u32(data)?;
        if signature != UUIDTEXT_SIGNATURE {
            return Err(nom::Err::Error(nom::error::Error::new(
                data,
                nom::error::ErrorKind::Tag,
            )));
        }

        let (input, major_version) = le_u32(input)?;
        let (input, minor_version) = le_u32(input)?;
        let (mut input, number_entries) = le_u32(input)?;

        let mut entries = Vec::with_capacity(number_entries as usize);
        for _ in 0..number_entries {
            let (next, range_start_offset) = le_u32(input)?;
            let (next, entry_size) = le_u32(next)?;
            entries.push(RawUUIDTextEntry {
                range_start_offset,
                entry_size,
            });
            input = next;
        }

        let footer_data = input;

        Ok((
            &[],
            RawUUIDText {
                major_version,
                minor_version,
                entries,
                footer_data,
            },
        ))
    }

    /// Image path at the end of `footer_data`, after all format string ranges.
    pub fn image_path(&self) -> Option<&'a str> {
        let total: u32 = self.entries.iter().map(|e| e.entry_size).sum();
        let start = total as usize;
        if start >= self.footer_data.len() {
            return None;
        }
        let (_, path) = utf8_str_from_cstring(&self.footer_data[start..]).ok()?;
        Some(path)
    }

    /// Extract format string at a given virtual offset.
    ///
    /// Iterates entries to find which range contains `offset`, then extracts
    /// the null-terminated string from `footer_data` at the corresponding position.
    pub fn format_string(&self, offset: u64) -> Option<&'a str> {
        let mut footer_pos: u32 = 0;
        for entry in &self.entries {
            if u64::from(entry.range_start_offset) > offset {
                footer_pos += entry.entry_size;
                continue;
            }

            let local_offset = (offset - u64::from(entry.range_start_offset)) as u32;
            let data_start = (local_offset + footer_pos) as usize;

            if data_start >= self.footer_data.len() || local_offset > entry.entry_size {
                footer_pos += entry.entry_size;
                continue;
            }

            let (_, s) = utf8_str_from_cstring(&self.footer_data[data_start..]).ok()?;
            return Some(s);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::helpers::tests::test_data_path;

    #[test]
    fn test_parse_uuidtext_big_sur() -> anyhow::Result<()> {
        let path = test_data_path().join("UUIDText/Big Sur/1FE459BBDC3E19BBF82D58415A2AE9");
        let buffer = std::fs::read(path)?;

        let (_, result) = RawUUIDText::parse(&buffer).unwrap();

        assert_eq!(result.major_version, 2);
        assert_eq!(result.minor_version, 1);
        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.entries[0].entry_size, 617);
        assert_eq!(result.entries[0].range_start_offset, 32048);
        assert_eq!(result.entries[1].entry_size, 2301);
        assert_eq!(result.entries[1].range_start_offset, 29747);
        assert_eq!(result.footer_data.len(), 2987);
        Ok(())
    }

    #[test]
    fn test_parse_uuidtext_high_sierra() -> anyhow::Result<()> {
        let path = test_data_path().join("UUIDText/High Sierra/425A2E5B5531B98918411B4379EE5F");
        let buffer = std::fs::read(path)?;

        let (_, result) = RawUUIDText::parse(&buffer).unwrap();

        assert_eq!(result.major_version, 2);
        assert_eq!(result.minor_version, 1);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].entry_size, 2740);
        assert_eq!(result.entries[0].range_start_offset, 21132);
        assert_eq!(result.footer_data.len(), 2951);
        Ok(())
    }

    #[test]
    fn test_bad_signature() -> anyhow::Result<()> {
        let data = [0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let result = RawUUIDText::parse(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            nom::Err::Error(e) => assert_eq!(e.code, nom::error::ErrorKind::Tag),
            other => panic!("Expected Error(Tag), got: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn test_image_path() -> anyhow::Result<()> {
        let path = test_data_path().join("UUIDText/Big Sur/1FE459BBDC3E19BBF82D58415A2AE9");
        let buffer = std::fs::read(path)?;

        let (_, result) = RawUUIDText::parse(&buffer).unwrap();
        let image_path = result.image_path();

        assert!(image_path.is_some());
        let image_path = image_path.unwrap();
        assert!(
            image_path.starts_with('/'),
            "Expected absolute path, got: {image_path}"
        );
        Ok(())
    }

    #[test]
    fn test_format_string() -> anyhow::Result<()> {
        let path = test_data_path().join("UUIDText/Big Sur/1FE459BBDC3E19BBF82D58415A2AE9");
        let buffer = std::fs::read(path)?;

        let (_, result) = RawUUIDText::parse(&buffer).unwrap();

        // Use the first entry's range_start_offset as a valid offset
        let offset = u64::from(result.entries[0].range_start_offset);
        let s = result.format_string(offset);
        assert!(s.is_some(), "Expected a format string at offset {offset}");
        let s = s.unwrap();
        assert!(!s.is_empty());
        Ok(())
    }
}
