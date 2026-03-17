use super::helpers::{anticipated_padding_size_8, u64_to_usize, utf8_str_from_cstring};
use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::map,
    error::{ErrorKind, make_error},
    multi::many_m_n,
    number::complete::{be_u128, le_u16, le_u32, le_u64},
};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct RawCatalogChunk<'a> {
    /// offset relative to start of catalog UUIDs
    pub catalog_subsystem_strings_offset: u16,
    /// offset relative to start of catalog UUIDs
    pub catalog_process_info_entries_offset: u16,
    pub number_process_information_entries: u16,
    /// offset relative to start of catalog UUIDs
    pub catalog_offset_sub_chunks: u16,
    pub number_sub_chunks: u16,
    /// unknown 6 bytes, padding? alignment?
    pub unknown: [u8; 6],
    pub earliest_firehose_timestamp: u64,
    /// array of UUIDs in big endian
    pub catalog_uuids: Vec<Uuid>,
    /// array of strings with end-of-string character
    pub catalog_subsystem_strings: &'a [u8],
    pub catalog_process_info_entries: HashMap<CatalogProcessInfoKey, ProcessInfoEntry>,
    pub catalog_subchunks: Vec<CatalogSubchunk>,
    /// subsystems lookups, keyed by `(subsystem_value, first_proc_id, second_proc_id)`
    pub subsystems_strings: HashMap<(u16, u64, u32), (&'a str, &'a str)>,
}

#[derive(Debug)]
pub struct SubsystemInfo<'a> {
    pub subsystem: &'a str,
    pub category: &'a str,
}

impl<'a> RawCatalogChunk<'a> {
    /// Parse log Catalog data. The log Catalog contains metadata related to log entries such as Process info, Subsystem info, and the compressed log entries
    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let mut tup = (le_u16, le_u16, le_u16, le_u16, le_u16);
        let (
            input,
            (
                catalog_subsystem_strings_offset,
                catalog_process_info_entries_offset,
                number_process_information_entries,
                catalog_offset_sub_chunks,
                number_sub_chunks,
            ),
        ) = tup.parse(input)?;

        const UNKNOWN_LENGTH: u8 = 6;
        let (input, unknown_slice) = take(UNKNOWN_LENGTH)(input)?;
        let mut unknown = [0u8; 6];
        unknown.copy_from_slice(unknown_slice);
        let (input, earliest_firehose_timestamp) = le_u64(input)?;

        const UUID_LENGTH: usize = 16;
        let number_catalog_uuids = catalog_subsystem_strings_offset as usize / UUID_LENGTH;

        let (input, catalog_uuids) = many_m_n(
            number_catalog_uuids,
            number_catalog_uuids,
            map(be_u128, |x| Uuid::from_u128(x)),
        )
        .parse(input)?;

        let subsystems_strings_length =
            catalog_process_info_entries_offset - catalog_subsystem_strings_offset;
        let (input, catalog_subsystem_strings) = take(subsystems_strings_length)(input)?;

        let (input, catalog_process_info_entries_vec) = many_m_n(
            number_process_information_entries as usize,
            number_process_information_entries as usize,
            |input| ProcessInfoEntry::parse(input, &catalog_uuids),
        )
        .parse(input)?;

        let mut catalog_process_info_entries = HashMap::new();
        for entry in catalog_process_info_entries_vec {
            catalog_process_info_entries.insert(
                CatalogProcessInfoKey(entry.first_number_proc_id, entry.second_number_proc_id),
                entry,
            );
        }
        let (input, catalog_subchunks) = many_m_n(
            number_sub_chunks as usize,
            number_sub_chunks as usize,
            CatalogSubchunk::parse,
        )
        .parse(input)?;

        let mut subsystems_strings = HashMap::with_capacity(catalog_process_info_entries.len());
        for entry in catalog_process_info_entries.values() {
            for subsystem in &entry.subsystem_entries {
                let (input, _) = take(subsystem.subsystem_offset)(catalog_subsystem_strings)?;
                let (_, subsystem_string) = utf8_str_from_cstring(input)?;

                let (input, _) = take(subsystem.category_offset)(catalog_subsystem_strings)?;
                let (_, category_string) = utf8_str_from_cstring(input)?;

                subsystems_strings.insert(
                    (
                        subsystem.identifer,
                        entry.first_number_proc_id,
                        entry.second_number_proc_id,
                    ),
                    (subsystem_string, category_string),
                );
            }
        }

        Ok((
            input,
            Self {
                catalog_subsystem_strings_offset,
                catalog_process_info_entries_offset,
                number_process_information_entries,
                catalog_offset_sub_chunks,
                number_sub_chunks,
                unknown,
                earliest_firehose_timestamp,
                catalog_uuids,
                catalog_subsystem_strings,
                catalog_process_info_entries,
                catalog_subchunks,
                subsystems_strings,
            },
        ))
    }

    /// Get subsystem and category based on the log entry `first_proc_id`, `second_proc_id`, log entry subsystem id and the associated Catalog.
    /// Results are cached so repeated lookups for the same key return cheap `Rc` clones.
    pub fn get_subsystem(
        &self,
        subsystem_value: u16,
        first_proc_id: u64,
        second_proc_id: u32,
    ) -> Option<SubsystemInfo<'a>> {
        let cache_key = (subsystem_value, first_proc_id, second_proc_id);
        self.subsystems_strings
            .get(&cache_key)
            .map(|(subsystem, category)| SubsystemInfo {
                subsystem,
                category,
            })
    }

    /// Get the full process info entry for a log entry's proc IDs.
    pub fn get_process_info(
        &self,
        first_proc_id: u64,
        second_proc_id: u32,
    ) -> Option<&ProcessInfoEntry> {
        self.catalog_process_info_entries
            .get(&CatalogProcessInfoKey(first_proc_id, second_proc_id))
    }

    /// Get the actual Process ID associated with log entry
    pub fn get_pid(&self, first_proc_id: u64, second_proc_id: u32) -> Option<u64> {
        self.catalog_process_info_entries
            .get(&CatalogProcessInfoKey(first_proc_id, second_proc_id))
            .map(|entry| u64::from(entry.pid))
    }

    /// Get the effictive user id associated with log entry. Can be mapped to an account name
    pub fn get_euid(&self, first_proc_id: u64, second_proc_id: u32) -> Option<u32> {
        self.catalog_process_info_entries
            .get(&CatalogProcessInfoKey(first_proc_id, second_proc_id))
            .map(|entry| entry.effective_user_id)
    }
}

/// First & Second Proc Ids
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct CatalogProcessInfoKey(pub u64, pub u32);

#[derive(Debug, Clone)]
pub struct ProcessInfoEntry {
    pub index: u16,
    /// flags?
    pub unknown: u16,
    pub catalog_main_uuid_index: u16,
    pub catalog_dsc_uuid_index: u16,
    pub first_number_proc_id: u64,
    pub second_number_proc_id: u32,
    pub pid: u32,
    /// euid
    pub effective_user_id: u32,
    pub unknown2: u32,
    pub number_uuids_entries: u32,
    pub unknown3: u32,
    /// Catalog process information UUID information entry
    pub uuid_info_entries: Vec<ProcessUUIDEntry>,
    pub number_subsystems: u32,
    pub unknown4: u32,
    /// Catalog process information sub system
    pub subsystem_entries: Vec<ProcessInfoSubsystem>,
    /// main UUID from `catalog_uuids`. Points to `UUIDinfo` file that contains strings
    pub main_uuid: Uuid,
    /// dsc UUID from `catalog_uuids`. Points to dsc shared string file that contains strings
    pub dsc_uuid: Option<Uuid>,
}

impl ProcessInfoEntry {
    /// Parse the Catalog Process Information entry
    fn parse<'a>(input: &'a [u8], uuids: &[Uuid]) -> IResult<&'a [u8], Self> {
        let mut catlog_tup = (le_u16, le_u16);
        let (input, (index, unknown)) = catlog_tup.parse(input)?;
        let (input, (catalog_main_uuid_index, catalog_dsc_uuid_index)) = catlog_tup.parse(input)?;
        let mut proc_tup = (le_u64, le_u32);
        let (input, (first_number_proc_id, second_number_proc_id)) = proc_tup.parse(input)?;

        let mut id_tup = (le_u32, le_u32, le_u32, le_u32, le_u32);
        let (input, (pid, effective_user_id, unknown2, number_uuids_entries, unknown3)) =
            id_tup.parse(input)?;

        let (input, uuid_info_entries) =
            many_m_n(number_uuids_entries as _, number_uuids_entries as _, |s| {
                ProcessUUIDEntry::parse(s, uuids)
            })
            .parse(input)?;

        let mut sub_tup = (le_u32, le_u32);
        let (input, (number_subsystems, unknown4)) = sub_tup.parse(input)?;

        let (input, subsystem_entries) = many_m_n(
            number_subsystems as _,
            number_subsystems as _,
            ProcessInfoSubsystem::parse,
        )
        .parse(input)?;

        // Grab parsed UUIDs from Catalag array based on process entry uuid index
        let main_uuid = uuids
            .get(catalog_main_uuid_index as usize)
            .copied()
            .unwrap_or_else(|| {
                log::warn!("[macos-unifiedlogs] Could not find main UUID in catalog");
                Uuid::nil()
            });

        let dsc_uuid = uuids.get(catalog_dsc_uuid_index as usize).copied();

        const SUBSYSTEM_SIZE: u64 = 6;
        let padding = anticipated_padding_size_8(number_subsystems.into(), SUBSYSTEM_SIZE);
        let padding = match u64_to_usize(padding) {
            Some(p) => p,
            None => {
                log::error!("[macos-unifiedlogs] u64 is bigger than system usize");
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                )));
            }
        };
        let (input, _) = take(padding)(input)?;

        Ok((
            input,
            ProcessInfoEntry {
                index,
                unknown,
                catalog_main_uuid_index,
                catalog_dsc_uuid_index,
                first_number_proc_id,
                second_number_proc_id,
                pid,
                effective_user_id,
                unknown2,
                number_uuids_entries,
                unknown3,
                uuid_info_entries,
                number_subsystems,
                unknown4,
                subsystem_entries,
                main_uuid,
                dsc_uuid,
            },
        ))
    }
}
/// Part of `ProcessInfoEntry`
#[derive(Debug, Clone)]
pub struct ProcessUUIDEntry {
    pub size: u32,
    pub unknown: u32,
    pub catalog_uuid_index: u16,
    pub load_address: u64,
    pub uuid: Uuid,
}

impl ProcessUUIDEntry {
    /// Parse the UUID metadata in the Catalog Process Entry (the Catalog Process Entry references the UUIDs array parsed in `parse_catalog` by index value)
    fn parse<'a>(input: &'a [u8], uuids: &[Uuid]) -> IResult<&'a [u8], Self> {
        let mut tup = (le_u32, le_u32, le_u16);
        let (input, (size, unknown, catalog_uuid_index)) = tup.parse(input)?;

        const LOAD_ADDRESS_SIZE: u8 = 6;
        let (input, mut load_address_vec) =
            map(take(LOAD_ADDRESS_SIZE), |x: &[u8]| x.to_vec()).parse(input)?;
        load_address_vec.push(0);
        load_address_vec.push(0);
        let load_address = match le_u64::<&[u8], ()>(&load_address_vec[..]) {
            Ok((_, load_address)) => load_address,
            Err(_) => return Err(nom::Err::Error(make_error(input, ErrorKind::Eof))),
        };

        let uuid: Uuid = *uuids
            .get(catalog_uuid_index as usize)
            .ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::Eof)))?;

        Ok((
            input,
            Self {
                size,
                unknown,
                catalog_uuid_index,
                load_address,
                uuid,
            },
        ))
    }
}

/// Part of `ProcessInfoEntry`
#[derive(Debug, Clone)]
pub struct ProcessInfoSubsystem {
    pub identifer: u16,
    /// Represents the offset to the subsystem from the start of the subsystem entries
    pub subsystem_offset: u16,
    /// Represents the offset to the subsystem category from the start of the subsystem entries
    pub category_offset: u16,
}

impl ProcessInfoSubsystem {
    /// Parse the Catalog Subsystem metadata. This helps get the subsystem (App Bundle ID) and the log entry category
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let mut tup = (le_u16, le_u16, le_u16);
        let (input, (identifer, subsystem_offset, category_offset)) = tup.parse(input)?;
        Ok((
            input,
            Self {
                identifer,
                subsystem_offset,
                category_offset,
            },
        ))
    }
}

/// Part of `CatalogChunk`, possible 64-bit alignment padding at end
#[derive(Debug, Clone)]
pub struct CatalogSubchunk {
    pub start: u64,
    pub end: u64,
    pub uncompressed_size: u32,
    /// Should always be LZ4 (value 0x100)
    pub compression_algorithm: u32,
    pub number_index: u32,
    /// indexes size = `number_index` * u16
    pub indexes: Vec<u16>,
    pub number_string_offsets: u32,
    /// `string_offsets` size = `number_string_offsets` * u16
    pub string_offsets: Vec<u16>,
}

impl CatalogSubchunk {
    /// Parse the Catalog Subchunk metadata. This metadata is related to the compressed (typically) Chunkset data
    fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let mut tup = (le_u64, le_u64, le_u32, le_u32, le_u32);
        let (input, (start, end, uncompressed_size, compression_algorithmn, number_index)) =
            tup.parse(input)?;

        const LZ4_COMPRESSION: u32 = 256;
        if compression_algorithmn != LZ4_COMPRESSION {
            return Err(nom::Err::Error(make_error(input, ErrorKind::OneOf)));
        }

        let (input, indexes) =
            many_m_n(number_index as _, number_index as _, le_u16).parse(input)?;

        let (input, number_string_offsets) = le_u32(input)?;

        let (input, string_offsets) = many_m_n(
            number_string_offsets as _,
            number_string_offsets as _,
            le_u16,
        )
        .parse(input)?;

        // calculate amount of padding needed based on number_string_offsets and number_index
        const OFFSET_SIZE: u64 = 2;
        let padding =
            anticipated_padding_size_8((number_index + number_string_offsets).into(), OFFSET_SIZE);

        let padding = match u64_to_usize(padding) {
            Some(p) => p,
            None => {
                log::error!("[macos-unifiedlogs] u64 is bigger than system usize");
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::TooLarge,
                )));
            }
        };
        let (input, _) = take(padding)(input)?;

        Ok((
            input,
            CatalogSubchunk {
                start,
                end,
                uncompressed_size,
                compression_algorithm: compression_algorithmn,
                number_index,
                indexes,
                number_string_offsets,
                string_offsets,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;
    use chunks::{ChunkPreamble, ChunkTag};
    use helpers::tests::test_data_path;

    #[test]
    fn test_parse_catalog() -> anyhow::Result<()> {
        let input = &[
            11, 96, 0, 0, 17, 0, 0, 0, 208, 1, 0, 0, 0, 0, 0, 0, 32, 0, 96, 0, 1, 0, 160, 0, 7, 0,
            0, 0, 0, 0, 0, 0, 20, 165, 44, 35, 253, 233, 2, 0, 43, 239, 210, 12, 24, 236, 56, 56,
            129, 79, 43, 78, 90, 243, 188, 236, 61, 5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54,
            231, 114, 172, 1, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105,
            103, 104, 116, 0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110,
            115, 116, 114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99,
            105, 110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 158,
            0, 0, 0, 0, 0, 0, 0, 55, 1, 0, 0, 158, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 19, 0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0,
            246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 1,
            0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
            99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0,
            0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
            0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87,
            79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107,
            20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255,
            0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57,
            68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
        ];

        let (input, preamble) = ChunkPreamble::parse(input)?;
        let (_, catalog) = RawCatalogChunk::parse(input)?;

        assert_eq!(preamble.tag, ChunkTag::Catalog);
        assert_eq!(preamble.sub_tag, 17);
        assert_eq!(preamble.data_size, 464);
        assert_eq!(catalog.catalog_subsystem_strings_offset, 32);
        assert_eq!(catalog.catalog_process_info_entries_offset, 96);
        assert_eq!(catalog.number_process_information_entries, 1);
        assert_eq!(catalog.catalog_offset_sub_chunks, 160);
        assert_eq!(catalog.number_sub_chunks, 7);
        assert_eq!(catalog.unknown, [0, 0, 0, 0, 0, 0]);
        assert_eq!(catalog.earliest_firehose_timestamp, 820223379547412);
        assert_eq!(
            catalog.catalog_uuids,
            [
                Uuid::parse_str("2BEFD20C18EC3838814F2B4E5AF3BCEC")?,
                Uuid::parse_str("3D05845F3F65358F9EBF2236E772AC01")?
            ]
        );
        assert_eq!(
            catalog.catalog_subsystem_strings,
            [
                99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105, 103, 104, 116,
                0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116,
                114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105,
                110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0
            ]
        );
        assert_eq!(catalog.catalog_process_info_entries.len(), 1);
        assert_eq!(
            catalog
                .catalog_process_info_entries
                .get(&CatalogProcessInfoKey(158, 311))
                .unwrap()
                .main_uuid,
            Uuid::parse_str("2BEFD20C18EC3838814F2B4E5AF3BCEC").unwrap()
        );
        assert_eq!(
            catalog
                .catalog_process_info_entries
                .get(&CatalogProcessInfoKey(158, 311))
                .unwrap()
                .dsc_uuid,
            Uuid::parse_str("3D05845F3F65358F9EBF2236E772AC01").ok()
        );

        assert_eq!(catalog.catalog_subchunks.len(), 7);
        Ok(())
    }

    #[test]
    fn test_parse_catalog_process_entry() -> anyhow::Result<()> {
        let input = &[
            0, 0, 0, 0, 0, 0, 1, 0, 158, 0, 0, 0, 0, 0, 0, 0, 55, 1, 0, 0, 158, 0, 0, 0, 88, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 19, 0, 78,
            0, 0, 0, 47, 0, 0, 0, 0, 0, 246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234,
            2, 0, 120, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48,
            89, 60, 28, 9, 234, 2, 0, 99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0,
            1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0,
            214, 108, 78, 32, 234, 2, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0,
            0, 19, 0, 47, 0, 128, 0, 87, 79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255,
            0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205,
            41, 234, 2, 0, 172, 57, 107, 20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
            0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194,
            43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 220, 202, 171, 57, 68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0, 240,
            254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
        ];

        let test_uuids = vec![
            Uuid::parse_str("2BEFD20C18EC3838814F2B4E5AF3BCEC")?, // MAIN
            Uuid::parse_str("3D05845F3F65358F9EBF2236E772AC01")?, // DSC
            Uuid::parse_str("3D05845F3F65358F9EBF2236E772AC02")?, // OTHER
        ];

        // let (_, process_entry) = CatalogChunk::parse_catalog_process_entry(subsystem_data, &test_data).unwrap();
        let (_, process_entry) = ProcessInfoEntry::parse(input, &test_uuids)?;
        assert_eq!(process_entry.index, 0);
        assert_eq!(process_entry.unknown, 0);
        assert_eq!(process_entry.catalog_main_uuid_index, 0);
        assert_eq!(process_entry.catalog_dsc_uuid_index, 1);
        assert_eq!(process_entry.first_number_proc_id, 158);
        assert_eq!(process_entry.second_number_proc_id, 311);
        assert_eq!(process_entry.pid, 158);
        assert_eq!(process_entry.effective_user_id, 88);
        assert_eq!(process_entry.unknown2, 0);
        assert_eq!(process_entry.number_uuids_entries, 0);
        assert_eq!(process_entry.unknown3, 0);
        assert_eq!(process_entry.uuid_info_entries.len(), 0);
        assert_eq!(process_entry.number_subsystems, 2);
        assert_eq!(process_entry.unknown4, 0);
        assert_eq!(process_entry.subsystem_entries.len(), 2);
        assert_eq!(process_entry.main_uuid, test_uuids[0]);
        assert_eq!(process_entry.dsc_uuid, Some(test_uuids[1]));
        Ok(())
    }

    #[test]
    fn test_parse_process_info_uuid_entry() -> anyhow::Result<()> {
        let input = &[
            87, 0, 0, 0, 19, 0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0, 246, 113, 118, 43, 250, 233, 2, 0,
            62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0,
            0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0, 99, 50, 207, 40, 18, 234, 2, 0,
            112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 153, 6,
            208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0,
            0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87, 79, 32, 234, 2, 0, 137, 5, 2,
            205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107, 20, 56, 234, 2, 0, 152, 255, 0,
            0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 53, 172, 105, 21, 56,
            234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0,
            0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57, 68, 234, 2, 0, 119, 171, 170,
            119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0,
        ];

        let (input, subsystems) = ProcessInfoSubsystem::parse(input)?;
        assert_eq!(subsystems.identifer, 87);
        assert_eq!(subsystems.subsystem_offset, 0);
        assert_eq!(subsystems.category_offset, 19);

        let (_, subsystems) = ProcessInfoSubsystem::parse(input)?;
        assert_eq!(subsystems.identifer, 78);
        assert_eq!(subsystems.subsystem_offset, 0);
        assert_eq!(subsystems.category_offset, 47);

        Ok(())
    }

    #[test]
    fn test_parse_catalog_subchunk() -> anyhow::Result<()> {
        let input = &[
            246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 1,
            0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
            99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0,
            0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
            0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87,
            79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107,
            20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255,
            0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57,
            68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
        ];

        let (data, subchunk) = CatalogSubchunk::parse(input)?;
        assert_eq!(subchunk.start, 820210633699830);
        assert_eq!(subchunk.end, 820274771182398);
        assert_eq!(subchunk.uncompressed_size, 65400);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        let (data, subchunk) = CatalogSubchunk::parse(data)?;
        assert_eq!(subchunk.start, 820274802743600);
        assert_eq!(subchunk.end, 820313668399715);
        assert_eq!(subchunk.uncompressed_size, 61552);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        let (_, subchunk) = CatalogSubchunk::parse(data)?;
        assert_eq!(subchunk.start, 820313685231257);
        assert_eq!(subchunk.end, 820374429029888);
        assert_eq!(subchunk.uncompressed_size, 65536);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        Ok(())
    }

    #[test]
    fn test_parse_catalog_subchunk_bad_compression() -> anyhow::Result<()> {
        let test_bad_compression = &[
            246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 2,
            0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
            99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0,
            0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
            0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87,
            79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107,
            20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255,
            0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57,
            68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
        ];

        assert!(CatalogSubchunk::parse(test_bad_compression).is_err());
        Ok(())
    }

    #[test]
    fn test_get_process_info() -> anyhow::Result<()> {
        let input = std::fs::read(test_data_path().join("Catalog Tests/big_sur_catalog.raw"))?;
        let (input, _preamble) = ChunkPreamble::parse(&input).unwrap();
        let (_, catalog) = RawCatalogChunk::parse(&input).unwrap();

        let entry = catalog.get_process_info(165, 406).unwrap();
        assert_eq!(entry.first_number_proc_id, 165);
        assert_eq!(entry.second_number_proc_id, 406);
        assert!(!entry.main_uuid.is_nil());
        assert!(entry.dsc_uuid.is_some());
        Ok(())
    }

    #[test]
    fn test_get_process_info_missing() -> anyhow::Result<()> {
        let input = std::fs::read(test_data_path().join("Catalog Tests/big_sur_catalog.raw"))?;
        let (input, _preamble) = ChunkPreamble::parse(&input).unwrap();
        let (_, catalog) = RawCatalogChunk::parse(&input).unwrap();

        assert!(catalog.get_process_info(999, 999).is_none());
        Ok(())
    }

    #[test]
    fn test_get_big_sur_subsystem() -> anyhow::Result<()> {
        let subsystem_value = 4;
        let first_proc_id = 165;
        let second_proc_id = 406;

        let input = std::fs::read(test_data_path().join("Catalog Tests/big_sur_catalog.raw"))?;

        let (input, _preamble) = ChunkPreamble::parse(&input).unwrap();
        let (_, catalog) = RawCatalogChunk::parse(&input).unwrap();

        let results = catalog
            .get_subsystem(subsystem_value, first_proc_id, second_proc_id)
            .unwrap();
        assert_eq!(results.subsystem, "com.apple.containermanager");
        assert_eq!(results.category, "xpc");
        Ok(())
    }
}
