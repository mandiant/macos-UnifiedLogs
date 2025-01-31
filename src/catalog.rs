// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::{preamble::LogPreamble, util::*};
use nom::{
    bytes::complete::take,
    combinator::map,
    error::{make_error, ErrorKind},
    multi::many_m_n,
    number::complete::{be_u128, le_u16, le_u32, le_u64},
    sequence::tuple,
    IResult,
};

#[derive(Debug, Clone, Default)]
pub struct CatalogChunk {
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
    /// offset relative to start of catalog UUIDs
    pub catalog_subsystem_strings_offset: u16,
    /// offset relative to start of catalog UUIDs
    pub catalog_process_info_entries_offset: u16,
    pub number_process_information_entries: u16,
    /// offset relative to start of catalog UUIDs
    pub catalog_offset_sub_chunks: u16,
    pub number_sub_chunks: u16,
    /// unknown 6 bytes, padding? alignment?
    pub unknown: Vec<u8>,
    pub earliest_firehose_timestamp: u64,
    /// array of UUIDs in big endian
    pub catalog_uuids: Vec<String>,
    /// array of strings with end-of-string character
    pub catalog_subsystem_strings: Vec<u8>,
    pub catalog_process_info_entries: Vec<ProcessInfoEntry>,
    pub catalog_subchunks: Vec<CatalogSubchunk>,
}

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
    pub main_uuid: String,
    /// dsc UUID from `catalog_uuids`. Points to dsc shared string file that contains strings
    pub dsc_uuid: String,
}

/// Part of `ProcessInfoEntry`
#[derive(Debug, Clone)]
pub struct ProcessUUIDEntry {
    pub size: u32,
    pub unknown: u32,
    pub catalog_uuid_index: u16,
    pub load_address: u64,
    pub uuid: String,
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

#[derive(Debug)]
pub struct SubsystemInfo {
    pub subsystem: String,
    pub category: String,
}

impl CatalogChunk {
    /// Parse log Catalog data. The log Catalog contains metadata related to log entries such as Process info, Subsystem info, and the compressed log entries
    pub fn parse_catalog(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, preamble) = LogPreamble::parse(input)?;

        let (
            input,
            (
                catalog_subsystem_strings_offset,
                catalog_process_info_entries_offset,
                number_process_information_entries,
                catalog_offset_sub_chunks,
                number_sub_chunks,
            ),
        ) = tuple((le_u16, le_u16, le_u16, le_u16, le_u16))(input)?;

        const UNKNOWN_LENGTH: u8 = 6;
        let (input, unknown) = map(take(UNKNOWN_LENGTH), |v: &[u8]| v.to_vec())(input)?;
        let (input, earliest_firehose_timestamp) = le_u64(input)?;

        const UUID_LENGTH: usize = 16;
        let number_catalog_uuids = catalog_subsystem_strings_offset as usize / UUID_LENGTH;

        let (input, catalog_uuids) = many_m_n(
            number_catalog_uuids,
            number_catalog_uuids,
            map(be_u128, |x| format!("{x:032X}")),
        )(input)?;

        let subsystems_strings_length =
            catalog_process_info_entries_offset - catalog_subsystem_strings_offset;
        let (input, subsystem_strings_data) = take(subsystems_strings_length)(input)?;
        let catalog_subsystem_strings = subsystem_strings_data.to_vec();

        let (input, catalog_process_info_entries) = many_m_n(
            number_process_information_entries as usize,
            number_process_information_entries as usize,
            |input| Self::parse_catalog_process_entry(input, &catalog_uuids),
        )(input)?;

        let (input, catalog_subchunks) = many_m_n(
            number_sub_chunks as usize,
            number_sub_chunks as usize,
            Self::parse_catalog_subchunk,
        )(input)?;
        Ok((
            input,
            CatalogChunk {
                chunk_tag: preamble.chunk_tag,
                chunk_sub_tag: preamble.chunk_sub_tag,
                chunk_data_size: preamble.chunk_data_size,
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
            },
        ))
    }

    /// Parse the Catalog Process Information entry
    fn parse_catalog_process_entry<'a>(
        input: &'a [u8],
        uuids: &[String],
    ) -> IResult<&'a [u8], ProcessInfoEntry> {
        let (input, (index, unknown)) = tuple((le_u16, le_u16))(input)?;
        let (input, (catalog_main_uuid_index, catalog_dsc_uuid_index)) =
            tuple((le_u16, le_u16))(input)?;
        let (input, (first_number_proc_id, second_number_proc_id)) =
            tuple((le_u64, le_u32))(input)?;
        let (input, (pid, effective_user_id, unknown2, number_uuids_entries, unknown3)) =
            tuple((le_u32, le_u32, le_u32, le_u32, le_u32))(input)?;

        let (input, uuid_info_entries) =
            many_m_n(number_uuids_entries as _, number_uuids_entries as _, |s| {
                Self::parse_process_info_uuid_entry(s, uuids)
            })(input)?;
        let (input, (number_subsystems, unknown4)) = tuple((le_u32, le_u32))(input)?;

        let (input, subsystem_entries) = many_m_n(
            number_subsystems as _,
            number_subsystems as _,
            Self::parse_process_info_subystem,
        )(input)?;

        // Grab parsed UUIDs from Catalag array based on process entry uuid index
        let main_uuid = uuids
            .get(catalog_main_uuid_index as usize)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                log::warn!("[macos-unifiedlogs] Could not find main UUID in catalog");
                String::new()
            });

        let dsc_uuid = uuids
            .get(catalog_dsc_uuid_index as usize)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                log::warn!("[macos-unifiedlogs] Could not find DSC UUID in catalog");
                String::new()
            });

        const SUBSYSTEM_SIZE: u64 = 6;
        let padding = anticipated_padding_size_8(number_subsystems.into(), SUBSYSTEM_SIZE);
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

    /// Parse the UUID metadata in the Catalog Process Entry (the Catalog Process Entry references the UUIDs array parsed in `parse_catalog` by index value)
    fn parse_process_info_uuid_entry<'a>(
        input: &'a [u8],
        uuids: &[String],
    ) -> IResult<&'a [u8], ProcessUUIDEntry> {
        let (input, (size, unknown, catalog_uuid_index)) = tuple((le_u32, le_u32, le_u16))(input)?;

        const LOAD_ADDRESS_SIZE: u8 = 6;
        let (input, mut load_address_vec) =
            map(take(LOAD_ADDRESS_SIZE), |x: &[u8]| x.to_vec())(input)?;
        load_address_vec.push(0);
        load_address_vec.push(0);
        let load_address = match le_u64::<&[u8], ()>(&load_address_vec[..]) {
            Ok((_, load_address)) => load_address,
            Err(_) => return Err(nom::Err::Error(make_error(input, ErrorKind::Eof))),
        };

        let uuid: String = uuids
            .get(catalog_uuid_index as usize)
            .ok_or_else(|| nom::Err::Error(make_error(input, ErrorKind::Eof)))?
            .to_string();

        Ok((
            input,
            ProcessUUIDEntry {
                size,
                unknown,
                catalog_uuid_index,
                load_address,
                uuid,
            },
        ))
    }

    /// Parse the Catalog Subsystem metadata. This helps get the subsystem (App Bundle ID) and the log entry category
    fn parse_process_info_subystem(input: &[u8]) -> IResult<&[u8], ProcessInfoSubsystem> {
        let (input, (identifer, subsystem_offset, category_offset)) =
            tuple((le_u16, le_u16, le_u16))(input)?;
        Ok((
            input,
            ProcessInfoSubsystem {
                identifer,
                subsystem_offset,
                category_offset,
            },
        ))
    }

    /// Parse the Catalog Subchunk metadata. This metadata is related to the compressed (typically) Chunkset data
    fn parse_catalog_subchunk(input: &[u8]) -> IResult<&[u8], CatalogSubchunk> {
        let (input, (start, end, uncompressed_size, compression_algorithmn, number_index)) =
            tuple((le_u64, le_u64, le_u32, le_u32, le_u32))(input)?;

        const LZ4_COMPRESSION: u32 = 256;
        if compression_algorithmn != LZ4_COMPRESSION {
            return Err(nom::Err::Error(make_error(input, ErrorKind::OneOf)));
        }

        let (input, indexes) = many_m_n(number_index as _, number_index as _, le_u16)(input)?;

        let (input, number_string_offsets) = le_u32(input)?;

        let (input, string_offsets) = many_m_n(
            number_string_offsets as _,
            number_string_offsets as _,
            le_u16,
        )(input)?;

        // calculate amount of padding needed based on number_string_offsets and number_index
        const OFFSET_SIZE: u64 = 2;
        let padding =
            anticipated_padding_size_8((number_index + number_string_offsets).into(), OFFSET_SIZE);

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

    /// Get subsystem and category based on the log entry `first_proc_id`, `second_proc_id`, log entry subsystem id and the associated Catalog
    pub fn get_subsystem(
        &self,
        subsystem_value: u16,
        first_proc_id: u64,
        second_proc_id: u32,
    ) -> nom::IResult<&[u8], SubsystemInfo> {
        let mut subsystem_info = SubsystemInfo {
            subsystem: String::new(),
            category: String::new(),
        };

        // Go through catalog entries until first and second proc id match the log entry
        for process_info in &self.catalog_process_info_entries {
            if first_proc_id == process_info.first_number_proc_id
                && second_proc_id == process_info.second_number_proc_id
            {
                // Go through subsystems in catalog entry until subsystem value is found
                for subsystems in &process_info.subsystem_entries {
                    if subsystem_value == subsystems.identifer {
                        let subsystem_data: &[u8] = &self.catalog_subsystem_strings;
                        let (input, _) = take(subsystems.subsystem_offset)(subsystem_data)?;
                        let (_, subsystem_string) = extract_string(input)?;

                        let (input, _) = take(subsystems.category_offset)(subsystem_data)?;
                        let (_, category_string) = extract_string(input)?;
                        subsystem_info.subsystem = subsystem_string;
                        subsystem_info.category = category_string;
                        return Ok((input, subsystem_info));
                    }
                }
            }
        }

        log::warn!("[macos-unifiedlogs] Did not find subsystem in log entry");
        subsystem_info.subsystem = String::from("Unknown subsystem");
        Ok((&[], subsystem_info))
    }

    /// Get the actual Process ID associated with log entry
    pub fn get_pid(&self, first_proc_id: u64, second_proc_id: u32) -> u64 {
        // Go through catalog entries until first and second proc id match the log entry
        for process_info in &self.catalog_process_info_entries {
            if first_proc_id == process_info.first_number_proc_id
                && second_proc_id == process_info.second_number_proc_id
            {
                return u64::from(process_info.pid);
            }
        }

        log::warn!("[macos-unifiedlogs] Did not find PID in log Catalog");
        0
    }

    /// Get the effictive user id associated with log entry. Can be mapped to an account name
    pub fn get_euid(&self, first_proc_id: u64, second_proc_id: u32) -> u32 {
        // Go through catalog entries until first and second proc id match the log entry
        for process_info in &self.catalog_process_info_entries {
            if first_proc_id == process_info.first_number_proc_id
                && second_proc_id == process_info.second_number_proc_id
            {
                return process_info.effective_user_id;
            }
        }
        log::warn!("[macos-unifiedlogs] Did not find EUID in log Catalog");
        0
    }
}

#[cfg(test)]
mod tests {
    use super::CatalogChunk;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_parse_catalog() {
        let test_chunk_catalog = [
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

        let (_, catalog_data) = CatalogChunk::parse_catalog(&test_chunk_catalog).unwrap();

        assert_eq!(catalog_data.chunk_tag, 0x600b);
        assert_eq!(catalog_data.chunk_sub_tag, 17);
        assert_eq!(catalog_data.chunk_data_size, 464);
        assert_eq!(catalog_data.catalog_subsystem_strings_offset, 32);
        assert_eq!(catalog_data.catalog_process_info_entries_offset, 96);
        assert_eq!(catalog_data.number_process_information_entries, 1);
        assert_eq!(catalog_data.catalog_offset_sub_chunks, 160);
        assert_eq!(catalog_data.number_sub_chunks, 7);
        assert_eq!(catalog_data.unknown, [0, 0, 0, 0, 0, 0]);
        assert_eq!(catalog_data.earliest_firehose_timestamp, 820223379547412);
        assert_eq!(
            catalog_data.catalog_uuids,
            [
                "2BEFD20C18EC3838814F2B4E5AF3BCEC",
                "3D05845F3F65358F9EBF2236E772AC01"
            ]
        );
        assert_eq!(
            catalog_data.catalog_subsystem_strings,
            [
                99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105, 103, 104, 116,
                0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116,
                114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105,
                110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0
            ]
        );
        assert_eq!(catalog_data.catalog_process_info_entries.len(), 1);
        assert_eq!(
            catalog_data.catalog_process_info_entries[0].main_uuid,
            "2BEFD20C18EC3838814F2B4E5AF3BCEC"
        );
        assert_eq!(
            catalog_data.catalog_process_info_entries[0].dsc_uuid,
            "3D05845F3F65358F9EBF2236E772AC01"
        );

        assert_eq!(catalog_data.catalog_subchunks.len(), 7)
    }

    #[test]
    fn test_parse_catalog_process_entry() {
        let subsystem_data = &[
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

        let test_data = vec![
            String::from("MAIN"),
            String::from("DSC"),
            String::from("OTHER"),
        ];

        let (_, process_entry) =
            CatalogChunk::parse_catalog_process_entry(subsystem_data, &test_data).unwrap();
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
        assert_eq!(process_entry.main_uuid, "MAIN");
        assert_eq!(process_entry.dsc_uuid, "DSC");
    }

    #[test]
    fn test_parse_process_info_uuid_entry() {
        let test_subsystem_data = &[
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

        let (data, subsystems) =
            CatalogChunk::parse_process_info_subystem(test_subsystem_data).unwrap();
        assert_eq!(subsystems.identifer, 87);
        assert_eq!(subsystems.subsystem_offset, 0);
        assert_eq!(subsystems.category_offset, 19);

        let (_, subsystems) = CatalogChunk::parse_process_info_subystem(data).unwrap();
        assert_eq!(subsystems.identifer, 78);
        assert_eq!(subsystems.subsystem_offset, 0);
        assert_eq!(subsystems.category_offset, 47);
    }

    #[test]
    fn test_parse_catalog_subchunk() {
        let test_subchunks = &[
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

        let (data, subchunk) = CatalogChunk::parse_catalog_subchunk(test_subchunks).unwrap();
        assert_eq!(subchunk.start, 820210633699830);
        assert_eq!(subchunk.end, 820274771182398);
        assert_eq!(subchunk.uncompressed_size, 65400);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        let (data, subchunk) = CatalogChunk::parse_catalog_subchunk(data).unwrap();
        assert_eq!(subchunk.start, 820274802743600);
        assert_eq!(subchunk.end, 820313668399715);
        assert_eq!(subchunk.uncompressed_size, 61552);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        let (_, subchunk) = CatalogChunk::parse_catalog_subchunk(data).unwrap();
        assert_eq!(subchunk.start, 820313685231257);
        assert_eq!(subchunk.end, 820374429029888);
        assert_eq!(subchunk.uncompressed_size, 65536);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);
    }

    #[test]
    fn test_parse_catalog_subchunk_bad_compression() {
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
        assert!(matches!(
            CatalogChunk::parse_catalog_subchunk(test_bad_compression),
            Err(_)
        ));
    }

    #[test]
    fn test_get_big_sur_subsystem() {
        let subsystem_value = 4;
        let first_proc_id = 165;
        let second_proc_id = 406;

        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Catalog Tests/big_sur_catalog.raw");
        let buffer = fs::read(test_path).unwrap();

        let (_, catalog) = CatalogChunk::parse_catalog(&buffer).unwrap();

        let (_, results) = catalog
            .get_subsystem(subsystem_value, first_proc_id, second_proc_id)
            .unwrap();
        assert_eq!(results.subsystem, "com.apple.containermanager");
        assert_eq!(results.category, "xpc");
    }
}
