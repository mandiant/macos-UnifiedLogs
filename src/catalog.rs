// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use byteorder::{LittleEndian, ReadBytesExt};
use log::{error, warn};
use nom::Needed;
use nom::{
    bytes::complete::take,
    number::complete::{be_u128, le_u16, le_u32, le_u64},
};
use std::mem::size_of;

use crate::{
    error::CatalogProcessUUIDEntryError,
    util::{extract_string, padding_size},
};

#[derive(Debug, Clone)]
pub struct CatalogChunk {
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
    pub catalog_subsystem_strings_offset: u16, // offset relative to start of catalog UUIDs
    pub catalog_process_info_entries_offset: u16, // offset relative to start of catalog UUIDs
    pub number_process_information_entries: u16,
    pub catalog_offset_sub_chunks: u16, // offset relative to start of catalog UUIDs
    pub number_sub_chunks: u16,
    pub unknown: Vec<u8>, // unknown 6 bytes, padding? alignment?
    pub earliest_firehose_timestamp: u64,
    pub catalog_uuids: Vec<String>, // array of UUIDs in big endian
    pub catalog_subsystem_strings: Vec<u8>, // array of strings with end-of-string character
    pub catalog_process_info_entries: Vec<ProcessInfoEntry>,
    pub catalog_subchunks: Vec<CatalogSubchunk>,
}

#[derive(Debug, Clone)]
pub struct ProcessInfoEntry {
    pub index: u16,
    pub unknown: u16, // flags?
    pub catalog_main_uuid_index: u16,
    pub catalog_dsc_uuid_index: u16,
    pub first_number_proc_id: u64,
    pub second_number_proc_id: u32,
    pub pid: u32,
    pub effective_user_id: u32, // euid
    pub unknown2: u32,
    pub number_uuids_entries: u32,
    pub unknown3: u32,
    pub uuid_info_entries: Vec<ProcessUUIDEntry>, // Catalog process information UUID information entry
    pub number_subsystems: u32,
    pub unknown4: u32,
    pub subsystem_entries: Vec<ProcessInfoSubsystem>, // Catalog process information sub system
    pub main_uuid: String, // main UUID from catalog_uuids. Points to UUIDinfo file that contains strings
    pub dsc_uuid: String, // dsc UUID from catalog_uuids. Points to dsc shared string file that contains strings
}

// Part of ProcessInfoEntry
#[derive(Debug, Clone)]
pub struct ProcessUUIDEntry {
    pub size: u32,
    pub unknown: u32,
    pub catalog_uuid_index: u16,
    pub load_address: u64,
    pub uuid: String,
}

// Part of ProcessInfoEntry
#[derive(Debug, Clone)]
pub struct ProcessInfoSubsystem {
    pub identifer: u16,
    pub subsystem_offset: u16, // Represents the offset to the subsystem from the start of the subsystem entries
    pub category_offset: u16, // Represents the offset to the subsystem category from the start of the subsystem entries
}

// Part of CatalogChunk, possible 64-bit alignment padding at end
#[derive(Debug, Clone)]
pub struct CatalogSubchunk {
    pub start: u64,
    pub end: u64,
    pub uncompressed_size: u32,
    pub compression_algorithm: u32, // Should always be LZ4 (value 0x100)
    pub number_index: u32,
    pub indexes: Vec<u16>, // indexes size = number_index * u16
    pub number_string_offsets: u32,
    pub string_offsets: Vec<u16>, // string_offsets size = number_string_offsets * u16
}

#[derive(Debug)]
pub struct SubsystemInfo {
    pub subsystem: String,
    pub category: String,
}

impl CatalogChunk {
    /// Parse log Catalog data. The log Catalog contains metadata related to log entries such as Process info, Subsystem info, and the compressed log entries
    pub fn parse_catalog(data: &[u8]) -> nom::IResult<&[u8], CatalogChunk> {
        let mut catalog_chunk = CatalogChunk {
            chunk_tag: 0,
            chunk_sub_tag: 0,
            chunk_data_size: 0,
            catalog_subsystem_strings_offset: 0,
            catalog_process_info_entries_offset: 0,
            number_process_information_entries: 0,
            catalog_offset_sub_chunks: 0,
            number_sub_chunks: 0,
            unknown: Vec::new(),
            earliest_firehose_timestamp: 0,
            catalog_uuids: Vec::new(),
            catalog_subsystem_strings: Vec::new(),
            catalog_process_info_entries: Vec::new(),
            catalog_subchunks: Vec::new(),
        };

        // Parse initial part Catalog chunk based on known sizes
        let (input, chunk_tag) = take(size_of::<u32>())(data)?;
        let (input, chunk_sub_tag) = take(size_of::<u32>())(input)?;
        let (input, chunk_data_size) = take(size_of::<u64>())(input)?;
        let (input, subsystem_string_offset) = take(size_of::<u16>())(input)?;
        let (input, process_info_entries_offset) = take(size_of::<u16>())(input)?;
        let (input, number_process_entries) = take(size_of::<u16>())(input)?;
        let (input, catalog_sub_chunks_offset) = take(size_of::<u16>())(input)?;
        let (input, number_sub_chunks) = take(size_of::<u16>())(input)?;

        let unknown_length: u8 = 6;
        let (input, unknown) = take(unknown_length)(input)?;
        let (mut input, earliest_firehose_timestamp) = take(size_of::<u64>())(input)?;

        let (_, catalog_chunk_tag) = le_u32(chunk_tag)?;
        let (_, catalog_chunk_sub_tag) = le_u32(chunk_sub_tag)?;
        let (_, catalog_chunk_data_size) = le_u64(chunk_data_size)?;
        let (_, catalog_subsystem_string_offset) = le_u16(subsystem_string_offset)?;
        let (_, catalog_process_info_entries_offset) = le_u16(process_info_entries_offset)?;
        let (_, catalog_number_process_entries) = le_u16(number_process_entries)?;

        let (_, catalog_catalog_sub_chunks_offset) = le_u16(catalog_sub_chunks_offset)?;
        let (_, catalog_number_sub_chunks) = le_u16(number_sub_chunks)?;
        let (_, earliest_firehose) = le_u64(earliest_firehose_timestamp)?;

        let uuid_length = 16;
        let number_catalog_uuids = catalog_subsystem_string_offset / uuid_length;
        let mut uuid_count = 0;

        // Nom all UUIDs based on offset of subsystem strings (offset divided by uuid length equals number of uuids)
        // UUIDs are 16 bytes
        while uuid_count < number_catalog_uuids {
            let (input_data, uuid) = take(size_of::<u128>())(input)?;
            let (_, uuid_be) = be_u128(uuid)?;

            catalog_chunk
                .catalog_uuids
                .push(format!("{:032X}", uuid_be));
            uuid_count += 1;
            input = input_data
        }

        catalog_chunk.chunk_tag = catalog_chunk_tag;
        catalog_chunk.chunk_sub_tag = catalog_chunk_sub_tag;
        catalog_chunk.chunk_data_size = catalog_chunk_data_size;
        catalog_chunk.catalog_subsystem_strings_offset = catalog_subsystem_string_offset;
        catalog_chunk.catalog_process_info_entries_offset = catalog_process_info_entries_offset;
        catalog_chunk.number_process_information_entries = catalog_number_process_entries;
        catalog_chunk.catalog_offset_sub_chunks = catalog_catalog_sub_chunks_offset;
        catalog_chunk.number_sub_chunks = catalog_number_sub_chunks;
        catalog_chunk.chunk_sub_tag = catalog_chunk_sub_tag;
        catalog_chunk.unknown = unknown.to_vec();
        catalog_chunk.earliest_firehose_timestamp = earliest_firehose;

        // Nom all subystem strings. Total length equals catalog_process_info_entries_offset minus catalog_subsystem_string_offset
        let subsystems_strings_length =
            catalog_process_info_entries_offset - catalog_subsystem_string_offset;
        let (mut input, subsystem_strings_data) = take(subsystems_strings_length)(input)?;
        catalog_chunk.catalog_subsystem_strings = subsystem_strings_data.to_vec();

        let mut proc_entry_count = 0;
        while proc_entry_count < catalog_chunk.number_process_information_entries {
            // Parse and get Process Entry data
            let (proc_input, mut process_entries) =
                CatalogChunk::parse_catalog_process_entry(input, &catalog_chunk.catalog_uuids)?;

            // Grab parsed UUIDs from Catalag array based on process entry uuid index
            for (key, uuid) in catalog_chunk.catalog_uuids.iter().enumerate() {
                if process_entries.catalog_main_uuid_index == key as u16 {
                    process_entries.main_uuid = uuid.to_string();
                }
                if process_entries.catalog_dsc_uuid_index == key as u16 {
                    process_entries.dsc_uuid = uuid.to_string();
                }
            }

            input = proc_input;
            proc_entry_count += 1;
            catalog_chunk
                .catalog_process_info_entries
                .push(process_entries);
        }

        let mut subchunk_count = 0;

        while subchunk_count < catalog_chunk.number_sub_chunks {
            // Get Catalog subchunk metadata
            let (subchunk_input, subchunks) = CatalogChunk::parse_catalog_subchunk(input)?;

            input = subchunk_input;
            subchunk_count += 1;
            catalog_chunk.catalog_subchunks.push(subchunks);
        }

        Ok((input, catalog_chunk))
    }

    // Parse the Catalog Process Information entry
    fn parse_catalog_process_entry<'a>(
        data: &'a [u8],
        uuids: &[String],
    ) -> nom::IResult<&'a [u8], ProcessInfoEntry> {
        let mut catalog_process_entry = ProcessInfoEntry {
            index: 0,
            unknown: 0,
            catalog_main_uuid_index: 0,
            catalog_dsc_uuid_index: 0,
            first_number_proc_id: 0,
            second_number_proc_id: 0,
            pid: 0,
            effective_user_id: 0,
            unknown2: 0,
            number_uuids_entries: 0,
            unknown3: 0,
            uuid_info_entries: Vec::new(),
            number_subsystems: 0,
            unknown4: 0,
            subsystem_entries: Vec::new(),
            main_uuid: String::new(),
            dsc_uuid: String::new(),
        };

        // Get all static sized data
        let (input, index) = take(size_of::<u16>())(data)?;
        let (input, unknown) = take(size_of::<u16>())(input)?;
        let (input, catalog_main_uuid_index) = take(size_of::<u16>())(input)?;
        let (input, catalog_dsc_uuid_index) = take(size_of::<u16>())(input)?;
        let (input, first_number_proc_id) = take(size_of::<u64>())(input)?;
        let (input, second_number_proc_id) = take(size_of::<u32>())(input)?;
        let (input, pid) = take(size_of::<u32>())(input)?;
        let (input, effective_user_id) = take(size_of::<u32>())(input)?;
        let (input, unknown2) = take(size_of::<u32>())(input)?;
        let (input, number_uuids_entries) = take(size_of::<u32>())(input)?;
        let (mut input, unknown3) = take(size_of::<u32>())(input)?;

        let (_, process_index) = le_u16(index)?;
        let (_, process_unknown) = le_u16(unknown)?;
        let (_, process_catalog_main_uuid_index) = le_u16(catalog_main_uuid_index)?;
        let (_, process_catalog_dsc_uuid_index) = le_u16(catalog_dsc_uuid_index)?;
        let (_, process_first_number_proc_id) = le_u64(first_number_proc_id)?;
        let (_, process_second_number_proc_id) = le_u32(second_number_proc_id)?;
        let (_, process_pid) = le_u32(pid)?;
        let (_, process_effective_user_id) = le_u32(effective_user_id)?;
        let (_, process_unknown2) = le_u32(unknown2)?;
        let (_, process_number_uuids_entries) = le_u32(number_uuids_entries)?;
        let (_, process_unknown3) = le_u32(unknown3)?;

        catalog_process_entry.index = process_index;
        catalog_process_entry.unknown = process_unknown;
        catalog_process_entry.catalog_main_uuid_index = process_catalog_main_uuid_index;
        catalog_process_entry.catalog_dsc_uuid_index = process_catalog_dsc_uuid_index;
        catalog_process_entry.first_number_proc_id = process_first_number_proc_id;
        catalog_process_entry.second_number_proc_id = process_second_number_proc_id;
        catalog_process_entry.pid = process_pid;
        catalog_process_entry.effective_user_id = process_effective_user_id;
        catalog_process_entry.unknown2 = process_unknown2;
        catalog_process_entry.number_uuids_entries = process_number_uuids_entries;
        catalog_process_entry.unknown3 = process_unknown3;

        // Continously get uuid entries based on number_uuids_entries
        let mut uuid_entries = 0;
        while uuid_entries < catalog_process_entry.number_uuids_entries {
            // Parse UUID metadata in Catalog Process Entry (the Catalog Process Entry references the UUIDs array parsed in parse_catalog by index)
            let process_uuid_metadata_result = CatalogChunk::parse_process_info_uuid_entry(input);
            match process_uuid_metadata_result {
                Ok((process_input, mut uuid_data)) => {
                    if uuids.len() < uuid_data.catalog_uuid_index as usize {
                        error!("Catalog Process UUID Index greater than Catalog UUID Array. Log is likely corrupted");
                        return Err(nom::Err::Incomplete(Needed::Unknown));
                    }
                    uuids[uuid_data.catalog_uuid_index as usize].clone_into(&mut uuid_data.uuid);
                    input = process_input;
                    uuid_entries += 1;
                    catalog_process_entry.uuid_info_entries.push(uuid_data);
                }
                Err(err) => {
                    error!("Failed to parse Catalog Process Entry: {:?}", err);
                    return Err(nom::Err::Incomplete(Needed::Unknown));
                }
            }
        }

        // Get static sized data after getting uuid entries
        let (input, number_subsystems) = take(size_of::<u32>())(input)?;
        let (mut input, unknown4) = take(size_of::<u32>())(input)?;
        let (_, process_number_subsystems) = le_u32(number_subsystems)?;
        let (_, process_unknown4) = le_u32(unknown4)?;
        catalog_process_entry.number_subsystems = process_number_subsystems;
        catalog_process_entry.unknown4 = process_unknown4;

        // Continuously get subsystem entries based on number_subsystems
        let mut subsystem_entries = 0;
        while subsystem_entries < catalog_process_entry.number_subsystems {
            let (process_input, subsystem) = CatalogChunk::parse_process_info_subystem(input)?;
            input = process_input;
            subsystem_entries += 1;
            catalog_process_entry.subsystem_entries.push(subsystem);
        }
        let subsystem_size = 6;
        let total_subsystem_size = catalog_process_entry.number_subsystems * subsystem_size;

        let padding = padding_size(total_subsystem_size.into());
        let (input, _) = take(padding)(input)?;

        Ok((input, catalog_process_entry))
    }

    // Parse the UUID metadata in the Catalog Process Entry (the Catalog Process Entry references the UUIDs array parsed in parse_catalog by index value)
    fn parse_process_info_uuid_entry(
        data: &[u8],
    ) -> nom::IResult<&[u8], ProcessUUIDEntry, CatalogProcessUUIDEntryError> {
        let mut process_uuid = ProcessUUIDEntry {
            size: 0,
            unknown: 0,
            catalog_uuid_index: 0,
            load_address: 0,
            uuid: String::new(),
        };

        let (input, size) = take(size_of::<u32>())(data)?;
        let (input, unknown) = take(size_of::<u32>())(input)?;
        let (input, catalog_uuid_index) = take(size_of::<u16>())(input)?;

        let load_address_size: u8 = 6;
        let (input, load_address) = take(load_address_size)(input)?;

        let (_, process_uuid_size) = le_u32(size)?;
        let (_, process_uuid_unknown) = le_u32(unknown)?;
        let (_, process_uuid_catalog_uuid_index) = le_u16(catalog_uuid_index)?;

        // Add padding to the load address offset
        let mut load_address_vec = load_address.to_vec();
        load_address_vec.push(0);
        load_address_vec.push(0);
        let mut load_address_buff: &[u8] = &load_address_vec;
        let process_load_address_result = load_address_buff.read_u64::<LittleEndian>();
        match process_load_address_result {
            Ok(process_load_address) => process_uuid.load_address = process_load_address,
            Err(err) => {
                error!(
                    "Failed to get Little Endian value of Catalog Process Entry load address: {:?}",
                    err
                );
                return Err(nom::Err::Failure(CatalogProcessUUIDEntryError {
                    message: String::from("failed to get Little Endian value"),
                }));
            }
        }

        process_uuid.size = process_uuid_size;
        process_uuid.unknown = process_uuid_unknown;
        process_uuid.catalog_uuid_index = process_uuid_catalog_uuid_index;

        Ok((input, process_uuid))
    }

    // Parse the Catalog Subsystem metadata. This helps get the subsystem (App Bundle ID) and the log entry category
    fn parse_process_info_subystem(data: &[u8]) -> nom::IResult<&[u8], ProcessInfoSubsystem> {
        let mut process_subsystem = ProcessInfoSubsystem {
            identifer: 0,
            subsystem_offset: 0,
            category_offset: 0,
        };

        let (input, identifer) = take(size_of::<u16>())(data)?;
        let (input, subsystem_offset) = take(size_of::<u16>())(input)?;
        let (input, category_offset) = take(size_of::<u16>())(input)?;

        let (_, process_identifier) = le_u16(identifer)?;
        let (_, process_subystem_offset) = le_u16(subsystem_offset)?;
        let (_, process_category_offset) = le_u16(category_offset)?;

        process_subsystem.identifer = process_identifier;
        process_subsystem.subsystem_offset = process_subystem_offset;
        process_subsystem.category_offset = process_category_offset;

        Ok((input, process_subsystem))
    }

    // Parse the Catalog Subchunk metadata. This metadata is related to the compressed (typically) Chunkset data
    fn parse_catalog_subchunk(data: &[u8]) -> nom::IResult<&[u8], CatalogSubchunk> {
        let mut catalog_subchunk = CatalogSubchunk {
            start: 0,
            end: 0,
            uncompressed_size: 0,
            compression_algorithm: 0,
            number_index: 0,
            indexes: Vec::new(),
            number_string_offsets: 0,
            string_offsets: Vec::new(),
        };

        // Get static size subchunk data
        let (input, start) = take(size_of::<u64>())(data)?;
        let (input, end) = take(size_of::<u64>())(input)?;
        let (input, uncompressed_size) = take(size_of::<u32>())(input)?;
        let (input, compression_algorithm) = take(size_of::<u32>())(input)?;
        let (mut input, number_indexes) = take(size_of::<u32>())(input)?;

        let (_, subchunk_start) = le_u64(start)?;
        let (_, subchunk_end) = le_u64(end)?;
        let (_, subchunk_uncompressed_size) = le_u32(uncompressed_size)?;
        let (_, subchunk_compression_algorithm) = le_u32(compression_algorithm)?;
        let (_, subchunk_number_indexes) = le_u32(number_indexes)?;

        // If the data is compressed (typically) the compression type should be 0x100 (256) which is LZ compressed
        let lz4_compressions = 256;
        if subchunk_compression_algorithm != lz4_compressions {
            error!(
                "Unknown compression algorithm: {}",
                subchunk_compression_algorithm
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        catalog_subchunk.start = subchunk_start;
        catalog_subchunk.end = subchunk_end;
        catalog_subchunk.uncompressed_size = subchunk_uncompressed_size;
        catalog_subchunk.compression_algorithm = subchunk_compression_algorithm;
        catalog_subchunk.number_index = subchunk_number_indexes;

        let mut index_count = 0;
        while index_count < subchunk_number_indexes {
            let (index_input, index) = take(size_of::<u16>())(input)?;
            let (_, subchunk_index) = le_u16(index)?;
            catalog_subchunk.indexes.push(subchunk_index);
            index_count += 1;
            input = index_input;
        }

        let (mut input, number_string_offsets) = take(size_of::<u32>())(input)?;
        let (_, subchunk_string_number_offsets) = le_u32(number_string_offsets)?;
        catalog_subchunk.number_string_offsets = subchunk_string_number_offsets;

        let mut strings_count = 0;
        while strings_count < subchunk_string_number_offsets {
            let (index_input, strings) = take(size_of::<u16>())(input)?;
            let (_, subchunk_strings_offset) = le_u16(strings)?;
            catalog_subchunk
                .string_offsets
                .push(subchunk_strings_offset);
            strings_count += 1;

            input = index_input;
        }

        // calculate amount of padding needed based on number_string_offsets and number_index
        let offset_size = 2;
        let total_subchunk_size = catalog_subchunk.number_string_offsets * offset_size
            + (catalog_subchunk.number_index * offset_size);
        let padding = padding_size(u64::from(total_subchunk_size));
        let (input, _) = take(padding)(input)?;

        Ok((input, catalog_subchunk))
    }

    // Get subsystem and category based on the log entry first_proc_id, second_proc_id, log entry subsystem id and the associated Catalog
    pub fn get_subsystem<'a>(
        subsystem_value: &u16,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalog: &'a CatalogChunk,
    ) -> nom::IResult<&'a [u8], SubsystemInfo> {
        let mut subsystem_info = SubsystemInfo {
            subsystem: String::new(),
            category: String::new(),
        };

        // Go through catalog entries until first and second proc id match the log entry
        for process_info in &catalog.catalog_process_info_entries {
            if first_proc_id == &process_info.first_number_proc_id
                && second_proc_id == &process_info.second_number_proc_id
            {
                // Go through subsystems in catalog entry until subsystem value is found
                for subsystems in &process_info.subsystem_entries {
                    if subsystem_value == &subsystems.identifer {
                        let subsystem_data: &[u8] = &catalog.catalog_subsystem_strings;
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

        warn!("[macos-unifiedlogs] Did not find subsystem in log entry");
        subsystem_info.subsystem = String::from("Unknown subsystem");
        Ok((&[], subsystem_info))
    }

    // Get the actual Process ID associated with log entry
    pub fn get_pid(first_proc_id: &u64, second_proc_id: &u32, catalog: &CatalogChunk) -> u64 {
        // Go through catalog entries until first and second proc id match the log entry
        for process_info in &catalog.catalog_process_info_entries {
            if first_proc_id == &process_info.first_number_proc_id
                && second_proc_id == &process_info.second_number_proc_id
            {
                return u64::from(process_info.pid);
            }
        }

        warn!("[macos-unifiedlogs] Did not find PID in log Catalog");
        0
    }

    // Get the effictive user id associated with log entry. Can be mapped to an account name
    pub fn get_euid(first_proc_id: &u64, second_proc_id: &u32, catalog: &CatalogChunk) -> u32 {
        // Go through catalog entries until first and second proc id match the log entry
        for process_info in &catalog.catalog_process_info_entries {
            if first_proc_id == &process_info.first_number_proc_id
                && second_proc_id == &process_info.second_number_proc_id
            {
                return process_info.effective_user_id;
            }
        }
        warn!("[macos-unifiedlogs] Did not find EUID in log Catalog");
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
        let subsystem_data = [
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

        let test_data = vec![String::from("0")];

        let (_, process_entry) =
            CatalogChunk::parse_catalog_process_entry(&subsystem_data, &test_data).unwrap();
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
        assert_eq!(process_entry.main_uuid, "");
        assert_eq!(process_entry.dsc_uuid, "");
    }

    #[test]
    fn test_parse_process_info_uuid_entry() {
        let test_subsystem_data = [
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
            CatalogChunk::parse_process_info_subystem(&test_subsystem_data).unwrap();
        assert_eq!(subsystems.identifer, 87);
        assert_eq!(subsystems.subsystem_offset, 0);
        assert_eq!(subsystems.category_offset, 19);

        let (_, subsystems) = CatalogChunk::parse_process_info_subystem(&data).unwrap();
        assert_eq!(subsystems.identifer, 78);
        assert_eq!(subsystems.subsystem_offset, 0);
        assert_eq!(subsystems.category_offset, 47);
    }

    #[test]
    fn test_parse_catalog_subchunk() {
        let test_subchunks = [
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

        let (data, subchunk) = CatalogChunk::parse_catalog_subchunk(&test_subchunks).unwrap();
        assert_eq!(subchunk.start, 820210633699830);
        assert_eq!(subchunk.end, 820274771182398);
        assert_eq!(subchunk.uncompressed_size, 65400);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        let (data, subchunk) = CatalogChunk::parse_catalog_subchunk(&data).unwrap();
        assert_eq!(subchunk.start, 820274802743600);
        assert_eq!(subchunk.end, 820313668399715);
        assert_eq!(subchunk.uncompressed_size, 61552);
        assert_eq!(subchunk.compression_algorithm, 256);
        assert_eq!(subchunk.number_index, 1);
        assert_eq!(subchunk.indexes, [0]);
        assert_eq!(subchunk.number_string_offsets, 3);
        assert_eq!(subchunk.string_offsets, [0, 19, 47]);

        let (_, subchunk) = CatalogChunk::parse_catalog_subchunk(&data).unwrap();
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
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: Incomplete(Unknown)")]
    fn test_parse_catalog_subchunk_bad_compression() {
        let test_bad_compression = [
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
        let (_, _) = CatalogChunk::parse_catalog_subchunk(&test_bad_compression).unwrap();
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

        let (_, results) = CatalogChunk::get_subsystem(
            &subsystem_value,
            &first_proc_id,
            &second_proc_id,
            &catalog,
        )
        .unwrap();
        assert_eq!(results.subsystem, "com.apple.containermanager");
        assert_eq!(results.category, "xpc");
    }
}
