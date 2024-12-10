// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::{debug, info, warn};
use nom::bytes::complete::take;

use crate::catalog::CatalogChunk;
use crate::dsc::SharedCacheStrings;
use crate::util::extract_string;
use crate::uuidtext::{UUIDText, UUIDTextEntry};

#[derive(Debug, Default)]
pub struct MessageData {
    pub library: String,
    pub format_string: String,
    pub process: String,
    pub library_uuid: String,
    pub process_uuid: String,
}

// Functions to help extract base format string based on flags associated with log entries
// Ex: "%s start"
impl MessageData {
    /// Extract string from the Shared Strings Cache (dsc data)
    //  Shared strings contain library and message string
    pub fn extract_shared_strings<'a>(
        shared_strings: &'a [SharedCacheStrings],
        strings_data: &'a [UUIDText],
        string_offset: u64,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
        original_offset: u64,
    ) -> nom::IResult<&'a [u8], MessageData> {
        debug!("[macos-unifiedlogs] Extracting format string from shared cache file (dsc)");
        let mut message_data = MessageData::default();

        // Check if the string offset is "dynamic" (the formatter is "%s")
        if original_offset & 0x80000000 != 0 {
            for shared_string in shared_strings {
                // Get shared string file (DSC) associated with log entry from Catalog
                let (dsc_uuid, main_uuid) =
                    MessageData::get_catalog_dsc(catalogs, first_proc_id, second_proc_id);
                if shared_string.dsc_uuid != dsc_uuid {
                    continue;
                }

                if let Some(ranges) = shared_string.ranges.first() {
                    shared_string.uuids[ranges.unknown_uuid_index as usize]
                        .path_string
                        .clone_into(&mut message_data.library);

                    shared_string.uuids[ranges.unknown_uuid_index as usize]
                        .uuid
                        .clone_into(&mut message_data.library_uuid);
                    message_data.format_string = String::from("%s");
                    message_data.process_uuid = main_uuid;

                    // Extract image path from second UUIDtext file
                    let (_, process_string) =
                        MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                    message_data.process = process_string;

                    return Ok((&[], message_data));
                }
            }
        }

        // Go through shared strings collections
        for shared_string in shared_strings {
            // Get shared string file (DSC) associated with log entry from Catalog
            let (dsc_uuid, main_uuid) =
                MessageData::get_catalog_dsc(catalogs, first_proc_id, second_proc_id);
            if shared_string.dsc_uuid != dsc_uuid {
                continue;
            }

            debug!(
                "[macos-unifiedlogs] Associated dsc file with log entry: {:?}",
                dsc_uuid
            );

            for ranges in &shared_string.ranges {
                if string_offset >= ranges.range_offset
                    && string_offset < (ranges.range_offset + u64::from(ranges.range_size))
                {
                    let offset = string_offset - ranges.range_offset;
                    let strings = &ranges.strings;
                    let string_data: &[u8] = strings;

                    // If the offset and string data are equal then the next range entry contains the string message
                    /* If offset = 2800, then the entry would be in range 322 (range 321 ends at 0x00000b04bfc0 and range 322 starts at 0x00000b04bfc0 )
                       Range 321:
                           uuid 208:       6B77361F-69AF-393F-97B8-9BDED38304B0
                           dsc range:      0x00000b04b4d0 .. 0x00000b04bfc0 (2800)
                           path:           /System/Library/PrivateFrameworks/IconFoundation.framework/Versions/A/IconFoundation

                       Range 322:
                           uuid 208:       6B77361F-69AF-393F-97B8-9BDED38304B0
                           dsc range:      0x00000b04bfc0 .. 0x00000b04c0ac (236)
                           path:           /System/Library/PrivateFrameworks/IconFoundation.framework/Versions/A/IconFoundation
                    */
                    if offset as usize == string_data.len() {
                        continue;
                    }

                    let (message_start, _) = take(offset)(string_data)?;
                    let (_, message_string) = extract_string(message_start)?;
                    message_data.format_string = message_string;

                    shared_string.uuids[ranges.unknown_uuid_index as usize]
                        .path_string
                        .clone_into(&mut message_data.library);

                    shared_string.uuids[ranges.unknown_uuid_index as usize]
                        .uuid
                        .clone_into(&mut message_data.library_uuid);
                    message_data.process_uuid = main_uuid;

                    // Extract image path from second UUIDtext file
                    let (_, process_string) =
                        MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                    message_data.process = process_string;
                    return Ok((&[], message_data));
                }
            }
        }

        // There is a chance the log entry does not have a valid offset
        // Apple reports as "~~> <Invalid shared cache code pointer offset>" or <Invalid shared cache format string offset>
        for shared_string in shared_strings {
            // Get shared string file (DSC) associated with log entry from Catalog
            let (dsc_uuid, main_uuid) =
                MessageData::get_catalog_dsc(catalogs, first_proc_id, second_proc_id);
            if shared_string.dsc_uuid != dsc_uuid {
                continue;
            }

            // Still get the image path/library for the log entry
            if let Some(ranges) = shared_string.ranges.first() {
                shared_string.uuids[ranges.unknown_uuid_index as usize]
                    .path_string
                    .clone_into(&mut message_data.library);

                shared_string.uuids[ranges.unknown_uuid_index as usize]
                    .uuid
                    .clone_into(&mut message_data.library_uuid);
                message_data.format_string = String::from("Error: Invalid shared string offset");
                message_data.process_uuid = main_uuid;

                // Extract image path from second UUIDtext file
                let (_, process_string) =
                    MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                message_data.process = process_string;

                return Ok((&[], message_data));
            }
        }

        warn!("[macos-unifiedlogs] Failed to get message string from Shared Strings DSC file");
        message_data.format_string = String::from("Unknown shared string message");

        Ok((&[], message_data))
    }

    /// Extract strings from the `UUIDText` file associated with log entry
    /// `UUIDText` file contains process and message string
    pub fn extract_format_strings<'a>(
        strings_data: &'a [UUIDText],
        string_offset: u64,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
        original_offset: u64,
    ) -> nom::IResult<&'a [u8], MessageData> {
        debug!("[macos-unifiedlogs] Extracting format string from UUID file");
        let (_, main_uuid) = MessageData::get_catalog_dsc(catalogs, first_proc_id, second_proc_id);

        // log entries with main_exe flag do not use dsc cache uuid file
        let mut message_data = MessageData {
            library_uuid: main_uuid.to_owned(),
            process_uuid: main_uuid,
            ..Default::default()
        };

        // If most significant bit is set, the string offset is "dynamic" (the formatter is "%s")
        if original_offset & 0x80000000 != 0 {
            for data in strings_data {
                if message_data.process_uuid.ends_with(&data.uuid) {
                    // Footer data is a collection of strings that ends with the image path/library associated with strings
                    let strings = &data.footer_data;
                    let footer_data: &[u8] = strings;

                    let (_, process_string) =
                        MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                    process_string.clone_into(&mut message_data.process);
                    message_data.library = process_string;
                    message_data.format_string = String::from("%s");

                    return Ok((&[], message_data));
                }
            }
        }

        // Go through the collection of parsed UUIDText files until matching UUID file is found
        for data in strings_data {
            if message_data.process_uuid.ends_with(&data.uuid) {
                let mut string_start = 0;
                for entry in &data.entry_descriptors {
                    // Identify start of string formatter offset
                    if entry.range_start_offset > string_offset as u32 {
                        string_start += entry.entry_size;
                        continue;
                    }

                    let offset = string_offset as u32 - entry.range_start_offset;
                    // Footer data is a collection of strings that ends with the image path/library associated with strings
                    let strings = &data.footer_data;
                    let footer_data: &[u8] = strings;

                    // Check to make sure footer/string data is larger than the offset
                    if (footer_data.len() < (offset + string_start) as usize)
                        || offset > entry.entry_size
                    {
                        string_start += entry.entry_size;
                        continue;
                    }

                    let (message_start, _) = take(offset + string_start)(footer_data)?;
                    let (_, message_string) = extract_string(message_start)?;

                    let (_, process_string) =
                        MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;

                    message_data.format_string = message_string;
                    // Process and library path are the same for log entries with main_exe
                    process_string.clone_into(&mut message_data.process);
                    message_data.library = process_string;

                    return Ok((&[], message_data));
                }
            }
        }

        // There is a chance the log entry does not have a valid offset
        // Apple labels as "error: ~~> Invalid bounds 4334340 for E502E11E-518F-38A7-9F0B-E129168338E7"
        for data in strings_data {
            if message_data.process_uuid.ends_with(&data.uuid) {
                // Footer data is a collection of strings that ends with the image process associated with the strings
                let strings = &data.footer_data;
                let footer_data: &[u8] = strings;

                let (_, process_string) =
                    MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                process_string.clone_into(&mut message_data.process);
                message_data.library = process_string;
                message_data.format_string = format!(
                    "Error: Invalid offset {} for UUID {}",
                    string_offset, message_data.process_uuid
                );

                return Ok((&[], message_data));
            }
        }

        warn!(
            "[macos-unifiedlogs] Failed to get message string from UUIDText file: {}",
            message_data.process_uuid
        );
        message_data.format_string = format!(
            "Failed to get string message from UUIDText file: {}",
            message_data.process_uuid
        );
        Ok((&[], message_data))
    }

    /// Extract strings from the `UUIDText` file associated with log entry that have `absolute` flag set
    /// `UUIDText` file contains process and message string
    pub fn extract_absolute_strings<'a>(
        strings_data: &'a [UUIDText],
        absolute_offset: u64,
        string_offset: u64,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
        original_offset: u64,
    ) -> nom::IResult<&'a [u8], MessageData> {
        debug!("[macos-unifiedlogs] Extracting format string from UUID file for log entry with Absolute flag");
        let mut uuid = String::new();
        // Go through Catalog associated with log entry and find UUID entry associated with log message (first_proc_id@second_proc_id)
        for process_info in &catalogs.catalog_process_info_entries {
            if first_proc_id == &process_info.first_number_proc_id
                && second_proc_id == &process_info.second_number_proc_id
            {
                // In addition to first_proc_id and second_proc_id, we need to go through UUID entries in the catalog
                // Entries with the Absolute flag have the UUID stored in an Vec of UUIDs and offsets/load_address
                // The correct UUID entry is the one where the absolute_offset value falls in between load_address and load_address size (uuids.load_address + uuids.size)
                for uuids in &process_info.uuid_info_entries {
                    if absolute_offset >= uuids.load_address
                        && absolute_offset <= (uuids.load_address + u64::from(uuids.size))
                    {
                        debug!(
                            "[macos-unifiedlogs] Absolute uuid file is: {:?}",
                            uuids.uuid
                        );
                        uuids.uuid.clone_into(&mut uuid);
                        break;
                    }
                }
            }
            if !uuid.is_empty() {
                break;
            }
        }
        // The UUID for log entries with absolute flag dont use the dsc uuid files
        let (_, main_uuid) = MessageData::get_catalog_dsc(catalogs, first_proc_id, second_proc_id);

        let mut message_data = MessageData {
            library: String::new(),
            format_string: String::new(),
            process: String::new(),
            library_uuid: uuid,
            process_uuid: main_uuid,
        };
        // If most significant bit is set, the string offset is "dynamic" (the formatter is "%s")
        if (original_offset & 0x80000000 != 0) || string_offset == absolute_offset {
            for data in strings_data {
                if message_data.library_uuid.ends_with(&data.uuid) {
                    // Footer data is a collection of strings that ends with the image path/library associated with strings
                    let strings = &data.footer_data;
                    let footer_data: &[u8] = strings;

                    // Extract image path from current UUIDtext file
                    let (_, library_string) =
                        MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                    message_data.library = library_string;

                    // Extract image path from second UUIDtext file
                    let (_, process_string) =
                        MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                    message_data.process = process_string;
                    message_data.format_string = String::from("%s");

                    return Ok((&[], message_data));
                }
            }
        }

        for data in strings_data {
            if message_data.library_uuid.ends_with(&data.uuid) {
                let mut string_start = 0;
                for entry in &data.entry_descriptors {
                    // Identify start of string formatter offset
                    if u64::from(entry.range_start_offset) > string_offset {
                        string_start += entry.entry_size;
                        continue;
                    }

                    let strings = &data.footer_data;
                    let footer_data: &[u8] = strings;

                    let offset = string_offset - u64::from(entry.range_start_offset);
                    // Check to make sure footer/string data is larger than the offset
                    if (footer_data.len() < (offset + u64::from(string_start)) as usize)
                        || offset > u64::from(entry.entry_size)
                    {
                        string_start += entry.entry_size;
                        continue;
                    }
                    let (message_start, _) = take(offset + u64::from(string_start))(footer_data)?;
                    let (_, message_string) = extract_string(message_start)?;

                    // Extract image path from current UUIDtext file
                    let (_, library_string) =
                        MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                    message_data.format_string = message_string;
                    message_data.library = library_string;

                    // Extract image path from second UUIDtext file
                    let (_, process_string) =
                        MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                    message_data.process = process_string;
                    return Ok((&[], message_data));
                }
            }
        }

        // There is a chance the log entry does not have a valid offset
        // Apple labels as "error: ~~> Invalid bounds 4334340 for E502E11E-518F-38A7-9F0B-E129168338E7"
        for data in strings_data {
            if message_data.library_uuid.ends_with(&data.uuid) {
                // Footer data is a collection of strings that ends with the image process associated with the strings
                let strings = &data.footer_data;
                let footer_data: &[u8] = strings;

                // Extract image path from current UUIDtext file
                let (_, library_string) =
                    MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                message_data.library = library_string;
                message_data.format_string = format!(
                    "Error: Invalid offset {} for absolute UUID {}",
                    string_offset, message_data.library_uuid
                );

                // Extract image path from second UUIDtext file
                let (_, process_string) =
                    MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                message_data.process = process_string;

                return Ok((&[], message_data));
            }
        }

        warn!(
            "[macos-unifiedlogs] Failed to get message string from absolute UUIDText file: {}",
            message_data.library_uuid
        );
        message_data.format_string = format!(
            "Failed to get string message from absolute UUIDText file: {}",
            message_data.library_uuid
        );
        Ok((&[], message_data))
    }

    /// Extract strings from an alt `UUIDText` file specified within the log entry that have `uuid_relative` flag set
    /// `UUIDText` files contains library and process and message string
    pub fn extract_alt_uuid_strings<'a>(
        strings_data: &'a [UUIDText],
        string_offset: u64,
        uuid: &str,
        first_proc_id: &u64,
        second_proc_id: &u32,
        catalogs: &CatalogChunk,
        original_offset: u64,
    ) -> nom::IResult<&'a [u8], MessageData> {
        debug!("[macos-unifiedlogs] Extracting format string from alt uuid");
        // Log entries with uuid_relative flags set have the UUID in the log itself. They do not use the dsc UUID files
        let (_, main_uuid) = MessageData::get_catalog_dsc(catalogs, first_proc_id, second_proc_id);

        let mut message_data = MessageData {
            library: String::new(),
            format_string: String::new(),
            process: String::new(),
            library_uuid: uuid.to_string(),
            process_uuid: main_uuid,
        };
        // If most significant bit is set, the string offset is "dynamic" (the formatter is "%s")
        if original_offset & 0x80000000 != 0 {
            for data in strings_data {
                if uuid.ends_with(&data.uuid) {
                    // Footer data is a collection of strings that ends with the image path/library associated with strings
                    let strings = &data.footer_data;
                    let footer_data: &[u8] = strings;

                    // Extract image path from current UUIDtext file
                    let (_, library_string) =
                        MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                    message_data.library = library_string;

                    // Extract image path from second UUIDtext file
                    let (_, process_string) =
                        MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                    message_data.process = process_string;
                    message_data.format_string = String::from("%s");

                    return Ok((&[], message_data));
                }
            }
        }

        for data in strings_data {
            if uuid.ends_with(&data.uuid) {
                let mut string_start = 0;
                for entry in &data.entry_descriptors {
                    // Identify start of string formatter offset
                    if entry.range_start_offset > string_offset as u32 {
                        string_start += entry.entry_size;
                        continue;
                    }
                    let offset = string_offset as u32 - entry.range_start_offset;
                    let strings = &data.footer_data;
                    let footer_data: &[u8] = strings;

                    // Check to make sure footer/string data is larger than the offset
                    // Or if the offset is greater than the entry size
                    // If offset greater than entry size then its not the correct UUIDText entry
                    if (footer_data.len() < offset as usize) || offset > entry.entry_size {
                        string_start += entry.entry_size;
                        continue;
                    }
                    let (message_start, _) = take(offset + string_start)(footer_data)?;
                    let (_, message_string) = extract_string(message_start)?;

                    // Extract image path from current UUIDtext file
                    let (_, library_string) =
                        MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;

                    // Extract image path from second UUIDtext file
                    let (_, process_string) =
                        MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                    message_data.process = process_string;

                    message_data.format_string = message_string;
                    message_data.library = library_string;
                    return Ok((&[], message_data));
                }
            }
        }

        // There is a chance the log entry does not have a valid offset
        // Apple labels as "error: ~~> Invalid bounds 4334340 for E502E11E-518F-38A7-9F0B-E129168338E7"
        for data in strings_data {
            if uuid.ends_with(&data.uuid) {
                // Footer data is a collection of strings that ends with the image process associated with the strings
                let strings = &data.footer_data;
                let footer_data: &[u8] = strings;

                // Extract image path from current UUIDtext file
                let (_, library_string) =
                    MessageData::uuidtext_image_path(footer_data, &data.entry_descriptors)?;
                message_data.library = library_string;
                message_data.format_string = format!(
                    "Error: Invalid offset {} for alternative UUID {}",
                    string_offset, uuid
                );

                // Extract image path from second UUIDtext file
                let (_, process_string) =
                    MessageData::get_uuid_image_path(&message_data.process_uuid, strings_data)?;
                message_data.process = process_string;

                return Ok((&[], message_data));
            }
        }

        warn!(
            "[macos-unifiedlogs] Failed to get message string from alternative UUIDText file: {}",
            uuid
        );
        message_data.format_string = format!(
            "Failed to get string message from alternative UUIDText file: {}",
            uuid
        );
        Ok((&[], message_data))
    }

    /// Get the image path at the end of the `UUIDText` file
    fn uuidtext_image_path<'a>(
        data: &'a [u8],
        entries: &[UUIDTextEntry],
    ) -> nom::IResult<&'a [u8], String> {
        // Add up all entry range offset sizes to get image library offset
        let mut image_library_offest: u32 = 0;
        for entry in entries {
            image_library_offest += entry.entry_size;
        }
        let (library_start, _) = take(image_library_offest)(data)?;
        extract_string(library_start)
    }

    /// Get the image path from provided `main_uuid` entry
    fn get_uuid_image_path<'a>(
        main_uuid: &str,
        entries: &'a [UUIDText],
    ) -> nom::IResult<&'a [u8], String> {
        for data in entries {
            if main_uuid.ends_with(&data.uuid) {
                return MessageData::uuidtext_image_path(
                    &data.footer_data,
                    &data.entry_descriptors,
                );
            }
        }
        // An UUID of all zeros is possilbe in the Catalog, if this happens there is no process path
        if main_uuid == "00000000000000000000000000000000" {
            info!("[macos-unifiedlogs] Got UUID of all zeros fom Catalog");
            return Ok((&[], String::new()));
        }
        warn!(
            "[macos-unifiedlogs] Failed to get path string from UUIDText file for entry: {}",
            main_uuid
        );

        Ok((
            &[],
            format!(
                "Failed to get path string from UUIDText file for entry: {}",
                main_uuid
            ),
        ))
    }

    // Grab dsc file name from the Catalog data based on first and second proc ids from the Firehose log
    fn get_catalog_dsc(
        catalogs: &CatalogChunk,
        first_proc_id: &u64,
        second_proc_id: &u32,
    ) -> (String, String) {
        let mut dsc_uuid = String::new();
        let mut main_uuid = String::new();

        for process_info in &catalogs.catalog_process_info_entries {
            if first_proc_id == &process_info.first_number_proc_id
                && second_proc_id == &process_info.second_number_proc_id
            {
                process_info.dsc_uuid.clone_into(&mut dsc_uuid);
                process_info.main_uuid.clone_into(&mut main_uuid);
                break;
            }
        }
        (dsc_uuid, main_uuid)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        chunks::firehose::message::MessageData,
        parser::{collect_shared_strings, collect_strings, parse_log},
    };

    #[test]
    fn test_extract_shared_strings_nonactivity() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 1331408102;
        let test_first_proc_id = 45;
        let test_second_proc_id = 188;

        let (_, results) = MessageData::extract_shared_strings(
            &shared_strings_results,
            &strings,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[0].catalog,
            0,
        )
        .unwrap();
        assert_eq!(
            results.library,
            "/System/Library/PrivateFrameworks/AppleLOM.framework/Versions/A/AppleLOM"
        );
        assert_eq!(results.library_uuid, "D8E5AF1CAF4F3CEB8731E6F240E8EA7D");

        assert_eq!(results.process, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results.process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");

        assert_eq!(results.format_string, "%@ start")
    }

    #[test]
    fn test_extract_shared_strings_nonactivity_bad_offset() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let bad_offset = 7;
        let test_first_proc_id = 45;
        let test_second_proc_id = 188;

        let (_, results) = MessageData::extract_shared_strings(
            &shared_strings_results,
            &strings,
            bad_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[0].catalog,
            0,
        )
        .unwrap();
        assert_eq!(results.library, "/usr/lib/system/libsystem_blocks.dylib");
        assert_eq!(results.library_uuid, "4DF6D8F5D9C23A968DE45E99D6B73DC8");

        assert_eq!(results.process, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results.process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");

        assert_eq!(results.format_string, "Error: Invalid shared string offset")
    }

    #[test]
    fn test_extract_shared_strings_nonactivity_dynamic() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 2420246585;
        let test_first_proc_id = 32;
        let test_second_proc_id = 424;
        let (_, results) = MessageData::extract_shared_strings(
            &shared_strings_results,
            &strings,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[2].catalog,
            test_offset,
        )
        .unwrap();

        assert_eq!(results.library, "/usr/lib/system/libsystem_blocks.dylib");
        assert_eq!(results.library_uuid, "4DF6D8F5D9C23A968DE45E99D6B73DC8");

        assert_eq!(
            results.process,
            "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT"
        );
        assert_eq!(results.process_uuid, "95A48BD740423BEFBA6E0818A2EED8BE");

        assert_eq!(results.format_string, "%s")
    }

    #[test]
    fn test_extract_format_strings_nonactivity() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 14960;
        let test_first_proc_id = 45;
        let test_second_proc_id = 188;
        let (_, results) = MessageData::extract_format_strings(
            &strings,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[0].catalog,
            test_offset,
        )
        .unwrap();

        assert_eq!(results.process, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results.process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");

        assert_eq!(results.library, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results.library_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");

        assert_eq!(results.format_string, "LOMD Start")
    }

    #[test]
    fn test_extract_format_strings_nonactivity_bad_offset() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let bad_offset = 1;
        let test_first_proc_id = 45;
        let test_second_proc_id = 188;
        let (_, results) = MessageData::extract_format_strings(
            &strings,
            bad_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[0].catalog,
            0,
        )
        .unwrap();

        assert_eq!(results.process, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(
            results.format_string,
            "Error: Invalid offset 1 for UUID 6C3ADF991F033C1C96C4ADFAA12D8CED"
        )
    }

    #[test]
    fn test_extract_format_strings_nonactivity_dynamic() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 2147519968;
        let test_first_proc_id = 38;
        let test_second_proc_id = 317;
        let (_, results) = MessageData::extract_format_strings(
            &strings,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[4].catalog,
            test_offset,
        )
        .unwrap();

        assert_eq!(results.process, "/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/UpdateSettingsTool");
        assert_eq!(results.process_uuid, "6F2A273A77993A719F649607CADC090B");

        assert_eq!(results.library, "/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/UpdateSettingsTool");
        assert_eq!(results.library_uuid, "6F2A273A77993A719F649607CADC090B");

        assert_eq!(results.format_string, "%s")
    }

    #[test]
    fn test_extract_format_strings_nonactivity_dynamic_bad_offset() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let bad_offset = 55;
        let test_first_proc_id = 38;
        let test_second_proc_id = 317;
        let (_, results) = MessageData::extract_format_strings(
            &strings,
            bad_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[4].catalog,
            bad_offset,
        )
        .unwrap();

        assert_eq!(results.process, "/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/UpdateSettingsTool");
        assert_eq!(
            results.format_string,
            "Error: Invalid offset 55 for UUID 6F2A273A77993A719F649607CADC090B"
        )
    }

    #[test]
    fn test_extract_absolute_strings_nonactivity() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 396912;
        let test_absolute_offset = 280925241119206;
        let test_first_proc_id = 0;
        let test_second_proc_id = 0;
        let (_, results) = MessageData::extract_absolute_strings(
            &strings,
            test_absolute_offset,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[0].catalog,
            0,
        )
        .unwrap();
        assert_eq!(
            results.library,
            "/System/Library/Extensions/AppleACPIPlatform.kext/Contents/MacOS/AppleACPIPlatform"
        );
        assert_eq!(results.format_string, "%s")
    }

    #[test]
    fn test_extract_absolute_strings_nonactivity_bad_offset() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 396912;
        let bad_offset = 12;
        let test_first_proc_id = 0;
        let test_second_proc_id = 0;
        let (_, results) = MessageData::extract_absolute_strings(
            &strings,
            bad_offset,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[0].catalog,
            0,
        )
        .unwrap();
        assert_eq!(results.library, "");
        assert_eq!(
            results.format_string,
            "Failed to get string message from absolute UUIDText file: "
        )
    }

    #[test]
    fn test_extract_absolute_strings_nonactivity_dynamic() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_offset = 102;
        let test_absolute_offset = 102;
        assert_eq!(log_data.catalog_data.len(), 56);

        let test_first_proc_id = 0;
        let test_second_proc_id = 0;
        let (_, results) = MessageData::extract_absolute_strings(
            &strings,
            test_absolute_offset,
            test_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[1].catalog,
            test_offset,
        )
        .unwrap();

        assert_eq!(
            results.library,
            "/System/Library/DriverExtensions/com.apple.AppleUserHIDDrivers.dext/"
        );
        assert_eq!(results.format_string, "%s")
    }

    #[test]
    fn test_extract_absolute_strings_nonactivity_dynamic_bad_offset() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let bad_offset = 111;
        let test_absolute_offset = 102;
        assert_eq!(log_data.catalog_data.len(), 56);

        let test_first_proc_id = 0;
        let test_second_proc_id = 0;
        let (_, results) = MessageData::extract_absolute_strings(
            &strings,
            test_absolute_offset,
            bad_offset,
            &test_first_proc_id,
            &test_second_proc_id,
            &log_data.catalog_data[1].catalog,
            bad_offset,
        )
        .unwrap();

        assert_eq!(
            results.library,
            "/System/Library/DriverExtensions/com.apple.AppleUserHIDDrivers.dext/"
        );
        assert_eq!(
            results.format_string,
            "Error: Invalid offset 111 for absolute UUID 0AB77111A2723F2697571948ECE9BDB5"
        )
    }

    #[test]
    fn test_extract_alt_uuid_strings() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();
        test_path.push("Persist/0000000000000005.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let first_proc_id = 105;
        let second_proc_id = 240;

        let test_offset = 221408;
        let test_uuid = "C275D5EEBAD43A86B74F16F3E62BF57D";
        let (_, results) = MessageData::extract_alt_uuid_strings(
            &strings,
            test_offset,
            test_uuid,
            &first_proc_id,
            &second_proc_id,
            &log_data.catalog_data[0].catalog,
            0,
        )
        .unwrap();
        assert_eq!(
            results.library,
            "/System/Library/OpenDirectory/Modules/SystemCache.bundle/Contents/MacOS/SystemCache"
        );
        assert_eq!(results.library_uuid, "C275D5EEBAD43A86B74F16F3E62BF57D");

        assert_eq!(results.process, "/usr/libexec/opendirectoryd");
        assert_eq!(results.process_uuid, "B736DF1625F538248E9527A8CEC4991E");
    }

    #[test]
    fn test_get_catalog_dsc() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");

        test_path.push("Persist/0000000000000002.tracev3");
        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let test_first_proc_id = 136;
        let test_second_proc_id = 342;
        let (dsc_uuid, main_uuid) = MessageData::get_catalog_dsc(
            &log_data.catalog_data[0].catalog,
            &test_first_proc_id,
            &test_second_proc_id,
        );

        assert_eq!(dsc_uuid, "80896B329EB13A10A7C5449B15305DE2");
        assert_eq!(main_uuid, "87721013944F3EA7A42C604B141CCDAA");
    }

    #[test]
    fn test_get_uuid_image_path() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let strings = collect_strings(&test_path.display().to_string()).unwrap();

        let test_uuid = "B736DF1625F538248E9527A8CEC4991E";

        let (_, image_path) = MessageData::get_uuid_image_path(&test_uuid, &strings).unwrap();

        assert_eq!(image_path, "/usr/libexec/opendirectoryd");
    }
}
