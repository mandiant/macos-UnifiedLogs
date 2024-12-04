// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::{clean_uuid, extract_string};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u64};
use std::mem::size_of;

/*
   Introduced in macOS Monterey (12).  Appears to be a "simpler" version of Statedump?
   So far appears to just contain a single string
*/
#[derive(Debug, Clone, Default)]
pub struct SimpleDump {
    pub chunk_tag: u32,
    pub chunk_subtag: u32,
    pub chunk_data_size: u64,
    pub first_proc_id: u64,
    pub second_proc_id: u64,
    pub continous_time: u64,
    pub thread_id: u64,
    pub unknown_offset: u32,
    pub unknown_ttl: u16,
    pub unknown_type: u16,
    pub sender_uuid: String,
    pub dsc_uuid: String,
    pub unknown_number_message_strings: u32,
    pub unknown_size_subsystem_string: u32,
    pub unknown_size_message_string: u32,
    pub subsystem: String,
    pub message_string: String,
}

impl SimpleDump {
    /// Parse Simpledump log entry.  Introduced in macOS Monterey (12)
    pub fn parse_simpledump(data: &[u8]) -> nom::IResult<&[u8], SimpleDump> {
        let mut simpledump_resuls = SimpleDump::default();

        let (input, chunk_tag) = take(size_of::<u32>())(data)?;
        let (input, chunk_sub_tag) = take(size_of::<u32>())(input)?;
        let (input, chunk_data_size) = take(size_of::<u64>())(input)?;
        let (input, first_number_proc_id) = take(size_of::<u64>())(input)?;
        let (input, second_number_proc_id) = take(size_of::<u64>())(input)?;

        let (input, continous_time) = take(size_of::<u64>())(input)?;
        let (input, thread_id) = take(size_of::<u64>())(input)?;
        let (input, unknown_offset) = take(size_of::<u32>())(input)?;
        let (input, unknown_ttl) = take(size_of::<u16>())(input)?;
        let (input, unknown_type) = take(size_of::<u16>())(input)?;
        let (input, sender_uuid) = take(size_of::<u128>())(input)?;
        let (input, dsc_uuid) = take(size_of::<u128>())(input)?;
        let (input, unknown_number_message_strings) = take(size_of::<u32>())(input)?;
        let (input, unknown_size_subsystem_string) = take(size_of::<u32>())(input)?;
        let (input, unknown_size_message_string) = take(size_of::<u32>())(input)?;

        let (_, simpledump_chunk_tag) = le_u32(chunk_tag)?;
        let (_, simpledump_chunk_sub_tag) = le_u32(chunk_sub_tag)?;
        let (_, simpledump_chunk_data_size) = le_u64(chunk_data_size)?;
        let (_, simpledump_first_proc_id) = le_u64(first_number_proc_id)?;
        let (_, simpledump_second_proc_id) = le_u64(second_number_proc_id)?;

        let (_, simpledump_continous_time) = le_u64(continous_time)?;
        let (_, simpledump_thread_id) = le_u64(thread_id)?;
        let (_, simpledump_unknown_offset) = le_u32(unknown_offset)?;
        let (_, simpledump_unknown_ttl) = le_u16(unknown_ttl)?;
        let (_, simpledump_unknown_type) = le_u16(unknown_type)?;
        let (_, simpledump_unknown_number_message_strings) =
            le_u32(unknown_number_message_strings)?;
        let (_, simpledump_unknown_size_subsystem_string) = le_u32(unknown_size_subsystem_string)?;
        let (_, simpledump_unknown_size_message_string) = le_u32(unknown_size_message_string)?;
        let sender_uuid_string = format!("{:02X?}", sender_uuid);
        let dsc_uuid_string = format!("{:02X?}", dsc_uuid);

        simpledump_resuls.chunk_tag = simpledump_chunk_tag;
        simpledump_resuls.chunk_subtag = simpledump_chunk_sub_tag;
        simpledump_resuls.chunk_data_size = simpledump_chunk_data_size;
        simpledump_resuls.continous_time = simpledump_continous_time;
        simpledump_resuls.first_proc_id = simpledump_first_proc_id;
        simpledump_resuls.second_proc_id = simpledump_second_proc_id;
        simpledump_resuls.thread_id = simpledump_thread_id;
        simpledump_resuls.unknown_offset = simpledump_unknown_offset;
        simpledump_resuls.unknown_ttl = simpledump_unknown_ttl;
        simpledump_resuls.unknown_type = simpledump_unknown_type;

        simpledump_resuls.sender_uuid = clean_uuid(&sender_uuid_string);
        simpledump_resuls.dsc_uuid = clean_uuid(&dsc_uuid_string);
        simpledump_resuls.unknown_number_message_strings =
            simpledump_unknown_number_message_strings;
        simpledump_resuls.unknown_size_subsystem_string = simpledump_unknown_size_subsystem_string;
        simpledump_resuls.unknown_size_message_string = simpledump_unknown_size_message_string;

        let (input, subsystem_string) = take(simpledump_unknown_size_subsystem_string)(input)?;
        let (input, message_string) = take(simpledump_unknown_size_message_string)(input)?;

        if !subsystem_string.is_empty() {
            let (_, simpledump_subsystem_string) = extract_string(subsystem_string)?;
            simpledump_resuls.subsystem = simpledump_subsystem_string;
        }
        if !message_string.is_empty() {
            let (_, simpledump_message_string) = extract_string(message_string)?;
            simpledump_resuls.message_string = simpledump_message_string;
        }
        Ok((input, simpledump_resuls))
    }
}

#[cfg(test)]
mod tests {
    use super::SimpleDump;

    #[test]
    fn test_parse_simpledump() {
        let test_data = [
            4, 96, 0, 0, 0, 0, 0, 0, 219, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 45, 182, 196, 71, 133, 4, 0, 0, 3, 234, 0, 0, 0, 0, 0, 0, 118, 118, 1, 0,
            0, 0, 0, 0, 13, 207, 62, 139, 73, 35, 50, 62, 179, 229, 84, 115, 7, 207, 14, 172, 61,
            5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54, 231, 114, 172, 1, 1, 0, 0, 0, 79, 0, 0,
            0, 56, 0, 0, 0, 117, 115, 101, 114, 47, 53, 48, 49, 47, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 109, 100, 119, 111, 114, 107, 101, 114, 46, 115, 104, 97, 114, 101, 100,
            46, 48, 66, 48, 48, 48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48,
            48, 48, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 32, 91, 52, 50, 50, 57, 93,
            0, 115, 101, 114, 118, 105, 99, 101, 32, 101, 120, 105, 116, 101, 100, 58, 32, 100,
            105, 114, 116, 121, 32, 61, 32, 48, 44, 32, 115, 117, 112, 112, 111, 114, 116, 101,
            100, 32, 112, 114, 101, 115, 115, 117, 114, 101, 100, 45, 101, 120, 105, 116, 32, 61,
            32, 49, 0, 0, 0, 0, 0, 0,
        ];
        let (_, results) = SimpleDump::parse_simpledump(&test_data).unwrap();
        assert_eq!(results.chunk_tag, 24580); // 0x6004 - simpledump chunk tag
        assert_eq!(results.chunk_subtag, 0);
        assert_eq!(results.chunk_data_size, 219);
        assert_eq!(results.first_proc_id, 1);
        assert_eq!(results.second_proc_id, 1);
        assert_eq!(results.continous_time, 4970481235501);
        assert_eq!(results.thread_id, 59907);
        assert_eq!(results.unknown_offset, 95862);
        assert_eq!(results.unknown_ttl, 0);
        assert_eq!(results.unknown_type, 0);
        assert_eq!(results.sender_uuid, "0DCF3E8B4923323EB3E5547307CF0EAC");
        assert_eq!(results.dsc_uuid, "3D05845F3F65358F9EBF2236E772AC01");
        assert_eq!(results.unknown_number_message_strings, 1);
        assert_eq!(results.unknown_size_subsystem_string, 79);
        assert_eq!(results.unknown_size_message_string, 56);
        assert_eq!(
            results.subsystem,
            "user/501/com.apple.mdworker.shared.0B000000-0000-0000-0000-000000000000 [4229]"
        );
        assert_eq!(
            results.message_string,
            "service exited: dirty = 0, supported pressured-exit = 1"
        );
    }
}
