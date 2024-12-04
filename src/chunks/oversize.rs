// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::chunks::firehose::firehose_log::{FirehoseItemData, FirehoseItemInfo, FirehosePreamble};
use log::{info, warn};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u64, le_u8};
use std::mem::size_of;

#[derive(Debug, Clone, Default)]
pub struct Oversize {
    pub chunk_tag: u32,
    pub chunk_subtag: u32,
    pub chunk_data_size: u64,
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub ttl: u8,
    pub unknown_reserved: Vec<u8>, // 3 bytes
    pub continuous_time: u64,
    pub data_ref_index: u32,
    pub public_data_size: u16,
    pub private_data_size: u16,
    pub message_items: FirehoseItemData,
}

impl Oversize {
    /// Parse the oversize log entry. Oversize entries contain strings that are too large to fit in a normal Firehose log entry
    pub fn parse_oversize(data: &[u8]) -> nom::IResult<&[u8], Oversize> {
        let mut oversize_results = Oversize::default();

        let (input, chunk_tag) = take(size_of::<u32>())(data)?;
        let (input, chunk_sub_tag) = take(size_of::<u32>())(input)?;
        let (input, chunk_data_size) = take(size_of::<u64>())(input)?;
        let (input, first_number_proc_id) = take(size_of::<u64>())(input)?;
        let (input, second_number_proc_id) = take(size_of::<u32>())(input)?;

        let (input, ttl) = take(size_of::<u8>())(input)?;
        let unknown_reserved_size: u8 = 3;
        let (input, unknown_reserved) = take(unknown_reserved_size)(input)?;
        let (input, continuous_time) = take(size_of::<u64>())(input)?;
        let (input, data_ref_index) = take(size_of::<u32>())(input)?;
        let (input, public_data_size) = take(size_of::<u16>())(input)?;
        let (input, private_data_size) = take(size_of::<u16>())(input)?;

        let (_, oversize_chunk_tag) = le_u32(chunk_tag)?;
        let (_, oversize_chunk_sub_tag) = le_u32(chunk_sub_tag)?;
        let (_, oversize_chunk_data_size) = le_u64(chunk_data_size)?;
        let (_, oversize_first_proc_id) = le_u64(first_number_proc_id)?;
        let (_, oversize_second_proc_id) = le_u32(second_number_proc_id)?;

        let (_, oversize_ttl) = le_u8(ttl)?;
        let (_, oversize_continous_time) = le_u64(continuous_time)?;
        let (_, oversize_data_ref_index) = le_u32(data_ref_index)?;
        let (_, oversize_public_data_size) = le_u16(public_data_size)?;
        let (_, oversize_private_data_size) = le_u16(private_data_size)?;

        oversize_results.chunk_tag = oversize_chunk_tag;
        oversize_results.chunk_subtag = oversize_chunk_sub_tag;
        oversize_results.chunk_data_size = oversize_chunk_data_size;
        oversize_results.first_proc_id = oversize_first_proc_id;
        oversize_results.second_proc_id = oversize_second_proc_id;
        oversize_results.ttl = oversize_ttl;
        oversize_results.continuous_time = oversize_continous_time;
        oversize_results.data_ref_index = oversize_data_ref_index;
        oversize_results.public_data_size = oversize_public_data_size;
        oversize_results.private_data_size = oversize_private_data_size;
        oversize_results.unknown_reserved = unknown_reserved.to_vec();

        let mut oversize_data_size =
            (oversize_results.public_data_size + oversize_results.private_data_size) as usize;

        // Contains item data like firehose (ex: 0x42)
        if oversize_data_size > input.len() {
            warn!("[macos-unifiedlogs] Oversize data size greater than Oversize remaining string size. Using remaining string size");
            oversize_data_size = input.len();
        }
        let (input, pub_data) = take(oversize_data_size)(input)?;

        let (message_data, _) = take(size_of::<u8>())(pub_data)?;
        let (message_data, item_count) = take(size_of::<u8>())(message_data)?;
        let (_, oversize_item_count) = le_u8(item_count)?;

        let empty_flags = 0;
        // Grab all message items from oversize data
        let (oversize_private_data, mut firehose_item_data) =
            FirehosePreamble::collect_items(message_data, &oversize_item_count, &empty_flags)?;
        let (_, _) =
            FirehosePreamble::parse_private_data(oversize_private_data, &mut firehose_item_data)?;
        oversize_results.message_items = firehose_item_data;
        Ok((input, oversize_results))
    }

    /// Function to get the firehose item info from the oversize log entry based on oversize (data ref) id, first proc id, and second proc id
    pub fn get_oversize_strings(
        data_ref: u32,
        first_proc_id: u64,
        second_proc_id: u32,
        oversize_data: &Vec<Oversize>,
    ) -> Vec<FirehoseItemInfo> {
        let mut message_strings: Vec<FirehoseItemInfo> = Vec::new();

        for oversize in oversize_data {
            if data_ref == oversize.data_ref_index
                && first_proc_id == oversize.first_proc_id
                && second_proc_id == oversize.second_proc_id
            {
                for message in &oversize.message_items.item_info {
                    let oversize_firehose = FirehoseItemInfo {
                        message_strings: message.message_strings.to_owned(),
                        item_type: message.item_type,
                        item_size: message.item_size,
                    };
                    message_strings.push(oversize_firehose);
                }
                return message_strings;
            }
        }
        // We may not find any oversize data (data may have rolled from logs?)
        info!("Did not find any oversize log entries from Data Ref ID: {}, First Proc ID: {}, and Second Proc ID: {}", data_ref, first_proc_id, second_proc_id);
        message_strings
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use crate::chunks::firehose::firehose_log::{FirehoseItemData, FirehoseItemInfo};
    use crate::chunks::oversize::Oversize;

    #[test]
    fn test_parse_oversize() {
        let test_data = [
            2, 96, 0, 0, 0, 0, 0, 0, 26, 13, 0, 0, 0, 0, 0, 0, 192, 0, 0, 0, 0, 0, 0, 0, 193, 0, 0,
            0, 14, 0, 0, 0, 15, 132, 249, 225, 2, 0, 0, 0, 1, 0, 0, 0, 250, 12, 0, 0, 2, 1, 34, 4,
            0, 0, 242, 12, 83, 97, 110, 100, 98, 111, 120, 58, 32, 100, 105, 115, 107, 97, 114, 98,
            105, 116, 114, 97, 116, 105, 111, 110, 100, 40, 54, 51, 41, 32, 83, 121, 115, 116, 101,
            109, 32, 80, 111, 108, 105, 99, 121, 58, 32, 100, 101, 110, 121, 40, 53, 41, 32, 102,
            105, 108, 101, 45, 114, 101, 97, 100, 45, 109, 101, 116, 97, 100, 97, 116, 97, 32, 47,
            86, 111, 108, 117, 109, 101, 115, 47, 86, 77, 119, 97, 114, 101, 32, 83, 104, 97, 114,
            101, 100, 32, 70, 111, 108, 100, 101, 114, 115, 10, 86, 105, 111, 108, 97, 116, 105,
            111, 110, 58, 32, 32, 32, 32, 32, 32, 32, 83, 121, 115, 116, 101, 109, 32, 80, 111,
            108, 105, 99, 121, 58, 32, 100, 101, 110, 121, 40, 53, 41, 32, 102, 105, 108, 101, 45,
            114, 101, 97, 100, 45, 109, 101, 116, 97, 100, 97, 116, 97, 32, 47, 86, 111, 108, 117,
            109, 101, 115, 47, 86, 77, 119, 97, 114, 101, 32, 83, 104, 97, 114, 101, 100, 32, 70,
            111, 108, 100, 101, 114, 115, 32, 10, 80, 114, 111, 99, 101, 115, 115, 58, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116, 105,
            111, 110, 100, 32, 91, 54, 51, 93, 10, 80, 97, 116, 104, 58, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 47, 117, 115, 114, 47, 108, 105, 98, 101, 120, 101, 99, 47,
            100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116, 105, 111, 110, 100, 10, 76,
            111, 97, 100, 32, 65, 100, 100, 114, 101, 115, 115, 58, 32, 32, 32, 32, 48, 120, 49,
            48, 55, 98, 57, 52, 48, 48, 48, 10, 73, 100, 101, 110, 116, 105, 102, 105, 101, 114,
            58, 32, 32, 32, 32, 32, 32, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116,
            105, 111, 110, 100, 10, 86, 101, 114, 115, 105, 111, 110, 58, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 63, 63, 63, 32, 40, 63, 63, 63, 41, 10, 67, 111, 100, 101, 32, 84, 121,
            112, 101, 58, 32, 32, 32, 32, 32, 32, 32, 120, 56, 54, 95, 54, 52, 32, 40, 78, 97, 116,
            105, 118, 101, 41, 10, 80, 97, 114, 101, 110, 116, 32, 80, 114, 111, 99, 101, 115, 115,
            58, 32, 32, 108, 97, 117, 110, 99, 104, 100, 32, 91, 49, 93, 10, 82, 101, 115, 112,
            111, 110, 115, 105, 98, 108, 101, 58, 32, 32, 32, 32, 32, 47, 117, 115, 114, 47, 108,
            105, 98, 101, 120, 101, 99, 47, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97,
            116, 105, 111, 110, 100, 32, 91, 54, 51, 93, 10, 85, 115, 101, 114, 32, 73, 68, 58, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 48, 10, 10, 68, 97, 116, 101, 47, 84, 105, 109, 101,
            58, 32, 32, 32, 32, 32, 32, 32, 50, 48, 50, 49, 45, 48, 56, 45, 49, 55, 32, 49, 57, 58,
            53, 56, 58, 52, 57, 46, 57, 53, 53, 32, 69, 68, 84, 10, 79, 83, 32, 86, 101, 114, 115,
            105, 111, 110, 58, 32, 32, 32, 32, 32, 32, 77, 97, 99, 32, 79, 83, 32, 88, 32, 49, 48,
            46, 49, 51, 46, 54, 32, 40, 49, 55, 71, 54, 54, 41, 10, 82, 101, 112, 111, 114, 116,
            32, 86, 101, 114, 115, 105, 111, 110, 58, 32, 32, 56, 10, 10, 10, 77, 101, 116, 97, 68,
            97, 116, 97, 58, 32, 123, 34, 101, 114, 114, 110, 111, 34, 58, 53, 44, 34, 112, 114,
            111, 102, 105, 108, 101, 45, 102, 108, 97, 103, 115, 34, 58, 48, 44, 34, 116, 97, 114,
            103, 101, 116, 34, 58, 34, 92, 47, 86, 111, 108, 117, 109, 101, 115, 92, 47, 86, 77,
            119, 97, 114, 101, 32, 83, 104, 97, 114, 101, 100, 32, 70, 111, 108, 100, 101, 114,
            115, 34, 44, 34, 112, 114, 111, 99, 101, 115, 115, 34, 58, 34, 100, 105, 115, 107, 97,
            114, 98, 105, 116, 114, 97, 116, 105, 111, 110, 100, 34, 44, 34, 112, 97, 116, 104, 34,
            58, 34, 92, 47, 86, 111, 108, 117, 109, 101, 115, 92, 47, 86, 77, 119, 97, 114, 101,
            32, 83, 104, 97, 114, 101, 100, 32, 70, 111, 108, 100, 101, 114, 115, 34, 44, 34, 112,
            114, 105, 109, 97, 114, 121, 45, 102, 105, 108, 116, 101, 114, 34, 58, 34, 112, 97,
            116, 104, 34, 44, 34, 110, 111, 114, 109, 97, 108, 105, 122, 101, 100, 95, 116, 97,
            114, 103, 101, 116, 34, 58, 91, 34, 86, 111, 108, 117, 109, 101, 115, 34, 44, 34, 86,
            77, 119, 97, 114, 101, 32, 83, 104, 97, 114, 101, 100, 32, 70, 111, 108, 100, 101, 114,
            115, 34, 93, 44, 34, 112, 108, 97, 116, 102, 111, 114, 109, 45, 112, 111, 108, 105, 99,
            121, 34, 58, 116, 114, 117, 101, 44, 34, 115, 117, 109, 109, 97, 114, 121, 34, 58, 34,
            100, 101, 110, 121, 40, 53, 41, 32, 102, 105, 108, 101, 45, 114, 101, 97, 100, 45, 109,
            101, 116, 97, 100, 97, 116, 97, 32, 92, 47, 86, 111, 108, 117, 109, 101, 115, 92, 47,
            86, 77, 119, 97, 114, 101, 32, 83, 104, 97, 114, 101, 100, 32, 70, 111, 108, 100, 101,
            114, 115, 34, 44, 34, 112, 108, 97, 116, 102, 111, 114, 109, 95, 98, 105, 110, 97, 114,
            121, 34, 58, 34, 121, 101, 115, 34, 44, 34, 111, 112, 101, 114, 97, 116, 105, 111, 110,
            34, 58, 34, 102, 105, 108, 101, 45, 114, 101, 97, 100, 45, 109, 101, 116, 97, 100, 97,
            116, 97, 34, 44, 34, 112, 114, 105, 109, 97, 114, 121, 45, 102, 105, 108, 116, 101,
            114, 45, 118, 97, 108, 117, 101, 34, 58, 34, 92, 47, 86, 111, 108, 117, 109, 101, 115,
            92, 47, 86, 77, 119, 97, 114, 101, 32, 83, 104, 97, 114, 101, 100, 32, 70, 111, 108,
            100, 101, 114, 115, 34, 44, 34, 117, 105, 100, 34, 58, 48, 44, 34, 104, 97, 114, 100,
            119, 97, 114, 101, 34, 58, 34, 77, 97, 99, 34, 44, 34, 102, 108, 97, 103, 115, 34, 58,
            53, 44, 34, 112, 114, 111, 99, 101, 115, 115, 45, 112, 97, 116, 104, 34, 58, 34, 92,
            47, 117, 115, 114, 92, 47, 108, 105, 98, 101, 120, 101, 99, 92, 47, 100, 105, 115, 107,
            97, 114, 98, 105, 116, 114, 97, 116, 105, 111, 110, 100, 34, 44, 34, 112, 105, 100, 34,
            58, 54, 51, 44, 34, 112, 114, 111, 102, 105, 108, 101, 34, 58, 34, 112, 108, 97, 116,
            102, 111, 114, 109, 34, 44, 34, 98, 117, 105, 108, 100, 34, 58, 34, 77, 97, 99, 32, 79,
            83, 32, 88, 32, 49, 48, 46, 49, 51, 46, 54, 32, 40, 49, 55, 71, 54, 54, 41, 34, 44, 34,
            115, 105, 103, 110, 105, 110, 103, 45, 105, 100, 34, 58, 34, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116, 105, 111,
            110, 100, 34, 44, 34, 97, 99, 116, 105, 111, 110, 34, 58, 34, 100, 101, 110, 121, 34,
            44, 34, 112, 108, 97, 116, 102, 111, 114, 109, 45, 98, 105, 110, 97, 114, 121, 34, 58,
            116, 114, 117, 101, 125, 10, 10, 84, 104, 114, 101, 97, 100, 32, 48, 32, 40, 105, 100,
            58, 32, 53, 52, 50, 41, 58, 10, 48, 32, 32, 32, 108, 105, 98, 115, 121, 115, 116, 101,
            109, 95, 107, 101, 114, 110, 101, 108, 46, 100, 121, 108, 105, 98, 32, 32, 32, 32, 32,
            32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102, 102, 54, 57, 51, 98, 98, 50, 51,
            54, 32, 95, 95, 103, 101, 116, 97, 116, 116, 114, 108, 105, 115, 116, 32, 43, 32, 49,
            48, 10, 49, 32, 32, 32, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116, 105,
            111, 110, 100, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48,
            48, 48, 48, 48, 48, 48, 49, 48, 55, 98, 57, 55, 100, 52, 54, 10, 50, 32, 32, 32, 100,
            105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116, 105, 111, 110, 100, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 48, 48, 48, 49, 48,
            55, 98, 97, 51, 49, 54, 48, 10, 51, 32, 32, 32, 67, 111, 114, 101, 70, 111, 117, 110,
            100, 97, 116, 105, 111, 110, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102, 102, 52, 49, 52, 51, 98, 53, 54, 98,
            32, 95, 95, 67, 70, 77, 97, 99, 104, 80, 111, 114, 116, 80, 101, 114, 102, 111, 114,
            109, 32, 43, 32, 51, 52, 55, 10, 52, 32, 32, 32, 67, 111, 114, 101, 70, 111, 117, 110,
            100, 97, 116, 105, 111, 110, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102, 102, 52, 49, 52, 51, 98, 51, 102, 57,
            32, 95, 95, 67, 70, 82, 85, 78, 76, 79, 79, 80, 95, 73, 83, 95, 67, 65, 76, 76, 73, 78,
            71, 95, 79, 85, 84, 95, 84, 79, 95, 65, 95, 83, 79, 85, 82, 67, 69, 49, 95, 80, 69, 82,
            70, 79, 82, 77, 95, 70, 85, 78, 67, 84, 73, 79, 78, 95, 95, 32, 43, 32, 52, 49, 10, 53,
            32, 32, 32, 67, 111, 114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55,
            102, 102, 102, 52, 49, 52, 51, 98, 51, 52, 53, 32, 95, 95, 67, 70, 82, 117, 110, 76,
            111, 111, 112, 68, 111, 83, 111, 117, 114, 99, 101, 49, 32, 43, 32, 53, 51, 51, 10, 54,
            32, 32, 32, 67, 111, 114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55,
            102, 102, 102, 52, 49, 52, 51, 50, 102, 48, 48, 32, 95, 95, 67, 70, 82, 117, 110, 76,
            111, 111, 112, 82, 117, 110, 32, 43, 32, 50, 56, 52, 56, 10, 55, 32, 32, 32, 67, 111,
            114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 32, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102, 102, 52,
            49, 52, 51, 50, 49, 53, 51, 32, 67, 70, 82, 117, 110, 76, 111, 111, 112, 82, 117, 110,
            83, 112, 101, 99, 105, 102, 105, 99, 32, 43, 32, 52, 56, 51, 10, 56, 32, 32, 32, 67,
            111, 114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 32, 32, 32, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102, 102,
            52, 49, 52, 55, 48, 98, 101, 51, 32, 67, 70, 82, 117, 110, 76, 111, 111, 112, 82, 117,
            110, 32, 43, 32, 57, 57, 10, 57, 32, 32, 32, 100, 105, 115, 107, 97, 114, 98, 105, 116,
            114, 97, 116, 105, 111, 110, 100, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
            32, 9, 48, 120, 48, 48, 48, 48, 48, 48, 48, 49, 48, 55, 98, 57, 97, 99, 98, 54, 10, 49,
            48, 32, 32, 108, 105, 98, 100, 121, 108, 100, 46, 100, 121, 108, 105, 98, 32, 32, 32,
            32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55,
            102, 102, 102, 54, 57, 50, 54, 98, 48, 49, 53, 32, 115, 116, 97, 114, 116, 32, 43, 32,
            49, 10, 49, 49, 32, 32, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116, 105,
            111, 110, 100, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 10, 10, 84, 104, 114, 101,
            97, 100, 32, 49, 32, 40, 105, 100, 58, 32, 54, 56, 55, 41, 58, 10, 48, 32, 32, 32, 108,
            105, 98, 115, 121, 115, 116, 101, 109, 95, 107, 101, 114, 110, 101, 108, 46, 100, 121,
            108, 105, 98, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102,
            102, 54, 57, 51, 98, 99, 50, 56, 97, 32, 95, 95, 119, 111, 114, 107, 113, 95, 107, 101,
            114, 110, 114, 101, 116, 117, 114, 110, 32, 43, 32, 49, 48, 10, 49, 32, 32, 32, 108,
            105, 98, 115, 121, 115, 116, 101, 109, 95, 112, 116, 104, 114, 101, 97, 100, 46, 100,
            121, 108, 105, 98, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102,
            102, 102, 54, 57, 53, 56, 50, 98, 101, 57, 32, 115, 116, 97, 114, 116, 95, 119, 113,
            116, 104, 114, 101, 97, 100, 32, 43, 32, 49, 51, 10, 10, 84, 104, 114, 101, 97, 100,
            32, 50, 32, 40, 105, 100, 58, 32, 49, 53, 52, 49, 41, 58, 10, 48, 32, 32, 32, 108, 105,
            98, 115, 121, 115, 116, 101, 109, 95, 107, 101, 114, 110, 101, 108, 46, 100, 121, 108,
            105, 98, 32, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102, 102,
            54, 57, 51, 98, 99, 50, 56, 97, 32, 95, 95, 119, 111, 114, 107, 113, 95, 107, 101, 114,
            110, 114, 101, 116, 117, 114, 110, 32, 43, 32, 49, 48, 10, 49, 32, 32, 32, 108, 105,
            98, 115, 121, 115, 116, 101, 109, 95, 112, 116, 104, 114, 101, 97, 100, 46, 100, 121,
            108, 105, 98, 32, 32, 32, 32, 32, 32, 32, 9, 48, 120, 48, 48, 48, 48, 55, 102, 102,
            102, 54, 57, 53, 56, 50, 98, 101, 57, 32, 115, 116, 97, 114, 116, 95, 119, 113, 116,
            104, 114, 101, 97, 100, 32, 43, 32, 49, 51, 10, 10, 66, 105, 110, 97, 114, 121, 32, 73,
            109, 97, 103, 101, 115, 58, 10, 32, 32, 32, 32, 32, 32, 32, 48, 120, 49, 48, 55, 98,
            57, 52, 48, 48, 48, 32, 45, 32, 32, 32, 32, 32, 32, 32, 32, 48, 120, 49, 48, 55, 98,
            97, 98, 102, 102, 102, 32, 32, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114, 97, 116,
            105, 111, 110, 100, 32, 40, 50, 57, 55, 46, 55, 48, 46, 49, 41, 32, 60, 49, 57, 48,
            101, 102, 55, 51, 102, 45, 99, 50, 48, 52, 45, 51, 49, 98, 99, 45, 98, 100, 53, 49, 45,
            101, 49, 98, 101, 52, 100, 101, 97, 102, 57, 48, 97, 62, 32, 47, 117, 115, 114, 47,
            108, 105, 98, 101, 120, 101, 99, 47, 100, 105, 115, 107, 97, 114, 98, 105, 116, 114,
            97, 116, 105, 111, 110, 100, 10, 32, 32, 32, 32, 48, 120, 55, 102, 102, 102, 52, 49,
            51, 97, 100, 48, 48, 48, 32, 45, 32, 32, 32, 32, 32, 48, 120, 55, 102, 102, 102, 52,
            49, 56, 52, 101, 102, 101, 102, 32, 32, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46,
            67, 111, 114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 32, 40, 54, 46, 57,
            32, 45, 32, 49, 52, 53, 52, 46, 57, 48, 41, 32, 60, 101, 53, 100, 53, 57, 52, 98, 102,
            45, 57, 49, 52, 50, 45, 51, 51, 50, 53, 45, 97, 54, 50, 100, 45, 99, 102, 52, 97, 97,
            102, 52, 55, 50, 54, 52, 50, 62, 32, 47, 83, 121, 115, 116, 101, 109, 47, 76, 105, 98,
            114, 97, 114, 121, 47, 70, 114, 97, 109, 101, 119, 111, 114, 107, 115, 47, 67, 111,
            114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 46, 102, 114, 97, 109, 101,
            119, 111, 114, 107, 47, 86, 101, 114, 115, 105, 111, 110, 115, 47, 65, 47, 67, 111,
            114, 101, 70, 111, 117, 110, 100, 97, 116, 105, 111, 110, 10, 32, 32, 32, 32, 48, 120,
            55, 102, 102, 102, 54, 57, 50, 54, 97, 48, 48, 48, 32, 45, 32, 32, 32, 32, 32, 48, 120,
            55, 102, 102, 102, 54, 57, 50, 56, 55, 102, 102, 55, 32, 32, 108, 105, 98, 100, 121,
            108, 100, 46, 100, 121, 108, 105, 98, 32, 40, 53, 53, 49, 46, 52, 41, 32, 60, 56, 49,
            98, 102, 51, 97, 56, 50, 45, 53, 55, 49, 57, 45, 51, 98, 53, 52, 45, 97, 98, 97, 57,
            45, 55, 54, 99, 56, 50, 100, 57, 51, 50, 99, 97, 99, 62, 32, 47, 117, 115, 114, 47,
            108, 105, 98, 47, 115, 121, 115, 116, 101, 109, 47, 108, 105, 98, 100, 121, 108, 100,
            46, 100, 121, 108, 105, 98, 10, 32, 32, 32, 32, 48, 120, 55, 102, 102, 102, 54, 57, 51,
            57, 102, 48, 48, 48, 32, 45, 32, 32, 32, 32, 32, 48, 120, 55, 102, 102, 102, 54, 57,
            51, 99, 53, 102, 102, 55, 32, 32, 108, 105, 98, 115, 121, 115, 116, 101, 109, 95, 107,
            101, 114, 110, 101, 108, 46, 100, 121, 108, 105, 98, 32, 40, 52, 53, 55, 48, 46, 55,
            49, 46, 50, 41, 32, 60, 102, 50, 50, 98, 56, 100, 55, 51, 45, 54, 57, 100, 56, 45, 51,
            54, 100, 55, 45, 98, 102, 54, 54, 45, 55, 102, 57, 97, 99, 55, 48, 99, 48, 56, 99, 50,
            62, 32, 47, 117, 115, 114, 47, 108, 105, 98, 47, 115, 121, 115, 116, 101, 109, 47, 108,
            105, 98, 115, 121, 115, 116, 101, 109, 95, 107, 101, 114, 110, 101, 108, 46, 100, 121,
            108, 105, 98, 10, 32, 32, 32, 32, 48, 120, 55, 102, 102, 102, 54, 57, 53, 56, 48, 48,
            48, 48, 32, 45, 32, 32, 32, 32, 32, 48, 120, 55, 102, 102, 102, 54, 57, 53, 56, 98,
            102, 102, 102, 32, 32, 108, 105, 98, 115, 121, 115, 116, 101, 109, 95, 112, 116, 104,
            114, 101, 97, 100, 46, 100, 121, 108, 105, 98, 32, 40, 51, 48, 49, 46, 53, 48, 46, 49,
            41, 32, 60, 48, 101, 53, 49, 99, 99, 98, 97, 45, 57, 49, 102, 50, 45, 51, 52, 101, 49,
            45, 98, 102, 50, 97, 45, 102, 101, 101, 102, 100, 51, 100, 51, 50, 49, 101, 52, 62, 32,
            47, 117, 115, 114, 47, 108, 105, 98, 47, 115, 121, 115, 116, 101, 109, 47, 108, 105,
            98, 115, 121, 115, 116, 101, 109, 95, 112, 116, 104, 114, 101, 97, 100, 46, 100, 121,
            108, 105, 98, 10, 10, 10, 0,
        ];
        let (_, oversize_results) = Oversize::parse_oversize(&test_data).unwrap();
        assert_eq!(oversize_results.chunk_tag, 0x6002);
        assert_eq!(oversize_results.chunk_subtag, 0);
        assert_eq!(oversize_results.chunk_data_size, 3354);
        assert_eq!(oversize_results.first_proc_id, 192);
        assert_eq!(oversize_results.second_proc_id, 193);
        assert_eq!(oversize_results.ttl, 14);
        assert_eq!(oversize_results.unknown_reserved, [0, 0, 0]);
        assert_eq!(oversize_results.continuous_time, 12381160463);
        assert_eq!(oversize_results.data_ref_index, 1);
        assert_eq!(oversize_results.public_data_size, 3322);
        assert_eq!(oversize_results.private_data_size, 0);
        assert_eq!(oversize_results.message_items.item_info[0].message_strings,  "Sandbox: diskarbitrationd(63) System Policy: deny(5) file-read-metadata /Volumes/VMware Shared Folders\nViolation:       System Policy: deny(5) file-read-metadata /Volumes/VMware Shared Folders \nProcess:         diskarbitrationd [63]\nPath:            /usr/libexec/diskarbitrationd\nLoad Address:    0x107b94000\nIdentifier:      diskarbitrationd\nVersion:         ??? (???)\nCode Type:       x86_64 (Native)\nParent Process:  launchd [1]\nResponsible:     /usr/libexec/diskarbitrationd [63]\nUser ID:         0\n\nDate/Time:       2021-08-17 19:58:49.955 EDT\nOS Version:      Mac OS X 10.13.6 (17G66)\nReport Version:  8\n\n\nMetaData: {\"errno\":5,\"profile-flags\":0,\"target\":\"\\/Volumes\\/VMware Shared Folders\",\"process\":\"diskarbitrationd\",\"path\":\"\\/Volumes\\/VMware Shared Folders\",\"primary-filter\":\"path\",\"normalized_target\":[\"Volumes\",\"VMware Shared Folders\"],\"platform-policy\":true,\"summary\":\"deny(5) file-read-metadata \\/Volumes\\/VMware Shared Folders\",\"platform_binary\":\"yes\",\"operation\":\"file-read-metadata\",\"primary-filter-value\":\"\\/Volumes\\/VMware Shared Folders\",\"uid\":0,\"hardware\":\"Mac\",\"flags\":5,\"process-path\":\"\\/usr\\/libexec\\/diskarbitrationd\",\"pid\":63,\"profile\":\"platform\",\"build\":\"Mac OS X 10.13.6 (17G66)\",\"signing-id\":\"com.apple.diskarbitrationd\",\"action\":\"deny\",\"platform-binary\":true}\n\nThread 0 (id: 542):\n0   libsystem_kernel.dylib        \t0x00007fff693bb236 __getattrlist + 10\n1   diskarbitrationd              \t0x0000000107b97d46\n2   diskarbitrationd              \t0x0000000107ba3160\n3   CoreFoundation                \t0x00007fff4143b56b __CFMachPortPerform + 347\n4   CoreFoundation                \t0x00007fff4143b3f9 __CFRUNLOOP_IS_CALLING_OUT_TO_A_SOURCE1_PERFORM_FUNCTION__ + 41\n5   CoreFoundation                \t0x00007fff4143b345 __CFRunLoopDoSource1 + 533\n6   CoreFoundation                \t0x00007fff41432f00 __CFRunLoopRun + 2848\n7   CoreFoundation                \t0x00007fff41432153 CFRunLoopRunSpecific + 483\n8   CoreFoundation                \t0x00007fff41470be3 CFRunLoopRun + 99\n9   diskarbitrationd              \t0x0000000107b9acb6\n10  libdyld.dylib                 \t0x00007fff6926b015 start + 1\n11  diskarbitrationd              \t0x0000000000000001\n\nThread 1 (id: 687):\n0   libsystem_kernel.dylib        \t0x00007fff693bc28a __workq_kernreturn + 10\n1   libsystem_pthread.dylib       \t0x00007fff69582be9 start_wqthread + 13\n\nThread 2 (id: 1541):\n0   libsystem_kernel.dylib        \t0x00007fff693bc28a __workq_kernreturn + 10\n1   libsystem_pthread.dylib       \t0x00007fff69582be9 start_wqthread + 13\n\nBinary Images:\n       0x107b94000 -        0x107babfff  diskarbitrationd (297.70.1) <190ef73f-c204-31bc-bd51-e1be4deaf90a> /usr/libexec/diskarbitrationd\n    0x7fff413ad000 -     0x7fff4184efef  com.apple.CoreFoundation (6.9 - 1454.90) <e5d594bf-9142-3325-a62d-cf4aaf472642> /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation\n    0x7fff6926a000 -     0x7fff69287ff7  libdyld.dylib (551.4) <81bf3a82-5719-3b54-aba9-76c82d932cac> /usr/lib/system/libdyld.dylib\n    0x7fff6939f000 -     0x7fff693c5ff7  libsystem_kernel.dylib (4570.71.2) <f22b8d73-69d8-36d7-bf66-7f9ac70c08c2> /usr/lib/system/libsystem_kernel.dylib\n    0x7fff69580000 -     0x7fff6958bfff  libsystem_pthread.dylib (301.50.1) <0e51ccba-91f2-34e1-bf2a-feefd3d321e4> /usr/lib/system/libsystem_pthread.dylib\n\n\n");
    }

    #[test]
    fn test_parse_oversize_private_strings() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Oversize Tests/oversize_private_strings.raw");
        let buffer = fs::read(test_path).unwrap();

        let (_, oversize_results) = Oversize::parse_oversize(&buffer).unwrap();
        assert_eq!(oversize_results.chunk_tag, 0x6002);
        assert_eq!(oversize_results.chunk_subtag, 0);
        assert_eq!(oversize_results.chunk_data_size, 2963);
        assert_eq!(oversize_results.first_proc_id, 86);
        assert_eq!(oversize_results.second_proc_id, 302);
        assert_eq!(oversize_results.ttl, 0);
        assert_eq!(oversize_results.unknown_reserved, [0, 0, 0]);
        assert_eq!(oversize_results.continuous_time, 96693842097);
        assert_eq!(oversize_results.data_ref_index, 1);
        assert_eq!(oversize_results.public_data_size, 8);
        assert_eq!(oversize_results.private_data_size, 2923);
        assert_eq!(
            oversize_results.message_items.item_info[0].message_strings,
            "updated queuedEvents[4]=(\n    \"FudEvent - Client:(null) Type:114 Filter:com.apple.MobileAccessoryUpdater.EA.app.multiasset.A2015.59 Data:<dictionary: 0x7fdac460fcd0> { count = 5, transaction: 0, voucher = 0x7fdac460e7c0, contents =\\n\\t\\\"Command\\\" => <uint64: 0x2a6f1a5c3cef6b9d>: 114\\n\\t\\\"PluginIdentifier\\\" => <string: 0x7fdac58122c0> { length = 49, contents = \\\"com.apple.MobileAccessoryUpdater.EAUpdaterService\\\" }\\n\\t\\\"_State\\\" => <uint64: 0x2a6f1a5c3ce84b9d>: 0\\n\\t\\\"XPCEventName\\\" => <string: 0x7fdac4507f90> { length = 59, contents = \\\"com.apple.MobileAccessoryUpdater.EA.app.multiasset.A2015.59\\\" }\\n\\t\\\"Notification\\\" => <string: 0x7fdac450a7c0> { length = 44, contents = \\\"com.apple.corespeech.voicetriggerassetchange\\\" }\\n} Options:{\\n}\",\n    \"FudEvent - Client:(null) Type:114 Filter:com.apple.MobileAccessoryUpdater.EA.app.multiasset.A1881.58 Data:<dictionary: 0x7fdac460fdc0> { count = 5, transaction: 0, voucher = 0x7fdac460e7c0, contents =\\n\\t\\\"Command\\\" => <uint64: 0x2a6f1a5c3cef6b9d>: 114\\n\\t\\\"PluginIdentifier\\\" => <string: 0x7fdac5813c40> { length = 49, contents = \\\"com.apple.MobileAccessoryUpdater.EAUpdaterService\\\" }\\n\\t\\\"_State\\\" => <uint64: 0x2a6f1a5c3ce84b9d>: 0\\n\\t\\\"XPCEventName\\\" => <string: 0x7fdac450b380> { length = 59, contents = \\\"com.apple.MobileAccessoryUpdater.EA.app.multiasset.A1881.58\\\" }\\n\\t\\\"Notification\\\" => <string: 0x7fdac4504780> { length = 44, contents = \\\"com.apple.corespeech.voicetriggerassetchange\\\" }\\n} Options:{\\n}\",\n    \"FudEvent - Client:(null) Type:114 Filter:com.apple.MobileAccessoryUpdater.EA.app.multiasset.A2048.57 Data:<dictionary: 0x7fdac460feb0> { count = 5, transaction: 0, voucher = 0x7fdac460e7c0, contents =\\n\\t\\\"Command\\\" => <uint64: 0x2a6f1a5c3cef6b9d>: 114\\n\\t\\\"PluginIdentifier\\\" => <string: 0x7fdac5805eb0> { length = 49, contents = \\\"com.apple.MobileAccessoryUpdater.EAUpdaterService\\\" }\\n\\t\\\"_State\\\" => <uint64: 0x2a6f1a5c3ce84b9d>: 0\\n\\t\\\"XPCEventName\\\" => <string: 0x7fdac4516980> { length = 59, contents = \\\"com.apple.MobileAccessoryUpdater.EA.app.multiasset.A2048.57\\\" }\\n\\t\\\"Notification\\\" => <string: 0x7fdac451eed0> { length = 44, contents = \\\"com.apple.corespeech.voicetriggerassetchange\\\" }\\n} Options:{\\n}\",\n    \"FudEvent - Client:(null) Type:114 Filter:com.apple.MobileAccessoryUpdater.EA.app.multiasset.A2032.61 Data:<dictionary: 0x7fdac46050c0> { count = 5, transaction: 0, voucher = 0x7fdac460e7c0, contents =\\n\\t\\\"Command\\\" => <uint64: 0x2a6f1a5c3cef6b9d>: 114\\n\\t\\\"PluginIdentifier\\\" => <string: 0x7fdac58064e0> { length = 49, contents = \\\"com.apple.MobileAccessoryUpdater.EAUpdaterService\\\" }\\n\\t\\\"_State\\\" => <uint64: 0x2a6f1a5c3ce84b9d>: 0\\n\\t\\\"XPCEventName\\\" => <string: 0x7fdac453ba80> { length = 59, contents = \\\"com.apple.MobileAccessoryUpdater.EA.app.multiasset.A2032.61\\\" }\\n\\t\\\"Notification\\\" => <string: 0x7fdac450d430> { length = 44, contents = \\\"com.apple.corespeech.voicetriggerassetchange\\\" }\\n} Options:{\\n}\"\n)"
        );
    }

    #[test]
    fn test_get_oversize_strings_big_sur() {
        let data = vec![Oversize {
            chunk_tag: 24578,
            chunk_subtag: 0,
            chunk_data_size: 1124,
            first_proc_id: 96,
            second_proc_id: 245,
            ttl: 0,
            unknown_reserved: Vec::new(),
            continuous_time: 5609252490,
            data_ref_index: 1,
            public_data_size: 1092,
            private_data_size: 0,
            message_items: FirehoseItemData {
                item_info: vec![
                    FirehoseItemInfo {
                        message_strings: String::from("system kext collection"),
                        item_type: 34,
                        item_size: 0,
                    },
                    FirehoseItemInfo {
                        message_strings: String::from(
                            "/System/Library/KernelCollections/SystemKernelExtensions.kc",
                        ),
                        item_type: 34,
                        item_size: 0,
                    },
                ],
                backtrace_strings: Vec::new(),
            },
        }];
        let data_ref = 1;
        let first_proc_id = 96;
        let second_proc_id = 245;
        let results =
            Oversize::get_oversize_strings(data_ref, first_proc_id, second_proc_id, &data);
        assert_eq!(results[0].message_strings, "system kext collection");
        assert_eq!(
            results[1].message_strings,
            "/System/Library/KernelCollections/SystemKernelExtensions.kc"
        );
    }
}
