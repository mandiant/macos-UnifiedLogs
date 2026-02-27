// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::{clean_uuid, extract_string};
use crate::{RcString, rc_string};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u64};
use std::mem::size_of;
use uuid::Uuid;

pub type SimpleDumpStr<'a> = SimpleDump<&'a str>;
pub type SimpleDumpOwned = SimpleDump<RcString>;

/*
   Introduced in macOS Monterey (12).  Appears to be a "simpler" version of Statedump?
   So far appears to just contain a single string
*/
#[derive(Debug, Clone, Default)]
pub struct SimpleDump<S>
where
    S: Default + ToString,
{
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
    pub sender_uuid: Uuid,
    pub dsc_uuid: Uuid,
    pub unknown_number_message_strings: u32,
    pub unknown_size_subsystem_string: u32,
    pub unknown_size_message_string: u32,
    pub subsystem: S,
    pub message_string: S,
}

impl<'a> SimpleDumpStr<'a> {
    pub fn into_owned(self) -> SimpleDumpOwned {
        SimpleDumpOwned {
            chunk_tag: self.chunk_tag,
            chunk_subtag: self.chunk_subtag,
            chunk_data_size: self.chunk_data_size,
            first_proc_id: self.first_proc_id,
            second_proc_id: self.second_proc_id,
            continous_time: self.continous_time,
            thread_id: self.thread_id,
            unknown_offset: self.unknown_offset,
            unknown_ttl: self.unknown_ttl,
            unknown_type: self.unknown_type,
            sender_uuid: self.sender_uuid,
            dsc_uuid: self.dsc_uuid,
            unknown_number_message_strings: self.unknown_number_message_strings,
            unknown_size_subsystem_string: self.unknown_size_subsystem_string,
            unknown_size_message_string: self.unknown_size_message_string,
            subsystem: rc_string!(self.subsystem),
            message_string: rc_string!(self.message_string),
        }
    }
}

impl<'a> SimpleDumpStr<'a> {
    /// Parse Simpledump log entry.  Introduced in macOS Monterey (12)
    pub fn parse_simpledump(data: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, chunk_tag) = le_u32(data)?;
        let (input, chunk_subtag) = le_u32(input)?;
        let (input, chunk_data_size) = le_u64(input)?;
        let (input, first_proc_id) = le_u64(input)?;
        let (input, second_proc_id) = le_u64(input)?;

        let (input, continous_time) = le_u64(input)?;
        let (input, thread_id) = le_u64(input)?;
        let (input, unknown_offset) = le_u32(input)?;
        let (input, unknown_ttl) = le_u16(input)?;
        let (input, unknown_type) = le_u16(input)?;
        let (input, sender_uuid_raw) = take(size_of::<u128>())(input)?;
        let (input, dsc_uuid_raw) = take(size_of::<u128>())(input)?;
        let (input, unknown_number_message_strings) = le_u32(input)?;
        let (input, unknown_size_subsystem_string) = le_u32(input)?;
        let (input, unknown_size_message_string) = le_u32(input)?;

        let sender_uuid = clean_uuid(&format!("{sender_uuid_raw:02X?}"));
        let dsc_uuid = clean_uuid(&format!("{dsc_uuid_raw:02X?}"));

        let (input, subsystem_data) = take(unknown_size_subsystem_string)(input)?;
        let (input, message_data) = take(unknown_size_message_string)(input)?;

        let mut subsystem: &str = Default::default();
        if !subsystem_data.is_empty() {
            let (_, s) = extract_string(subsystem_data)?;
            subsystem = s;
        }
        let mut message_string: &str = Default::default();
        if !message_data.is_empty() {
            let (_, s) = extract_string(message_data)?;
            message_string = s;
        }

        Ok((
            input,
            SimpleDump {
                chunk_tag,
                chunk_subtag,
                chunk_data_size,
                first_proc_id,
                second_proc_id,
                continous_time,
                thread_id,
                unknown_offset,
                unknown_ttl,
                unknown_type,
                sender_uuid,
                dsc_uuid,
                unknown_number_message_strings,
                unknown_size_subsystem_string,
                unknown_size_message_string,
                subsystem,
                message_string,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

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
        assert_eq!(
            results.sender_uuid,
            Uuid::parse_str("0DCF3E8B4923323EB3E5547307CF0EAC").unwrap()
        );
        assert_eq!(
            results.dsc_uuid,
            Uuid::parse_str("3D05845F3F65358F9EBF2236E772AC01").unwrap()
        );
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
