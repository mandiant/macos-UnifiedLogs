// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::chunks::firehose::activity::FirehoseActivity;
use crate::chunks::firehose::flags::FirehoseFormatters;
use crate::chunks::firehose::loss::FirehoseLoss;
use crate::chunks::firehose::nonactivity::FirehoseNonActivity;
use crate::chunks::firehose::signpost::FirehoseSignpost;
use crate::chunks::firehose::trace::FirehoseTrace;
use crate::util::{encode_standard, extract_string_size, padding_size, padding_size_four};
use log::{debug, error, warn};
use nom::bytes::complete::take_while;
use nom::number::complete::{be_u128, le_i16, le_i32, le_i64, le_i8};
use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
};
use serde::Serialize;
use std::mem::size_of;

#[derive(Debug, Clone)]
pub struct FirehosePreamble {
    pub chunk_tag: u32,
    pub chunk_sub_tag: u32,
    pub chunk_data_size: u64,
    pub first_number_proc_id: u64,
    pub second_number_proc_id: u32,
    pub ttl: u8,
    pub collapsed: u8,
    pub unknown: Vec<u8>,                 // reserved?
    pub public_data_size: u16, // Size includes the size itself and the 8 bytes below and the public data
    pub private_data_virtual_offset: u16, // value is 0x1000 (4096) if there is NO private data
    pub unkonwn2: u16,
    pub unknown3: u16,
    pub base_continous_time: u64,
    pub public_data: Vec<Firehose>,
}

#[derive(Debug, Clone)]
pub struct Firehose {
    pub unknown_log_activity_type: u8, // 0x2 is Activity, 0x4 is non-activity, 0x6 is signpost, 0x3 trace
    pub unknown_log_type: u8, // Unkonwn but possibly log type (Info/Activity, Debug, Error, Fault, Signpost, System, Default)
    pub flags: u16,
    pub format_string_location: u32,
    pub thread_id: u64,
    pub continous_time_delta: u32,
    pub continous_time_delta_upper: u16,
    pub data_size: u16,
    pub firehose_activity: FirehoseActivity,
    pub firehose_non_activity: FirehoseNonActivity,
    pub firehose_loss: FirehoseLoss,
    pub firehose_signpost: FirehoseSignpost,
    pub firehose_trace: FirehoseTrace,
    pub unknown_item: u8,
    pub number_items: u8,
    pub message: FirehoseItemData, // Log values extracted
}

#[derive(Debug)]
pub struct FirehoseItemType {
    pub item_type: u8,
    item_size: u8,
    offset: u16,
    message_string_size: u16,
    pub message_strings: String,
}

#[derive(Debug, Clone)]
pub struct FirehoseItemData {
    pub item_info: Vec<FirehoseItemInfo>,
    pub backtrace_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirehoseItemInfo {
    pub message_strings: String, // The message entry.
    pub item_type: u8,           // Type of item: strings, numbers, objects, precision
    pub item_size: u16,          // Size of message in bytes
}

impl FirehosePreamble {
    /// Parse the start of the Firehose data
    pub fn parse_firehose_preamble(
        firehose_input_data: &[u8],
    ) -> nom::IResult<&[u8], FirehosePreamble> {
        let mut firehose_data = FirehosePreamble {
            chunk_tag: 0,
            chunk_sub_tag: 0,
            chunk_data_size: 0,
            first_number_proc_id: 0,
            second_number_proc_id: 0,
            collapsed: 0,
            unknown: Vec::new(),
            public_data_size: 0,
            private_data_virtual_offset: 0,
            unkonwn2: 0,
            unknown3: 0,
            base_continous_time: 0,
            public_data: Vec::new(),
            ttl: 0,
        };

        let (input, chunk_tag) = take(size_of::<u32>())(firehose_input_data)?;
        let (input, chunk_sub_tag) = take(size_of::<u32>())(input)?;
        let (input, chunk_data_size) = take(size_of::<u64>())(input)?;
        let (input, first_number_proc_id) = take(size_of::<u64>())(input)?;
        let (input, second_number_proc_id) = take(size_of::<u32>())(input)?;
        let (input, ttl) = take(size_of::<u8>())(input)?;
        let (input, collapsed) = take(size_of::<u8>())(input)?;

        let (input, unknown) = take(size_of::<u16>())(input)?;

        let (input, public_data_size) = take(size_of::<u16>())(input)?;
        let (input, private_data_virtual_offset) = take(size_of::<u16>())(input)?;
        let (input, unknown2) = take(size_of::<u16>())(input)?;
        let (input, unknown3) = take(size_of::<u16>())(input)?;
        let (log_data, base_continous_time) = take(size_of::<u64>())(input)?;

        let (_, firehose_chunk_tag) = le_u32(chunk_tag)?;
        let (_, firehose_chunk_sub_tag) = le_u32(chunk_sub_tag)?;
        let (_, firehose_chunk_data_size) = le_u64(chunk_data_size)?;
        let (_, firehose_first_proc_id) = le_u64(first_number_proc_id)?;
        let (_, firehose_second_proc_id) = le_u32(second_number_proc_id)?;
        let (_, firehose_collapsed) = le_u8(collapsed)?;
        let (_, firehose_ttl) = le_u8(ttl)?;

        let (_, firehose_public_data_size) = le_u16(public_data_size)?;
        let (_, firehose_private_data_virtual_offset) = le_u16(private_data_virtual_offset)?;
        let (_, firehose_unknown2) = le_u16(unknown2)?;
        let (_, firehose_unknown3) = le_u16(unknown3)?;
        let (_, firehose_base_continous_time) = le_u64(base_continous_time)?;

        firehose_data.chunk_tag = firehose_chunk_tag;
        firehose_data.chunk_sub_tag = firehose_chunk_sub_tag;
        firehose_data.chunk_data_size = firehose_chunk_data_size;
        firehose_data.first_number_proc_id = firehose_first_proc_id;
        firehose_data.second_number_proc_id = firehose_second_proc_id;
        firehose_data.collapsed = firehose_collapsed;
        firehose_data.ttl = firehose_ttl;

        firehose_data.unknown = unknown.to_vec();

        firehose_data.public_data_size = firehose_public_data_size;
        firehose_data.private_data_virtual_offset = firehose_private_data_virtual_offset;
        firehose_data.unkonwn2 = firehose_unknown2;
        firehose_data.unknown3 = firehose_unknown3;
        firehose_data.base_continous_time = firehose_base_continous_time;

        // firehose_public_data_size includes the 16 bytes before the public data offset
        let public_data_size_offset = 16;
        let (mut input, mut public_data) =
            take(firehose_public_data_size - public_data_size_offset)(log_data)?;

        let log_types = [0x2, 0x6, 0x4, 0x7, 0x3];

        let remnant_data = 0x0;
        // Go through all the public data associated with log Firehose entry
        while !public_data.is_empty() {
            let (firehose_input, firehose_public_data) =
                FirehosePreamble::parse_firehose(public_data)?;
            public_data = firehose_input;
            if !log_types.contains(&firehose_public_data.unknown_log_activity_type)
                || public_data.len() < 24
            {
                if remnant_data == firehose_public_data.unknown_log_activity_type {
                    break;
                }
                if firehose_private_data_virtual_offset != 0x1000 {
                    let private_offst = 0x1000;
                    let private_data_offset = private_offst - firehose_private_data_virtual_offset;
                    // Calculate start of private data. If the remaining input is greater than private data offset.
                    // Remove any padding/junk data in front of the private data
                    if input.len() > private_data_offset.into() && public_data.is_empty() {
                        let leftover_data = input.len() - private_data_offset as usize;
                        let (private_data, _) = take(leftover_data)(input)?;
                        input = private_data;
                    } else {
                        // If log data and public data are the same size. Use private data offset to calculate the private data
                        if log_data.len()
                            == (firehose_public_data_size - public_data_size_offset) as usize
                        {
                            let (private_input_data, _) = take(
                                (firehose_private_data_virtual_offset - public_data_size_offset)
                                    as usize
                                    - public_data.len(),
                            )(log_data)?;
                            input = private_input_data;
                        } else {
                            // If we have private data, then any leftover public data is actually prepended to the private data
                            /*
                            buffer:             2736 bytes
                                00000000: b0 0a aa 0a 00 00 00 03 19 6d c9 a4 1d 08 00 00 .........m......
                                ...
                                00000a90: ce fa d2 b0 10 00 12 00 aa 0a 4b 00 35 60 00 00 ..........K.5`..
                                00000aa0: 01 00 43 01 21 04 00 00 4b 00 43 6f 6e 66 69 67 ..C.!...K.Config <- Config is actually in private data
                            privdata:           1366 bytes
                                00000000: 43 6f 6e 66 69 67 52 65 73 6f 6c 76 65 72 73 3a ConfigResolvers:
                                00000010: 20 55 6e 73 63 6f 70 65 64 20 72 65 73 6f 6c 76  Unscoped resolv
                                00000020: 65 72 5b 35 5d 20 64 6f 6d 61 69 6e 20 61 2e 65 er[5] domain a.e
                                00000030: 2e 66 2e 69 70 36 2e 61 72 70 61 20 6e 5f 6e 61 .f.ip6.arpa n_na
                                00000040: 6d 65 73 65 72 76 65 72 20 30 00 43 6f 6e 66 69 meserver 0.Confi
                            */
                            let (private_input_data, _) = take(
                                (firehose_public_data_size - public_data_size_offset) as usize
                                    - public_data.len(),
                            )(log_data)?;
                            input = private_input_data;
                        }
                    }
                }
                firehose_data.public_data.push(firehose_public_data);
                break;
            }
            firehose_data.public_data.push(firehose_public_data);
        }

        // If there is private data, go through and update any logs that have private data items
        if firehose_private_data_virtual_offset != 0x1000 {
            debug!("[macos-unifiedlogs] Parsing Private Firehose Data");
            // Nom any padding
            let (mut private_input, _) = take_while(|b: u8| b == 0)(input)?;

            // if we nom the rest of the data (all zeros) then the private data is actually zeros
            // Or if the firehose data is collapsed, then there was no padding
            if private_input.is_empty() || firehose_data.collapsed == 1 {
                private_input = input;
            }

            for data in &mut firehose_data.public_data {
                // Only non-activity firehose entries appears to have private strings
                if data.firehose_non_activity.private_strings_size == 0 {
                    continue;
                }
                // Get the start of private string data
                let string_offset = data.firehose_non_activity.private_strings_offset
                    - firehose_private_data_virtual_offset;
                let (private_string_start, _) = take(string_offset)(private_input)?;
                let _ =
                    FirehosePreamble::parse_private_data(private_string_start, &mut data.message);
            }
            input = private_input;
        }
        Ok((input, firehose_data))
    }

    /// Collect all the Firehose items (log message entries) in the log entry (chunk)
    pub fn collect_items<'a>(
        data: &'a [u8],
        firehose_number_items: &u8,
        firehose_flags: &u16,
    ) -> nom::IResult<&'a [u8], FirehoseItemData> {
        /*
           Firehose Items are message types related to the log entry (chunk). There appear to be four (4) types:
           strings, numbers, objects, precision
        */
        let mut item_count: u8 = 0;
        let mut items_data: Vec<FirehoseItemType> = Vec::new();

        let mut firehose_input = data;
        let mut firehose_item_data = FirehoseItemData {
            item_info: Vec::new(),
            backtrace_strings: Vec::new(),
        };

        // Firehose number item values
        let number_item_type: Vec<u8> = vec![0x0, 0x2];
        // Dynamic precision item types?
        let precision_items = [0x10, 0x12];
        //  Likely realted to private string. Seen only "<private>" values
        // 0x85 and 0x5 added in macOS Sequioa
        let sensitive_items = [0x5, 0x45, 0x85];
        let object_items = [0x40, 0x42];

        while &item_count < firehose_number_items {
            // Get non-number values first since the values are at the end of the of the log (chunk) entry data
            let (item_value_input, mut item) =
                FirehosePreamble::get_firehose_items(firehose_input)?;
            firehose_input = item_value_input;

            // Precision items just contain the length for the actual item
            // Ex: %*s
            if precision_items.contains(&item.item_type) {
                items_data.push(item);
                item_count += 1;
                continue;
            }

            // Firehose number item values immediately follow the item type
            if number_item_type.contains(&item.item_type) {
                let (item_value_input, message_number) =
                    FirehosePreamble::parse_item_number(firehose_input, u16::from(item.item_size))?;

                item.message_strings = format!("{}", message_number);
                firehose_input = item_value_input;
                item_count += 1;
                items_data.push(item);
                continue;
            }

            // A message size of 0 and is an object type is "(null)"
            if item.message_string_size == 0 && object_items.contains(&item.item_type) {
                item.message_strings = String::from("(null)");
            }
            items_data.push(item);
            item_count += 1;
        }

        // Backtrace data appears before Firehose item strings
        // It only exists if log entry has_context_data flag set
        // Backtrace data can also exist in Oversize log entries. However, Oversize entries do not have has_context_data flags. Instead we check for possible signature
        let has_context_data: u16 = 0x1000;
        let backtrace_signature_size: usize = 3;

        if (firehose_flags & has_context_data) != 0 {
            debug!("[macos-unifiedlogs] Identified Backtrace data in Firehose log chunk");
            let (backtrace_input, backtrace_data) =
                FirehosePreamble::get_backtrace_data(firehose_input)?;
            firehose_input = backtrace_input;
            firehose_item_data.backtrace_strings = backtrace_data;
        } else if firehose_input.len() > backtrace_signature_size {
            let backtrace_signature = [1, 0, 18];
            let (_, backtrace_sig) = take(backtrace_signature_size)(firehose_input)?;
            if backtrace_signature == backtrace_sig {
                let (backtrace_input, backtrace_data) =
                    FirehosePreamble::get_backtrace_data(firehose_input)?;
                firehose_input = backtrace_input;
                firehose_item_data.backtrace_strings = backtrace_data;
            }
        }

        // 0x81 and 0xf1 Added in macOS Sequioa
        let private_strings: Vec<u8> = vec![0x21, 0x25, 0x35, 0x31, 0x41, 0x81, 0xf1];
        let private_number = 0x1;
        // Now at the end of firehose item types.
        // Remaining data (if any) contains strings for the string item types
        let string_item: Vec<u8> = vec![0x20, 0x22, 0x40, 0x42, 0x30, 0x31, 0x32, 0xf2];

        for item in &mut items_data {
            // We already got number items above since the values immediantly follow the number type
            if number_item_type.contains(&item.item_type) {
                continue;
            }

            // Check if item type is a private string. This is used for privacy related data
            if private_strings.contains(&item.item_type)
                || sensitive_items.contains(&item.item_type)
            {
                item.message_strings = String::from("<private>");
                continue;
            }

            if item.item_type == private_number {
                continue;
            }

            // We already got item precision info above
            if precision_items.contains(&item.item_type) {
                continue;
            }

            if item.message_string_size == 0 && !item.message_strings.is_empty() {
                continue;
            }

            if firehose_input.is_empty() {
                break;
            }
            if string_item.contains(&item.item_type) {
                let (item_value_input, message_string) = FirehosePreamble::parse_item_string(
                    firehose_input,
                    &item.item_type,
                    item.message_string_size,
                )?;
                firehose_input = item_value_input;
                item.message_strings = message_string;
            } else {
                error!(
                    "[macos-unifiedlogs] Unknown Firehose item: {}",
                    &item.item_type
                );
                debug!("[macos-unifiedlogs] Firehose item data: {:?}", data);
            }
        }

        // We now have all of the firehose items and the data
        // Go through and append to vec
        for item in items_data {
            let item_info = FirehoseItemInfo {
                message_strings: item.message_strings,
                item_type: item.item_type,
                item_size: item.message_string_size,
            };
            firehose_item_data.item_info.push(item_info);
        }
        Ok((firehose_input, firehose_item_data))
    }

    /// Parse any private firehose data and update any firehose items that use private data
    pub fn parse_private_data<'a>(
        data: &'a [u8],
        firehose_item_data: &mut FirehoseItemData,
    ) -> nom::IResult<&'a [u8], ()> {
        let private_strings: Vec<u8> = vec![0x21, 0x25, 0x41, 0x35, 0x31, 0x81, 0xf1];
        let private_number = 0x1;

        let mut private_string_start = data;
        // Go through all firehose items, for each private item entry get the private value
        for firehose_info in &mut firehose_item_data.item_info {
            if private_strings.contains(&firehose_info.item_type) {
                // Base64 encode arbitrary data. Need to further parse them based on base string formatters
                if firehose_info.item_type == private_strings[3]
                    || firehose_info.item_type == private_strings[4]
                {
                    if private_string_start.len() < firehose_info.item_size.into() {
                        let (private_data, pointer_object) =
                            take(private_string_start.len())(private_string_start)?;
                        private_string_start = private_data;
                        firehose_info.message_strings = encode_standard(pointer_object);

                        continue;
                    }

                    let (private_data, pointer_object) =
                        take(firehose_info.item_size)(private_string_start)?;
                    private_string_start = private_data;
                    firehose_info.message_strings = encode_standard(pointer_object);
                    continue;
                }

                let (private_data, private_string) =
                    extract_string_size(private_string_start, u64::from(firehose_info.item_size))?;

                private_string_start = private_data;
                firehose_info.message_strings = private_string;
            } else if firehose_info.item_type == private_number {
                let (private_data, private_string) = FirehosePreamble::parse_item_number(
                    private_string_start,
                    firehose_info.item_size,
                )?;
                private_string_start = private_data;
                firehose_info.message_strings = format!("{}", private_string);
            }
        }
        Ok((private_string_start, ()))
    }

    // Parse all the different types of Firehose data (activity, non-activity, loss, trace, signpost)
    fn parse_firehose(data: &[u8]) -> nom::IResult<&[u8], Firehose> {
        let mut firehose_results = Firehose {
            unknown_log_activity_type: 0,
            unknown_log_type: 0,
            flags: 0,
            format_string_location: 0,
            thread_id: 0,
            continous_time_delta: 0,
            continous_time_delta_upper: 0,
            data_size: 0,
            firehose_activity: FirehoseActivity {
                unknown_activity_id: 0,
                unknown_sentinal: 0,
                pid: 0,
                unknown_activity_id_2: 0,
                unknown_sentinal_2: 0,
                unknown_activity_id_3: 0,
                unknown_sentinal_3: 0,
                unknown_message_string_ref: 0,
                unknown_pc_id: 0,
                firehose_formatters: FirehoseFormatters {
                    main_exe: false,
                    shared_cache: false,
                    has_large_offset: 0,
                    large_shared_cache: 0,
                    absolute: false,
                    uuid_relative: String::new(),
                    main_plugin: false,
                    pc_style: false,
                    main_exe_alt_index: 0,
                },
            },
            firehose_non_activity: FirehoseNonActivity {
                unknown_activity_id: 0,
                unknown_sentinal: 0,
                private_strings_offset: 0,
                private_strings_size: 0,
                unknown_message_string_ref: 0,
                subsystem_value: 0,
                ttl_value: 0,
                data_ref_value: 0,
                unknown_pc_id: 0,
                firehose_formatters: FirehoseFormatters {
                    main_exe: false,
                    shared_cache: false,
                    has_large_offset: 0,
                    large_shared_cache: 0,
                    absolute: false,
                    uuid_relative: String::new(),
                    main_plugin: false,
                    pc_style: false,
                    main_exe_alt_index: 0,
                },
            },
            firehose_loss: FirehoseLoss {
                start_time: 0,
                end_time: 0,
                count: 0,
            },
            firehose_trace: FirehoseTrace {
                unknown_pc_id: 0,
                message_data: FirehoseItemData {
                    item_info: Vec::new(),
                    backtrace_strings: Vec::new(),
                },
            },
            firehose_signpost: FirehoseSignpost {
                unknown_pc_id: 0,
                unknown_activity_id: 0,
                unknown_sentinel: 0,
                subsystem: 0,
                signpost_id: 0,
                signpost_name: 0,
                private_strings_offset: 0,
                private_strings_size: 0,
                ttl_value: 0,
                firehose_formatters: FirehoseFormatters {
                    main_exe: false,
                    shared_cache: false,
                    has_large_offset: 0,
                    large_shared_cache: 0,
                    absolute: false,
                    uuid_relative: String::new(),
                    main_plugin: false,
                    pc_style: false,
                    main_exe_alt_index: 0,
                },
                data_ref_value: 0,
            },
            unknown_item: 0,
            number_items: 0,
            message: FirehoseItemData {
                item_info: Vec::new(),
                backtrace_strings: Vec::new(),
            },
        };

        let (input, unknown_log_activity_type) = take(size_of::<u8>())(data)?;
        let (input, unknown_log_type) = take(size_of::<u8>())(input)?;
        let (input, flags) = take(size_of::<u16>())(input)?;
        let (input, format_string_location) = take(size_of::<u32>())(input)?;

        let (input, thread_id) = take(size_of::<u64>())(input)?;

        let (input, continous_time_delta) = take(size_of::<u32>())(input)?;
        let (input, continous_time_delta_upper) = take(size_of::<u16>())(input)?;
        let (input, data_size) = take(size_of::<u16>())(input)?;

        let (_, firehose_unknown_log_activity_type) = le_u8(unknown_log_activity_type)?;
        let (_, firehose_unknown_log_type) = le_u8(unknown_log_type)?;
        let (_, firehose_flags) = le_u16(flags)?;
        let (_, firehose_format_string_location) = le_u32(format_string_location)?;
        let (_, firehose_continous_delta_upper) = le_u16(continous_time_delta_upper)?;
        let (_, firehose_continous_delta) = le_u32(continous_time_delta)?;

        let (_, firehose_thread_id) = le_u64(thread_id)?;
        let (_, firehose_data_size) = le_u16(data_size)?;

        firehose_results.unknown_log_activity_type = firehose_unknown_log_activity_type;
        firehose_results.unknown_log_type = firehose_unknown_log_type;
        firehose_results.flags = firehose_flags;
        firehose_results.format_string_location = firehose_format_string_location;
        firehose_results.thread_id = firehose_thread_id;
        firehose_results.continous_time_delta_upper = firehose_continous_delta_upper;
        firehose_results.continous_time_delta = firehose_continous_delta;
        firehose_results.data_size = firehose_data_size;

        let (mut input, mut firehose_input) = take(firehose_data_size)(input)?;

        // Log activity type (unknown_log_activity_type)
        let activity: u8 = 0x2;
        let signpost: u8 = 0x6;
        let nonactivity: u8 = 0x4;
        let loss: u8 = 0x7;
        let trace: u8 = 0x3;

        // Unknown types
        let unknown_remnant_data = 0x0; // 0x0 appears to be remnant data or garbage data (log command does not parse it either)

        if firehose_unknown_log_activity_type == activity {
            let (activity_data, activity) = FirehoseActivity::parse_activity(
                firehose_input,
                &firehose_flags,
                &firehose_unknown_log_type,
            )?;
            firehose_input = activity_data;
            firehose_results.firehose_activity = activity;
        } else if firehose_unknown_log_activity_type == nonactivity {
            let (non_activity_data, non_activity) =
                FirehoseNonActivity::parse_non_activity(firehose_input, &firehose_flags)?;
            firehose_input = non_activity_data;
            firehose_results.firehose_non_activity = non_activity;
        } else if firehose_unknown_log_activity_type == signpost {
            let (process_data, firehose_signpost) =
                FirehoseSignpost::parse_signpost(firehose_input, &firehose_flags)?;
            firehose_input = process_data;
            firehose_results.firehose_signpost = firehose_signpost;
        } else if firehose_unknown_log_activity_type == loss {
            let (loss_data, firehose_loss) = FirehoseLoss::parse_firehose_loss(firehose_input)?;
            firehose_results.firehose_loss = firehose_loss;
            firehose_input = loss_data;
        } else if firehose_unknown_log_activity_type == trace {
            let (trace_data, firehose_trace) = FirehoseTrace::parse_firehose_trace(firehose_input)?;
            firehose_results.firehose_trace = firehose_trace;
            firehose_input = trace_data;

            firehose_results.message = firehose_results.firehose_trace.message_data.clone();
        } else if firehose_unknown_log_activity_type == unknown_remnant_data {
            return Ok((input, firehose_results));
        } else {
            warn!(
                "[macos-unifiedlogs] Unknown log activity type: {} -  {} bytes left",
                firehose_unknown_log_activity_type,
                input.len()
            );
            debug!("[macos-unifiedlogs] Firehose data: {:X?}", data);
            return Ok((input, firehose_results));
        }

        let minimum_item_size = 6;
        if firehose_input.len() < minimum_item_size {
            // Nom any zero padding
            let (remaining_data, _) = take_while(|b: u8| b == 0)(input)?;

            input = remaining_data;
            return Ok((input, firehose_results));
        }

        let (firehose_input, unknown_item) = take(size_of::<u8>())(firehose_input)?;
        let (firehose_input, number_items) = take(size_of::<u8>())(firehose_input)?;

        let (_, firehose_unknown_item) = le_u8(unknown_item)?;
        let (_, firehose_number_items) = le_u8(number_items)?;

        firehose_results.unknown_item = firehose_unknown_item;
        firehose_results.number_items = firehose_number_items;

        let (_, firehose_item_data) = FirehosePreamble::collect_items(
            firehose_input,
            &firehose_number_items,
            &firehose_flags,
        )?;

        firehose_results.message = firehose_item_data;

        // Nom any zero padding
        let (remaining_data, taken_data) = take_while(|b: u8| b == 0)(input)?;

        // Verify we did not nom into remnant/junk data
        let padding_data = padding_size(firehose_data_size.into());
        let (mut input, _) = take(padding_data)(input)?;
        if (padding_data as usize) > taken_data.len() {
            input = remaining_data;
        }

        Ok((input, firehose_results))
    }

    // Parse Backtrace data for log entry (chunk). This only exists if has_context_data flag is set
    fn get_backtrace_data(data: &[u8]) -> nom::IResult<&[u8], Vec<String>> {
        let (input, _unknown_data) = take(size_of::<u16>())(data)?;
        let (input, _unknown_data2) = take(size_of::<u8>())(input)?;
        let (input, number_uuids) = take(size_of::<u8>())(input)?;
        let (mut input, number_offsets) = take(size_of::<u16>())(input)?;

        let (_, backtrace_uuid_count) = le_u8(number_uuids)?;
        let (_, backtrace_offsets_count) = le_u16(number_offsets)?;

        let mut uuid_vec: Vec<String> = Vec::new();
        let mut count = 0;
        while count < backtrace_uuid_count {
            let (uuid_input, uuid_data) = take(size_of::<u128>())(input)?;
            let (_, uuid) = be_u128(uuid_data)?;
            uuid_vec.push(format!("{:X}", uuid));
            input = uuid_input;
            count += 1;
        }
        count = 0;
        let mut offsets_vec: Vec<u32> = Vec::new();
        while (u16::from(count)) < backtrace_offsets_count {
            let (offset_input, offset) = take(size_of::<u32>())(input)?;
            let (_, backtrace_offsets) = le_u32(offset)?;
            offsets_vec.push(backtrace_offsets);
            input = offset_input;
            count += 1;
        }

        let mut backtrace_data: Vec<String> = Vec::new();
        count = 0;
        while (u16::from(count)) < backtrace_offsets_count {
            let (index_input, index) = take(size_of::<u8>())(input)?;
            let (_, uuid_index) = le_u8(index)?;
            if (uuid_index as usize) < uuid_vec.len() {
                backtrace_data.push(format!(
                    "{:?} +0x{:?}",
                    uuid_vec[uuid_index as usize], offsets_vec[count as usize]
                ));
            } else {
                backtrace_data.push(format!(
                    "00000000-0000-0000-0000-000000000000 +0x{:?}",
                    offsets_vec[count as usize]
                ));
            }
            input = index_input;
            count += 1;
        }
        let padding_size = padding_size_four(u64::from(backtrace_offsets_count));
        let (backtrace_input, _) = take(padding_size)(input)?;
        input = backtrace_input;
        Ok((input, backtrace_data))
    }

    // Get the strings, precision, and private (sensitive) firehose message items
    fn get_firehose_items(data: &[u8]) -> nom::IResult<&[u8], FirehoseItemType> {
        let (firehose_input, item_type) = take(size_of::<u8>())(data)?;
        let (mut firehose_input, item_size) = take(size_of::<u8>())(firehose_input)?;
        let (_, item_type) = le_u8(item_type)?;
        let (_, item_size) = le_u8(item_size)?;

        let mut item = FirehoseItemType {
            item_type,
            item_size,
            offset: 0,
            message_string_size: 0,
            message_strings: String::new(),
        };

        // Firehose string item values
        let string_item: Vec<u8> = vec![
            0x20, 0x21, 0x22, 0x25, 0x40, 0x41, 0x42, 0x30, 0x31, 0x32, 0xf2, 0x35, 0x81, 0xf1,
        ];
        let private_number = 0x1;
        // String and private number items metadata is 4 bytes
        // first two (2) bytes point to the offset of the string data
        // last two (2) bytes is the size of of string
        if string_item.contains(&item.item_type) || item.item_type == private_number {
            // The offset is relative to start of string data (after all other firehose items)
            let (input, offset) = take(size_of::<u16>())(firehose_input)?;
            let (_, message_offset) = le_u16(offset)?;
            let (input, message_data_size) = take(size_of::<u16>())(input)?;
            let (_, message_size) = le_u16(message_data_size)?;

            item.offset = message_offset;
            item.message_string_size = message_size;
            firehose_input = input;
        }

        // Precision items just contain the length for the actual item. Ex: %*s
        let precision_items = [0x10, 0x12];
        if precision_items.contains(&item.item_type) {
            let (input, _) = take(item.item_size)(firehose_input)?;
            firehose_input = input;
        }
        let sensitive_items = [0x5, 0x45, 0x85];
        if sensitive_items.contains(&item.item_type) {
            let (input, offset) = take(size_of::<u16>())(firehose_input)?;
            let (_, message_offset) = le_u16(offset)?;
            let (input, message_data_size) = take(size_of::<u16>())(input)?;
            let (_, message_size) = le_u16(message_data_size)?;

            item.offset = message_offset;
            item.message_string_size = message_size;
            firehose_input = input;
        }
        Ok((firehose_input, item))
    }

    // Parse the item string
    fn parse_item_string<'a>(
        data: &'a [u8],
        item_type: &u8,
        message_size: u16,
    ) -> nom::IResult<&'a [u8], String> {
        // If message item size is greater than the remaining data, just use the rest of the data
        if message_size as usize > data.len() {
            return extract_string_size(data, data.len() as u64);
        }

        let (input, message_data) = take(message_size)(data)?;
        let arbitrary: Vec<u8> = vec![0x30, 0x31, 0x32];
        // 0x30, 0x31, and 0x32 represent arbitrary data, need to be decoded again
        // Ex: name: %{private, mask.hash, mdnsresponder:domain_name}.*P, type: A, rdata: %{private, mask.hash, network:in_addr}.4P
        if arbitrary.contains(item_type) {
            return Ok((input, encode_standard(message_data)));
        }

        let base64_raw_bytes: u8 = 0xf2;
        if item_type == &base64_raw_bytes {
            return Ok((input, encode_standard(message_data)));
        }

        let (_, message_string) = extract_string_size(message_data, u64::from(message_size))?;
        Ok((input, message_string))
    }

    // Parse the Firehose item number
    fn parse_item_number(data: &[u8], item_size: u16) -> nom::IResult<&[u8], i64> {
        let (input, message_data) = take(item_size)(data)?;
        let message_number = match item_size {
            4 => {
                let (_, message) = le_i32(message_data)?;
                i64::from(message)
            }
            2 => {
                let (_, message) = le_i16(message_data)?;
                i64::from(message)
            }
            8 => {
                let (_, message) = le_i64(message_data)?;
                message
            }
            1 => {
                let (_, message) = le_i8(message_data)?;
                i64::from(message)
            }
            _ => {
                warn!(
                    "[macos-unifiedlogs] Unknown number size support: {:?}",
                    item_size
                );
                debug!("[macos-unifiedlogs] Item data: {:?}", data);
                -9999
            }
        };
        Ok((input, message_number))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, path::PathBuf};

    use super::{FirehoseItemData, FirehoseItemInfo, FirehosePreamble};

    #[test]
    fn test_parse_firehose_preamble() {
        let test_firehose_data = [
            1, 96, 0, 0, 0, 0, 0, 0, 192, 15, 0, 0, 0, 0, 0, 0, 227, 1, 0, 0, 0, 0, 0, 0, 99, 4, 0,
            0, 0, 0, 0, 0, 176, 15, 0, 16, 0, 0, 0, 3, 153, 49, 153, 58, 209, 3, 0, 0, 4, 0, 4, 2,
            112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 49, 0, 96, 156, 185, 7,
            23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83,
            116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 52, 54, 58, 32, 101,
            110, 116, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 73, 211, 0,
            0, 0, 0, 0, 0, 170, 14, 10, 0, 16, 0, 63, 0, 96, 156, 185, 7, 23, 1, 34, 1, 66, 4, 0,
            0, 49, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97, 116, 101, 70, 111,
            114, 85, 115, 101, 114, 58, 49, 50, 54, 54, 58, 32, 83, 65, 58, 32, 99, 117, 114, 114,
            101, 110, 116, 83, 116, 97, 116, 101, 58, 32, 50, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7,
            186, 14, 0, 0, 0, 0, 0, 0, 241, 76, 14, 0, 16, 0, 63, 0, 96, 156, 185, 7, 23, 1, 34, 1,
            66, 4, 0, 0, 49, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97, 116,
            101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 54, 54, 58, 32, 83, 65, 58, 32, 99,
            117, 114, 114, 101, 110, 116, 83, 116, 97, 116, 101, 58, 32, 50, 0, 0, 4, 0, 2, 2, 32,
            127, 50, 0, 186, 14, 0, 0, 0, 0, 0, 0, 243, 97, 14, 0, 16, 0, 8, 0, 202, 201, 13, 0,
            186, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 204, 195, 14, 0,
            16, 0, 48, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 34, 0, 83, 65, 67, 83, 104,
            105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103, 58,
            52, 57, 54, 58, 32, 101, 110, 116, 101, 114, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14,
            0, 0, 0, 0, 0, 0, 187, 247, 23, 0, 16, 0, 74, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4,
            0, 0, 60, 0, 83, 65, 67, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83,
            104, 111, 119, 105, 110, 103, 58, 53, 48, 53, 58, 32, 101, 120, 105, 116, 58, 32, 105,
            115, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105,
            110, 103, 32, 61, 32, 48, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 2, 32, 127, 50, 0, 186, 14, 0,
            0, 0, 0, 0, 0, 113, 161, 24, 0, 16, 0, 8, 0, 196, 47, 42, 0, 102, 0, 0, 0, 4, 0, 4, 2,
            96, 182, 161, 3, 91, 230, 0, 0, 0, 0, 0, 0, 124, 41, 20, 80, 150, 0, 28, 0, 11, 206,
            107, 3, 54, 0, 0, 2, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 8, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4, 0, 4, 2, 144, 182, 161, 3, 186, 14, 0, 0, 0, 0, 0, 0, 169, 201, 20, 80, 150,
            0, 28, 0, 104, 207, 107, 3, 54, 0, 0, 2, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 8, 5, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0,
            172, 1, 129, 52, 164, 0, 49, 0, 96, 156, 185, 7, 23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83,
            65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97, 116, 101, 70, 111, 114, 85, 115,
            101, 114, 58, 49, 50, 52, 54, 58, 32, 101, 110, 116, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0,
            4, 0, 4, 2, 112, 174, 185, 7, 87, 232, 0, 0, 0, 0, 0, 0, 177, 70, 129, 52, 164, 0, 49,
            0, 96, 156, 185, 7, 23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101, 115, 115,
            105, 111, 110, 83, 116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 52,
            54, 58, 32, 101, 110, 116, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185,
            7, 186, 14, 0, 0, 0, 0, 0, 0, 108, 29, 135, 52, 164, 0, 63, 0, 96, 156, 185, 7, 23, 1,
            34, 1, 66, 4, 0, 0, 49, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97,
            116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 54, 54, 58, 32, 83, 65, 58, 32,
            99, 117, 114, 114, 101, 110, 116, 83, 116, 97, 116, 101, 58, 32, 51, 0, 0, 4, 0, 2, 2,
            0, 127, 50, 0, 186, 14, 0, 0, 0, 0, 0, 0, 39, 46, 135, 52, 164, 0, 8, 0, 202, 201, 13,
            0, 186, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 214, 129,
            135, 52, 164, 0, 48, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 34, 0, 83, 65, 67,
            83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110,
            103, 58, 52, 57, 54, 58, 32, 101, 110, 116, 101, 114, 0, 4, 0, 4, 2, 112, 174, 185, 7,
            87, 232, 0, 0, 0, 0, 0, 0, 129, 190, 135, 52, 164, 0, 63, 0, 96, 156, 185, 7, 23, 1,
            34, 1, 66, 4, 0, 0, 49, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97,
            116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 54, 54, 58, 32, 83, 65, 58, 32,
            99, 117, 114, 114, 101, 110, 116, 83, 116, 97, 116, 101, 58, 32, 51, 0, 0, 4, 0, 4, 2,
            112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 111, 24, 141, 52, 164, 0, 74, 0, 96, 156,
            185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 60, 0, 83, 65, 67, 83, 104, 105, 101, 108, 100, 87,
            105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103, 58, 53, 48, 53, 58, 32, 101,
            120, 105, 116, 58, 32, 105, 115, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111,
            119, 83, 104, 111, 119, 105, 110, 103, 32, 61, 32, 48, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 2,
            0, 127, 50, 0, 186, 14, 0, 0, 0, 0, 0, 0, 218, 54, 117, 55, 164, 0, 8, 0, 196, 47, 42,
            0, 102, 0, 0, 0, 4, 0, 4, 0, 96, 229, 48, 2, 104, 233, 0, 0, 0, 0, 0, 0, 250, 34, 131,
            39, 171, 0, 16, 0, 98, 140, 31, 2, 0, 1, 0, 8, 150, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0,
            128, 228, 48, 2, 104, 233, 0, 0, 0, 0, 0, 0, 100, 244, 131, 39, 171, 0, 30, 0, 238, 39,
            223, 1, 35, 4, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 150, 0, 0, 0, 33, 4, 0, 0, 0,
            0, 0, 0, 4, 0, 4, 0, 192, 228, 48, 2, 104, 233, 0, 0, 0, 0, 0, 0, 156, 248, 131, 39,
            171, 0, 24, 0, 248, 40, 223, 1, 0, 3, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 150, 0,
            0, 0, 4, 0, 4, 2, 96, 182, 161, 3, 104, 233, 0, 0, 0, 0, 0, 0, 97, 179, 140, 39, 171,
            0, 28, 0, 11, 206, 107, 3, 54, 0, 0, 2, 0, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 144, 182, 161, 3, 186, 14, 0, 0, 0, 0, 0, 0, 226,
            13, 142, 39, 171, 0, 28, 0, 104, 207, 107, 3, 54, 0, 0, 2, 0, 8, 8, 0, 0, 0, 0, 0, 0,
            0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 96, 182, 161, 3, 99, 233, 0,
            0, 0, 0, 0, 0, 233, 233, 149, 39, 171, 0, 28, 0, 11, 206, 107, 3, 54, 0, 0, 2, 0, 8, 9,
            0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 96, 229, 48,
            2, 202, 232, 0, 0, 0, 0, 0, 0, 51, 189, 188, 39, 171, 0, 16, 0, 98, 140, 31, 2, 0, 1,
            0, 8, 149, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 128, 228, 48, 2, 104, 233, 0, 0, 0, 0, 0,
            0, 123, 62, 189, 39, 171, 0, 30, 0, 238, 39, 223, 1, 35, 4, 0, 4, 0, 0, 0, 0, 0, 4, 0,
            0, 0, 0, 0, 4, 149, 0, 0, 0, 33, 4, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 192, 228, 48, 2, 104,
            233, 0, 0, 0, 0, 0, 0, 98, 67, 189, 39, 171, 0, 24, 0, 248, 40, 223, 1, 0, 3, 0, 4, 0,
            0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 149, 0, 0, 0, 4, 0, 4, 2, 144, 144, 243, 18, 99, 233,
            0, 0, 0, 0, 0, 0, 222, 140, 189, 39, 171, 0, 189, 0, 136, 175, 234, 18, 177, 0, 35, 10,
            32, 4, 0, 0, 38, 0, 0, 8, 48, 29, 118, 0, 0, 96, 0, 0, 66, 4, 38, 0, 14, 0, 66, 4, 52,
            0, 28, 0, 66, 4, 80, 0, 31, 0, 66, 4, 0, 0, 0, 0, 65, 4, 0, 0, 0, 0, 65, 4, 0, 0, 0, 0,
            66, 4, 111, 0, 3, 0, 66, 4, 114, 0, 3, 0, 65, 86, 70, 105, 103, 82, 111, 117, 116, 105,
            110, 103, 67, 111, 110, 116, 101, 120, 116, 82, 111, 117, 116, 101, 67, 111, 110, 102,
            105, 103, 85, 112, 100, 97, 116, 101, 100, 0, 52, 56, 52, 50, 50, 50, 51, 51, 53, 50,
            50, 50, 54, 0, 99, 111, 110, 102, 105, 103, 85, 112, 100, 97, 116, 101, 82, 101, 97,
            115, 111, 110, 69, 110, 100, 101, 100, 78, 111, 111, 112, 0, 114, 111, 117, 116, 105,
            110, 103, 77, 97, 110, 97, 103, 101, 114, 95, 104, 97, 110, 100, 108, 101, 82, 111,
            117, 116, 101, 65, 119, 97, 121, 0, 78, 79, 0, 78, 79, 0, 0, 0, 0, 4, 0, 4, 2, 144,
            182, 161, 3, 186, 14, 0, 0, 0, 0, 0, 0, 213, 193, 218, 39, 171, 0, 28, 0, 104, 207,
            107, 3, 54, 0, 0, 2, 0, 8, 9, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 4, 0, 4, 2, 112, 69, 76, 12, 104, 233, 0, 0, 0, 0, 0, 0, 17, 94, 168, 40, 171, 0,
            30, 0, 22, 181, 70, 12, 22, 1, 35, 2, 65, 4, 0, 0, 0, 0, 64, 4, 0, 0, 10, 0, 48, 46,
            55, 48, 52, 49, 48, 49, 54, 0, 0, 0, 4, 0, 4, 2, 96, 182, 161, 3, 104, 233, 0, 0, 0, 0,
            0, 0, 219, 50, 32, 232, 177, 0, 28, 0, 11, 206, 107, 3, 54, 0, 0, 2, 0, 8, 10, 0, 0, 0,
            0, 0, 0, 0, 0, 8, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 144, 182, 161, 3,
            186, 14, 0, 0, 0, 0, 0, 0, 29, 176, 32, 232, 177, 0, 28, 0, 104, 207, 107, 3, 54, 0, 0,
            2, 0, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 8, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2,
            144, 144, 243, 18, 104, 233, 0, 0, 0, 0, 0, 0, 67, 134, 39, 232, 177, 0, 189, 0, 136,
            175, 234, 18, 177, 0, 35, 10, 32, 4, 0, 0, 38, 0, 0, 8, 48, 29, 118, 0, 0, 96, 0, 0,
            66, 4, 38, 0, 14, 0, 66, 4, 52, 0, 28, 0, 66, 4, 80, 0, 31, 0, 66, 4, 0, 0, 0, 0, 65,
            4, 0, 0, 0, 0, 65, 4, 0, 0, 0, 0, 66, 4, 111, 0, 3, 0, 66, 4, 114, 0, 3, 0, 65, 86, 70,
            105, 103, 82, 111, 117, 116, 105, 110, 103, 67, 111, 110, 116, 101, 120, 116, 82, 111,
            117, 116, 101, 67, 111, 110, 102, 105, 103, 85, 112, 100, 97, 116, 101, 100, 0, 52, 56,
            55, 49, 50, 50, 49, 55, 52, 54, 55, 50, 56, 0, 99, 111, 110, 102, 105, 103, 85, 112,
            100, 97, 116, 101, 82, 101, 97, 115, 111, 110, 69, 110, 100, 101, 100, 78, 111, 111,
            112, 0, 114, 111, 117, 116, 105, 110, 103, 77, 97, 110, 97, 103, 101, 114, 95, 104, 97,
            110, 100, 108, 101, 82, 111, 117, 116, 101, 65, 119, 97, 121, 0, 78, 79, 0, 78, 79, 0,
            0, 0, 0, 4, 0, 4, 2, 96, 182, 161, 3, 129, 233, 0, 0, 0, 0, 0, 0, 255, 163, 136, 232,
            177, 0, 28, 0, 11, 206, 107, 3, 54, 0, 0, 2, 0, 8, 11, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 144, 182, 161, 3, 186, 14, 0, 0, 0, 0, 0, 0,
            12, 137, 137, 232, 177, 0, 28, 0, 104, 207, 107, 3, 54, 0, 0, 2, 0, 8, 11, 0, 0, 0, 0,
            0, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 69, 76, 12, 129,
            233, 0, 0, 0, 0, 0, 0, 98, 9, 164, 232, 177, 0, 30, 0, 22, 181, 70, 12, 22, 1, 35, 2,
            65, 4, 0, 0, 0, 0, 64, 4, 0, 0, 10, 0, 48, 46, 54, 51, 53, 55, 52, 50, 50, 0, 0, 0, 4,
            16, 4, 2, 220, 230, 161, 3, 186, 14, 0, 0, 0, 0, 0, 0, 76, 242, 207, 232, 177, 0, 14,
            0, 88, 179, 32, 3, 51, 0, 35, 1, 65, 4, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 176, 229, 48, 2,
            129, 233, 0, 0, 0, 0, 0, 0, 228, 147, 135, 235, 177, 0, 16, 0, 131, 142, 31, 2, 0, 1,
            0, 8, 150, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 240, 228, 48, 2, 129, 233, 0, 0, 0, 0, 0,
            0, 146, 215, 135, 235, 177, 0, 30, 0, 129, 44, 223, 1, 35, 4, 0, 4, 0, 0, 0, 0, 0, 4,
            1, 0, 0, 0, 0, 4, 150, 0, 0, 0, 33, 4, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 48, 229, 48, 2,
            129, 233, 0, 0, 0, 0, 0, 0, 0, 217, 135, 235, 177, 0, 24, 0, 127, 45, 223, 1, 0, 3, 0,
            4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 150, 0, 0, 0, 4, 0, 4, 0, 176, 229, 48, 2, 129,
            233, 0, 0, 0, 0, 0, 0, 151, 240, 137, 235, 177, 0, 16, 0, 131, 142, 31, 2, 0, 1, 0, 8,
            149, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 240, 228, 48, 2, 129, 233, 0, 0, 0, 0, 0, 0, 7,
            33, 138, 235, 177, 0, 30, 0, 129, 44, 223, 1, 35, 4, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0,
            0, 0, 4, 149, 0, 0, 0, 33, 4, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, 48, 229, 48, 2, 129, 233,
            0, 0, 0, 0, 0, 0, 246, 33, 138, 235, 177, 0, 24, 0, 127, 45, 223, 1, 0, 3, 0, 4, 0, 0,
            0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 149, 0, 0, 0, 4, 0, 2, 2, 112, 98, 50, 0, 186, 14, 0, 0,
            0, 0, 0, 0, 44, 130, 197, 237, 177, 0, 8, 0, 180, 56, 9, 0, 186, 0, 0, 0, 4, 0, 4, 2,
            112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 138, 169, 207, 237, 177, 0, 48, 0, 96,
            156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 34, 0, 83, 65, 67, 83, 104, 105, 101, 108, 100,
            87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103, 58, 52, 57, 54, 58, 32,
            101, 110, 116, 101, 114, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0,
            105, 27, 216, 237, 177, 0, 74, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 60, 0,
            83, 65, 67, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111,
            119, 105, 110, 103, 58, 53, 48, 53, 58, 32, 101, 120, 105, 116, 58, 32, 105, 115, 83,
            104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103,
            32, 61, 32, 48, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0,
            0, 0, 79, 252, 217, 237, 177, 0, 48, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 34,
            0, 83, 65, 67, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111,
            119, 105, 110, 103, 58, 52, 57, 54, 58, 32, 101, 110, 116, 101, 114, 0, 4, 0, 4, 2,
            112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 67, 249, 223, 237, 177, 0, 74, 0, 96, 156,
            185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 60, 0, 83, 65, 67, 83, 104, 105, 101, 108, 100, 87,
            105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103, 58, 53, 48, 53, 58, 32, 101,
            120, 105, 116, 58, 32, 105, 115, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111,
            119, 83, 104, 111, 119, 105, 110, 103, 32, 61, 32, 48, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 2,
            80, 98, 50, 0, 186, 14, 0, 0, 0, 0, 0, 0, 1, 240, 28, 157, 179, 0, 8, 0, 180, 56, 9, 0,
            186, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 92, 138, 42,
            157, 179, 0, 48, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 34, 0, 83, 65, 67, 83,
            104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103,
            58, 52, 57, 54, 58, 32, 101, 110, 116, 101, 114, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186,
            14, 0, 0, 0, 0, 0, 0, 0, 111, 47, 157, 179, 0, 74, 0, 96, 156, 185, 7, 24, 1, 34, 1,
            66, 4, 0, 0, 60, 0, 83, 65, 67, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111,
            119, 83, 104, 111, 119, 105, 110, 103, 58, 53, 48, 53, 58, 32, 101, 120, 105, 116, 58,
            32, 105, 115, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111,
            119, 105, 110, 103, 32, 61, 32, 48, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7,
            186, 14, 0, 0, 0, 0, 0, 0, 92, 146, 49, 157, 179, 0, 48, 0, 96, 156, 185, 7, 24, 1, 34,
            1, 66, 4, 0, 0, 34, 0, 83, 65, 67, 83, 104, 105, 101, 108, 100, 87, 105, 110, 100, 111,
            119, 83, 104, 111, 119, 105, 110, 103, 58, 52, 57, 54, 58, 32, 101, 110, 116, 101, 114,
            0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 48, 165, 53, 157, 179, 0,
            74, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 60, 0, 83, 65, 67, 83, 104, 105,
            101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103, 58, 53,
            48, 53, 58, 32, 101, 120, 105, 116, 58, 32, 105, 115, 83, 104, 105, 101, 108, 100, 87,
            105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103, 32, 61, 32, 48, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 236, 184, 97, 157,
            179, 0, 49, 0, 96, 156, 185, 7, 23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101,
            115, 115, 105, 111, 110, 83, 116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58,
            49, 50, 52, 54, 58, 32, 101, 110, 116, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2,
            112, 174, 185, 7, 129, 233, 0, 0, 0, 0, 0, 0, 65, 208, 97, 157, 179, 0, 49, 0, 96, 156,
            185, 7, 23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110,
            83, 116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 52, 54, 58, 32,
            101, 110, 116, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14,
            0, 0, 0, 0, 0, 0, 186, 180, 102, 157, 179, 0, 63, 0, 96, 156, 185, 7, 23, 1, 34, 1, 66,
            4, 0, 0, 49, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97, 116, 101,
            70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 54, 54, 58, 32, 83, 65, 58, 32, 99, 117,
            114, 114, 101, 110, 116, 83, 116, 97, 116, 101, 58, 32, 50, 0, 0, 4, 0, 2, 2, 32, 127,
            50, 0, 186, 14, 0, 0, 0, 0, 0, 0, 222, 192, 102, 157, 179, 0, 8, 0, 202, 201, 13, 0,
            186, 0, 0, 0, 4, 0, 4, 2, 112, 174, 185, 7, 186, 14, 0, 0, 0, 0, 0, 0, 124, 254, 102,
            157, 179, 0, 48, 0, 96, 156, 185, 7, 24, 1, 34, 1, 66, 4, 0, 0, 34, 0, 83, 65, 67, 83,
            104, 105, 101, 108, 100, 87, 105, 110, 100, 111, 119, 83, 104, 111, 119, 105, 110, 103,
            58, 52, 57, 54, 58, 32, 101, 110, 116, 101, 114, 0, 4, 0, 4, 2, 112, 174, 185, 7, 129,
            233, 0, 0, 0, 0, 0, 0, 134, 30, 103, 157, 179, 0, 63, 0, 96, 156, 185, 7, 23, 1, 34, 1,
            66, 4, 0, 0, 49, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83, 116, 97, 116,
            101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 54, 54, 58, 32, 83, 65, 58, 32, 99,
            117, 114, 114, 101, 110, 116, 83, 116, 97, 116, 101, 58, 32, 50, 0, 0, 1, 96, 0, 0, 0,
            0, 0, 0, 232, 15, 0, 0, 0, 0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0,
            216, 15, 0, 16, 0, 0, 0, 3, 34, 79, 194, 43, 115, 4, 0, 0, 4, 0, 45, 2, 224, 238, 31,
            18, 54, 234, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 37, 0, 210, 250, 0, 0, 0, 0, 0, 128,
            100, 211, 25, 18, 1, 0, 2, 0, 14, 0, 34, 2, 0, 4, 135, 16, 0, 0, 34, 4, 0, 0, 5, 0,
            100, 101, 110, 121, 0, 0, 0, 0, 4, 16, 45, 2, 240, 59, 32, 18, 54, 234, 0, 0, 0, 0, 0,
            0, 63, 12, 0, 0, 16, 0, 20, 0, 210, 250, 0, 0, 0, 0, 0, 128, 79, 15, 31, 18, 1, 0, 2,
            0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 242, 233, 0, 0, 0, 0, 0, 0,
            225, 250, 255, 255, 15, 0, 163, 0, 210, 250, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0,
            2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 86, 0, 66, 4, 86, 0, 15, 0, 66, 4, 101, 0, 24, 0, 120,
            112, 99, 115, 101, 114, 118, 105, 99, 101, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 67, 114, 121, 112, 116, 111, 84, 111, 107, 101, 110, 75, 105, 116, 46, 112,
            105, 118, 116, 111, 107, 101, 110, 40, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 99, 116, 107, 100, 40, 53, 48, 49, 41, 62, 58, 52,
            53, 50, 93, 41, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97,
            99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105,
            118, 101, 78, 111, 110, 70, 111, 99, 97, 108, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 176, 15,
            32, 18, 235, 233, 0, 0, 0, 0, 0, 0, 149, 134, 234, 0, 16, 0, 16, 0, 212, 250, 0, 0, 0,
            0, 0, 128, 50, 81, 27, 18, 1, 0, 2, 0, 4, 0, 45, 2, 208, 15, 32, 18, 235, 233, 0, 0, 0,
            0, 0, 0, 43, 145, 234, 0, 16, 0, 38, 0, 212, 250, 0, 0, 0, 0, 0, 128, 194, 82, 27, 18,
            1, 0, 2, 0, 16, 0, 0, 3, 0, 4, 135, 16, 0, 0, 0, 4, 245, 1, 0, 0, 0, 4, 245, 1, 0, 0,
            0, 0, 2, 1, 44, 0, 32, 250, 31, 18, 53, 234, 0, 0, 0, 0, 0, 0, 72, 69, 236, 0, 16, 0,
            16, 0, 213, 250, 0, 0, 0, 0, 0, 128, 15, 39, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 32, 249,
            31, 18, 53, 234, 0, 0, 0, 0, 0, 0, 244, 109, 236, 0, 16, 0, 119, 0, 213, 250, 0, 0, 0,
            0, 0, 128, 162, 30, 26, 18, 1, 0, 2, 0, 16, 0, 34, 1, 66, 4, 0, 0, 93, 0, 91, 120, 112,
            99, 115, 101, 114, 118, 105, 99, 101, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46,
            67, 114, 121, 112, 116, 111, 84, 111, 107, 101, 110, 75, 105, 116, 46, 112, 105, 118,
            116, 111, 107, 101, 110, 40, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97,
            112, 112, 108, 101, 46, 99, 116, 107, 100, 40, 53, 48, 49, 41, 62, 58, 52, 53, 50, 93,
            41, 40, 53, 48, 49, 41, 62, 58, 52, 50, 51, 49, 93, 0, 0, 4, 0, 45, 2, 240, 253, 31,
            18, 53, 234, 0, 0, 0, 0, 0, 0, 65, 165, 236, 0, 16, 0, 41, 0, 213, 250, 0, 0, 0, 0, 0,
            128, 54, 56, 26, 18, 1, 0, 2, 0, 16, 0, 34, 2, 66, 4, 0, 0, 5, 0, 2, 8, 0, 0, 0, 0, 0,
            0, 0, 0, 52, 50, 51, 49, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 160, 254, 31, 18, 53,
            234, 0, 0, 0, 0, 0, 0, 140, 217, 236, 0, 16, 0, 31, 0, 213, 250, 0, 0, 0, 0, 0, 128,
            227, 61, 26, 18, 1, 0, 2, 0, 16, 0, 34, 1, 66, 4, 0, 0, 5, 0, 52, 50, 51, 49, 0, 0, 2,
            1, 61, 2, 192, 250, 31, 18, 53, 234, 0, 0, 0, 0, 0, 0, 64, 66, 14, 1, 16, 0, 40, 0,
            193, 250, 0, 0, 0, 0, 0, 128, 196, 1, 0, 0, 0, 0, 0, 0, 193, 250, 0, 0, 0, 0, 0, 128,
            214, 250, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31,
            18, 53, 234, 0, 0, 0, 0, 0, 0, 237, 112, 14, 1, 16, 0, 181, 0, 214, 250, 0, 0, 0, 0, 0,
            128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 115, 0, 66, 4, 115, 0, 34,
            0, 50, 51, 54, 45, 52, 53, 50, 45, 49, 50, 57, 50, 32, 40, 116, 97, 114, 103, 101, 116,
            58, 91, 120, 112, 99, 115, 101, 114, 118, 105, 99, 101, 60, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 67, 114, 121, 112, 116, 111, 84, 111, 107, 101, 110, 75, 105, 116,
            46, 112, 105, 118, 116, 111, 107, 101, 110, 40, 91, 100, 97, 101, 109, 111, 110, 60,
            99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 116, 107, 100, 40, 53, 48, 49, 41,
            62, 58, 52, 53, 50, 93, 41, 40, 53, 48, 49, 41, 62, 58, 52, 50, 51, 49, 93, 41, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 116,
            107, 100, 40, 53, 48, 49, 41, 62, 58, 52, 53, 50, 93, 0, 0, 0, 0, 2, 1, 61, 2, 160,
            250, 31, 18, 53, 234, 0, 0, 0, 0, 0, 0, 126, 67, 16, 1, 16, 0, 40, 0, 193, 250, 0, 0,
            0, 0, 0, 128, 196, 1, 0, 0, 0, 0, 0, 0, 193, 250, 0, 0, 0, 0, 0, 128, 215, 250, 0, 0,
            0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 53, 234, 0, 0,
            0, 0, 0, 0, 15, 88, 17, 1, 16, 0, 209, 1, 215, 250, 0, 0, 0, 0, 0, 128, 82, 115, 24,
            18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 93, 0, 66, 4, 93, 0, 34, 0, 66, 4, 127, 0,
            44, 1, 91, 120, 112, 99, 115, 101, 114, 118, 105, 99, 101, 60, 99, 111, 109, 46, 97,
            112, 112, 108, 101, 46, 67, 114, 121, 112, 116, 111, 84, 111, 107, 101, 110, 75, 105,
            116, 46, 112, 105, 118, 116, 111, 107, 101, 110, 40, 91, 100, 97, 101, 109, 111, 110,
            60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 116, 107, 100, 40, 53, 48, 49,
            41, 62, 58, 52, 53, 50, 93, 41, 40, 53, 48, 49, 41, 62, 58, 52, 50, 51, 49, 93, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 116,
            107, 100, 40, 53, 48, 49, 41, 62, 58, 52, 53, 50, 93, 0, 60, 82, 66, 83, 65, 115, 115,
            101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32,
            34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 101, 120, 116, 101, 110, 115, 105,
            111, 110, 46, 115, 101, 115, 115, 105, 111, 110, 34, 32, 73, 68, 58, 50, 51, 54, 45,
            52, 53, 50, 45, 49, 50, 57, 51, 32, 116, 97, 114, 103, 101, 116, 58, 52, 50, 51, 49,
            32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 76,
            101, 103, 97, 99, 121, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 114, 101,
            113, 117, 101, 115, 116, 101, 100, 82, 101, 97, 115, 111, 110, 58, 86, 105, 101, 119,
            83, 101, 114, 118, 105, 99, 101, 32, 114, 101, 97, 115, 111, 110, 58, 86, 105, 101,
            119, 83, 101, 114, 118, 105, 99, 101, 32, 102, 108, 97, 103, 115, 58, 40, 32, 65, 108,
            108, 111, 119, 73, 100, 108, 101, 83, 108, 101, 101, 112, 32, 80, 114, 101, 118, 101,
            110, 116, 84, 97, 115, 107, 83, 117, 115, 112, 101, 110, 100, 32, 80, 114, 101, 118,
            101, 110, 116, 84, 97, 115, 107, 84, 104, 114, 111, 116, 116, 108, 101, 68, 111, 119,
            110, 32, 41, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105,
            111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98,
            117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 86,
            97, 108, 105, 100, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 0,
            4, 0, 45, 2, 48, 187, 31, 18, 53, 234, 0, 0, 0, 0, 0, 0, 146, 111, 17, 1, 16, 0, 39, 0,
            215, 250, 0, 0, 0, 0, 0, 128, 61, 86, 23, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0,
            13, 0, 50, 51, 54, 45, 52, 53, 50, 45, 49, 50, 57, 51, 0, 0, 4, 0, 45, 2, 112, 204, 31,
            18, 53, 234, 0, 0, 0, 0, 0, 0, 247, 170, 17, 1, 16, 0, 141, 0, 215, 250, 0, 0, 0, 0, 0,
            128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 115, 0, 50, 51, 54, 45,
            52, 53, 50, 45, 49, 50, 57, 51, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 120, 112,
            99, 115, 101, 114, 118, 105, 99, 101, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46,
            67, 114, 121, 112, 116, 111, 84, 111, 107, 101, 110, 75, 105, 116, 46, 112, 105, 118,
            116, 111, 107, 101, 110, 40, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97,
            112, 112, 108, 101, 46, 99, 116, 107, 100, 40, 53, 48, 49, 41, 62, 58, 52, 53, 50, 93,
            41, 40, 53, 48, 49, 41, 62, 58, 52, 50, 51, 49, 93, 41, 0, 0, 0, 0, 2, 1, 61, 2, 180,
            201, 31, 18, 54, 234, 0, 0, 0, 0, 0, 0, 246, 130, 18, 1, 16, 0, 40, 0, 215, 250, 0, 0,
            0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 215, 250, 0, 0, 0, 0, 0, 128, 216, 250, 0, 0,
            0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 2, 1, 61, 2, 180, 201, 31, 18, 235, 233, 0,
            0, 0, 0, 0, 0, 167, 225, 152, 7, 16, 0, 40, 0, 214, 250, 0, 0, 0, 0, 0, 128, 236, 0, 0,
            0, 0, 0, 0, 0, 214, 250, 0, 0, 0, 0, 0, 128, 217, 250, 0, 0, 0, 0, 0, 128, 64, 63, 24,
            18, 1, 0, 2, 0, 2, 1, 61, 2, 96, 200, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 72, 178, 155,
            7, 16, 0, 40, 0, 214, 250, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 214, 250, 0,
            0, 0, 0, 0, 128, 218, 250, 0, 0, 0, 0, 0, 128, 7, 35, 24, 18, 1, 0, 2, 0, 2, 1, 44, 0,
            160, 250, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 129, 38, 41, 167, 17, 0, 16, 0, 219, 250,
            0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 235,
            233, 0, 0, 0, 0, 0, 0, 185, 178, 43, 167, 17, 0, 113, 1, 219, 250, 0, 0, 0, 0, 0, 128,
            82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 39, 0, 66, 4, 39, 0, 30, 0, 66,
            4, 69, 0, 6, 1, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58,
            51, 53, 52, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 112, 111, 119, 101, 114, 100, 62, 58, 57, 55, 93, 0, 60, 82, 66, 83, 65,
            115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114,
            124, 32, 34, 65, 112, 112, 32, 105, 115, 32, 104, 111, 108, 100, 105, 110, 103, 32,
            112, 111, 119, 101, 114, 32, 97, 115, 115, 101, 114, 116, 105, 111, 110, 34, 32, 73,
            68, 58, 50, 51, 54, 45, 57, 55, 45, 49, 50, 57, 52, 32, 116, 97, 114, 103, 101, 116,
            58, 51, 53, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60,
            82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124,
            32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46,
            97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 80, 111, 119, 101, 114,
            65, 115, 115, 101, 114, 116, 105, 111, 110, 34, 32, 115, 111, 117, 114, 99, 101, 69,
            110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41,
            34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110,
            67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116,
            101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
            45, 2, 112, 204, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 93, 46, 45, 167, 17, 0, 86, 0,
            219, 250, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0,
            60, 0, 50, 51, 54, 45, 57, 55, 45, 49, 50, 57, 52, 32, 40, 116, 97, 114, 103, 101, 116,
            58, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46,
            98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51, 53, 52,
            93, 41, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 164, 134,
            47, 167, 17, 0, 40, 0, 219, 250, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 219,
            250, 0, 0, 0, 0, 0, 128, 220, 250, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4,
            0, 45, 2, 64, 239, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 147, 194, 50, 167, 17, 0, 65, 0,
            219, 250, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0,
            39, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51, 53,
            52, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0, 0,
            0, 26, 197, 50, 167, 17, 0, 65, 0, 219, 250, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1,
            0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101,
            108, 112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 64,
            237, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 168, 199, 50, 167, 17, 0, 65, 0, 219, 250, 0,
            0, 0, 0, 0, 128, 106, 208, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 98, 97,
            99, 107, 117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0,
            0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 73, 202,
            50, 167, 17, 0, 65, 0, 219, 250, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14,
            0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46,
            97, 112, 112, 108, 101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108, 112,
            101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 64, 240, 31, 18,
            78, 235, 0, 0, 0, 0, 0, 0, 114, 210, 50, 167, 17, 0, 65, 0, 219, 250, 0, 0, 0, 0, 0,
            128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 98, 97, 99, 107, 117,
            112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0, 0,
            0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 68, 113, 57, 167, 17,
            0, 16, 0, 221, 250, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112,
            206, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 157, 247, 57, 167, 17, 0, 122, 0, 221, 250, 0,
            0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 60, 0, 66, 4,
            60, 0, 30, 0, 50, 51, 54, 45, 57, 55, 45, 49, 50, 57, 52, 32, 40, 116, 97, 114, 103,
            101, 116, 58, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51,
            53, 52, 93, 41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 112, 111, 119, 101, 114, 100, 62, 58, 57, 55, 93, 0, 0, 0, 0, 0, 0, 0, 2,
            1, 44, 0, 192, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 36, 135, 24, 172, 17, 0, 16, 0,
            222, 250, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31,
            18, 80, 235, 0, 0, 0, 0, 0, 0, 96, 202, 24, 172, 17, 0, 135, 0, 222, 250, 0, 0, 0, 0,
            0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 62, 0, 66, 4, 62, 0,
            41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 50, 56, 50, 32, 40, 116, 97, 114, 103, 101,
            116, 58, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 108, 111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49,
            54, 52, 93, 41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41,
            62, 58, 49, 53, 55, 93, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0,
            135, 187, 74, 172, 17, 0, 16, 0, 223, 250, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0,
            2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 22, 255, 76, 172, 17, 0,
            105, 1, 223, 250, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4,
            0, 0, 68, 0, 66, 4, 68, 0, 53, 0, 66, 4, 121, 0, 202, 0, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111,
            109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49,
            49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52,
            93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 99, 111, 114, 101, 115, 101, 114, 118, 105, 99, 101, 115, 46, 108, 97, 117, 110,
            99, 104, 115, 101, 114, 118, 105, 99, 101, 115, 100, 62, 58, 49, 50, 55, 93, 0, 60, 82,
            66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105, 112,
            116, 111, 114, 124, 32, 34, 102, 114, 111, 110, 116, 109, 111, 115, 116, 58, 52, 52,
            52, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 50, 55, 45, 49, 50, 57, 53, 32, 116, 97,
            114, 103, 101, 116, 58, 52, 52, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115,
            58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98,
            117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 108, 97, 117, 110, 99, 104, 115, 101, 114, 118, 105, 99, 101, 115,
            100, 34, 32, 110, 97, 109, 101, 58, 34, 82, 111, 108, 101, 85, 115, 101, 114, 73, 110,
            116, 101, 114, 97, 99, 116, 105, 118, 101, 70, 111, 99, 97, 108, 34, 32, 115, 111, 117,
            114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110,
            117, 108, 108, 41, 34, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112,
            204, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 109, 109, 78, 172, 17, 0, 116, 0, 223, 250, 0,
            0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 90, 0, 50,
            51, 54, 45, 49, 50, 55, 45, 49, 50, 57, 53, 32, 40, 116, 97, 114, 103, 101, 116, 58,
            91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114,
            103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117,
            109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53,
            48, 49, 41, 62, 58, 52, 52, 52, 93, 41, 0, 0, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 168,
            15, 0, 0, 0, 0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 152, 15, 0,
            16, 0, 0, 0, 3, 245, 50, 18, 216, 116, 4, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 235,
            233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 40, 0, 223, 250, 0, 0, 0, 0, 0, 128, 236, 0,
            0, 0, 0, 0, 0, 0, 223, 250, 0, 0, 0, 0, 0, 128, 128, 251, 0, 0, 0, 0, 0, 128, 64, 63,
            24, 18, 1, 0, 2, 0, 2, 1, 61, 2, 160, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 121, 132,
            0, 0, 16, 0, 40, 0, 65, 251, 0, 0, 0, 0, 0, 128, 164, 0, 0, 0, 0, 0, 0, 0, 65, 251, 0,
            0, 0, 0, 0, 128, 129, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45,
            2, 64, 239, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 188, 178, 3, 0, 16, 0, 94, 0, 223, 250,
            0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114,
            103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117,
            109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53,
            48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 79, 235, 0,
            0, 0, 0, 0, 0, 123, 181, 3, 0, 16, 0, 94, 0, 223, 250, 0, 0, 0, 0, 0, 128, 115, 205,
            25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111,
            109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49,
            49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52,
            93, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 59, 185, 3, 0,
            16, 0, 94, 0, 223, 250, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1,
            66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104,
            114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56,
            49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 16,
            206, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 96, 250, 3, 0, 16, 0, 114, 1, 129, 251, 0, 0,
            0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 40, 0, 66, 4, 40,
            0, 30, 0, 66, 4, 70, 0, 6, 1, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46,
            97, 112, 112, 108, 101, 46, 108, 111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62,
            58, 49, 54, 52, 58, 49, 54, 52, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 112, 111, 119, 101, 114, 100, 62, 58, 57, 55, 93,
            0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114,
            105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 32, 105, 115, 32, 104, 111, 108,
            100, 105, 110, 103, 32, 112, 111, 119, 101, 114, 32, 97, 115, 115, 101, 114, 116, 105,
            111, 110, 34, 32, 73, 68, 58, 50, 51, 54, 45, 57, 55, 45, 49, 50, 57, 54, 32, 116, 97,
            114, 103, 101, 116, 58, 49, 54, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115,
            58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98,
            117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 80,
            111, 119, 101, 114, 65, 115, 115, 101, 114, 116, 105, 111, 110, 34, 32, 115, 111, 117,
            114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110,
            117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105,
            116, 105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114,
            105, 98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101,
            114, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 81, 235, 0, 0, 0, 0, 0, 0, 48, 132, 4, 0, 16, 0,
            136, 0, 223, 250, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4,
            0, 0, 62, 0, 66, 4, 62, 0, 15, 0, 66, 4, 77, 0, 21, 0, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109,
            105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49,
            52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110,
            110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116,
            101, 114, 97, 99, 116, 105, 118, 101, 70, 111, 99, 97, 108, 0, 4, 0, 45, 2, 112, 204,
            31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 232, 32, 5, 0, 16, 0, 87, 0, 129, 251, 0, 0, 0, 0,
            0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 61, 0, 50, 51, 54, 45,
            57, 55, 45, 49, 50, 57, 54, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 108, 111, 103, 105,
            110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52, 93, 41, 0, 0, 2,
            1, 44, 0, 192, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 209, 208, 6, 0, 16, 0, 16, 0,
            130, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 2, 1, 61, 2, 180, 201, 31,
            18, 235, 233, 0, 0, 0, 0, 0, 0, 80, 209, 6, 0, 16, 0, 40, 0, 129, 251, 0, 0, 0, 0, 0,
            128, 236, 0, 0, 0, 0, 0, 0, 0, 129, 251, 0, 0, 0, 0, 0, 128, 131, 251, 0, 0, 0, 0, 0,
            128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 80, 235, 0, 0, 0, 0, 0,
            0, 210, 121, 9, 0, 16, 0, 147, 0, 130, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0,
            2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 62, 0, 66, 4, 62, 0, 53, 0, 50, 51, 54, 45, 49, 50,
            55, 45, 49, 50, 55, 53, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 100, 97, 101, 109,
            111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 108, 111, 103, 105, 110,
            119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52, 93, 41, 0, 91, 100,
            97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 114,
            101, 115, 101, 114, 118, 105, 99, 101, 115, 46, 108, 97, 117, 110, 99, 104, 115, 101,
            114, 118, 105, 99, 101, 115, 100, 62, 58, 49, 50, 55, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45,
            2, 64, 239, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 154, 166, 9, 0, 16, 0, 66, 0, 129, 251,
            0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 40, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 108,
            111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52,
            93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 50,
            169, 9, 0, 16, 0, 66, 0, 129, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0,
            14, 0, 34, 1, 66, 4, 0, 0, 40, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109,
            46, 97, 112, 112, 108, 101, 46, 108, 111, 103, 105, 110, 119, 105, 110, 100, 111, 119,
            62, 58, 49, 54, 52, 58, 49, 54, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31,
            18, 78, 235, 0, 0, 0, 0, 0, 0, 167, 172, 9, 0, 16, 0, 66, 0, 129, 251, 0, 0, 0, 0, 0,
            128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 40, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 108, 111, 103, 105,
            110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52, 93, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 64, 240, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 51, 180, 9, 0, 16, 0,
            66, 0, 129, 251, 0, 0, 0, 0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 40, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 108, 111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58,
            49, 54, 52, 93, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 80, 235, 0, 0, 0,
            0, 0, 0, 35, 77, 10, 0, 16, 0, 16, 0, 132, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1,
            0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 164, 233, 11, 0, 16,
            0, 98, 1, 132, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66,
            4, 0, 0, 68, 0, 66, 4, 68, 0, 53, 0, 66, 4, 121, 0, 195, 0, 91, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114,
            111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56,
            49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52,
            52, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 99, 111, 114, 101, 115, 101, 114, 118, 105, 99, 101, 115, 46, 108, 97, 117,
            110, 99, 104, 115, 101, 114, 118, 105, 99, 101, 115, 100, 62, 58, 49, 50, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 110, 111, 116, 105, 102, 105, 99, 97, 116, 105, 111,
            110, 58, 52, 52, 52, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 50, 55, 45, 49, 50, 57,
            55, 32, 116, 97, 114, 103, 101, 116, 58, 52, 52, 52, 32, 97, 116, 116, 114, 105, 98,
            117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116,
            116, 114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 108, 97, 117, 110, 99, 104, 115, 101, 114,
            118, 105, 99, 101, 115, 100, 34, 32, 110, 97, 109, 101, 58, 34, 76, 83, 78, 111, 116,
            105, 102, 105, 99, 97, 116, 105, 111, 110, 34, 32, 115, 111, 117, 114, 99, 101, 69,
            110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41,
            34, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 80, 235, 0,
            0, 0, 0, 0, 0, 246, 203, 12, 0, 16, 0, 116, 0, 132, 251, 0, 0, 0, 0, 0, 128, 210, 109,
            24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 90, 0, 50, 51, 54, 45, 49, 50, 55, 45,
            49, 50, 57, 55, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111,
            109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49,
            49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52,
            93, 41, 0, 0, 0, 0, 0, 2, 1, 61, 2, 192, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 62,
            90, 14, 0, 16, 0, 40, 0, 65, 251, 0, 0, 0, 0, 0, 128, 164, 0, 0, 0, 0, 0, 0, 0, 65,
            251, 0, 0, 0, 0, 0, 128, 134, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 2,
            1, 61, 2, 180, 201, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 95, 62, 14, 0, 16, 0, 40, 0,
            132, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 132, 251, 0, 0, 0, 0, 0, 128,
            133, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31,
            18, 80, 235, 0, 0, 0, 0, 0, 0, 54, 40, 17, 0, 16, 0, 123, 0, 134, 251, 0, 0, 0, 0, 0,
            128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 61, 0, 66, 4, 61, 0, 30,
            0, 50, 51, 54, 45, 57, 55, 45, 49, 50, 57, 54, 32, 40, 116, 97, 114, 103, 101, 116, 58,
            91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 108,
            111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52,
            93, 41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 112, 111, 119, 101, 114, 100, 62, 58, 57, 55, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45,
            2, 64, 239, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 79, 167, 17, 0, 16, 0, 94, 0, 132, 251,
            0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114,
            103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117,
            109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53,
            48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 80, 235, 0,
            0, 0, 0, 0, 0, 100, 169, 17, 0, 16, 0, 94, 0, 132, 251, 0, 0, 0, 0, 0, 128, 115, 205,
            25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111,
            109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49,
            49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52,
            93, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 211, 172, 17, 0,
            16, 0, 94, 0, 132, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1,
            66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104,
            114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56,
            49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 48,
            14, 32, 18, 235, 233, 0, 0, 0, 0, 0, 0, 156, 123, 18, 0, 16, 0, 136, 0, 132, 251, 0, 0,
            0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 62, 0, 66, 4, 62,
            0, 15, 0, 66, 4, 77, 0, 21, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116,
            105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67,
            104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51,
            56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45,
            97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116,
            105, 118, 101, 70, 111, 99, 97, 108, 0, 2, 1, 44, 0, 160, 250, 31, 18, 235, 233, 0, 0,
            0, 0, 0, 0, 169, 191, 49, 0, 16, 0, 16, 0, 135, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26,
            18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 26, 112, 51,
            0, 16, 0, 130, 1, 135, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34,
            3, 66, 4, 0, 0, 68, 0, 66, 4, 68, 0, 41, 0, 66, 4, 109, 0, 239, 0, 91, 97, 112, 112,
            60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104,
            114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50,
            51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58,
            52, 52, 52, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41,
            62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110,
            68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 86, 105,
            115, 105, 98, 108, 101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 50, 57,
            56, 32, 116, 97, 114, 103, 101, 116, 58, 52, 52, 52, 32, 97, 116, 116, 114, 105, 98,
            117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116,
            116, 114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97,
            109, 101, 58, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32, 115, 111, 117,
            114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110,
            117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105,
            116, 105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114,
            105, 98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101,
            114, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 180, 77, 52, 0, 16,
            0, 116, 0, 135, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1,
            66, 4, 0, 0, 90, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 50, 57, 56, 32, 40, 116, 97,
            114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104,
            114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56,
            49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 41, 0, 0, 0, 0, 0, 2, 1,
            61, 2, 180, 201, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 182, 176, 53, 0, 16, 0, 40, 0, 135,
            251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 135, 251, 0, 0, 0, 0, 0, 128, 136,
            251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 235,
            233, 0, 0, 0, 0, 0, 0, 12, 7, 57, 0, 16, 0, 94, 0, 135, 251, 0, 0, 0, 0, 0, 128, 198,
            202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114,
            111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56,
            49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52,
            52, 93, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 240, 15, 0, 0, 0, 0, 0, 0, 236, 0, 0, 0, 0,
            0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 224, 15, 0, 16, 0, 0, 0, 3, 192, 60, 75, 216, 116,
            4, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0,
            94, 0, 135, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111,
            109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53,
            49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18,
            235, 233, 0, 0, 0, 0, 0, 0, 48, 53, 0, 0, 16, 0, 94, 0, 135, 251, 0, 0, 0, 0, 0, 128,
            74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104,
            114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50,
            51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58,
            52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 80, 235, 0, 0, 0, 0, 0, 0, 145,
            96, 0, 0, 16, 0, 136, 0, 135, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17,
            0, 34, 3, 66, 4, 0, 0, 62, 0, 66, 4, 62, 0, 15, 0, 66, 4, 77, 0, 21, 0, 97, 112, 112,
            60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104,
            114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50,
            51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 0,
            114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101,
            114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 70, 111, 99, 97, 108, 0, 2, 1,
            44, 0, 160, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 105, 186, 4, 0, 16, 0, 16, 0, 137,
            251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 80,
            235, 0, 0, 0, 0, 0, 0, 109, 190, 6, 0, 16, 0, 134, 1, 137, 251, 0, 0, 0, 0, 0, 128, 82,
            115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 72, 0, 66, 4, 72, 0, 41, 0, 66, 4,
            113, 0, 239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111,
            46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51,
            50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32,
            73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 50, 57, 57, 32, 116, 97, 114, 103, 101,
            116, 58, 52, 48, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9,
            60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101,
            124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 86,
            105, 115, 105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105,
            114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10,
            9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109,
            112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 80,
            235, 0, 0, 0, 0, 0, 0, 208, 175, 7, 0, 16, 0, 120, 0, 137, 251, 0, 0, 0, 0, 0, 128,
            210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 94, 0, 50, 51, 54, 45, 49, 53,
            55, 45, 49, 50, 57, 57, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105,
            115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115,
            115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53,
            48, 49, 41, 62, 58, 52, 48, 52, 93, 41, 0, 2, 1, 61, 2, 180, 201, 31, 18, 78, 235, 0,
            0, 0, 0, 0, 0, 97, 27, 9, 0, 16, 0, 40, 0, 137, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0,
            0, 0, 0, 0, 137, 251, 0, 0, 0, 0, 0, 128, 138, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18,
            1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 179, 255, 12, 0,
            16, 0, 98, 0, 137, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1,
            66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105,
            111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46,
            51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 179, 2, 13, 0, 16,
            0, 98, 0, 137, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66,
            4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111,
            46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51,
            50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 0, 0, 0, 0,
            0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 61, 6, 13, 0, 16, 0,
            98, 0, 137, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46,
            99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50,
            52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0,
            0, 4, 0, 45, 2, 48, 14, 32, 18, 235, 233, 0, 0, 0, 0, 0, 0, 104, 127, 13, 0, 16, 0,
            143, 0, 137, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4,
            0, 0, 66, 0, 66, 4, 66, 0, 15, 0, 66, 4, 81, 0, 24, 0, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97,
            108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51,
            50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62,
            0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101,
            114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 78, 111, 110, 70, 111, 99, 97,
            108, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 190, 179, 18, 0,
            16, 0, 16, 0, 139, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2,
            16, 206, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 133, 81, 20, 0, 16, 0, 98, 1, 139, 251, 0,
            0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 36, 0, 66, 4,
            36, 0, 41, 0, 66, 4, 77, 0, 239, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109,
            46, 97, 112, 112, 108, 101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62,
            58, 52, 56, 53, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56,
            56, 41, 62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105,
            111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112,
            86, 105, 115, 105, 98, 108, 101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45,
            49, 51, 48, 48, 32, 116, 97, 114, 103, 101, 116, 58, 52, 56, 53, 32, 97, 116, 116, 114,
            105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110,
            65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58,
            34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32,
            110, 97, 109, 101, 58, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32, 115,
            111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34,
            40, 110, 117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105,
            115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116,
            116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102,
            116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62,
            0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 19, 20,
            21, 0, 16, 0, 84, 0, 139, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0,
            34, 1, 66, 4, 0, 0, 58, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 48, 32, 40, 116,
            97, 114, 103, 101, 116, 58, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97,
            112, 112, 108, 101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52,
            56, 53, 93, 41, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 235, 233, 0, 0, 0, 0, 0,
            0, 193, 99, 22, 0, 16, 0, 40, 0, 139, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0,
            0, 139, 251, 0, 0, 0, 0, 0, 128, 140, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2,
            0, 4, 0, 45, 2, 64, 239, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 208, 52, 24, 0, 16, 0, 62,
            0, 139, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 36, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0,
            0, 4, 0, 45, 2, 240, 236, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 4, 56, 24, 0, 16, 0, 62,
            0, 139, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 36, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0,
            0, 4, 0, 45, 2, 144, 238, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 193, 59, 24, 0, 16, 0, 62,
            0, 139, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 36, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0,
            0, 4, 0, 45, 2, 64, 240, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 27, 69, 24, 0, 16, 0, 62,
            0, 139, 251, 0, 0, 0, 0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 36, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0,
            0, 2, 1, 44, 0, 160, 250, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 41, 166, 92, 0, 16, 0, 16,
            0, 141, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31,
            18, 81, 235, 0, 0, 0, 0, 0, 0, 205, 247, 94, 0, 16, 0, 213, 1, 141, 251, 0, 0, 0, 0, 0,
            128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 36, 0, 66, 4, 36, 0, 36,
            0, 66, 4, 72, 0, 103, 1, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97,
            112, 112, 108, 101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52,
            56, 53, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93,
            0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114,
            105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 78, 97, 112, 32, 97, 100, 97, 112,
            116, 101, 114, 32, 97, 115, 115, 101, 114, 116, 105, 111, 110, 34, 32, 73, 68, 58, 50,
            51, 54, 45, 52, 56, 53, 45, 49, 51, 48, 49, 32, 116, 97, 114, 103, 101, 116, 58, 52,
            56, 53, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66,
            83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108, 101,
            116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111, 108,
            105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 62, 44, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114,
            105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46,
            97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58,
            34, 69, 110, 97, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105,
            114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10,
            9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116,
            101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 80, 114, 101,
            118, 101, 110, 116, 84, 105, 109, 101, 114, 84, 104, 114, 111, 116, 116, 108, 101, 84,
            105, 101, 114, 52, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111,
            110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 10, 9, 93, 62, 0,
            0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 222, 80, 96, 0, 16,
            0, 84, 0, 141, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66,
            4, 0, 0, 58, 0, 50, 51, 54, 45, 52, 56, 53, 45, 49, 51, 48, 49, 32, 40, 116, 97, 114,
            103, 101, 116, 58, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93,
            41, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 242, 189,
            97, 0, 16, 0, 40, 0, 141, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 141, 251,
            0, 0, 0, 0, 0, 128, 142, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45,
            2, 64, 239, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 72, 212, 100, 0, 16, 0, 62, 0, 141, 251,
            0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105,
            110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 4, 0, 45, 2,
            240, 236, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 220, 214, 100, 0, 16, 0, 62, 0, 141, 251,
            0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105,
            110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 4, 0, 45, 2,
            144, 238, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 234, 218, 100, 0, 16, 0, 62, 0, 141, 251,
            0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105,
            110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 4, 0, 45, 2,
            64, 240, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 203, 229, 100, 0, 16, 0, 62, 0, 141, 251,
            0, 0, 0, 0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105,
            110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 2, 1, 44, 0,
            192, 250, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 194, 66, 104, 0, 16, 0, 16, 0, 143, 251,
            0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 235,
            233, 0, 0, 0, 0, 0, 0, 112, 114, 104, 0, 16, 0, 126, 0, 143, 251, 0, 0, 0, 0, 0, 128,
            56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 58, 0, 66, 4, 58, 0, 36, 0, 50,
            51, 54, 45, 52, 56, 53, 45, 49, 50, 56, 51, 32, 40, 116, 97, 114, 103, 101, 116, 58,
            91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70,
            105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 41, 0, 91, 100,
            97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105, 110,
            100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 2, 1, 61, 2, 180,
            201, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 219, 33, 172, 0, 16, 0, 40, 0, 221, 250, 0, 0,
            0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 221, 250, 0, 0, 0, 0, 0, 128, 144, 251, 0, 0,
            0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 2, 1, 61, 2, 96, 200, 31, 18, 78, 235, 0, 0,
            0, 0, 0, 0, 245, 130, 177, 0, 16, 0, 40, 0, 221, 250, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0,
            0, 0, 0, 0, 221, 250, 0, 0, 0, 0, 0, 128, 145, 251, 0, 0, 0, 0, 0, 128, 7, 35, 24, 18,
            1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 157, 128, 181, 0,
            16, 0, 66, 0, 145, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1,
            66, 4, 0, 0, 40, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 108, 111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49,
            54, 52, 58, 49, 54, 52, 93, 0, 0, 0, 0, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 8, 15, 0, 0,
            0, 0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 248, 14, 0, 16, 0, 0,
            0, 3, 183, 208, 0, 217, 116, 4, 0, 0, 4, 0, 45, 2, 64, 239, 31, 18, 78, 235, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 16, 0, 65, 0, 145, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1,
            0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101,
            108, 112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240,
            236, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 239, 20, 0, 0, 16, 0, 65, 0, 145, 251, 0, 0, 0,
            0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 98, 97, 99, 107,
            117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 64, 237, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 36, 24, 0, 0, 16, 0,
            65, 0, 145, 251, 0, 0, 0, 0, 0, 128, 106, 208, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 39, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51,
            53, 52, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 78, 235, 0, 0, 0, 0,
            0, 0, 129, 26, 0, 0, 16, 0, 65, 0, 145, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0,
            2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 98, 97, 99, 107, 117, 112, 100, 45, 104, 101, 108,
            112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 64, 239,
            31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 169, 33, 0, 0, 16, 0, 62, 0, 145, 251, 0, 0, 0, 0,
            0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105, 110,
            100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 4, 0, 45, 2, 240,
            236, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 18, 36, 0, 0, 16, 0, 62, 0, 145, 251, 0, 0, 0,
            0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105, 110,
            100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 4, 0, 45, 2, 144,
            238, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 105, 39, 0, 0, 16, 0, 62, 0, 145, 251, 0, 0, 0,
            0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 36, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 70, 105, 110,
            100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0, 0, 4, 0, 45, 2, 64,
            240, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 186, 39, 0, 0, 16, 0, 65, 0, 145, 251, 0, 0, 0,
            0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 39, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 98, 97, 99, 107,
            117, 112, 100, 45, 104, 101, 108, 112, 101, 114, 62, 58, 51, 53, 52, 93, 0, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 64, 240, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 161, 47, 0, 0, 16, 0,
            62, 0, 145, 251, 0, 0, 0, 0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 36, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 70, 105, 110, 100, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 53, 93, 0, 0,
            0, 4, 0, 45, 2, 240, 236, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 99, 161, 0, 0, 16, 0, 66,
            0, 145, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 40, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 108, 111, 103, 105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58,
            49, 54, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 235, 233, 0, 0, 0,
            0, 0, 0, 201, 164, 0, 0, 16, 0, 66, 0, 145, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18,
            1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 40, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 108, 111, 103, 105, 110, 119, 105, 110, 100,
            111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 64,
            240, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 3, 172, 0, 0, 16, 0, 66, 0, 145, 251, 0, 0, 0,
            0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 40, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 108, 111, 103,
            105, 110, 119, 105, 110, 100, 111, 119, 62, 58, 49, 54, 52, 58, 49, 54, 52, 93, 0, 0,
            0, 0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 70, 208, 47,
            0, 16, 0, 16, 0, 146, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45,
            2, 16, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 56, 178, 49, 0, 16, 0, 130, 1, 146, 251,
            0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 68, 0, 66,
            4, 68, 0, 41, 0, 66, 4, 109, 0, 239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117,
            109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46,
            51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 91, 100,
            97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 68, 114, 97, 119, 105, 110, 103, 34, 32,
            73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 50, 32, 116, 97, 114, 103, 101,
            116, 58, 52, 52, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9,
            60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101,
            124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 68,
            114, 97, 119, 105, 110, 103, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105,
            114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10,
            9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109,
            112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112, 204,
            31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 218, 152, 50, 0, 16, 0, 116, 0, 146, 251, 0, 0, 0,
            0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 90, 0, 50, 51, 54,
            45, 49, 53, 55, 45, 49, 51, 48, 50, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97,
            112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103,
            46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109,
            46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49,
            41, 62, 58, 52, 52, 52, 93, 41, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 235, 233,
            0, 0, 0, 0, 0, 0, 20, 231, 51, 0, 16, 0, 40, 0, 146, 251, 0, 0, 0, 0, 0, 128, 236, 0,
            0, 0, 0, 0, 0, 0, 146, 251, 0, 0, 0, 0, 0, 128, 147, 251, 0, 0, 0, 0, 0, 128, 64, 63,
            24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 204, 189,
            55, 0, 16, 0, 94, 0, 146, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0,
            34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116,
            105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67,
            104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51,
            56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2,
            240, 236, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 249, 192, 55, 0, 16, 0, 94, 0, 146, 251,
            0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114,
            103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117,
            109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53,
            48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 235, 233,
            0, 0, 0, 0, 0, 0, 49, 198, 55, 0, 16, 0, 94, 0, 146, 251, 0, 0, 0, 0, 0, 128, 74, 210,
            25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111,
            109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49,
            49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52,
            93, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 80, 235, 0, 0, 0, 0, 0, 0, 234, 248, 55, 0,
            16, 0, 136, 0, 146, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3,
            66, 4, 0, 0, 62, 0, 66, 4, 62, 0, 15, 0, 66, 4, 77, 0, 21, 0, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114,
            111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56,
            49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 0, 114,
            117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73,
            110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 70, 111, 99, 97, 108, 0, 2, 1, 44, 0,
            160, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 127, 14, 224, 0, 16, 0, 16, 0, 148, 251,
            0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 80, 235,
            0, 0, 0, 0, 0, 0, 54, 164, 225, 0, 16, 0, 155, 1, 148, 251, 0, 0, 0, 0, 0, 128, 82,
            115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 72, 0, 66, 4, 72, 0, 41, 0, 66, 4,
            113, 0, 4, 1, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46,
            99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50,
            52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 70, 85, 83, 66, 80, 114, 111, 99, 101, 115, 115, 87,
            105, 110, 100, 111, 119, 83, 116, 97, 116, 101, 58, 32, 118, 105, 115, 105, 98, 108,
            101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 51, 32, 116, 97,
            114, 103, 101, 116, 58, 52, 48, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115,
            58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98,
            117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 102, 117, 115, 101, 98, 111, 97, 114, 100, 34, 32, 110, 97, 109,
            101, 58, 34, 86, 105, 115, 105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69,
            110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41,
            34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110,
            67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116,
            101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2,
            112, 204, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 138, 153, 226, 0, 16, 0, 120, 0, 148, 251,
            0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 94, 0, 50,
            51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 51, 32, 40, 116, 97, 114, 103, 101, 116, 58,
            91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111,
            109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100,
            101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53,
            51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 41, 0, 2, 1, 61, 2, 180, 201, 31,
            18, 79, 235, 0, 0, 0, 0, 0, 0, 118, 204, 227, 0, 16, 0, 40, 0, 148, 251, 0, 0, 0, 0, 0,
            128, 236, 0, 0, 0, 0, 0, 0, 0, 148, 251, 0, 0, 0, 0, 0, 128, 149, 251, 0, 0, 0, 0, 0,
            128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 78, 235, 0, 0, 0, 0, 0,
            0, 134, 205, 229, 0, 16, 0, 98, 0, 148, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1,
            0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108,
            115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52,
            52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52,
            48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0, 0,
            0, 129, 207, 229, 0, 16, 0, 98, 0, 148, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1,
            0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108,
            115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52,
            52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52,
            48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 78, 235, 0, 0, 0, 0, 0,
            0, 85, 210, 229, 0, 16, 0, 98, 0, 148, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0,
            2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115,
            116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52,
            51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48,
            52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 80, 235, 0, 0, 0, 0, 0, 0,
            146, 33, 230, 0, 16, 0, 143, 0, 148, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2,
            0, 17, 0, 34, 3, 66, 4, 0, 0, 66, 0, 66, 4, 66, 0, 15, 0, 66, 4, 81, 0, 24, 0, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118,
            105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111,
            115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40,
            53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118,
            101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 78, 111,
            110, 70, 111, 99, 97, 108, 0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 78, 235, 0, 0, 0, 0, 0,
            0, 198, 97, 232, 0, 16, 0, 16, 0, 150, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0,
            2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 98, 147, 232, 0, 16, 0,
            167, 0, 150, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4,
            0, 0, 94, 0, 66, 4, 94, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 50, 56, 53, 32,
            40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116,
            117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51,
            53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52,
            93, 41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62,
            58, 49, 53, 55, 93, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0,
            192, 38, 233, 0, 16, 0, 16, 0, 151, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2,
            0, 1, 96, 0, 0, 0, 0, 0, 0, 40, 15, 0, 0, 0, 0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1,
            0, 0, 0, 0, 0, 0, 24, 15, 0, 16, 0, 0, 0, 3, 202, 43, 235, 217, 116, 4, 0, 0, 4, 0, 45,
            2, 16, 206, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 151, 1, 151, 251, 0,
            0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 68, 0, 66, 4,
            68, 0, 41, 0, 66, 4, 109, 0, 4, 1, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109,
            46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51,
            50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 70, 85, 83, 66, 80, 114, 111, 99, 101, 115, 115, 87,
            105, 110, 100, 111, 119, 83, 116, 97, 116, 101, 58, 32, 118, 105, 115, 105, 98, 108,
            101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 52, 32, 116, 97,
            114, 103, 101, 116, 58, 52, 52, 52, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115,
            58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98,
            117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 102, 117, 115, 101, 98, 111, 97, 114, 100, 34, 32, 110, 97, 109,
            101, 58, 34, 86, 105, 115, 105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69,
            110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41,
            34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110,
            67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116,
            101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 4, 0, 45, 2, 112, 204,
            31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 87, 249, 0, 0, 16, 0, 116, 0, 151, 251, 0, 0, 0, 0,
            0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 90, 0, 50, 51, 54, 45,
            49, 53, 55, 45, 49, 51, 48, 52, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99,
            104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51,
            50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62,
            58, 52, 52, 52, 93, 41, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 79, 235, 0, 0, 0,
            0, 0, 0, 251, 226, 1, 0, 16, 0, 40, 0, 151, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0,
            0, 0, 0, 151, 251, 0, 0, 0, 0, 0, 128, 152, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1,
            0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 59, 64, 4, 0, 16, 0,
            94, 0, 151, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111,
            109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53,
            49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18,
            80, 235, 0, 0, 0, 0, 0, 0, 27, 66, 4, 0, 16, 0, 94, 0, 151, 251, 0, 0, 0, 0, 0, 128,
            115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104,
            114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50,
            51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58,
            52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 168,
            68, 4, 0, 16, 0, 94, 0, 151, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14,
            0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46,
            67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50,
            51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45,
            2, 48, 14, 32, 18, 79, 235, 0, 0, 0, 0, 0, 0, 90, 147, 4, 0, 16, 0, 136, 0, 151, 251,
            0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 62, 0, 66,
            4, 62, 0, 15, 0, 66, 4, 77, 0, 21, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46,
            67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50,
            51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103,
            45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99,
            116, 105, 118, 101, 70, 111, 99, 97, 108, 0, 2, 1, 44, 0, 192, 250, 31, 18, 80, 235, 0,
            0, 0, 0, 0, 0, 156, 174, 6, 0, 16, 0, 16, 0, 153, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26,
            18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 241, 218, 6,
            0, 16, 0, 163, 0, 153, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34,
            2, 66, 4, 0, 0, 90, 0, 66, 4, 90, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 50, 56,
            52, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105,
            117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52,
            56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 41,
            0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46,
            87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49,
            53, 55, 93, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0,
            63, 137, 97, 6, 16, 0, 40, 0, 150, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0,
            150, 251, 0, 0, 0, 0, 0, 128, 154, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0,
            2, 1, 61, 2, 96, 200, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 20, 67, 100, 6, 16, 0, 40, 0,
            150, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 150, 251, 0, 0, 0, 0, 0, 128,
            155, 251, 0, 0, 0, 0, 0, 128, 7, 35, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18,
            81, 235, 0, 0, 0, 0, 0, 0, 222, 107, 101, 6, 16, 0, 94, 0, 155, 251, 0, 0, 0, 0, 0,
            128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112,
            60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104,
            114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50,
            51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58,
            52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 39,
            110, 101, 6, 16, 0, 94, 0, 155, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0,
            14, 0, 34, 1, 66, 4, 0, 0, 68, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 111, 114, 103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46,
            67, 104, 114, 111, 109, 105, 117, 109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50,
            51, 56, 49, 49, 53, 49, 40, 53, 48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45,
            2, 144, 238, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 171, 218, 101, 6, 16, 0, 94, 0, 155,
            251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 68, 0,
            91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114,
            103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117,
            109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53,
            48, 49, 41, 62, 58, 52, 52, 52, 93, 0, 0, 0, 4, 0, 45, 2, 64, 239, 31, 18, 80, 235, 0,
            0, 0, 0, 0, 0, 76, 9, 102, 6, 16, 0, 98, 0, 155, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25,
            18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97,
            108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51,
            50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62,
            58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 80, 235, 0, 0,
            0, 0, 0, 0, 107, 11, 102, 6, 16, 0, 98, 0, 155, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25,
            18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97,
            108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51,
            50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62,
            58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 80, 235, 0, 0,
            0, 0, 0, 0, 34, 14, 102, 6, 16, 0, 98, 0, 155, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25,
            18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97,
            108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51,
            50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62,
            58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 78, 235, 0, 0, 0,
            0, 0, 0, 85, 215, 102, 6, 16, 0, 143, 0, 155, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18,
            1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 66, 0, 66, 4, 66, 0, 15, 0, 66, 4, 81, 0, 24, 0,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101,
            46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51,
            56, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105,
            118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 78,
            111, 110, 70, 111, 99, 97, 108, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 78, 235, 0, 0, 0, 0,
            0, 0, 174, 28, 105, 6, 16, 0, 136, 0, 155, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1,
            0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 62, 0, 66, 4, 62, 0, 15, 0, 66, 4, 77, 0, 21, 0,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 111, 114,
            103, 46, 99, 104, 114, 111, 109, 105, 117, 109, 46, 67, 104, 114, 111, 109, 105, 117,
            109, 46, 51, 50, 51, 56, 49, 49, 52, 56, 46, 51, 50, 51, 56, 49, 49, 53, 49, 40, 53,
            48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101,
            0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 70, 111, 99,
            97, 108, 0, 2, 1, 44, 0, 160, 250, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 254, 203, 108, 6,
            16, 0, 16, 0, 156, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2,
            16, 206, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 209, 39, 110, 6, 16, 0, 134, 1, 156, 251,
            0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 72, 0, 66,
            4, 72, 0, 41, 0, 66, 4, 113, 0, 239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115,
            116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52,
            51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48,
            52, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62,
            58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68,
            101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 68, 114, 97,
            119, 105, 110, 103, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 53,
            32, 116, 97, 114, 103, 101, 116, 58, 52, 48, 52, 32, 97, 116, 116, 114, 105, 98, 117,
            116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116,
            114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109,
            101, 58, 34, 65, 112, 112, 68, 114, 97, 119, 105, 110, 103, 34, 32, 115, 111, 117, 114,
            99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117,
            108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116,
            105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105,
            98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114,
            65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 4, 0,
            45, 2, 112, 204, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 100, 230, 110, 6, 16, 0, 120, 0,
            156, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0,
            94, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 53, 32, 40, 116, 97, 114, 103, 101,
            116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99,
            111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52,
            52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 58, 52, 48, 52, 93, 41, 0, 2, 1, 61, 2,
            180, 201, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 20, 218, 111, 6, 16, 0, 40, 0, 156, 251,
            0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 156, 251, 0, 0, 0, 0, 0, 128, 157, 251,
            0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 78, 235,
            0, 0, 0, 0, 0, 0, 70, 187, 113, 6, 16, 0, 98, 0, 156, 251, 0, 0, 0, 0, 0, 128, 198,
            202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105, 115,
            117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115, 115,
            46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49,
            41, 62, 58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 78,
            235, 0, 0, 0, 0, 0, 0, 241, 188, 113, 6, 16, 0, 98, 0, 156, 251, 0, 0, 0, 0, 0, 128,
            115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105,
            115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115,
            115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53,
            48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18,
            78, 235, 0, 0, 0, 0, 0, 0, 84, 191, 113, 6, 16, 0, 98, 0, 156, 251, 0, 0, 0, 0, 0, 128,
            74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 72, 0, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 118, 105,
            115, 117, 97, 108, 115, 116, 117, 100, 105, 111, 46, 99, 111, 100, 101, 46, 111, 115,
            115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46, 51, 50, 52, 52, 51, 53, 51, 56, 40, 53,
            48, 49, 41, 62, 58, 52, 48, 52, 93, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18,
            78, 235, 0, 0, 0, 0, 0, 0, 129, 250, 113, 6, 16, 0, 143, 0, 156, 251, 0, 0, 0, 0, 0,
            128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 66, 0, 66, 4, 66, 0, 15,
            0, 66, 4, 81, 0, 24, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 118, 105, 115, 117, 97, 108, 115, 116, 117, 100, 105,
            111, 46, 99, 111, 100, 101, 46, 111, 115, 115, 46, 51, 50, 52, 52, 51, 53, 51, 51, 46,
            51, 50, 52, 52, 51, 53, 51, 56, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105,
            110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114,
            97, 99, 116, 105, 118, 101, 78, 111, 110, 70, 111, 99, 97, 108, 0, 0, 2, 1, 44, 0, 160,
            250, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 124, 161, 133, 21, 16, 0, 16, 0, 158, 251, 0,
            0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 1, 96, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0,
            0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 240, 15, 0, 16, 0, 0, 0,
            3, 151, 96, 115, 239, 116, 4, 0, 0, 4, 0, 45, 2, 16, 206, 31, 18, 78, 235, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 16, 0, 105, 1, 158, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0,
            2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 43, 0, 66, 4, 43, 0, 41, 0, 66, 4, 84, 0, 239, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111,
            110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52,
            56, 51, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41,
            62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110,
            68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 68, 114, 97,
            119, 105, 110, 103, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 54,
            32, 116, 97, 114, 103, 101, 116, 58, 52, 56, 51, 32, 97, 116, 116, 114, 105, 98, 117,
            116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116,
            114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109,
            101, 58, 34, 65, 112, 112, 68, 114, 97, 119, 105, 110, 103, 34, 32, 115, 111, 117, 114,
            99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117,
            108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116,
            105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105,
            98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114,
            65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0,
            0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 110, 167, 1, 0, 16,
            0, 91, 0, 158, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66,
            4, 0, 0, 65, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 54, 32, 40, 116, 97, 114,
            103, 101, 116, 58, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53,
            48, 49, 41, 62, 58, 52, 56, 51, 93, 41, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31,
            18, 78, 235, 0, 0, 0, 0, 0, 0, 82, 106, 3, 0, 16, 0, 40, 0, 158, 251, 0, 0, 0, 0, 0,
            128, 236, 0, 0, 0, 0, 0, 0, 0, 158, 251, 0, 0, 0, 0, 0, 128, 159, 251, 0, 0, 0, 0, 0,
            128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 81, 235, 0, 0, 0, 0, 0,
            0, 248, 168, 7, 0, 16, 0, 69, 0, 158, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0,
            2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110,
            116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2,
            240, 236, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 214, 171, 7, 0, 16, 0, 69, 0, 158, 251, 0,
            0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0, 91,
            100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111,
            110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52,
            56, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 67,
            176, 7, 0, 16, 0, 69, 0, 158, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14,
            0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46,
            97, 112, 112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101,
            114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 64, 240, 31,
            18, 81, 235, 0, 0, 0, 0, 0, 0, 165, 190, 7, 0, 16, 0, 69, 0, 158, 251, 0, 0, 0, 0, 0,
            128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116,
            114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93,
            0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 210, 154, 14, 0,
            16, 0, 16, 0, 160, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2,
            16, 206, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 247, 154, 16, 0, 16, 0, 135, 1, 160, 251,
            0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 73, 0, 66,
            4, 73, 0, 41, 0, 66, 4, 114, 0, 239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118,
            101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53,
            48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            49, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108,
            101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62,
            58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68,
            101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 68, 114, 97,
            119, 105, 110, 103, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 55,
            32, 116, 97, 114, 103, 101, 116, 58, 54, 52, 49, 32, 97, 116, 116, 114, 105, 98, 117,
            116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116,
            114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109,
            101, 58, 34, 65, 112, 112, 68, 114, 97, 119, 105, 110, 103, 34, 32, 115, 111, 117, 114,
            99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117,
            108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116,
            105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105,
            98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114,
            65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 4, 0, 45,
            2, 112, 204, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 226, 159, 17, 0, 16, 0, 121, 0, 160,
            251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 95,
            0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 55, 32, 40, 116, 97, 114, 103, 101, 116,
            58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99,
            111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108,
            117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51,
            53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 41, 0, 0, 0, 0, 0, 0,
            0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 180, 255, 18, 0, 16, 0,
            40, 0, 160, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 160, 251, 0, 0, 0, 0, 0,
            128, 161, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239,
            31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 67, 37, 22, 0, 16, 0, 99, 0, 160, 251, 0, 0, 0, 0,
            0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 73, 0, 91, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111,
            98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46,
            97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236,
            31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 14, 40, 22, 0, 16, 0, 99, 0, 160, 251, 0, 0, 0, 0,
            0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 73, 0, 91, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111,
            98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46,
            97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238,
            31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 133, 43, 22, 0, 16, 0, 99, 0, 160, 251, 0, 0, 0, 0,
            0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 73, 0, 91, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111,
            98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46,
            97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32,
            18, 78, 235, 0, 0, 0, 0, 0, 0, 66, 146, 22, 0, 16, 0, 136, 0, 160, 251, 0, 0, 0, 0, 0,
            128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 67, 0, 66, 4, 67, 0, 15,
            0, 66, 4, 82, 0, 16, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115,
            101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52,
            46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105,
            110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114,
            97, 99, 116, 105, 118, 101, 0, 2, 1, 44, 0, 160, 250, 31, 18, 78, 235, 0, 0, 0, 0, 0,
            0, 214, 10, 27, 0, 16, 0, 16, 0, 162, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0,
            2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 181, 169, 28, 0, 16, 0,
            145, 1, 162, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4,
            0, 0, 83, 0, 66, 4, 83, 0, 41, 0, 66, 4, 124, 0, 239, 0, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104,
            117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104,
            105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46,
            51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 91, 100,
            97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 68, 114, 97, 119, 105, 110, 103, 34, 32,
            73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 56, 32, 116, 97, 114, 103, 101,
            116, 58, 54, 52, 51, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9,
            60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101,
            124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 68,
            114, 97, 119, 105, 110, 103, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105,
            114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10,
            9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109,
            112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112,
            204, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 127, 172, 29, 0, 16, 0, 131, 0, 162, 251, 0, 0,
            0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 105, 0, 50, 51,
            54, 45, 49, 53, 55, 45, 49, 51, 48, 56, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115,
            121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53,
            57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54,
            52, 51, 93, 41, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 235, 233, 0, 0, 0, 0,
            0, 0, 46, 236, 30, 0, 16, 0, 40, 0, 162, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0,
            0, 0, 162, 251, 0, 0, 0, 0, 0, 128, 163, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0,
            2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 91, 25, 34, 0, 16, 0,
            109, 0, 162, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66,
            4, 0, 0, 83, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97,
            116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115,
            120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53,
            48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 235,
            233, 0, 0, 0, 0, 0, 0, 44, 28, 34, 0, 16, 0, 109, 0, 162, 251, 0, 0, 0, 0, 0, 128, 115,
            205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 83, 0, 91, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116,
            104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116,
            104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49,
            46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 0,
            0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 200, 31, 34, 0, 16, 0,
            109, 0, 162, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 83, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116,
            101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120,
            46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49,
            41, 62, 58, 54, 52, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 78, 235, 0, 0, 0,
            0, 0, 0, 216, 206, 34, 0, 16, 0, 146, 0, 162, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18,
            1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 77, 0, 66, 4, 77, 0, 15, 0, 66, 4, 92, 0, 16, 0,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115,
            121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53,
            57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 0, 114,
            117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73,
            110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 160,
            250, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 87, 3, 39, 0, 16, 0, 16, 0, 164, 251, 0, 0, 0,
            0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 235, 233, 0, 0,
            0, 0, 0, 0, 213, 221, 40, 0, 16, 0, 136, 1, 164, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24,
            18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 74, 0, 66, 4, 74, 0, 41, 0, 66, 4, 115, 0,
            239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107,
            116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51,
            50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 68, 114, 97, 119, 105, 110, 103, 34, 32,
            73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 48, 57, 32, 116, 97, 114, 103, 101,
            116, 58, 54, 52, 55, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9,
            60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101,
            124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 68,
            114, 97, 119, 105, 110, 103, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105,
            114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10,
            9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109,
            112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 4, 0, 45, 2, 112, 204, 31, 18, 235, 233,
            0, 0, 0, 0, 0, 0, 192, 228, 41, 0, 16, 0, 122, 0, 164, 251, 0, 0, 0, 0, 0, 128, 210,
            109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 96, 0, 50, 51, 54, 45, 49, 53, 55,
            45, 49, 51, 48, 57, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120,
            116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101,
            110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40,
            53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 41, 0, 0, 0, 0, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0,
            0, 216, 15, 0, 0, 0, 0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 200,
            15, 0, 16, 0, 0, 0, 3, 44, 216, 158, 239, 116, 4, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18,
            78, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 40, 0, 164, 251, 0, 0, 0, 0, 0, 128, 236,
            0, 0, 0, 0, 0, 0, 0, 164, 251, 0, 0, 0, 0, 0, 128, 165, 251, 0, 0, 0, 0, 0, 128, 64,
            63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 169,
            12, 3, 0, 16, 0, 100, 0, 164, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0,
            14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100,
            46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53,
            49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 42,
            15, 3, 0, 16, 0, 100, 0, 164, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0,
            14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100,
            46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53,
            49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 134,
            18, 3, 0, 16, 0, 100, 0, 164, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14,
            0, 34, 1, 66, 4, 0, 0, 74, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100,
            46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53,
            49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 81, 235, 0, 0, 0, 0, 0, 0, 61, 105,
            3, 0, 16, 0, 137, 0, 164, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0,
            34, 3, 66, 4, 0, 0, 68, 0, 66, 4, 68, 0, 15, 0, 66, 4, 83, 0, 16, 0, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101,
            120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105,
            101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53,
            40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105,
            118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 0,
            0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 29, 103,
            6, 1, 16, 0, 16, 0, 166, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0,
            45, 2, 16, 206, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 227, 87, 8, 1, 16, 0, 136, 1, 166,
            251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 74, 0,
            66, 4, 74, 0, 41, 0, 66, 4, 115, 0, 239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108,
            111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46,
            50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41,
            62, 58, 54, 52, 55, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97,
            112, 112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40,
            56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116,
            105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112,
            112, 86, 105, 115, 105, 98, 108, 101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55,
            45, 49, 51, 49, 48, 32, 116, 97, 114, 103, 101, 116, 58, 54, 52, 55, 32, 97, 116, 116,
            114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105,
            110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110,
            58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34,
            32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32,
            115, 111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58,
            34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117,
            105, 115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65,
            116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65,
            102, 116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93,
            62, 0, 4, 0, 45, 2, 112, 204, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 39, 76, 9, 1, 16, 0,
            122, 0, 166, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66,
            4, 0, 0, 96, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 48, 32, 40, 116, 97, 114,
            103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101,
            115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53,
            55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 41,
            0, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 45, 142,
            12, 1, 16, 0, 40, 0, 166, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 166, 251,
            0, 0, 0, 0, 0, 128, 167, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45,
            2, 48, 14, 32, 18, 79, 235, 0, 0, 0, 0, 0, 0, 243, 189, 14, 1, 16, 0, 137, 0, 166, 251,
            0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 68, 0, 66,
            4, 68, 0, 15, 0, 66, 4, 83, 0, 16, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100,
            46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53,
            49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 0, 114,
            117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73,
            110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2,
            64, 239, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 117, 239, 14, 1, 16, 0, 100, 0, 166, 251,
            0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112,
            99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53,
            48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2,
            240, 236, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 144, 241, 14, 1, 16, 0, 100, 0, 166, 251,
            0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112,
            99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53,
            48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2,
            144, 238, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 204, 244, 14, 1, 16, 0, 100, 0, 166, 251,
            0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112,
            99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53,
            48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 0, 0, 0, 0, 2, 1, 44, 0,
            160, 250, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 121, 232, 18, 1, 16, 0, 16, 0, 168, 251,
            0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 81, 235,
            0, 0, 0, 0, 0, 0, 181, 76, 20, 1, 16, 0, 145, 1, 168, 251, 0, 0, 0, 0, 0, 128, 82, 115,
            24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 83, 0, 66, 4, 83, 0, 41, 0, 66, 4, 124,
            0, 239, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116,
            101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120,
            46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49,
            41, 62, 58, 54, 52, 51, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46,
            97, 112, 112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114,
            40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115, 101, 114, 116,
            105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32, 34, 65, 112,
            112, 86, 105, 115, 105, 98, 108, 101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55,
            45, 49, 51, 49, 49, 32, 116, 97, 114, 103, 101, 116, 58, 54, 52, 51, 32, 97, 116, 116,
            114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105,
            110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110,
            58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 110, 97, 112, 34,
            32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32,
            115, 111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58,
            34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117,
            105, 115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65,
            116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65,
            102, 116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93,
            62, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0,
            230, 1, 21, 1, 16, 0, 131, 0, 168, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2,
            0, 18, 0, 34, 1, 66, 4, 0, 0, 105, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 49,
            32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120,
            111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45,
            109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50,
            50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 41, 0, 0, 0, 0, 0, 0, 2, 1, 61,
            2, 180, 201, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 45, 5, 22, 1, 16, 0, 40, 0, 168, 251,
            0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 168, 251, 0, 0, 0, 0, 0, 128, 169, 251,
            0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 78, 235,
            0, 0, 0, 0, 0, 0, 83, 43, 25, 1, 16, 0, 109, 0, 168, 251, 0, 0, 0, 0, 0, 128, 198, 202,
            25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 83, 0, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104,
            117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104,
            105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46,
            51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 0, 0, 0,
            4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 220, 45, 25, 1, 16, 0, 109,
            0, 168, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 83, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116,
            101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120,
            46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49,
            41, 62, 58, 54, 52, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 78, 235, 0, 0,
            0, 0, 0, 0, 7, 49, 25, 1, 16, 0, 109, 0, 168, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18,
            1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 83, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46,
            120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103,
            45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57,
            50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2,
            48, 14, 32, 18, 78, 235, 0, 0, 0, 0, 0, 0, 115, 129, 25, 1, 16, 0, 146, 0, 168, 251, 0,
            0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 77, 0, 66, 4,
            77, 0, 15, 0, 66, 4, 92, 0, 16, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111,
            114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109,
            97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50,
            55, 54, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116,
            105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118,
            101, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0,
            140, 208, 29, 1, 16, 0, 16, 0, 170, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2,
            0, 4, 0, 45, 2, 16, 206, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 108, 72, 31, 1, 16, 0, 105,
            1, 170, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0,
            0, 43, 0, 66, 4, 43, 0, 41, 0, 66, 4, 84, 0, 239, 0, 91, 100, 97, 101, 109, 111, 110,
            60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99,
            101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 91, 100, 97,
            101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110,
            100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0,
            60, 82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32,
            73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 50, 32, 116, 97, 114, 103, 101,
            116, 58, 52, 56, 51, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9,
            60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101,
            124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 97, 112, 112, 110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 86,
            105, 115, 105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105,
            114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10,
            9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109,
            112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112,
            204, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 9, 6, 32, 1, 16, 0, 91, 0, 170, 251, 0, 0, 0,
            0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 65, 0, 50, 51, 54,
            45, 49, 53, 55, 45, 49, 51, 49, 50, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 100,
            97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110,
            116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56,
            51, 93, 41, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0,
            160, 11, 33, 1, 16, 0, 40, 0, 170, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0,
            170, 251, 0, 0, 0, 0, 0, 128, 171, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0,
            4, 0, 45, 2, 64, 239, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 100, 177, 34, 1, 16, 0, 69, 0,
            170, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0,
            43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41,
            62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0,
            0, 0, 161, 179, 34, 1, 16, 0, 69, 0, 170, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1,
            0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101,
            110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 4, 0, 45,
            2, 144, 238, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 216, 182, 34, 1, 16, 0, 69, 0, 170,
            251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0,
            91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99,
            111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58,
            52, 56, 51, 93, 0, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 80, 15, 0, 0, 0, 0, 0, 0, 236, 0,
            0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 64, 15, 0, 16, 0, 0, 0, 3, 212, 149, 193,
            240, 116, 4, 0, 0, 4, 0, 45, 2, 64, 240, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            16, 0, 69, 0, 170, 251, 0, 0, 0, 0, 0, 128, 195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1,
            66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40,
            53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 81,
            235, 0, 0, 0, 0, 0, 0, 216, 244, 3, 0, 16, 0, 16, 0, 172, 251, 0, 0, 0, 0, 0, 128, 105,
            42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 173,
            113, 5, 0, 16, 0, 135, 1, 172, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2, 0,
            18, 0, 34, 3, 66, 4, 0, 0, 73, 0, 66, 4, 73, 0, 41, 0, 66, 4, 114, 0, 239, 0, 91, 97,
            112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46,
            111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117,
            46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53,
            48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60,
            99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101,
            114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115,
            115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124,
            32, 34, 65, 112, 112, 86, 105, 115, 105, 98, 108, 101, 34, 32, 73, 68, 58, 50, 51, 54,
            45, 49, 53, 55, 45, 49, 51, 49, 51, 32, 116, 97, 114, 103, 101, 116, 58, 54, 52, 49,
            32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66, 83, 68,
            111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 100, 111,
            109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112,
            110, 97, 112, 34, 32, 110, 97, 109, 101, 58, 34, 65, 112, 112, 86, 105, 115, 105, 98,
            108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111, 110, 109,
            101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82, 66, 83,
            65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108, 101, 116,
            105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111, 108, 105,
            99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 62, 10, 9, 93, 62, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0,
            151, 47, 6, 0, 16, 0, 121, 0, 172, 251, 0, 0, 0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2,
            0, 18, 0, 34, 1, 66, 4, 0, 0, 95, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 51,
            32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105,
            99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118,
            101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53,
            48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            49, 93, 41, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 80, 235, 0, 0, 0, 0,
            0, 0, 75, 64, 7, 0, 16, 0, 40, 0, 172, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0,
            0, 172, 251, 0, 0, 0, 0, 0, 128, 173, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2,
            0, 4, 0, 45, 2, 64, 239, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 168, 154, 9, 0, 16, 0, 99,
            0, 172, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46,
            108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57,
            51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0,
            4, 0, 45, 2, 240, 236, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 221, 156, 9, 0, 16, 0, 99, 0,
            172, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0,
            73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46,
            108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57,
            51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0,
            4, 0, 45, 2, 144, 238, 31, 18, 81, 235, 0, 0, 0, 0, 0, 0, 27, 160, 9, 0, 16, 0, 99, 0,
            172, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0,
            73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46,
            108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57,
            51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0,
            4, 0, 45, 2, 48, 14, 32, 18, 79, 235, 0, 0, 0, 0, 0, 0, 13, 17, 10, 0, 16, 0, 136, 0,
            172, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0,
            67, 0, 66, 4, 67, 0, 15, 0, 66, 4, 82, 0, 16, 0, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105,
            118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51,
            53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 0, 114,
            117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73,
            110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 0, 2, 1, 44, 0, 160, 250, 31, 18, 79,
            235, 0, 0, 0, 0, 0, 0, 126, 19, 177, 0, 16, 0, 16, 0, 174, 251, 0, 0, 0, 0, 0, 128,
            105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0,
            83, 78, 179, 0, 16, 0, 156, 1, 174, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1, 0, 2,
            0, 18, 0, 34, 3, 66, 4, 0, 0, 73, 0, 66, 4, 73, 0, 41, 0, 66, 4, 114, 0, 4, 1, 91, 97,
            112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46,
            111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117,
            46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53,
            48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60,
            99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101,
            114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115,
            115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124,
            32, 34, 70, 85, 83, 66, 80, 114, 111, 99, 101, 115, 115, 87, 105, 110, 100, 111, 119,
            83, 116, 97, 116, 101, 58, 32, 118, 105, 115, 105, 98, 108, 101, 34, 32, 73, 68, 58,
            50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 52, 32, 116, 97, 114, 103, 101, 116, 58,
            54, 52, 49, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82,
            66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 102,
            117, 115, 101, 98, 111, 97, 114, 100, 34, 32, 110, 97, 109, 101, 58, 34, 86, 105, 115,
            105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111,
            110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82,
            66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108,
            101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111,
            108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116,
            105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 79,
            235, 0, 0, 0, 0, 0, 0, 195, 208, 180, 0, 16, 0, 121, 0, 174, 251, 0, 0, 0, 0, 0, 128,
            210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 95, 0, 50, 51, 54, 45, 49, 53,
            55, 45, 49, 51, 49, 52, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106,
            101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112,
            112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53,
            48, 49, 41, 62, 58, 54, 52, 49, 93, 41, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 61, 2, 180, 201,
            31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 90, 236, 182, 0, 16, 0, 40, 0, 174, 251, 0, 0, 0, 0,
            0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 174, 251, 0, 0, 0, 0, 0, 128, 175, 251, 0, 0, 0, 0,
            0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 79, 235, 0, 0, 0, 0,
            0, 0, 55, 71, 186, 0, 16, 0, 99, 0, 174, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1,
            0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105,
            118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51,
            53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54,
            52, 49, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0,
            234, 73, 186, 0, 16, 0, 99, 0, 174, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2,
            0, 14, 0, 34, 1, 66, 4, 0, 0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118,
            101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53,
            48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            49, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0,
            155, 77, 186, 0, 16, 0, 99, 0, 174, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2,
            0, 14, 0, 34, 1, 66, 4, 0, 0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99,
            97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118,
            101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53,
            48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52,
            49, 93, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 235, 233, 0, 0, 0, 0, 0, 0, 113,
            197, 186, 0, 16, 0, 136, 0, 174, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0,
            17, 0, 34, 3, 66, 4, 0, 0, 67, 0, 66, 4, 67, 0, 15, 0, 66, 4, 82, 0, 16, 0, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111,
            98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46,
            97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48,
            40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105, 110, 103, 45, 97, 99, 116, 105,
            118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114, 97, 99, 116, 105, 118, 101, 0,
            2, 1, 44, 0, 160, 250, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 97, 148, 192, 0, 16, 0, 16,
            0, 176, 251, 0, 0, 0, 0, 0, 128, 105, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 16, 206, 31,
            18, 235, 233, 0, 0, 0, 0, 0, 0, 195, 81, 194, 0, 16, 0, 166, 1, 176, 251, 0, 0, 0, 0,
            0, 128, 82, 115, 24, 18, 1, 0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 83, 0, 66, 4, 83, 0,
            41, 0, 66, 4, 124, 0, 4, 1, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116,
            105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114,
            45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99,
            111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114,
            118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 60, 82, 66, 83, 65, 115, 115,
            101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105, 112, 116, 111, 114, 124, 32,
            34, 70, 85, 83, 66, 80, 114, 111, 99, 101, 115, 115, 87, 105, 110, 100, 111, 119, 83,
            116, 97, 116, 101, 58, 32, 118, 105, 115, 105, 98, 108, 101, 34, 32, 73, 68, 58, 50,
            51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 53, 32, 116, 97, 114, 103, 101, 116, 58, 54,
            52, 51, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 58, 91, 10, 9, 60, 82, 66,
            83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32,
            100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 102,
            117, 115, 101, 98, 111, 97, 114, 100, 34, 32, 110, 97, 109, 101, 58, 34, 86, 105, 115,
            105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69, 110, 118, 105, 114, 111,
            110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41, 34, 62, 44, 10, 9, 60, 82,
            66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110, 67, 111, 109, 112, 108,
            101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116, 101, 124, 32, 112, 111,
            108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112, 108, 105, 99, 97, 116,
            105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 4, 0, 45, 2, 112, 204, 31, 18, 235, 233, 0,
            0, 0, 0, 0, 0, 43, 117, 195, 0, 16, 0, 131, 0, 176, 251, 0, 0, 0, 0, 0, 128, 210, 109,
            24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 105, 0, 50, 51, 54, 45, 49, 53, 55, 45,
            49, 51, 49, 53, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112,
            112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104,
            117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104,
            105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46,
            51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 41, 0, 0,
            0, 0, 0, 0, 2, 1, 61, 2, 180, 201, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 2, 180, 196, 0,
            16, 0, 40, 0, 176, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 176, 251, 0, 0,
            0, 0, 0, 128, 177, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2,
            64, 239, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 5, 18, 200, 0, 16, 0, 109, 0, 176, 251, 0,
            0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 83, 0, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 103, 105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115,
            121, 110, 99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53,
            57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54,
            52, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 6,
            21, 200, 0, 16, 0, 109, 0, 176, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0,
            14, 0, 34, 1, 66, 4, 0, 0, 83, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97,
            116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46, 120, 111,
            114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103, 45, 109,
            97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57, 50, 50,
            55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238,
            31, 18, 235, 233, 0, 0, 0, 0, 0, 0, 235, 24, 200, 0, 16, 0, 109, 0, 176, 251, 0, 0, 0,
            0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 83, 0, 91, 97, 112,
            112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103,
            105, 116, 104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110,
            99, 116, 104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50,
            50, 55, 49, 46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51,
            93, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18, 78, 235, 0, 0, 0, 0, 0, 0, 222, 175, 200,
            0, 16, 0, 146, 0, 176, 251, 0, 0, 0, 0, 0, 128, 201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34,
            3, 66, 4, 0, 0, 77, 0, 66, 4, 77, 0, 15, 0, 66, 4, 92, 0, 16, 0, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116,
            104, 117, 98, 46, 120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116,
            104, 105, 110, 103, 45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49,
            46, 51, 50, 53, 57, 50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105,
            110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114,
            97, 99, 116, 105, 118, 101, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 160, 250, 31, 18, 80,
            235, 0, 0, 0, 0, 0, 0, 31, 143, 205, 0, 16, 0, 16, 0, 178, 251, 0, 0, 0, 0, 0, 128,
            105, 42, 26, 18, 1, 0, 2, 0, 1, 96, 0, 0, 0, 0, 0, 0, 16, 16, 0, 0, 0, 0, 0, 0, 157, 0,
            0, 0, 0, 0, 0, 0, 52, 1, 0, 0, 0, 0, 0, 0, 0, 16, 0, 16, 0, 0, 0, 3, 212, 212, 216, 41,
            115, 4, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 214, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
            0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0,
            1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 66, 0, 0, 0, 0, 0, 0, 0,
            0, 8, 66, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0,
            0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 2, 1, 21, 2,
            208, 110, 164, 6, 214, 233, 0, 0, 0, 0, 0, 0, 97, 87, 224, 1, 16, 0, 36, 0, 208, 250,
            0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 208, 250, 0, 0, 0, 0, 0, 128, 92, 228, 0,
            0, 0, 0, 0, 128, 147, 21, 160, 6, 0, 0, 0, 0, 4, 0, 5, 2, 240, 120, 164, 6, 214, 233,
            0, 0, 0, 0, 0, 0, 48, 118, 227, 1, 16, 0, 125, 0, 92, 228, 0, 0, 0, 0, 0, 128, 235, 61,
            163, 6, 83, 0, 34, 2, 0, 8, 135, 16, 0, 0, 122, 136, 29, 9, 66, 4, 0, 0, 93, 0, 91,
            120, 112, 99, 115, 101, 114, 118, 105, 99, 101, 60, 99, 111, 109, 46, 97, 112, 112,
            108, 101, 46, 67, 114, 121, 112, 116, 111, 84, 111, 107, 101, 110, 75, 105, 116, 46,
            112, 105, 118, 116, 111, 107, 101, 110, 40, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 116, 107, 100, 40, 53, 48, 49, 41, 62,
            58, 52, 53, 50, 93, 41, 40, 53, 48, 49, 41, 62, 58, 52, 50, 51, 49, 93, 0, 0, 0, 0, 4,
            0, 5, 2, 160, 108, 164, 6, 214, 233, 0, 0, 0, 0, 0, 0, 5, 22, 228, 1, 16, 0, 22, 0, 92,
            228, 0, 0, 0, 0, 0, 128, 86, 10, 162, 6, 84, 0, 0, 1, 0, 4, 135, 16, 0, 0, 0, 0, 2, 1,
            21, 2, 208, 110, 164, 6, 27, 234, 0, 0, 0, 0, 0, 0, 122, 73, 235, 1, 16, 0, 36, 0, 210,
            250, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 210, 250, 0, 0, 0, 0, 0, 128, 93,
            228, 0, 0, 0, 0, 0, 128, 147, 21, 160, 6, 0, 0, 0, 0, 4, 0, 5, 2, 160, 108, 164, 6, 27,
            234, 0, 0, 0, 0, 0, 0, 220, 179, 235, 1, 16, 0, 22, 0, 93, 228, 0, 0, 0, 0, 0, 128, 86,
            10, 162, 6, 84, 0, 0, 1, 0, 4, 135, 16, 0, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 27,
            234, 0, 0, 0, 0, 0, 0, 85, 177, 132, 23, 16, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0,
            41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 8, 33, 0, 0, 0, 0, 0, 0, 0, 0, 8, 34, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
            0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99,
            104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 1, 10, 2, 192, 184, 0, 0, 214, 233, 0, 0, 0,
            0, 0, 0, 77, 169, 38, 24, 16, 0, 36, 0, 181, 68, 0, 0, 161, 247, 205, 111, 229, 209,
            49, 1, 157, 239, 1, 129, 177, 149, 3, 123, 16, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0, 4, 2, 0,
            0, 0, 0, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 252, 234, 0, 0, 0, 0, 0, 0, 248, 216,
            189, 28, 16, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0,
            32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 103, 0, 0,
            0, 0, 0, 0, 0, 0, 8, 231, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0,
            4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0,
            0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 5, 235, 0, 0, 0, 0, 0, 0, 55, 159, 71, 29, 16, 0, 94,
            0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0,
            32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 66, 0, 0, 0, 0, 0, 0, 0, 0, 8,
            66, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0,
            100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0,
            66, 15, 13, 4, 235, 0, 0, 0, 0, 0, 0, 43, 171, 46, 42, 16, 0, 94, 0, 122, 179, 12, 13,
            2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0,
            8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 97, 0, 0, 0, 0, 0, 0, 0, 0, 8, 98, 0, 0, 0, 0, 0, 0,
            0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97,
            116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 214, 233, 0,
            0, 0, 0, 0, 0, 120, 0, 199, 128, 16, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34,
            9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4,
            0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101,
            110, 116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 214, 233, 0, 0, 0, 0, 0, 0, 220, 211,
            147, 167, 16, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0,
            32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1,
            0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0,
            4, 0, 44, 2, 0, 66, 15, 13, 39, 234, 0, 0, 0, 0, 0, 0, 73, 20, 207, 253, 16, 0, 94, 0,
            122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32,
            4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105,
            115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15,
            13, 1, 235, 0, 0, 0, 0, 0, 0, 113, 228, 210, 8, 17, 0, 94, 0, 122, 179, 12, 13, 2, 0,
            4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4,
            0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99,
            104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 1, 235, 0, 0, 0, 0,
            0, 0, 95, 90, 187, 77, 17, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4,
            0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0,
            0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110,
            116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 5, 235, 0, 0, 0, 0, 0, 0, 143, 138, 66, 108,
            17, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1,
            0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 33, 0, 0, 0, 0, 0, 0,
            0, 0, 8, 3, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0,
            0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44,
            2, 0, 66, 15, 13, 27, 234, 0, 0, 0, 0, 0, 0, 106, 126, 165, 122, 17, 0, 94, 0, 122,
            179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2,
            0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 33, 0, 0, 0, 0, 0, 0, 0, 0, 8, 3, 0, 0,
            0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 100, 105,
            115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15,
            13, 252, 234, 0, 0, 0, 0, 0, 0, 150, 168, 131, 126, 17, 0, 94, 0, 122, 179, 12, 13, 2,
            0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116,
            99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 249, 234, 0, 0,
            0, 0, 0, 0, 130, 250, 183, 132, 17, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34,
            9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4,
            0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101,
            110, 116, 0, 0, 0, 4, 1, 4, 2, 16, 15, 98, 5, 136, 3, 0, 0, 0, 0, 0, 0, 78, 125, 10,
            174, 17, 0, 60, 0, 6, 70, 70, 5, 3, 0, 34, 4, 0, 4, 3, 220, 1, 0, 32, 4, 0, 0, 24, 0,
            0, 4, 108, 7, 0, 0, 0, 8, 25, 0, 0, 0, 0, 0, 0, 0, 82, 101, 109, 111, 118, 101, 87,
            105, 110, 100, 111, 119, 115, 70, 114, 111, 109, 83, 112, 97, 99, 101, 115, 0, 0, 0, 0,
            0, 4, 1, 4, 2, 64, 14, 98, 5, 136, 3, 0, 0, 0, 0, 0, 0, 248, 150, 10, 174, 17, 0, 60,
            0, 182, 104, 70, 5, 3, 0, 34, 4, 0, 4, 3, 220, 1, 0, 32, 4, 0, 0, 24, 0, 0, 4, 108, 7,
            0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 82, 101, 109, 111, 118, 101, 87, 105, 110, 100,
            111, 119, 115, 70, 114, 111, 109, 83, 112, 97, 99, 101, 115, 0, 0, 0, 0, 0, 4, 1, 4, 2,
            16, 15, 98, 5, 136, 3, 0, 0, 0, 0, 0, 0, 133, 138, 11, 174, 17, 0, 60, 0, 6, 70, 70, 5,
            3, 0, 34, 4, 0, 4, 3, 220, 1, 0, 32, 4, 0, 0, 24, 0, 0, 4, 110, 7, 0, 0, 0, 8, 25, 0,
            0, 0, 0, 0, 0, 0, 82, 101, 109, 111, 118, 101, 87, 105, 110, 100, 111, 119, 115, 70,
            114, 111, 109, 83, 112, 97, 99, 101, 115, 0, 0, 0, 0, 0, 4, 1, 4, 2, 64, 14, 98, 5,
            136, 3, 0, 0, 0, 0, 0, 0, 254, 155, 11, 174, 17, 0, 60, 0, 182, 104, 70, 5, 3, 0, 34,
            4, 0, 4, 3, 220, 1, 0, 32, 4, 0, 0, 24, 0, 0, 4, 110, 7, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0,
            0, 0, 82, 101, 109, 111, 118, 101, 87, 105, 110, 100, 111, 119, 115, 70, 114, 111, 109,
            83, 112, 97, 99, 101, 115, 0, 0, 0, 0, 0, 4, 1, 4, 2, 16, 15, 98, 5, 136, 3, 0, 0, 0,
            0, 0, 0, 98, 0, 74, 174, 17, 0, 52, 0, 6, 70, 70, 5, 3, 0, 34, 4, 0, 4, 3, 220, 1, 0,
            32, 4, 0, 0, 16, 0, 0, 4, 108, 7, 0, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0, 84, 101, 114,
            109, 105, 110, 97, 116, 101, 87, 105, 110, 100, 111, 119, 0, 0, 0, 0, 0, 4, 1, 4, 2,
            16, 15, 98, 5, 136, 3, 0, 0, 0, 0, 0, 0, 132, 36, 111, 174, 17, 0, 52, 0, 6, 70, 70, 5,
            3, 0, 34, 4, 0, 4, 3, 220, 1, 0, 32, 4, 0, 0, 16, 0, 0, 4, 110, 7, 0, 0, 0, 8, 1, 0, 0,
            0, 0, 0, 0, 0, 84, 101, 114, 109, 105, 110, 97, 116, 101, 87, 105, 110, 100, 111, 119,
            0, 0, 0, 0, 0, 4, 1, 4, 2, 176, 203, 97, 5, 136, 3, 0, 0, 0, 0, 0, 0, 104, 116, 218,
            174, 17, 0, 75, 0, 77, 15, 55, 5, 3, 0, 34, 5, 0, 4, 11, 79, 3, 0, 32, 4, 0, 0, 26, 0,
            0, 4, 40, 5, 0, 0, 32, 4, 26, 0, 7, 0, 32, 4, 33, 0, 4, 0, 83, 101, 116, 87, 105, 110,
            100, 111, 119, 72, 97, 115, 75, 101, 121, 65, 112, 112, 101, 97, 114, 97, 110, 99, 101,
            0, 97, 99, 116, 105, 118, 101, 0, 107, 101, 121, 0, 0, 0, 0, 0, 0, 4, 1, 4, 2, 176,
            203, 97, 5, 136, 3, 0, 0, 0, 0, 0, 0, 88, 160, 218, 174, 17, 0, 77, 0, 77, 15, 55, 5,
            3, 0, 34, 5, 0, 4, 11, 79, 3, 0, 32, 4, 0, 0, 27, 0, 0, 4, 40, 5, 0, 0, 32, 4, 27, 0,
            7, 0, 32, 4, 34, 0, 5, 0, 83, 101, 116, 87, 105, 110, 100, 111, 119, 72, 97, 115, 77,
            97, 105, 110, 65, 112, 112, 101, 97, 114, 97, 110, 99, 101, 0, 97, 99, 116, 105, 118,
            101, 0, 109, 97, 105, 110, 0, 0, 0, 0, 4, 0, 44, 2, 16, 221, 120, 8, 136, 3, 0, 0, 0,
            0, 0, 0, 199, 37, 5, 176, 17, 0, 53, 0, 92, 172, 120, 8, 1, 0, 2, 0, 75, 0, 35, 4, 65,
            4, 0, 0, 0, 0, 0, 4, 75, 0, 0, 0, 64, 4, 0, 0, 9, 0, 64, 4, 9, 0, 8, 0, 111, 99, 99,
            108, 117, 100, 101, 100, 0, 118, 105, 115, 105, 98, 108, 101, 0, 0, 0, 0, 4, 0, 44, 2,
            128, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 22, 57, 5, 176, 17, 0, 32, 0, 2, 182, 120,
            8, 1, 0, 2, 0, 75, 0, 35, 2, 65, 4, 0, 0, 0, 0, 64, 4, 0, 0, 8, 0, 118, 105, 115, 105,
            98, 108, 101, 0, 4, 0, 44, 2, 16, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 172, 189, 5,
            176, 17, 0, 53, 0, 92, 172, 120, 8, 1, 0, 2, 0, 75, 0, 35, 4, 65, 4, 0, 0, 0, 0, 0, 4,
            69, 0, 0, 0, 64, 4, 0, 0, 9, 0, 64, 4, 9, 0, 8, 0, 111, 99, 99, 108, 117, 100, 101,
            100, 0, 118, 105, 115, 105, 98, 108, 101, 0, 0, 0, 0, 4, 0, 44, 2, 16, 221, 120, 8,
            136, 3, 0, 0, 0, 0, 0, 0, 249, 207, 5, 176, 17, 0, 53, 0, 92, 172, 120, 8, 1, 0, 2, 0,
            75, 0, 35, 4, 65, 4, 0, 0, 0, 0, 0, 4, 40, 5, 0, 0, 64, 4, 0, 0, 9, 0, 64, 4, 9, 0, 8,
            0, 111, 99, 99, 108, 117, 100, 101, 100, 0, 118, 105, 115, 105, 98, 108, 101, 0, 0, 0,
            0, 4, 0, 44, 2, 128, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 67, 214, 5, 176, 17, 0, 32,
            0, 2, 182, 120, 8, 1, 0, 2, 0, 75, 0, 35, 2, 65, 4, 0, 0, 0, 0, 64, 4, 0, 0, 8, 0, 118,
            105, 115, 105, 98, 108, 101, 0, 4, 0, 44, 2, 0, 66, 15, 13, 4, 235, 0, 0, 0, 0, 0, 0,
            176, 97, 130, 179, 17, 0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0,
            0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 99,
            0, 0, 0, 0, 0, 0, 0, 0, 8, 98, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0,
            0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116,
            0, 0, 0, 4, 0, 44, 2, 0, 66, 15, 13, 4, 235, 0, 0, 0, 0, 0, 0, 119, 126, 86, 194, 17,
            0, 94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0,
            1, 0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0,
            0, 100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2,
            16, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 165, 221, 149, 199, 17, 0, 49, 0, 92, 172,
            120, 8, 1, 0, 2, 0, 75, 0, 35, 4, 65, 4, 0, 0, 0, 0, 0, 4, 103, 0, 0, 0, 64, 4, 0, 0,
            5, 0, 64, 4, 5, 0, 8, 0, 110, 111, 110, 101, 0, 118, 105, 115, 105, 98, 108, 101, 0, 0,
            0, 0, 0, 0, 0, 0, 4, 0, 44, 2, 128, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 6, 244, 149,
            199, 17, 0, 32, 0, 2, 182, 120, 8, 1, 0, 2, 0, 75, 0, 35, 2, 65, 4, 0, 0, 0, 0, 64, 4,
            0, 0, 8, 0, 118, 105, 115, 105, 98, 108, 101, 0, 4, 0, 44, 2, 16, 221, 120, 8, 136, 3,
            0, 0, 0, 0, 0, 0, 214, 49, 151, 199, 17, 0, 49, 0, 92, 172, 120, 8, 1, 0, 2, 0, 75, 0,
            35, 4, 65, 4, 0, 0, 0, 0, 0, 4, 100, 0, 0, 0, 64, 4, 0, 0, 5, 0, 64, 4, 5, 0, 8, 0,
            110, 111, 110, 101, 0, 118, 105, 115, 105, 98, 108, 101, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
            44, 2, 128, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 32, 62, 151, 199, 17, 0, 32, 0, 2,
            182, 120, 8, 1, 0, 2, 0, 75, 0, 35, 2, 65, 4, 0, 0, 0, 0, 64, 4, 0, 0, 8, 0, 118, 105,
            115, 105, 98, 108, 101, 0, 4, 0, 44, 2, 16, 221, 120, 8, 136, 3, 0, 0, 0, 0, 0, 0, 52,
            232, 155, 199, 17, 0, 49, 0, 92, 172, 120, 8, 1, 0, 2, 0, 75, 0, 35, 4, 65, 4, 0, 0, 0,
            0, 0, 4, 105, 0, 0, 0, 64, 4, 0, 0, 5, 0, 64, 4, 5, 0, 8, 0, 110, 111, 110, 101, 0,
            118, 105, 115, 105, 98, 108, 101, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 44, 2, 128, 221, 120,
            8, 136, 3, 0, 0, 0, 0, 0, 0, 185, 252, 155, 199, 17, 0, 32, 0, 2, 182, 120, 8, 1, 0, 2,
            0, 75, 0, 35, 2, 65, 4, 0, 0, 0, 0, 64, 4, 0, 0, 8, 0, 118, 105, 115, 105, 98, 108,
            101, 0, 4, 0, 44, 2, 0, 66, 15, 13, 27, 234, 0, 0, 0, 0, 0, 0, 24, 250, 9, 201, 17, 0,
            94, 0, 122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1,
            0, 32, 4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 99, 0, 0, 0, 0, 0, 0, 0, 0,
            8, 98, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0,
            100, 105, 115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 4, 0, 44, 2, 0,
            66, 15, 13, 4, 235, 0, 0, 0, 0, 0, 0, 15, 141, 195, 228, 17, 0, 94, 0, 122, 179, 12,
            13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32, 4, 2, 0, 14, 0,
            0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0,
            0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105, 115, 112, 97,
            116, 99, 104, 69, 118, 101, 110, 116, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 184, 15, 0, 0,
            0, 0, 0, 0, 236, 0, 0, 0, 0, 0, 0, 0, 192, 1, 0, 0, 0, 0, 0, 0, 168, 15, 0, 16, 0, 0,
            0, 3, 242, 224, 144, 241, 116, 4, 0, 0, 4, 0, 45, 2, 16, 206, 31, 18, 80, 235, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 16, 0, 157, 1, 178, 251, 0, 0, 0, 0, 0, 128, 82, 115, 24, 18, 1,
            0, 2, 0, 18, 0, 34, 3, 66, 4, 0, 0, 74, 0, 66, 4, 74, 0, 41, 0, 66, 4, 115, 0, 4, 1,
            91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111,
            109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111,
            112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50,
            53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100,
            111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 60,
            82, 66, 83, 65, 115, 115, 101, 114, 116, 105, 111, 110, 68, 101, 115, 99, 114, 105,
            112, 116, 111, 114, 124, 32, 34, 70, 85, 83, 66, 80, 114, 111, 99, 101, 115, 115, 87,
            105, 110, 100, 111, 119, 83, 116, 97, 116, 101, 58, 32, 118, 105, 115, 105, 98, 108,
            101, 34, 32, 73, 68, 58, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 54, 32, 116, 97,
            114, 103, 101, 116, 58, 54, 52, 55, 32, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115,
            58, 91, 10, 9, 60, 82, 66, 83, 68, 111, 109, 97, 105, 110, 65, 116, 116, 114, 105, 98,
            117, 116, 101, 124, 32, 100, 111, 109, 97, 105, 110, 58, 34, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 102, 117, 115, 101, 98, 111, 97, 114, 100, 34, 32, 110, 97, 109,
            101, 58, 34, 86, 105, 115, 105, 98, 108, 101, 34, 32, 115, 111, 117, 114, 99, 101, 69,
            110, 118, 105, 114, 111, 110, 109, 101, 110, 116, 58, 34, 40, 110, 117, 108, 108, 41,
            34, 62, 44, 10, 9, 60, 82, 66, 83, 65, 99, 113, 117, 105, 115, 105, 116, 105, 111, 110,
            67, 111, 109, 112, 108, 101, 116, 105, 111, 110, 65, 116, 116, 114, 105, 98, 117, 116,
            101, 124, 32, 112, 111, 108, 105, 99, 121, 58, 65, 102, 116, 101, 114, 65, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 62, 10, 9, 93, 62, 0, 0, 0, 0, 4, 0, 45, 2, 112,
            204, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 190, 93, 1, 0, 16, 0, 122, 0, 178, 251, 0, 0,
            0, 0, 0, 128, 210, 109, 24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 96, 0, 50, 51,
            54, 45, 49, 53, 55, 45, 49, 51, 49, 54, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91,
            97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109,
            46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112,
            99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53,
            48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 41, 0, 0, 0, 0, 0, 0, 0, 2,
            1, 61, 2, 180, 201, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 61, 173, 2, 0, 16, 0, 40, 0,
            178, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 178, 251, 0, 0, 0, 0, 0, 128,
            179, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18,
            78, 235, 0, 0, 0, 0, 0, 0, 224, 146, 5, 0, 16, 0, 100, 0, 178, 251, 0, 0, 0, 0, 0, 128,
            198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91, 97, 112, 112, 60,
            97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101,
            120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105,
            101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31,
            18, 78, 235, 0, 0, 0, 0, 0, 0, 21, 150, 5, 0, 16, 0, 100, 0, 178, 251, 0, 0, 0, 0, 0,
            128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91, 97, 112, 112,
            60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101,
            120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105,
            101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31,
            18, 78, 235, 0, 0, 0, 0, 0, 0, 168, 153, 5, 0, 16, 0, 100, 0, 178, 251, 0, 0, 0, 0, 0,
            128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 74, 0, 91, 97, 112, 112,
            60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101,
            120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105,
            101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53,
            40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93, 0, 0, 0, 0, 0, 4, 0, 45, 2, 48, 14, 32, 18,
            78, 235, 0, 0, 0, 0, 0, 0, 130, 254, 5, 0, 16, 0, 137, 0, 178, 251, 0, 0, 0, 0, 0, 128,
            201, 16, 27, 18, 1, 0, 2, 0, 17, 0, 34, 3, 66, 4, 0, 0, 68, 0, 66, 4, 68, 0, 15, 0, 66,
            4, 83, 0, 16, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100, 101, 115,
            107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56, 53, 55,
            46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 0, 114, 117, 110, 110, 105,
            110, 103, 45, 97, 99, 116, 105, 118, 101, 0, 85, 115, 101, 114, 73, 110, 116, 101, 114,
            97, 99, 116, 105, 118, 101, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 79,
            235, 0, 0, 0, 0, 0, 0, 182, 236, 215, 28, 16, 0, 16, 0, 180, 251, 0, 0, 0, 0, 0, 128,
            251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0,
            38, 57, 216, 28, 16, 0, 168, 0, 180, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2,
            0, 18, 0, 34, 2, 66, 4, 0, 0, 95, 0, 66, 4, 95, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55,
            45, 49, 51, 49, 51, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97,
            112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106,
            101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112,
            112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53,
            48, 49, 41, 62, 58, 54, 52, 49, 93, 41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99,
            111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114,
            118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 2, 1, 44, 0, 192, 250, 31,
            18, 79, 235, 0, 0, 0, 0, 0, 0, 159, 224, 216, 28, 16, 0, 16, 0, 181, 251, 0, 0, 0, 0,
            0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 79, 235, 0, 0, 0,
            0, 0, 0, 197, 8, 217, 28, 16, 0, 138, 0, 181, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18,
            1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 65, 0, 66, 4, 65, 0, 41, 0, 50, 51, 54, 45, 49,
            53, 55, 45, 49, 51, 49, 50, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116,
            114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93,
            41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58,
            49, 53, 55, 93, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 79, 235, 0, 0, 0,
            0, 0, 0, 64, 236, 217, 28, 16, 0, 16, 0, 182, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18,
            1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 169, 16, 218, 28,
            16, 0, 178, 0, 182, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2,
            66, 4, 0, 0, 105, 0, 66, 4, 105, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49,
            49, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46,
            120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103,
            45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57,
            50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 41, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100,
            111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 0, 0,
            0, 0, 0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 35, 113, 219, 28,
            16, 0, 16, 0, 183, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45, 2,
            112, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 223, 146, 219, 28, 16, 0, 169, 0, 183,
            251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 96, 0,
            66, 4, 96, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 48, 32, 40, 116, 97,
            114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100,
            101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56,
            53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93,
            41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58,
            49, 53, 55, 93, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 79, 235, 0, 0,
            0, 0, 0, 0, 220, 155, 213, 30, 16, 0, 16, 0, 184, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26,
            18, 1, 0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 72, 10, 214,
            30, 16, 0, 168, 0, 184, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0,
            34, 2, 66, 4, 0, 0, 95, 0, 66, 4, 95, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51,
            49, 52, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116,
            105, 118, 101, 45, 115, 101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57,
            51, 53, 48, 52, 52, 52, 46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58,
            54, 52, 49, 93, 41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56,
            56, 41, 62, 58, 49, 53, 55, 93, 0, 2, 1, 44, 0, 192, 250, 31, 18, 79, 235, 0, 0, 0, 0,
            0, 0, 36, 73, 231, 30, 16, 0, 16, 0, 185, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1,
            0, 2, 0, 4, 0, 45, 2, 112, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 232, 164, 231, 30,
            16, 0, 178, 0, 185, 251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2,
            66, 4, 0, 0, 105, 0, 66, 4, 105, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49,
            53, 32, 40, 116, 97, 114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46,
            120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103,
            45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57,
            50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 58, 54, 52, 51, 93, 41, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 87, 105, 110, 100,
            111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58, 49, 53, 55, 93, 0, 0, 0,
            0, 0, 0, 0, 2, 1, 44, 0, 192, 250, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 130, 139, 232,
            30, 16, 0, 16, 0, 186, 251, 0, 0, 0, 0, 0, 128, 251, 42, 26, 18, 1, 0, 2, 0, 4, 0, 45,
            2, 112, 206, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 172, 203, 232, 30, 16, 0, 169, 0, 186,
            251, 0, 0, 0, 0, 0, 128, 56, 132, 24, 18, 1, 0, 2, 0, 18, 0, 34, 2, 66, 4, 0, 0, 96, 0,
            66, 4, 96, 0, 41, 0, 50, 51, 54, 45, 49, 53, 55, 45, 49, 51, 49, 54, 32, 40, 116, 97,
            114, 103, 101, 116, 58, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99, 108, 111, 117, 100, 46, 100,
            101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116, 46, 50, 55, 54, 53, 49, 56,
            53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49, 41, 62, 58, 54, 52, 55, 93,
            41, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101,
            46, 87, 105, 110, 100, 111, 119, 83, 101, 114, 118, 101, 114, 40, 56, 56, 41, 62, 58,
            49, 53, 55, 93, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 45, 2, 160, 200, 31, 18, 79, 235, 0, 0,
            0, 0, 0, 0, 111, 202, 27, 35, 16, 0, 103, 0, 180, 251, 0, 0, 0, 0, 0, 128, 1, 44, 24,
            18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 77, 0, 97, 112, 112, 60, 97, 112, 112, 108,
            105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 103, 105, 116, 104, 117, 98, 46,
            120, 111, 114, 45, 103, 97, 116, 101, 46, 115, 121, 110, 99, 116, 104, 105, 110, 103,
            45, 109, 97, 99, 111, 115, 120, 46, 51, 50, 53, 57, 50, 50, 55, 49, 46, 51, 50, 53, 57,
            50, 50, 55, 54, 40, 53, 48, 49, 41, 62, 0, 0, 4, 0, 45, 2, 160, 200, 31, 18, 79, 235,
            0, 0, 0, 0, 0, 0, 218, 223, 27, 35, 16, 0, 94, 0, 180, 251, 0, 0, 0, 0, 0, 128, 1, 44,
            24, 18, 1, 0, 2, 0, 18, 0, 34, 1, 66, 4, 0, 0, 68, 0, 97, 112, 112, 60, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 46, 99, 111, 109, 46, 110, 101, 120, 116, 99,
            108, 111, 117, 100, 46, 100, 101, 115, 107, 116, 111, 112, 99, 108, 105, 101, 110, 116,
            46, 50, 55, 54, 53, 49, 56, 53, 55, 46, 51, 50, 50, 53, 48, 56, 52, 53, 40, 53, 48, 49,
            41, 62, 0, 0, 0, 4, 0, 45, 2, 160, 200, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 183, 240,
            27, 35, 16, 0, 93, 0, 180, 251, 0, 0, 0, 0, 0, 128, 1, 44, 24, 18, 1, 0, 2, 0, 18, 0,
            34, 1, 66, 4, 0, 0, 67, 0, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115,
            101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52,
            46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 0, 0, 0, 0, 2, 1, 61, 2,
            180, 201, 31, 18, 79, 235, 0, 0, 0, 0, 0, 0, 35, 171, 28, 35, 16, 0, 40, 0, 180, 251,
            0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 180, 251, 0, 0, 0, 0, 0, 128, 187, 251,
            0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0, 2, 1, 61, 2, 96, 200, 31, 18, 79, 235,
            0, 0, 0, 0, 0, 0, 23, 50, 33, 35, 16, 0, 40, 0, 180, 251, 0, 0, 0, 0, 0, 128, 236, 0,
            0, 0, 0, 0, 0, 0, 180, 251, 0, 0, 0, 0, 0, 128, 188, 251, 0, 0, 0, 0, 0, 128, 7, 35,
            24, 18, 1, 0, 2, 0, 4, 0, 45, 2, 64, 239, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 56, 178,
            36, 35, 16, 0, 69, 0, 188, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14,
            0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46,
            97, 112, 112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101,
            114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 240, 236, 31,
            18, 80, 235, 0, 0, 0, 0, 0, 0, 150, 181, 36, 35, 16, 0, 69, 0, 188, 251, 0, 0, 0, 0, 0,
            128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101,
            109, 111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116,
            114, 111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93,
            0, 0, 0, 0, 4, 0, 45, 2, 144, 238, 31, 18, 80, 235, 0, 0, 0, 0, 0, 0, 13, 186, 36, 35,
            16, 0, 69, 0, 188, 251, 0, 0, 0, 0, 0, 128, 74, 210, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1,
            66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109, 111, 110, 60, 99, 111, 109, 46, 97, 112,
            112, 108, 101, 46, 99, 111, 110, 116, 114, 111, 108, 99, 101, 110, 116, 101, 114, 40,
            53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0, 0, 0, 0, 4, 0, 45, 2, 64, 240, 31, 18, 80,
            235, 0, 0, 0, 0, 0, 0, 242, 200, 36, 35, 16, 0, 69, 0, 188, 251, 0, 0, 0, 0, 0, 128,
            195, 214, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0, 0, 43, 0, 91, 100, 97, 101, 109,
            111, 110, 60, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 99, 111, 110, 116, 114,
            111, 108, 99, 101, 110, 116, 101, 114, 40, 53, 48, 49, 41, 62, 58, 52, 56, 51, 93, 0,
            0, 0, 0, 4, 0, 45, 2, 64, 239, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 183, 221, 36, 35, 16,
            0, 99, 0, 188, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66,
            4, 0, 0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111,
            110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101,
            101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46,
            50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0,
            0, 0, 4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 55, 225, 36, 35, 16, 0,
            99, 0, 188, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4,
            0, 0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110,
            46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46,
            108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57,
            51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0,
            1, 96, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 133, 16, 0, 0, 0, 0, 0, 0, 157, 38,
            0, 0, 0, 0, 0, 0, 136, 0, 0, 16, 0, 0, 0, 2, 42, 188, 25, 14, 104, 4, 0, 0, 2, 1, 4, 0,
            240, 243, 53, 0, 176, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 12, 0, 176, 249, 0, 0,
            0, 0, 0, 128, 163, 133, 51, 0, 0, 0, 0, 0, 2, 1, 4, 0, 32, 250, 53, 0, 177, 232, 0, 0,
            0, 0, 0, 0, 209, 67, 85, 0, 16, 0, 12, 0, 177, 249, 0, 0, 0, 0, 0, 128, 237, 115, 51,
            0, 0, 0, 0, 0, 2, 1, 4, 0, 48, 57, 126, 0, 179, 232, 0, 0, 0, 0, 0, 0, 40, 101, 197, 1,
            16, 0, 12, 0, 178, 249, 0, 0, 0, 0, 0, 128, 105, 67, 61, 0, 0, 0, 0, 0,
        ];
        let (mut data, firehose) =
            FirehosePreamble::parse_firehose_preamble(&test_firehose_data).unwrap();
        assert_eq!(firehose.chunk_tag, 0x6001);
        assert_eq!(firehose.chunk_sub_tag, 0);
        assert_eq!(firehose.chunk_data_size, 4032);
        assert_eq!(firehose.first_number_proc_id, 483);
        assert_eq!(firehose.second_number_proc_id, 1123);
        assert_eq!(firehose.collapsed, 0);
        assert_eq!(firehose.ttl, 0);
        assert_eq!(firehose.unknown, [0, 0]);
        assert_eq!(firehose.public_data_size, 4016);
        assert_eq!(firehose.private_data_virtual_offset, 4096);
        assert_eq!(firehose.unkonwn2, 0);
        assert_eq!(firehose.unknown3, 768);
        assert_eq!(firehose.base_continous_time, 4197166166425);

        let mut firehouse_result_count = firehose.public_data.len();
        while data.len() != 0 {
            let (test_data, firehose) = FirehosePreamble::parse_firehose_preamble(&data).unwrap();
            data = test_data;
            firehouse_result_count += firehose.public_data.len();
        }
        assert_eq!(firehouse_result_count, 371)
    }

    #[test]
    fn test_parse_firehose() {
        let test_firehose_data = [
            4, 0, 45, 2, 64, 239, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 183, 221, 36, 35, 16, 0, 99,
            0, 188, 251, 0, 0, 0, 0, 0, 128, 198, 202, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46,
            108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57,
            51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0,
            4, 0, 45, 2, 240, 236, 31, 18, 78, 235, 0, 0, 0, 0, 0, 0, 55, 225, 36, 35, 16, 0, 99,
            0, 188, 251, 0, 0, 0, 0, 0, 128, 115, 205, 25, 18, 1, 0, 2, 0, 14, 0, 34, 1, 66, 4, 0,
            0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 46,
            99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115, 101, 101, 46,
            108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52, 46, 50, 57,
            51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0, 0, 0, 0, 0, 0,
        ];

        let (_, firehose) = FirehosePreamble::parse_firehose(&test_firehose_data).unwrap();
        assert_eq!(firehose.unknown_log_activity_type, 4);
        assert_eq!(firehose.unknown_log_type, 0);
        assert_eq!(firehose.flags, 557);
        assert_eq!(firehose.format_string_location, 304082752);
        assert_eq!(firehose.thread_id, 60238);
        assert_eq!(firehose.continous_time_delta, 589618615);
        assert_eq!(firehose.continous_time_delta_upper, 16);
        assert_eq!(firehose.data_size, 99);
        assert_eq!(firehose.firehose_non_activity.unknown_activity_id, 64444);
        assert_eq!(firehose.firehose_non_activity.unknown_sentinal, 2147483648);
        assert_eq!(firehose.firehose_non_activity.private_strings_offset, 0);
        assert_eq!(firehose.firehose_non_activity.private_strings_size, 0);
        assert_eq!(firehose.firehose_non_activity.unknown_message_string_ref, 0);
        assert_eq!(
            firehose.firehose_non_activity.firehose_formatters.main_exe,
            false
        );

        assert_eq!(firehose.firehose_non_activity.subsystem_value, 14);
        assert_eq!(firehose.firehose_non_activity.ttl_value, 0);
        assert_eq!(firehose.firehose_non_activity.data_ref_value, 0);
        assert_eq!(
            firehose
                .firehose_non_activity
                .firehose_formatters
                .large_shared_cache,
            2
        );
        assert_eq!(
            firehose
                .firehose_non_activity
                .firehose_formatters
                .has_large_offset,
            1
        );
        assert_eq!(firehose.firehose_non_activity.unknown_pc_id, 303680198);
        assert_eq!(firehose.unknown_item, 34);
        assert_eq!(firehose.number_items, 1);
        assert_eq!(
            firehose.message.item_info[0].message_strings,
            "[app<application.com.objective-see.lulu.app.29350444.29350450(501)>:641]"
        );
    }

    #[test]
    fn test_parse_firehose_private_data_zeros() {
        let data = [
            1, 96, 0, 0, 0, 0, 0, 0, 170, 2, 0, 0, 0, 0, 0, 0, 59, 37, 18, 0, 0, 0, 0, 0, 70, 249,
            40, 0, 0, 1, 0, 0, 152, 2, 254, 15, 0, 0, 0, 2, 131, 242, 63, 252, 246, 138, 9, 0, 2,
            1, 4, 0, 240, 67, 56, 0, 174, 149, 170, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 12, 0, 144,
            131, 160, 0, 0, 0, 0, 128, 214, 201, 53, 0, 0, 0, 0, 0, 2, 1, 21, 2, 16, 85, 128, 0,
            175, 149, 170, 0, 0, 0, 0, 0, 198, 111, 97, 0, 16, 0, 36, 0, 116, 131, 160, 0, 0, 0, 0,
            128, 58, 37, 18, 0, 0, 0, 0, 0, 116, 131, 160, 0, 0, 0, 0, 128, 145, 131, 160, 0, 0, 0,
            0, 128, 217, 143, 63, 0, 0, 0, 0, 0, 2, 1, 21, 2, 32, 74, 56, 0, 175, 149, 170, 0, 0,
            0, 0, 0, 126, 204, 117, 0, 16, 0, 36, 0, 116, 131, 160, 0, 0, 0, 0, 128, 58, 37, 18, 0,
            0, 0, 0, 0, 116, 131, 160, 0, 0, 0, 0, 128, 146, 131, 160, 0, 0, 0, 0, 128, 29, 184,
            53, 0, 0, 0, 0, 0, 4, 0, 5, 2, 128, 122, 77, 2, 175, 149, 170, 0, 0, 0, 0, 0, 218, 39,
            146, 0, 16, 0, 106, 0, 116, 131, 160, 0, 0, 0, 0, 128, 5, 31, 56, 2, 18, 0, 34, 2, 66,
            4, 0, 0, 39, 0, 66, 4, 39, 0, 39, 0, 47, 83, 121, 115, 116, 101, 109, 47, 76, 105, 98,
            114, 97, 114, 121, 47, 83, 101, 99, 117, 114, 105, 116, 121, 47, 108, 100, 97, 112,
            100, 108, 46, 98, 117, 110, 100, 108, 101, 0, 123, 56, 55, 49, 57, 49, 99, 97, 54, 45,
            48, 102, 99, 57, 45, 49, 49, 100, 52, 45, 56, 52, 57, 97, 45, 48, 48, 48, 53, 48, 50,
            98, 53, 50, 49, 50, 50, 125, 0, 0, 0, 0, 0, 0, 0, 4, 0, 5, 2, 128, 122, 77, 2, 175,
            149, 170, 0, 0, 0, 0, 0, 22, 10, 147, 0, 16, 0, 113, 0, 116, 131, 160, 0, 0, 0, 0, 128,
            5, 31, 56, 2, 18, 0, 34, 2, 66, 4, 0, 0, 46, 0, 66, 4, 46, 0, 39, 0, 47, 83, 121, 115,
            116, 101, 109, 47, 76, 105, 98, 114, 97, 114, 121, 47, 70, 114, 97, 109, 101, 119, 111,
            114, 107, 115, 47, 83, 101, 99, 117, 114, 105, 116, 121, 46, 102, 114, 97, 109, 101,
            119, 111, 114, 107, 0, 123, 56, 55, 49, 57, 49, 99, 97, 48, 45, 48, 102, 99, 57, 45,
            49, 49, 100, 52, 45, 56, 52, 57, 97, 45, 48, 48, 48, 53, 48, 50, 98, 53, 50, 49, 50,
            50, 125, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 3, 1, 81, 62, 0, 0, 175, 149, 170, 0, 0, 0, 0,
            0, 93, 12, 238, 0, 16, 0, 24, 0, 116, 131, 160, 0, 0, 0, 0, 128, 255, 15, 1, 0, 68, 54,
            0, 0, 67, 1, 33, 4, 0, 0, 1, 0, 4, 0, 3, 1, 34, 62, 0, 0, 175, 149, 170, 0, 0, 0, 0, 0,
            132, 224, 240, 0, 16, 0, 24, 0, 116, 131, 160, 0, 0, 0, 0, 128, 254, 15, 1, 0, 23, 51,
            0, 0, 67, 1, 33, 4, 0, 0, 1, 0, 4, 0, 5, 2, 208, 150, 65, 6, 175, 149, 170, 0, 0, 0, 0,
            0, 209, 145, 99, 1, 16, 0, 16, 0, 116, 131, 160, 0, 0, 0, 0, 128, 252, 218, 62, 6, 1,
            0, 0, 0, 4, 0, 4, 2, 64, 153, 65, 6, 175, 149, 170, 0, 0, 0, 0, 0, 240, 9, 131, 253,
            22, 0, 8, 0, 140, 94, 64, 6, 1, 0, 0, 0, 4, 0, 4, 2, 96, 153, 65, 6, 175, 149, 170, 0,
            0, 0, 0, 0, 167, 26, 131, 253, 22, 0, 8, 0, 216, 115, 64, 6, 1, 0, 0, 0, 0, 0,
        ];
        let (_, results) = FirehosePreamble::parse_firehose_preamble(&data).unwrap();
        assert_eq!(results.private_data_virtual_offset, 4094);
        assert_eq!(results.first_number_proc_id, 1189179);
        assert_eq!(results.second_number_proc_id, 2685254);
        assert_eq!(results.base_continous_time, 2686068189033091);
        assert_eq!(results.public_data_size, 664);
        assert_eq!(results.public_data.len(), 10);
        assert_eq!(results.collapsed, 1);
    }

    #[test]
    fn test_get_firehose_items() {
        let test_data = [
            66, 4, 0, 0, 73, 0, 91, 97, 112, 112, 60, 97, 112, 112, 108, 105, 99, 97, 116, 105,
            111, 110, 46, 99, 111, 109, 46, 111, 98, 106, 101, 99, 116, 105, 118, 101, 45, 115,
            101, 101, 46, 108, 117, 108, 117, 46, 97, 112, 112, 46, 50, 57, 51, 53, 48, 52, 52, 52,
            46, 50, 57, 51, 53, 48, 52, 53, 48, 40, 53, 48, 49, 41, 62, 58, 54, 52, 49, 93, 0,
        ];
        let (_, results) = FirehosePreamble::get_firehose_items(&test_data).unwrap();
        assert_eq!(results.item_type, 66);
        assert_eq!(results.item_size, 4);
        assert_eq!(results.offset, 0);
        assert_eq!(results.message_string_size, 73);
    }

    #[test]
    fn test_parse_item_number() {
        let test_data = [1, 0, 0, 0];
        let test_size = 4;
        let (_, results) = FirehosePreamble::parse_item_number(&test_data, test_size).unwrap();
        assert_eq!(results, 1);
    }

    #[test]
    fn test_parse_item_string() {
        let test_data = [55, 57, 54, 46, 49, 48, 48, 0];
        let test_item = 34;
        let test_size = 8;
        let (_, results) =
            FirehosePreamble::parse_item_string(&test_data, &test_item, test_size).unwrap();
        assert_eq!(results, "796.100");
    }

    #[test]
    fn test_parse_firehose_has_private_strings_big_sur() {
        let test_data = [
            1, 96, 0, 0, 0, 0, 0, 0, 163, 0, 0, 0, 0, 0, 0, 0, 143, 0, 0, 0, 0, 0, 0, 0, 100, 1, 0,
            0, 0, 1, 0, 0, 56, 0, 165, 15, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 1, 16, 63,
            0, 0, 189, 3, 0, 0, 0, 0, 0, 0, 143, 31, 133, 28, 1, 0, 16, 0, 165, 15, 91, 0, 120, 58,
            0, 0, 67, 1, 33, 4, 0, 0, 91, 0, 82, 101, 99, 114, 101, 97, 116, 105, 110, 103, 32, 83,
            121, 115, 116, 101, 109, 46, 107, 101, 121, 99, 104, 97, 105, 110, 32, 98, 101, 99, 97,
            117, 115, 101, 32, 105, 116, 32, 99, 97, 110, 110, 111, 116, 32, 117, 110, 108, 111,
            99, 107, 59, 32, 115, 101, 101, 32, 47, 117, 115, 114, 47, 108, 105, 98, 101, 120, 101,
            99, 47, 115, 101, 99, 117, 114, 105, 116, 121, 45, 99, 104, 101, 99, 107, 115, 121,
            115, 116, 101, 109, 0,
        ];
        let (_, firehose) = FirehosePreamble::parse_firehose_preamble(&test_data).unwrap();
        assert_eq!(firehose.chunk_tag, 0x6001);
        assert_eq!(firehose.chunk_sub_tag, 0);
        assert_eq!(firehose.chunk_data_size, 163);
        assert_eq!(firehose.first_number_proc_id, 143);
        assert_eq!(firehose.second_number_proc_id, 356);
        assert_eq!(firehose.collapsed, 1);
        assert_eq!(firehose.ttl, 0);
        assert_eq!(firehose.unknown, [0, 0]);
        assert_eq!(firehose.public_data_size, 56);
        assert_eq!(firehose.private_data_virtual_offset, 4005);
        assert_eq!(firehose.unkonwn2, 0);
        assert_eq!(firehose.unknown3, 512);
        assert_eq!(firehose.base_continous_time, 0);

        assert_eq!(firehose.public_data.len(), 1);
        assert_eq!(firehose.public_data[0].unknown_log_activity_type, 4);
        assert_eq!(firehose.public_data[0].unknown_log_type, 0);
        assert_eq!(firehose.public_data[0].flags, 258);
        assert_eq!(firehose.public_data[0].format_string_location, 16144);
        assert_eq!(firehose.public_data[0].thread_id, 957);
        assert_eq!(firehose.public_data[0].continous_time_delta_upper, 1);
        assert_eq!(firehose.public_data[0].continous_time_delta, 478486415);
        assert_eq!(firehose.public_data[0].data_size, 16);

        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .unknown_activity_id,
            0
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .unknown_sentinal,
            0
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .private_strings_offset,
            4005
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .private_strings_size,
            91
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .unknown_message_string_ref,
            0
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .subsystem_value,
            0
        );
        assert_eq!(firehose.public_data[0].firehose_non_activity.ttl_value, 0);
        assert_eq!(
            firehose.public_data[0].firehose_non_activity.data_ref_value,
            0
        );
        assert_eq!(
            firehose.public_data[0].firehose_non_activity.unknown_pc_id,
            14968
        );

        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .main_exe,
            true
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .shared_cache,
            false
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .has_large_offset,
            0
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .large_shared_cache,
            0
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .absolute,
            false
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .uuid_relative,
            String::new()
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .main_plugin,
            false
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .pc_style,
            false
        );
        assert_eq!(
            firehose.public_data[0]
                .firehose_non_activity
                .firehose_formatters
                .main_exe_alt_index,
            0
        );
    }

    #[test]
    fn test_get_backtrace() {
        let test_data = [
            1, 0, 18, 7, 19, 0, 73, 103, 10, 236, 77, 93, 51, 131, 144, 108, 35, 245, 104, 53, 31,
            203, 169, 187, 202, 141, 55, 86, 63, 143, 187, 183, 127, 59, 151, 143, 42, 81, 94, 53,
            105, 87, 179, 55, 63, 107, 172, 169, 193, 26, 210, 26, 101, 9, 10, 32, 146, 176, 222,
            171, 50, 147, 154, 138, 220, 226, 237, 32, 38, 224, 186, 122, 214, 20, 242, 194, 62,
            137, 144, 67, 67, 221, 84, 138, 229, 177, 106, 194, 74, 58, 138, 149, 63, 163, 164, 42,
            215, 219, 179, 150, 30, 162, 252, 36, 0, 196, 33, 0, 55, 62, 183, 136, 73, 210, 38, 64,
            67, 155, 91, 36, 0, 0, 171, 102, 0, 0, 118, 1, 3, 0, 237, 0, 3, 0, 6, 56, 0, 0, 140,
            73, 0, 0, 219, 0, 3, 0, 196, 162, 33, 0, 205, 110, 38, 0, 189, 35, 0, 0, 215, 42, 0, 0,
            91, 40, 0, 0, 181, 56, 0, 0, 35, 38, 0, 0, 6, 56, 0, 0, 118, 41, 1, 0, 112, 47, 1, 0,
            23, 52, 0, 0, 47, 36, 0, 0, 6, 6, 5, 5, 4, 4, 5, 3, 3, 3, 2, 2, 1, 4, 4, 4, 4, 0, 0, 0,
            99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 112, 114, 105, 118, 97, 116, 101, 46,
            115, 117, 103, 103, 101, 115, 116, 105, 111, 110, 115, 46, 101, 118, 101, 110, 116,
            115, 0,
        ];
        let (_, results) = FirehosePreamble::get_backtrace_data(&test_data).unwrap();
        assert_eq!(results.len(), 19);
        assert_eq!(
            results,
            vec![
                "\"FC2400C42100373EB78849D22640439B\" +0x9307",
                "\"FC2400C42100373EB78849D22640439B\" +0x26283",
                "\"6AC24A3A8A953FA3A42AD7DBB3961EA2\" +0x196982",
                "\"6AC24A3A8A953FA3A42AD7DBB3961EA2\" +0x196845",
                "\"BA7AD614F2C23E89904343DD548AE5B1\" +0x14342",
                "\"BA7AD614F2C23E89904343DD548AE5B1\" +0x18828",
                "\"6AC24A3A8A953FA3A42AD7DBB3961EA2\" +0x196827",
                "\"A2092B0DEAB32939A8ADCE2ED2026E0\" +0x2204356",
                "\"A2092B0DEAB32939A8ADCE2ED2026E0\" +0x2518733",
                "\"A2092B0DEAB32939A8ADCE2ED2026E0\" +0x9149",
                "\"5E356957B3373F6BACA9C11AD21A6509\" +0x10967",
                "\"5E356957B3373F6BACA9C11AD21A6509\" +0x10331",
                "\"A9BBCA8D37563F8FBBB77F3B978F2A51\" +0x14517",
                "\"BA7AD614F2C23E89904343DD548AE5B1\" +0x9763",
                "\"BA7AD614F2C23E89904343DD548AE5B1\" +0x14342",
                "\"BA7AD614F2C23E89904343DD548AE5B1\" +0x76150",
                "\"BA7AD614F2C23E89904343DD548AE5B1\" +0x77680",
                "\"49670AEC4D5D3383906C23F568351FCB\" +0x13335",
                "\"49670AEC4D5D3383906C23F568351FCB\" +0x9263"
            ]
        );
    }

    #[test]
    fn test_collect_items() {
        let test_data = [65, 4, 0, 0, 0, 0];
        let firehose_number_items = 1;
        let firehose_flags = 513;
        let (_, results) =
            FirehosePreamble::collect_items(&test_data, &firehose_number_items, &firehose_flags)
                .unwrap();
        assert_eq!(results.item_info[0].message_strings, "<private>");
        assert_eq!(results.item_info[0].item_type, 65);
        assert_eq!(results.backtrace_strings.len(), 0);
    }

    #[test]
    fn test_parse_firehose_preamble_private_public_values() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Chunkset Tests/private_public_data.raw");

        let mut open = File::open(test_path).unwrap();

        let mut buffer = Vec::new();
        open.read_to_end(&mut buffer).unwrap();

        let (_, results) = FirehosePreamble::parse_firehose_preamble(&buffer).unwrap();

        assert_eq!(results.public_data.len(), 51);

        let mut private_public_string_count = 0;
        for entries in results.public_data {
            for firehose_entries in entries.message.item_info {
                if firehose_entries.message_strings == "EMAIL_PRIVATE_LINK_MENU_TITLE"
                    || firehose_entries.message_strings == "Send private link by email …"
                {
                    private_public_string_count += 1;
                }
            }
        }
        // EMAIL_PRIVATE_LINK_MENU_TITLE is a private string
        // Send private link by email … is a public string
        // both in same log entry
        assert_eq!(private_public_string_count, 2);
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_collect_items_bad_length() {
        let test_data = [65, 4];
        let firehose_number_items = 1;
        let firehose_flags = 513;
        let (_, _) =
            FirehosePreamble::collect_items(&test_data, &firehose_number_items, &firehose_flags)
                .unwrap();
    }

    #[test]
    fn test_parse_private_data() {
        let test_data = [
            60, 83, 90, 69, 120, 116, 114, 97, 99, 116, 111, 114, 60, 48, 120, 49, 53, 55, 56, 48,
            101, 101, 54, 48, 62, 32, 112, 114, 101, 112, 97, 114, 101, 100, 58, 89, 32, 118, 97,
            108, 105, 100, 58, 89, 32, 112, 97, 116, 104, 69, 110, 100, 105, 110, 103, 58, 99, 111,
            109, 46, 97, 112, 112, 108, 101, 46, 110, 115, 117, 114, 108, 115, 101, 115, 115, 105,
            111, 110, 100, 47, 67, 70, 78, 101, 116, 119, 111, 114, 107, 68, 111, 119, 110, 108,
            111, 97, 100, 95, 121, 87, 104, 53, 107, 56, 46, 116, 109, 112, 32, 101, 114, 114, 111,
            114, 58, 40, 110, 117, 108, 108, 41, 62, 58, 32, 83, 117, 112, 112, 108, 121, 32, 98,
            121, 116, 101, 115, 32, 119, 105, 116, 104, 32, 108, 101, 110, 103, 116, 104, 32, 54,
            53, 53, 51, 54, 32, 98, 101, 103, 97, 110, 0,
        ];
        let mut results: FirehoseItemData = FirehoseItemData {
            item_info: Vec::new(),
            backtrace_strings: Vec::new(),
        };
        let firehose_item: FirehoseItemInfo = FirehoseItemInfo {
            message_strings: String::new(),
            item_type: 33,
            item_size: 161,
        };
        results.item_info.push(firehose_item);
        let (_, _) = FirehosePreamble::parse_private_data(&test_data, &mut results).unwrap();

        assert_eq!(results.item_info[0].message_strings, "<SZExtractor<0x15780ee60> prepared:Y valid:Y pathEnding:com.apple.nsurlsessiond/CFNetworkDownload_yWh5k8.tmp error:(null)>: Supply bytes with length 65536 began")
    }

    #[test]
    fn test_parse_private_number_data() {
        let test_data = [60, 83, 90, 69, 120, 116, 114, 97];
        let mut results: FirehoseItemData = FirehoseItemData {
            item_info: Vec::new(),
            backtrace_strings: Vec::new(),
        };
        let firehose_item: FirehoseItemInfo = FirehoseItemInfo {
            message_strings: String::new(),
            item_type: 1,
            item_size: 8,
        };
        results.item_info.push(firehose_item);
        let (_, _) = FirehosePreamble::parse_private_data(&test_data, &mut results).unwrap();

        assert_eq!(results.item_info[0].message_strings, "7021802828932469564")
    }

    #[test]
    fn test_collect_items_unknown_item() {
        let test_data = [
            99, 4, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4, 0, 0, 0, 0, 4, 0, 0, 0, 0,
        ];
        let firehose_number_items = 1;
        let firehose_flags = 513;
        let (_, results) =
            FirehosePreamble::collect_items(&test_data, &firehose_number_items, &firehose_flags)
                .unwrap();
        assert_eq!(results.item_info[0].message_strings, "");
        assert_eq!(results.item_info[0].item_type, 99);
        assert_eq!(results.backtrace_strings.len(), 0);
    }

    #[test]
    fn test_firehose_header_continous_time_zero() {
        let test_data = [
            1, 96, 0, 0, 0, 0, 0, 0, 8, 16, 0, 0, 0, 0, 0, 0, 59, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0,
            0, 0, 0, 0, 248, 15, 0, 16, 0, 16, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 2, 96, 181,
            7, 0, 110, 2, 0, 0, 0, 0, 0, 0, 145, 82, 253, 56, 2, 0, 22, 0, 192, 190, 4, 0, 1, 0, 2,
            1, 34, 4, 0, 0, 8, 0, 52, 56, 51, 46, 55, 48, 48, 0, 0, 0, 4, 0, 2, 2, 96, 160, 7, 0,
            149, 2, 0, 0, 0, 0, 0, 0, 11, 10, 22, 65, 2, 0, 63, 0, 150, 69, 4, 0, 2, 0, 2, 4, 32,
            4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 66, 4, 2, 0, 18, 0, 32, 4, 20, 0, 11, 0, 0, 0, 47,
            65, 99, 116, 105, 118, 101, 32, 68, 105, 114, 101, 99, 116, 111, 114, 121, 0, 32, 97,
            115, 32, 104, 105, 100, 100, 101, 110, 0, 0, 4, 0, 2, 2, 96, 160, 7, 0, 149, 2, 0, 0,
            0, 0, 0, 0, 95, 252, 71, 65, 2, 0, 52, 0, 150, 69, 4, 0, 2, 0, 2, 4, 32, 4, 0, 0, 1, 0,
            32, 4, 1, 0, 1, 0, 66, 4, 2, 0, 7, 0, 32, 4, 9, 0, 11, 0, 0, 0, 47, 76, 111, 99, 97,
            108, 0, 32, 97, 115, 32, 104, 105, 100, 100, 101, 110, 0, 0, 0, 0, 0, 4, 0, 2, 2, 224,
            164, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 102, 107, 93, 65, 2, 0, 79, 0, 224, 244, 3, 0, 1,
            0, 2, 2, 66, 4, 0, 0, 8, 0, 34, 4, 8, 0, 51, 0, 47, 83, 101, 97, 114, 99, 104, 0, 47,
            76, 105, 98, 114, 97, 114, 121, 47, 80, 114, 101, 102, 101, 114, 101, 110, 99, 101,
            115, 47, 79, 112, 101, 110, 68, 105, 114, 101, 99, 116, 111, 114, 121, 47, 67, 111,
            110, 102, 105, 103, 117, 114, 97, 116, 105, 111, 110, 115, 47, 0, 0, 4, 0, 2, 2, 112,
            166, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 108, 129, 94, 65, 2, 0, 92, 0, 209, 253, 3, 0, 1,
            0, 2, 2, 66, 4, 0, 0, 8, 0, 66, 4, 8, 0, 64, 0, 47, 83, 101, 97, 114, 99, 104, 0, 47,
            76, 105, 98, 114, 97, 114, 121, 47, 80, 114, 101, 102, 101, 114, 101, 110, 99, 101,
            115, 47, 79, 112, 101, 110, 68, 105, 114, 101, 99, 116, 111, 114, 121, 47, 67, 111,
            110, 102, 105, 103, 117, 114, 97, 116, 105, 111, 110, 115, 47, 47, 83, 101, 97, 114,
            99, 104, 46, 112, 108, 105, 115, 116, 0, 0, 0, 0, 0, 4, 0, 2, 2, 96, 160, 7, 0, 149, 2,
            0, 0, 0, 0, 0, 0, 198, 144, 94, 65, 2, 0, 43, 0, 150, 69, 4, 0, 2, 0, 2, 4, 32, 4, 0,
            0, 1, 0, 32, 4, 1, 0, 1, 0, 66, 4, 2, 0, 8, 0, 32, 4, 10, 0, 1, 0, 0, 0, 47, 83, 101,
            97, 114, 99, 104, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 2, 96, 160, 7, 0, 149, 2, 0, 0, 0, 0,
            0, 0, 218, 0, 106, 65, 2, 0, 53, 0, 150, 69, 4, 0, 2, 0, 2, 4, 32, 4, 0, 0, 1, 0, 32,
            4, 1, 0, 1, 0, 66, 4, 2, 0, 8, 0, 32, 4, 10, 0, 11, 0, 0, 0, 47, 76, 68, 65, 80, 118,
            51, 0, 32, 97, 115, 32, 104, 105, 100, 100, 101, 110, 0, 0, 0, 0, 4, 0, 2, 2, 96, 160,
            7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 176, 255, 116, 65, 2, 0, 56, 0, 150, 69, 4, 0, 2, 0, 2,
            4, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 66, 4, 2, 0, 11, 0, 32, 4, 13, 0, 11, 0, 0, 0,
            47, 67, 111, 110, 102, 105, 103, 117, 114, 101, 0, 32, 97, 115, 32, 104, 105, 100, 100,
            101, 110, 0, 4, 0, 2, 2, 224, 164, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 63, 138, 136, 65, 2,
            0, 81, 0, 224, 244, 3, 0, 1, 0, 2, 2, 66, 4, 0, 0, 10, 0, 34, 4, 10, 0, 51, 0, 47, 67,
            111, 110, 116, 97, 99, 116, 115, 0, 47, 76, 105, 98, 114, 97, 114, 121, 47, 80, 114,
            101, 102, 101, 114, 101, 110, 99, 101, 115, 47, 79, 112, 101, 110, 68, 105, 114, 101,
            99, 116, 111, 114, 121, 47, 67, 111, 110, 102, 105, 103, 117, 114, 97, 116, 105, 111,
            110, 115, 47, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 2, 2, 112, 166, 7, 0, 149, 2, 0, 0, 0, 0,
            0, 0, 100, 26, 138, 65, 2, 0, 96, 0, 209, 253, 3, 0, 1, 0, 2, 2, 66, 4, 0, 0, 10, 0,
            66, 4, 10, 0, 66, 0, 47, 67, 111, 110, 116, 97, 99, 116, 115, 0, 47, 76, 105, 98, 114,
            97, 114, 121, 47, 80, 114, 101, 102, 101, 114, 101, 110, 99, 101, 115, 47, 79, 112,
            101, 110, 68, 105, 114, 101, 99, 116, 111, 114, 121, 47, 67, 111, 110, 102, 105, 103,
            117, 114, 97, 116, 105, 111, 110, 115, 47, 47, 67, 111, 110, 116, 97, 99, 116, 115, 46,
            112, 108, 105, 115, 116, 0, 4, 0, 2, 2, 96, 160, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 127,
            41, 138, 65, 2, 0, 45, 0, 150, 69, 4, 0, 2, 0, 2, 4, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1,
            0, 66, 4, 2, 0, 10, 0, 32, 4, 12, 0, 1, 0, 0, 0, 47, 67, 111, 110, 116, 97, 99, 116,
            115, 0, 0, 0, 0, 0, 4, 0, 2, 2, 32, 128, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 105, 23, 104,
            67, 2, 0, 8, 0, 86, 122, 2, 0, 2, 0, 0, 0, 4, 0, 2, 2, 96, 160, 7, 0, 198, 2, 0, 0, 0,
            0, 0, 0, 4, 105, 122, 67, 2, 0, 53, 0, 150, 69, 4, 0, 2, 0, 2, 4, 32, 4, 0, 0, 1, 0,
            32, 4, 1, 0, 4, 0, 66, 4, 5, 0, 15, 0, 32, 4, 20, 0, 1, 0, 0, 115, 117, 98, 0, 47, 76,
            111, 99, 97, 108, 47, 68, 101, 102, 97, 117, 108, 116, 0, 0, 0, 0, 0, 2, 1, 2, 0, 112,
            167, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 33, 251, 126, 67, 2, 0, 12, 0, 80, 0, 0, 0, 0, 0,
            0, 128, 148, 3, 4, 0, 0, 0, 0, 0, 2, 1, 2, 0, 112, 167, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0,
            189, 237, 146, 67, 2, 0, 12, 0, 81, 0, 0, 0, 0, 0, 0, 128, 148, 3, 4, 0, 0, 0, 0, 0, 4,
            0, 3, 2, 208, 167, 7, 0, 201, 2, 0, 0, 0, 0, 0, 0, 210, 210, 156, 67, 2, 0, 29, 0, 80,
            0, 0, 0, 0, 0, 0, 128, 113, 150, 4, 0, 2, 0, 2, 1, 66, 4, 0, 0, 7, 0, 47, 76, 111, 99,
            97, 108, 0, 0, 0, 0, 4, 0, 3, 2, 208, 167, 7, 0, 152, 2, 0, 0, 0, 0, 0, 0, 133, 143,
            163, 67, 2, 0, 37, 0, 81, 0, 0, 0, 0, 0, 0, 128, 113, 150, 4, 0, 2, 0, 2, 1, 66, 4, 0,
            0, 15, 0, 47, 76, 111, 99, 97, 108, 47, 68, 101, 102, 97, 117, 108, 116, 0, 0, 0, 0, 2,
            1, 2, 0, 144, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 63, 2, 174, 67, 2, 0, 12, 0, 82, 0,
            0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 112, 167, 7, 0, 149, 2, 0,
            0, 0, 0, 0, 0, 207, 141, 30, 68, 2, 0, 12, 0, 83, 0, 0, 0, 0, 0, 0, 128, 148, 3, 4, 0,
            0, 0, 0, 0, 4, 0, 3, 2, 208, 167, 7, 0, 201, 2, 0, 0, 0, 0, 0, 0, 135, 40, 46, 68, 2,
            0, 30, 0, 83, 0, 0, 0, 0, 0, 0, 128, 113, 150, 4, 0, 2, 0, 2, 1, 66, 4, 0, 0, 8, 0, 47,
            83, 101, 97, 114, 99, 104, 0, 0, 0, 2, 1, 2, 0, 144, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0,
            0, 121, 211, 50, 68, 2, 0, 12, 0, 84, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0,
            4, 0, 2, 2, 128, 182, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 183, 118, 74, 68, 2, 0, 8, 0,
            120, 201, 4, 0, 1, 0, 0, 0, 2, 1, 2, 0, 240, 188, 7, 0, 211, 2, 0, 0, 0, 0, 0, 0, 237,
            96, 77, 68, 2, 0, 12, 0, 85, 0, 0, 0, 0, 0, 0, 128, 14, 22, 5, 0, 0, 0, 0, 0, 2, 1, 19,
            0, 144, 129, 7, 0, 211, 2, 0, 0, 0, 0, 0, 0, 165, 204, 81, 68, 2, 0, 28, 0, 85, 0, 0,
            0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 86, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0,
            0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 176, 2, 0, 0, 0, 0, 0, 0, 43, 85, 223, 68, 2, 0,
            36, 0, 86, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 86, 0, 0, 0, 0, 0, 0, 128,
            87, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 240, 188, 7, 0, 211,
            2, 0, 0, 0, 0, 0, 0, 238, 110, 2, 69, 2, 0, 12, 0, 88, 0, 0, 0, 0, 0, 0, 128, 14, 22,
            5, 0, 0, 0, 0, 0, 2, 1, 19, 0, 144, 129, 7, 0, 211, 2, 0, 0, 0, 0, 0, 0, 22, 27, 3, 69,
            2, 0, 28, 0, 88, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 89, 0, 0, 0, 0, 0, 0,
            128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0,
            118, 47, 17, 69, 2, 0, 36, 0, 89, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 89,
            0, 0, 0, 0, 0, 0, 128, 90, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 4, 0, 10,
            2, 192, 149, 3, 0, 198, 2, 0, 0, 0, 0, 0, 0, 232, 5, 76, 69, 2, 0, 24, 0, 119, 48, 2,
            0, 91, 240, 239, 78, 191, 142, 58, 183, 183, 206, 80, 92, 202, 151, 165, 240, 1, 0, 0,
            0, 4, 0, 10, 2, 0, 150, 3, 0, 198, 2, 0, 0, 0, 0, 0, 0, 123, 56, 76, 69, 2, 0, 48, 0,
            107, 49, 2, 0, 91, 240, 239, 78, 191, 142, 58, 183, 183, 206, 80, 92, 202, 151, 165,
            240, 1, 0, 0, 4, 0, 4, 100, 0, 0, 0, 0, 4, 250, 0, 0, 0, 0, 4, 100, 0, 0, 0, 0, 4, 244,
            1, 0, 0, 2, 1, 19, 0, 144, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 197, 70, 91, 69, 2, 0,
            28, 0, 48, 0, 0, 0, 0, 0, 0, 128, 87, 0, 0, 0, 0, 0, 0, 0, 91, 0, 0, 0, 0, 0, 0, 128,
            43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 83,
            57, 115, 69, 2, 0, 36, 0, 48, 0, 0, 0, 0, 0, 0, 128, 87, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0,
            0, 0, 0, 0, 128, 92, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2,
            176, 129, 7, 0, 218, 2, 0, 0, 0, 0, 0, 0, 85, 38, 119, 69, 2, 0, 36, 0, 92, 0, 0, 0, 0,
            0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 92, 0, 0, 0, 0, 0, 0, 128, 93, 0, 0, 0, 0, 0, 0,
            128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 27, 0, 128, 124, 3, 0, 202, 2, 0, 0, 0, 0, 0, 0,
            180, 174, 82, 75, 2, 0, 44, 0, 65, 0, 0, 0, 0, 0, 0, 128, 52, 0, 0, 0, 0, 0, 0, 0, 94,
            0, 0, 0, 0, 0, 0, 128, 20, 60, 1, 0, 91, 240, 239, 78, 191, 142, 58, 183, 183, 206, 80,
            92, 202, 151, 165, 240, 0, 0, 0, 0, 4, 0, 3, 2, 160, 131, 7, 0, 223, 2, 0, 0, 0, 0, 0,
            0, 202, 23, 87, 75, 2, 0, 37, 0, 65, 0, 0, 0, 0, 0, 0, 128, 195, 148, 2, 0, 2, 0, 2, 2,
            66, 4, 0, 0, 9, 0, 0, 4, 2, 0, 0, 0, 103, 101, 116, 112, 119, 117, 105, 100, 0, 0, 0,
            0, 4, 0, 3, 2, 160, 131, 7, 0, 202, 2, 0, 0, 0, 0, 0, 0, 94, 173, 88, 75, 2, 0, 37, 0,
            177, 0, 0, 0, 0, 0, 0, 128, 195, 148, 2, 0, 2, 0, 2, 2, 66, 4, 0, 0, 9, 0, 0, 4, 2, 0,
            0, 0, 103, 101, 116, 112, 119, 117, 105, 100, 0, 0, 0, 0, 2, 1, 27, 0, 128, 124, 3, 0,
            201, 2, 0, 0, 0, 0, 0, 0, 53, 143, 107, 75, 2, 0, 44, 0, 48, 0, 0, 0, 0, 0, 0, 128, 87,
            0, 0, 0, 0, 0, 0, 0, 95, 0, 0, 0, 0, 0, 0, 128, 20, 60, 1, 0, 91, 240, 239, 78, 191,
            142, 58, 183, 183, 206, 80, 92, 202, 151, 165, 240, 0, 0, 0, 0, 4, 0, 3, 2, 160, 131,
            7, 0, 218, 2, 0, 0, 0, 0, 0, 0, 3, 55, 153, 75, 2, 0, 37, 0, 48, 0, 0, 0, 0, 0, 0, 128,
            195, 148, 2, 0, 2, 0, 2, 2, 66, 4, 0, 0, 9, 0, 0, 4, 2, 0, 0, 0, 103, 101, 116, 112,
            119, 117, 105, 100, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 218, 2, 0, 0, 0, 0, 0, 0,
            198, 84, 136, 77, 2, 0, 36, 0, 182, 0, 0, 0, 0, 0, 0, 128, 65, 0, 0, 0, 0, 0, 0, 0,
            182, 0, 0, 0, 0, 0, 0, 128, 208, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2,
            1, 19, 2, 176, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 11, 143, 139, 77, 2, 0, 36, 0, 208,
            0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 128, 209, 0, 0,
            0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 0, 144, 129, 7, 0, 202, 2, 0, 0,
            0, 0, 0, 0, 57, 51, 178, 77, 2, 0, 28, 0, 182, 0, 0, 0, 0, 0, 0, 128, 65, 0, 0, 0, 0,
            0, 0, 0, 210, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129,
            7, 0, 218, 2, 0, 0, 0, 0, 0, 0, 117, 196, 196, 77, 2, 0, 36, 0, 182, 0, 0, 0, 0, 0, 0,
            128, 65, 0, 0, 0, 0, 0, 0, 0, 182, 0, 0, 0, 0, 0, 0, 128, 211, 0, 0, 0, 0, 0, 0, 128,
            43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 0, 144, 129, 7, 0, 218, 2, 0, 0, 0, 0, 0, 0, 252,
            223, 207, 77, 2, 0, 28, 0, 182, 0, 0, 0, 0, 0, 0, 128, 65, 0, 0, 0, 0, 0, 0, 0, 212, 0,
            0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 7, 3, 0, 0,
            0, 0, 0, 0, 165, 245, 209, 77, 2, 0, 36, 0, 212, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0,
            0, 0, 0, 212, 0, 0, 0, 0, 0, 0, 128, 213, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0,
            0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 6, 3, 0, 0, 0, 0, 0, 0, 94, 88, 40, 78, 2, 0, 36, 0,
            183, 0, 0, 0, 0, 0, 0, 128, 65, 0, 0, 0, 0, 0, 0, 0, 183, 0, 0, 0, 0, 0, 0, 128, 214,
            0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 149, 2,
            0, 0, 0, 0, 0, 0, 251, 88, 43, 78, 2, 0, 36, 0, 214, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0,
            0, 0, 0, 0, 0, 214, 0, 0, 0, 0, 0, 0, 128, 215, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0,
            0, 0, 0, 0, 2, 1, 2, 0, 232, 129, 7, 0, 198, 2, 0, 0, 0, 0, 0, 0, 190, 47, 49, 78, 2,
            0, 12, 0, 216, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 232, 129,
            7, 0, 198, 2, 0, 0, 0, 0, 0, 0, 153, 1, 68, 78, 2, 0, 12, 0, 217, 0, 0, 0, 0, 0, 0,
            128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 218, 2, 0, 0, 0, 0, 0, 0,
            202, 100, 90, 78, 2, 0, 36, 0, 216, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0,
            216, 0, 0, 0, 0, 0, 0, 128, 218, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2,
            1, 19, 2, 176, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 122, 148, 92, 78, 2, 0, 36, 0, 218,
            0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 218, 0, 0, 0, 0, 0, 0, 128, 219, 0, 0,
            0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 27, 0, 128, 124, 3, 0, 202, 2, 0, 0,
            0, 0, 0, 0, 126, 98, 93, 78, 2, 0, 44, 0, 183, 0, 0, 0, 0, 0, 0, 128, 65, 0, 0, 0, 0,
            0, 0, 0, 220, 0, 0, 0, 0, 0, 0, 128, 20, 60, 1, 0, 91, 240, 239, 78, 191, 142, 58, 183,
            183, 206, 80, 92, 202, 151, 165, 240, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 202, 2,
            0, 0, 0, 0, 0, 0, 177, 30, 94, 78, 2, 0, 36, 0, 220, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0,
            0, 0, 0, 0, 0, 183, 0, 0, 0, 0, 0, 0, 128, 221, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0,
            0, 0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 201, 2, 0, 0, 0, 0, 0, 0, 121, 56, 97, 78, 2,
            0, 36, 0, 221, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 221, 0, 0, 0, 0, 0, 0,
            128, 222, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 232, 129, 7,
            0, 198, 2, 0, 0, 0, 0, 0, 0, 151, 19, 173, 78, 2, 0, 12, 0, 223, 0, 0, 0, 0, 0, 0, 128,
            122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 7, 3, 0, 0, 0, 0, 0, 0, 56,
            185, 189, 78, 2, 0, 36, 0, 217, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 217, 0,
            0, 0, 0, 0, 0, 128, 224, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2,
            176, 129, 7, 0, 6, 3, 0, 0, 0, 0, 0, 0, 214, 177, 192, 78, 2, 0, 36, 0, 224, 0, 0, 0,
            0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 224, 0, 0, 0, 0, 0, 0, 128, 225, 0, 0, 0, 0, 0,
            0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 232, 129, 7, 0, 198, 2, 0, 0, 0, 0, 0,
            0, 67, 212, 2, 79, 2, 0, 12, 0, 226, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0,
            2, 1, 19, 2, 144, 129, 7, 0, 23, 3, 0, 0, 0, 0, 0, 0, 130, 167, 41, 79, 2, 0, 36, 0,
            223, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 223, 0, 0, 0, 0, 0, 0, 128, 227,
            0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 218, 2,
            0, 0, 0, 0, 0, 0, 6, 193, 46, 79, 2, 0, 36, 0, 227, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0,
            0, 0, 0, 0, 227, 0, 0, 0, 0, 0, 0, 128, 228, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0,
            0, 0, 0, 2, 1, 2, 0, 232, 129, 7, 0, 198, 2, 0, 0, 0, 0, 0, 0, 163, 140, 70, 79, 2, 0,
            12, 0, 229, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 232, 129, 7,
            0, 198, 2, 0, 0, 0, 0, 0, 0, 32, 170, 237, 79, 2, 0, 12, 0, 230, 0, 0, 0, 0, 0, 0, 128,
            122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 144, 129, 7, 0, 149, 2, 0, 0, 0, 0, 0, 0, 79,
            141, 239, 79, 2, 0, 36, 0, 226, 0, 0, 0, 0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 226, 0,
            0, 0, 0, 0, 0, 128, 231, 0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2,
            176, 129, 7, 0, 202, 2, 0, 0, 0, 0, 0, 0, 185, 201, 243, 79, 2, 0, 36, 0, 231, 0, 0, 0,
            0, 0, 0, 128, 59, 0, 0, 0, 0, 0, 0, 0, 231, 0, 0, 0, 0, 0, 0, 128, 232, 0, 0, 0, 0, 0,
            0, 128, 122, 137, 2, 0, 0, 0, 0, 0, 2, 1, 2, 0, 232, 129, 7, 0, 198, 2, 0, 0, 0, 0, 0,
            0, 30, 120, 183, 81, 2, 0, 12, 0, 233, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0, 0, 0, 0,
            0, 2, 1, 19, 2, 144, 129, 7, 0, 223, 2, 0, 0, 0, 0, 0, 0, 154, 0, 6, 83, 2, 0, 36, 0,
            150, 0, 0, 0, 0, 0, 0, 128, 60, 0, 0, 0, 0, 0, 0, 0, 150, 0, 0, 0, 0, 0, 0, 128, 234,
            0, 0, 0, 0, 0, 0, 128, 43, 137, 2, 0, 0, 0, 0, 0, 2, 1, 19, 2, 176, 129, 7, 0, 223, 2,
            0, 0, 0, 0, 0, 0, 134, 94, 14, 83, 2, 0, 36, 0, 150, 0, 0, 0, 0, 0, 0, 128, 60, 0, 0,
            0, 0, 0, 0, 0, 150, 0, 0, 0, 0, 0, 0, 128, 235, 0, 0, 0, 0, 0, 0, 128, 122, 137, 2, 0,
            0, 0, 0, 0,
        ];

        let (mut data, firehose) = FirehosePreamble::parse_firehose_preamble(&test_data).unwrap();
        assert_eq!(firehose.chunk_tag, 0x6001);
        assert_eq!(firehose.chunk_sub_tag, 0);
        assert_eq!(firehose.chunk_data_size, 4104);
        assert_eq!(firehose.first_number_proc_id, 59);
        assert_eq!(firehose.second_number_proc_id, 60);
        assert_eq!(firehose.collapsed, 0);
        assert_eq!(firehose.ttl, 0);
        assert_eq!(firehose.unknown, [0, 0]);
        assert_eq!(firehose.public_data_size, 4088);
        assert_eq!(firehose.private_data_virtual_offset, 4096);
        assert_eq!(firehose.unkonwn2, 4096);
        assert_eq!(firehose.unknown3, 768);
        assert_eq!(firehose.base_continous_time, 0);

        let mut firehouse_result_count = firehose.public_data.len();
        while data.len() != 0 {
            let (test_data, firehose) = FirehosePreamble::parse_firehose_preamble(&data).unwrap();
            data = test_data;
            firehouse_result_count += firehose.public_data.len();
        }
        assert_eq!(firehouse_result_count, 66)
    }
}
