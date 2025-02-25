// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::mem::size_of;

use crate::chunks::firehose::firehose_log::FirehoseItemInfo;
use crate::decoders::decoder;
use log::{error, info, warn};
use nom::Parser;
use nom::branch::alt;
use nom::bytes::complete::{is_a, is_not, take, take_until};
use nom::character::complete::digit0;
use regex::Regex;

struct FormatAndMessage {
    formatter: String,
    message: String,
}

const FLOAT_TYPES: [&str; 6] = ["f", "F", "e", "E", "g", "G"];
const INT_TYPES: [&str; 4] = ["d", "D", "i", "u"];
const HEX_TYPES: [&str; 5] = ["x", "X", "a", "A", "p"];
const OCTAL_TYPES: [&str; 2] = ["o", "O"];
const ERROR_TYPES: [&str; 1] = ["m"];
const STRING_TYPES: [&str; 6] = ["c", "s", "@", "S", "C", "P"];

/// Format the Unified Log message entry based on the parsed log items. Formatting follows the C lang prinf formatting process
pub fn format_firehose_log_message(
    format_string: String,
    item_message: &Vec<FirehoseItemInfo>,
    message_re: &Regex,
) -> String {
    let mut log_message = format_string;
    let mut format_and_message_vec: Vec<FormatAndMessage> = Vec::new();
    info!("Unified log base message: {:?}", log_message);
    info!("Unified log entry strings: {:?}", item_message);

    // Some log entries may be completely empty (no format string or message data)
    /*
        tp 1976 + 32:       log default (shared_cache, has_subsystem)
        thread:         0000000000000d8f
        time:           +56.919s
        walltime:       1642303846 - 2022-01-15 19:30:46 (Saturday)
        location:       pc:0x1bd34bda fmt:0x1bde2be0
        image uuid:     4CA1B500-20EF-3E30-B63B-3E3579524A7F
        image path:     /System/Library/PrivateFrameworks/TelephonyUtilities.framework/Versions/A/TelephonyUtilities
        format:
        subsystem:      156 com.apple.calls.telephonyutilities.Default
    */
    if log_message.is_empty() && item_message.is_empty() {
        return String::new();
    }
    if log_message.is_empty() {
        return item_message[0].message_strings.to_owned();
    }
    let results = message_re.find_iter(&log_message);

    let mut item_index = 0;
    for formatter in results {
        // Skip literal "% " values
        if formatter.as_str().starts_with("% ") {
            continue;
        }

        let mut format_and_message = FormatAndMessage {
            formatter: String::new(),
            message: String::new(),
        };

        // %% is literal %
        if formatter.as_str() == "%%" {
            format_and_message.formatter = formatter.as_str().to_string();
            format_and_message.message = String::from("%");
            format_and_message_vec.push(format_and_message);
            continue;
        }

        // Sometimes the log message does not have all of the message strings
        // Apple labels them: "<decode: missing data>"
        if item_index >= item_message.len() {
            format_and_message.formatter = formatter.as_str().to_string();
            format_and_message.message = String::from("<Missing message data>");
            format_and_message_vec.push(format_and_message);
            continue;
        }
        let mut formatted_log_message = item_message[item_index].message_strings.to_owned();
        let formatter_string = formatter.as_str();

        // If the formatter does not have a type then the entry is the literal foramt
        // Ex: RDAlarmNotificationConsumer {identifier: %{public}%@ currentSet: %@, count: %{public}%d}
        //  -> RDAlarmNotificationConsumer {identifier: {public}<private> allowedSet: <private>, count {public}0}
        if formatter_string.starts_with("%{") && formatter_string.ends_with('}') {
            format_and_message.formatter = formatter_string.to_string();
            formatter_string.to_string().remove(0);
            format_and_message.message = formatter_string.to_string();
            format_and_message_vec.push(format_and_message);
            continue;
        }

        let private_strings = [0x1, 0x21, 0x31, 0x41];
        let private_number = 0x1;
        let private_message = 0x8000;
        if formatter_string.starts_with("%{") {
            // If item type is [0x1, 0x21, 0x31, 0x41] and the value is zero. Its appears to be a private string
            /*
               0x31 (object type) example below
                tp 16 + 413:        log default (shared_cache, has_subsystem)
                pubdata:
                00000000: 04 00 04 02 50 f7 cf 2e ea ae 00 00 00 00 00 00 ....P...........
                00000010: 00 00 00 00 10 00 85 01 1a 74 bf 2e 0d 00 03 20 .........t.....
                00000020: 22 04 00 00 02 00 41 04 00 00 00 00 42 04 02 00 ".....A.....B...
                00000030: 56 00 22 04 58 00 04 00 12 04 10 00 00 00 32 04 V.".X.........2.
                00000040: 5c 00 10 00 01 04 00 00 00 00 02 04 4f c0 00 00 \...........O...
                00000050: 12 04 10 00 00 00 31 04 00 00 00 00 42 04 6c 00 ......1.....B.l.
                00000060: 39 00 02 04 01 00 00 00 02 04 43 03 00 00 02 04 9.........C.....
                00000070: 00 00 00 00 02 04 00 00 00 00 02 04 00 00 00 00 ................
                00000080: 02 04 12 00 00 00 22 04 a5 00 04 00 02 04 00 00 ......".........
                00000090: 00 00 02 04 12 00 00 00 02 04 00 00 00 00 02 04 ................
                000000a0: 0f 00 00 00 02 04 00 00 00 00 02 04 28 00 00 00 ............(...
                000000b0: 02 08 2b 23 00 00 00 00 00 00 02 08 ad 03 00 00 ..+#............
                000000c0: 00 00 00 00 02 08 08 00 00 00 00 00 00 00 02 08 ................
                000000d0: 08 00 00 00 00 00 00 00 02 04 00 00 00 00 02 04 ................
                000000e0: 0a 00 00 00 02 08 00 00 00 00 00 00 00 00 02 04 ................
                000000f0: 00 00 00 00 39 00 73 74 72 65 61 6d 2c 20 62 75 ....9.stream, bu
                00000100: 6e 64 6c 65 20 69 64 3a 20 74 72 75 73 74 64 2c ndle id: trustd,
                00000110: 20 70 69 64 3a 20 31 35 38 2c 20 74 72 61 66 66  pid: 158, traff
                00000120: 69 63 20 63 6c 61 73 73 3a 20 31 30 30 2c 20 74 ic class: 100, t
                00000130: 6c 73 2c 20 69 6e 64 65 66 69 6e 69 74 65 2c 20 ls, indefinite,
                00000140: 6e 6f 20 63 65 6c 6c 75 6c 61 72 00 39 2e 31 00 no cellular.9.1.
                00000150: 11 5c 75 bd e7 7e 40 c2 ba cf 46 cc b6 32 da 2c .\u..~@...F..2.,
                00000160: 73 61 74 69 73 66 69 65 64 20 28 50 61 74 68 20 satisfied (Path
                00000170: 69 73 20 73 61 74 69 73 66 69 65 64 29 2c 20 69 is satisfied), i
                00000180: 6e 74 65 72 66 61 63 65 3a 20 65 6e 30 2c 20 69 nterface: en0, i
                00000190: 70 76 34 2c 20 64 6e 73 00 54 43 50 00          pv4, dns.TCP.       thread:         000000000000aeea
                    time:           +68.719s
                    walltime:       1640404673 - 2021-12-24 22:57:53 (Friday)
                    location:       pc:0x2ebf741a fmt:0x2ecff750
                    image uuid:     E185D902-AC7F-3044-87C0-AE2887C59CE7
                    image path:     /usr/lib/libnetwork.dylib
                    format:         [%{public}s %{private}@ %{public}@] cancelled
                    [%s %{uuid_t}.16P %{private,network:in_addr}d.%d<->%{private,network:sockaddr}.*P]
                    Connected Path: %@
                    Duration: %u.%03us, DNS @%u.%03us took %u.%03us, %{public}s @%u.%03us took %u.%03us, TLS took %u.%03us
                    bytes in/out: %llu/%llu, packets in/out: %llu/%llu, rtt: %u.%03us, retransmitted packets: %llu, out-of-order packets: %u
                    subsystem:      13 com.apple.network.

                    [9 <private> stream, bundle id: trustd, pid: 158, traffic class: 100, tls, indefinite, no cellular] cancelled
                    [9.1 115C75BD-E77E-40C2-BACF-46CCB632DA2C <private>.49231<-><private>]
                    Connected Path: satisfied (Path is satisfied), interface: en0, ipv4, dns
                    Duration: 1.835s, DNS @0.000s took 0.018s, TCP @0.018s took 0.015s, TLS took 0.040s
                    bytes in/out: 9003/941, packets in/out: 8/8, rtt: 0.010s, retransmitted packets: 0, out-of-order packets: 0
            */
            if private_strings.contains(&item_message[item_index].item_type)
                && item_message[item_index].message_strings.is_empty()
                && item_message[item_index].item_size == 0
                || (item_message[item_index].item_type == private_number
                    && item_message[item_index].item_size == private_message)
            {
                formatted_log_message = String::from("<private>");
            } else {
                let results = parse_type_formatter(
                    formatter_string,
                    item_message,
                    item_message[item_index].item_type,
                    item_index,
                );
                match results {
                    Ok((_, formatted_message)) => formatted_log_message = formatted_message,
                    Err(err) => warn!(
                        "Failed to format message type ex: public/private: {:?}",
                        err
                    ),
                }
            }
        } else {
            // If item type is [0x1, 0x21, 0x31, 0x41] and the size is zero (or 0x8000 for 0x1). Its appears to be a literal <private> string
            /*
                0x1 (number type) example below
                tp 456 + 54:        log default (main_exe)
                pubdata:
                00000000: 04 00 02 00 d8 07 90 00 00 00 00 00 00 00 00 00 ................
                00000010: 64 54 af 0a 00 00 1e 00 9c 00 89 00 01 04 01 04 dT..............
                00000020: 00 00 00 00 01 04 00 00 00 00 01 04 00 00 00 00 ................
                00000030: 01 04 00 00 00 00                               ......              thread:         0000000000000000
                    time:           +0.179s
                    walltime:       1642303789 - 2022-01-15 19:29:49 (Saturday)
                    location:       pc:0x89009c fmt:0x9007d8
                    image uuid:     ABC69550-60C2-34FE-B307-C24A8C39309C
                    image path:     /kernel
                    format:         kext submap [0x%lx - 0x%lx], kernel text [0x%lx - 0x%lx]
                kext submap [0x<private> - 0x<private>], kernel text [0x<private> - 0x<private>]
            */
            if private_strings.contains(&item_message[item_index].item_type)
                && item_message[item_index].message_strings.is_empty()
                && item_message[item_index].item_size == 0
                || (item_message[item_index].item_type == private_number
                    && item_message[item_index].item_size == private_message)
            {
                formatted_log_message = String::from("<private>");
            } else {
                let results = parse_formatter(
                    formatter_string,
                    item_message,
                    item_message[item_index].item_type,
                    item_index,
                );
                match results {
                    Ok((_, formatted_message)) => formatted_log_message = formatted_message,
                    Err(err) => warn!("[macos-unifiedlogs] Failed to format message: {:?}", err),
                }
            }
        }

        const PRECISION_ITEMS: [u8; 2] = [0x10, 0x12]; // dynamic precision item types?
        // If the item message was a precision type increment to actual value
        if PRECISION_ITEMS.contains(&item_message[item_index].item_type) {
            item_index += 1;
        }

        if item_index >= item_message.len() {
            format_and_message.formatter = formatter.as_str().to_string();
            format_and_message.message = String::from("<Missing message data>");
            format_and_message_vec.push(format_and_message);
            continue;
        }

        // Also seen number type value 0 also used for dynamic width/precision value
        let dynamic_precision_value = 0x0;
        if (item_message[item_index].item_type == dynamic_precision_value
            && item_message[item_index].item_size == 0)
            && formatter_string.contains("%*")
        {
            item_index += 1;
        }

        item_index += 1;
        format_and_message.formatter = formatter.as_str().to_string();
        format_and_message.message = formatted_log_message;
        format_and_message_vec.push(format_and_message);
    }

    let mut log_message_vec: Vec<String> = Vec::new();
    for values in format_and_message_vec {
        // Split the values by printf formatter
        // We have to do this instead of using replace because our replacement string may also contain a printf formatter
        let message_results = log_message.split_once(&values.formatter);
        match message_results {
            Some((message_part, remaining_message)) => {
                log_message_vec.push(message_part.to_string());
                log_message_vec.push(values.message);
                log_message = remaining_message.to_string();
            }
            None => error!(
                "Failed to split log message ({}) by printf formatter: {}",
                log_message, &values.formatter
            ),
        }
    }
    log_message_vec.push(log_message);
    log_message_vec.join("")
}

// Format strings are based on C printf formats. Parse format specification
fn parse_formatter<'a>(
    formatter: &'a str,
    message_value: &'a [FirehoseItemInfo],
    item_type: u8,
    item_index: usize,
) -> nom::IResult<&'a str, String> {
    let mut index = item_index;

    const PRECISION_ITEMS: [u8; 2] = [0x10, 0x12];
    let mut precision_value = 0;
    if PRECISION_ITEMS.contains(&item_type) {
        precision_value = message_value[index].item_size as usize;
        index += 1;

        if index >= message_value.len() {
            error!(
                "[macos-unifiedlogs] Index now greater than messages array. This should not have happened. Index: {index}. Message Array len: {}",
                message_value.len()
            );
            return Ok(("", String::from("Failed to format string due index length")));
        }
    }

    let mut message = message_value[index].message_strings.to_owned();

    let number_item_type: Vec<u8> = vec![0x0, 0x1, 0x2];

    // If the message formatter is expects a string/character and the message string is a number type
    // Try to convert to a character/string
    if formatter.to_lowercase().ends_with('c')
        && number_item_type.contains(&message_value[index].item_type)
    {
        let char_results = message_value[index].message_strings.parse::<u32>();
        match char_results {
            Ok(char_message) => message = (char_message as u8 as char).to_string(),
            Err(err) => {
                error!(
                    "[macos-unifiedlogs] Failed to parse number item to char string: {:?}",
                    err
                );
                return Ok((
                    "",
                    String::from("Failed to parse number item to char string"),
                ));
            }
        }
    }

    let mut left_justify = false;
    //let mut space_value = false;
    let mut hashtag = false;
    let mut pad_zero = false;
    let mut plus_minus = false;
    let mut width_index = 1;
    //let mut has_apostrophe = false;
    for (index, format_values) in formatter.chars().enumerate() {
        if index == 0 {
            continue;
        }

        match format_values {
            '-' => left_justify = true,
            '+' => plus_minus = true,
            //' ' => space_value = true,
            '#' => hashtag = true,
            '0' => pad_zero = true,
            // '\'' => has_apostrophe = true,
            _ => {
                width_index = index;
                break;
            }
        }
    }

    let mut formatter_message = &formatter[width_index..];
    let (input, mut width) = digit0(formatter_message)?;
    formatter_message = input;
    let width_value;

    if formatter_message.starts_with('*') {
        // Also seen number type value 0 used for dynamic width/precision value
        const DYNAMIC_PRECISION_VALUE: u8 = 0x0;
        if item_type == DYNAMIC_PRECISION_VALUE && message_value[index].item_size == 0 {
            precision_value = message_value[index].item_size as usize;
            index += 1;
            if index >= message_value.len() {
                error!(
                    "[macos-unifiedlogs] Index now greater than messages array. This should not have happened. Index: {index}. Message Array len: {}",
                    message_value.len()
                );
                return Ok((
                    "",
                    String::from("Failed to format precision/dynamic string due index length"),
                ));
            }
            message_value[index]
                .message_strings
                .clone_into(&mut message);
        }

        width_value = format!("{}", precision_value);
        width = width_value.as_str();
        let (input, _) = take(size_of::<u8>())(formatter_message)?;
        formatter_message = input;
    }

    if formatter_message.starts_with('.') {
        let (input, _) = is_a(".")(formatter_message)?;
        let (input, precision_data) = is_not("hljzZtqLdDiuUoOcCxXfFeEgGaASspPn%@")(input)?;
        if precision_data != "*" {
            let precision_results = precision_data.parse::<usize>();
            match precision_results {
                Ok(value) => precision_value = value,
                Err(err) => error!(
                    "[macos-unifiedlogs] Failed to parse format precision value: {:?}",
                    err
                ),
            }
        } else if precision_value != 0 {
            // For dynamic length use the length of the message string
            precision_value = message_value.len();
        }
        formatter_message = input;
    }

    // Get Length data if it exists or get the type format
    let (input, length_data) =
        alt((is_a("hlwIztq"), is_a("cmCdiouxXeEfgGaAnpsSZP@"))).parse(formatter_message)?;
    formatter_message = input;

    let mut type_data = length_data;
    let length_values = ["h", "hh", "l", "ll", "w", "I", "z", "t", "q"];
    if length_values.contains(&length_data) {
        let (_, type_format) = is_a("cmCdiouxXeEfgGaAnpsSZP@")(formatter_message)?;
        type_data = type_format;
    }

    // Error types map error code to error message string. Currently not mapping to error message string
    // Ex: open on %s: %m
    //    "open on /var/folders: No such file or directory"
    // "No such file or directory" is error code 2
    if ERROR_TYPES.contains(&type_data) {
        message = format!("Error code: {}", message);
        return Ok(("", message));
    }

    if !width.is_empty() {
        let mut width_value = 0;
        let width_results = width.parse::<usize>();
        match width_results {
            Ok(value) => width_value = value,
            Err(err) => error!(
                "[macos-unifiedlogs] Failed to parse format width value: {:?}",
                err
            ),
        }
        if pad_zero {
            // Pad using zeros instead of spaces
            if left_justify {
                message = format_alignment_left(
                    message,
                    width_value,
                    precision_value,
                    type_data,
                    plus_minus,
                    hashtag,
                )
            } else {
                message = format_alignment_right(
                    message,
                    width_value,
                    precision_value,
                    type_data,
                    plus_minus,
                    hashtag,
                )
            }
        } else {
            // Pad spaces instead of zeros
            if left_justify {
                message = format_alignment_left_space(
                    message,
                    width_value,
                    precision_value,
                    type_data,
                    plus_minus,
                    hashtag,
                )
            } else {
                message = format_alignment_right_space(
                    message,
                    width_value,
                    precision_value,
                    type_data,
                    plus_minus,
                    hashtag,
                )
            }
        }
    } else if left_justify {
        message = format_left(message, precision_value, type_data, plus_minus, hashtag)
    } else {
        message = format_right(message, precision_value, type_data, plus_minus, hashtag);
    }

    Ok(("", message))
}

// Function to parse formatters containing types. Ex: %{errno}d, %{public}s, %{private}s, %{sensitive}
fn parse_type_formatter<'a>(
    formatter: &'a str,
    message_value: &'a [FirehoseItemInfo],
    item_type: u8,
    item_index: usize,
) -> nom::IResult<&'a str, String> {
    let (format, format_type) = take_until("}")(formatter)?;

    let apple_object = decoder::check_objects(format_type, message_value, item_type, item_index);

    // If we successfully decoded an apple object, then there is nothing to format.
    // Signpost entries have not been seen with custom objects
    if !apple_object.is_empty() {
        return Ok(("", apple_object));
    }

    let (_, mut message) = parse_formatter(format, message_value, item_type, item_index)?;
    if format_type.contains("signpost") {
        let (_, signpost_message) = parse_signpost_format(format_type)?;
        message = format!("{} ({})", message, signpost_message);
    }
    Ok(("", message))
}

// Try to parse additional signpost metadata.
// Ex: %{public,signpost.description:attribute}@
//     %{public,signpost.telemetry:number1,name=SOSSignpostNameSOSCCCopyApplicantPeerInfo}d
fn parse_signpost_format(signpost_format: &str) -> nom::IResult<&str, String> {
    let mut signpost_message;
    let (signpost_value, _) = is_a("%{")(signpost_format)?;

    if signpost_format.starts_with("%{sign") {
        let signpost_vec: Vec<&str> = signpost_value.split(',').collect();
        signpost_message = signpost_vec[0].to_string();
    } else {
        let signpost_vec: Vec<&str> = signpost_value.split(',').collect();
        signpost_message = signpost_vec[1].to_string();
        signpost_message = signpost_message.trim().to_string();
    }
    Ok(("", signpost_message))
}

// Align the message to the left and pad using zeros instead of spaces
fn format_alignment_left(
    format_message: String,
    format_width: usize,
    format_precision: usize,
    type_data: &str,
    plus_minus: bool,
    hashtag: bool,
) -> String {
    let mut message = format_message;
    let mut precision_value = format_precision;
    let mut plus_option = String::new();

    let mut adjust_width = 0;
    if plus_minus {
        plus_option = String::from("+");
        adjust_width = 1;
    }

    if FLOAT_TYPES.contains(&type_data) {
        let float_message = parse_float(message);
        if precision_value == 0 {
            let message_float = float_message.to_string();
            let float_precision: Vec<&str> = message_float.split('.').collect();
            if float_precision.len() == 2 {
                precision_value = float_precision[1].len();
            }
        }
        message = format!(
            "{plus_symbol}{:0<width$.precision$}",
            float_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if INT_TYPES.contains(&type_data) {
        let int_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:0<width$.precision$}",
            int_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if STRING_TYPES.contains(&type_data) {
        if precision_value == 0 {
            precision_value = message.len()
        }
        message = format!(
            "{plus_symbol}{:0<width$.precision$}",
            message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if HEX_TYPES.contains(&type_data) {
        let hex_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:0<#width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:0<width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    } else if OCTAL_TYPES.contains(&type_data) {
        let octal_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:0<#width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:0<width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    }
    message
}

// Align the message to the right and pad using zeros instead of spaces
fn format_alignment_right(
    format_message: String,
    format_width: usize,
    format_precision: usize,
    type_data: &str,
    plus_minus: bool,
    hashtag: bool,
) -> String {
    let mut message = format_message;
    let mut precision_value = format_precision;
    let mut plus_option = String::new();

    let mut adjust_width = 0;
    if plus_minus {
        plus_option = String::from("+");
        adjust_width = 1;
    }

    if FLOAT_TYPES.contains(&type_data) {
        let float_message = parse_float(message);
        if precision_value == 0 {
            let message_float = float_message.to_string();
            let float_precision: Vec<&str> = message_float.split('.').collect();
            if float_precision.len() == 2 {
                precision_value = float_precision[1].len();
            }
        }
        message = format!(
            "{plus_symbol}{:0>width$.precision$}",
            float_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if INT_TYPES.contains(&type_data) {
        let int_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:0>width$.precision$}",
            int_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if STRING_TYPES.contains(&type_data) {
        if precision_value == 0 {
            precision_value = message.len()
        }
        message = format!(
            "{plus_symbol}{:0>width$.precision$}",
            message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if HEX_TYPES.contains(&type_data) {
        let hex_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:0>#width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:0>width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    } else if OCTAL_TYPES.contains(&type_data) {
        let octal_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:0>#width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:0>width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    }
    message
}

// Align the message to the left and pad using spaces
fn format_alignment_left_space(
    format_message: String,
    format_width: usize,
    format_precision: usize,
    type_data: &str,
    plus_minus: bool,
    hashtag: bool,
) -> String {
    let mut message = format_message;
    let mut precision_value = format_precision;
    let mut plus_option = String::new();

    let mut adjust_width = 0;
    if plus_minus {
        plus_option = String::from("+");
        adjust_width = 1;
    }

    if FLOAT_TYPES.contains(&type_data) {
        let float_message = parse_float(message);
        if precision_value == 0 {
            let message_float = float_message.to_string();
            let float_precision: Vec<&str> = message_float.split('.').collect();
            if float_precision.len() == 2 {
                precision_value = float_precision[1].len();
            }
        }
        message = format!(
            "{plus_symbol}{:<width$.precision$}",
            float_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if INT_TYPES.contains(&type_data) {
        let int_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:<width$.precision$}",
            int_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if STRING_TYPES.contains(&type_data) {
        if precision_value == 0 {
            precision_value = message.len()
        }
        message = format!(
            "{plus_symbol}{:<width$.precision$}",
            message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if HEX_TYPES.contains(&type_data) {
        let hex_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:<#width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:<width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    } else if OCTAL_TYPES.contains(&type_data) {
        let octal_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:<#width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:<width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    }
    message
}

// Align the message to the right and pad using spaces
fn format_alignment_right_space(
    format_message: String,
    format_width: usize,
    format_precision: usize,
    type_data: &str,
    plus_minus: bool,
    hashtag: bool,
) -> String {
    let mut message = format_message;
    let mut precision_value = format_precision;
    let mut plus_option = String::new();

    let mut adjust_width = 0;
    if plus_minus {
        plus_option = String::from("+");
        adjust_width = 1;
    }

    if FLOAT_TYPES.contains(&type_data) {
        let float_message = parse_float(message);
        if precision_value == 0 {
            let message_float = float_message.to_string();
            let float_precision: Vec<&str> = message_float.split('.').collect();
            if float_precision.len() == 2 {
                precision_value = float_precision[1].len();
            }
        }
        message = format!(
            "{plus_symbol}{:>width$.precision$}",
            float_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if INT_TYPES.contains(&type_data) {
        let int_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:>width$.precision$}",
            int_message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if STRING_TYPES.contains(&type_data) {
        if precision_value == 0 {
            precision_value = message.len()
        }
        message = format!(
            "{plus_symbol}{:>width$.precision$}",
            message,
            width = format_width - adjust_width,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if HEX_TYPES.contains(&type_data) {
        let hex_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:>#width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:>width$.precision$X}",
                hex_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    } else if OCTAL_TYPES.contains(&type_data) {
        let octal_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:>#width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:>width$.precision$o}",
                octal_message,
                width = format_width - adjust_width,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    }
    message
}

// Align the message to the left
fn format_left(
    format_message: String,
    format_precision: usize,
    type_data: &str,
    plus_minus: bool,
    hashtag: bool,
) -> String {
    let mut message = format_message;
    let mut precision_value = format_precision;
    let mut plus_option = String::new();

    if plus_minus {
        plus_option = String::from("+");
    }

    if FLOAT_TYPES.contains(&type_data) {
        let float_message = parse_float(message);
        if precision_value == 0 {
            let message_float = float_message.to_string();
            let float_precision: Vec<&str> = message_float.split('.').collect();
            if float_precision.len() == 2 {
                precision_value = float_precision[1].len();
            }
        }

        message = format!(
            "{plus_symbol}{:<.precision$}",
            float_message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if INT_TYPES.contains(&type_data) {
        let int_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:<.precision$}",
            int_message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if STRING_TYPES.contains(&type_data) {
        if precision_value == 0 {
            precision_value = message.len()
        }
        message = format!(
            "{plus_symbol}{:<.precision$}",
            message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if HEX_TYPES.contains(&type_data) {
        let hex_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:<#.precision$X}",
                hex_message,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:<.precision$X}",
                hex_message,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    } else if OCTAL_TYPES.contains(&type_data) {
        let octal_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:<#.precision$o}",
                octal_message,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:<.precision$o}",
                octal_message,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    }
    message
}

// Align the message to the right (default)
fn format_right(
    format_message: String,
    format_precision: usize,
    type_data: &str,
    plus_minus: bool,
    hashtag: bool,
) -> String {
    let mut message = format_message;
    let mut precision_value = format_precision;
    let mut plus_option = String::new();

    if plus_minus {
        plus_option = String::from("+");
    }

    if FLOAT_TYPES.contains(&type_data) {
        let float_message = parse_float(message);
        if precision_value == 0 {
            let message_float = float_message.to_string();
            let float_precision: Vec<&str> = message_float.split('.').collect();
            if float_precision.len() == 2 {
                precision_value = float_precision[1].len();
            }
        }

        message = format!(
            "{plus_symbol}{:>.precision$}",
            float_message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if INT_TYPES.contains(&type_data) {
        let int_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:>.precision$}",
            int_message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if STRING_TYPES.contains(&type_data) {
        if precision_value == 0 {
            precision_value = message.len()
        }
        message = format!(
            "{plus_symbol}{:>.precision$}",
            message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    } else if HEX_TYPES.contains(&type_data) {
        let hex_message = parse_int(message);
        if hashtag {
            message = format!(
                "{plus_symbol}{:>#.precision$X}",
                hex_message,
                precision = precision_value,
                plus_symbol = plus_option
            );
        } else {
            message = format!(
                "{plus_symbol}{:>.precision$X}",
                hex_message,
                precision = precision_value,
                plus_symbol = plus_option
            );
        }
    } else if OCTAL_TYPES.contains(&type_data) {
        let octal_message = parse_int(message);
        message = format!(
            "{plus_symbol}{:>#.precision$o}",
            octal_message,
            precision = precision_value,
            plus_symbol = plus_option
        );
    }
    message
}

// Parse the float string log message to float value
fn parse_float(message: String) -> f64 {
    let byte_results = message.parse::<i64>();
    match byte_results {
        Ok(bytes) => return f64::from_bits(bytes as u64),
        Err(err) => error!(
            "[macos-unifiedlogs] Failed to parse float log message value: {}, err: {:?}",
            message, err
        ),
    }
    f64::from_bits(0)
}

// Parse the int string log message to int value
fn parse_int(message: String) -> i64 {
    let int_results = message.parse::<i64>();
    match int_results {
        Ok(message) => return message,
        Err(err) => error!(
            "[macos-unifiedlogs] Failed to parse int log message value: {}, err: {:?}",
            message, err
        ),
    }
    0
}

#[cfg(test)]
mod tests {
    use crate::chunks::firehose::firehose_log::FirehoseItemInfo;
    use crate::message::{
        format_alignment_left, format_alignment_left_space, format_alignment_right,
        format_alignment_right_space, format_firehose_log_message, format_left, format_right,
        parse_float, parse_formatter, parse_int, parse_signpost_format, parse_type_formatter,
    };
    use regex::Regex;

    #[test]
    fn test_format_firehose_log_message() {
        let test_data = String::from("opendirectoryd (build %{public}s) launched...");
        let item_message = vec![FirehoseItemInfo {
            message_strings: String::from("796.100"),
            item_type: 34,
            item_size: 0,
        }];
        let message_re = Regex::new(r"(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))").unwrap();

        let log_string = format_firehose_log_message(test_data, &item_message, &message_re);
        assert_eq!(log_string, "opendirectoryd (build 796.100) launched...")
    }

    #[test]
    fn test_parse_formatter() {
        let test_format = "%+04d";
        let mut test_message = Vec::new();

        let test_data = FirehoseItemInfo {
            message_strings: String::from("2"),
            item_type: 2,
            item_size: 2,
        };
        test_message.push(test_data);

        let item_index = 0;
        let (_, formatted_results) = parse_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "+002");

        let test_format = "%04d";
        let (_, formatted_results) = parse_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "0002");

        let test_format = "%#4x";
        let (_, formatted_results) = parse_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, " 0x2");

        let test_format = "%#04o";
        test_message[0].message_strings = String::from("100");
        let (_, formatted_results) = parse_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "0o144");

        let test_format = "%07o";
        let (_, formatted_results) = parse_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "0000144");

        let test_format = "%x";
        test_message[0].message_strings = String::from("10");
        let (_, formatted_results) = parse_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "A");

        let test_float = "%+09.4f";
        test_message[0].message_strings = String::from("4570111009880014848");
        let (_, formatted_results) = parse_formatter(
            test_float,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "+000.0035");

        let test_float = "%9.4f";
        let (_, formatted_results) = parse_formatter(
            test_float,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "   0.0035");

        let test_float = "%-8.4f";
        let (_, formatted_results) = parse_formatter(
            test_float,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "0.0035  ");

        let test_float = "%f";
        test_message[0].message_strings = String::from("4614286721111404799");
        let (_, formatted_results) = parse_formatter(
            test_float,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "3.154944");

        let test_int = "%d";
        test_message[0].message_strings = String::from("-248");
        let (_, formatted_results) = parse_formatter(
            test_int,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "-248");

        let test_float = "%f";
        test_message[0].message_strings = String::from("-4611686018427387904");
        let (_, formatted_results) = parse_formatter(
            test_float,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "-2");

        let test_float = "%f";
        test_message[0].message_strings = String::from("-4484628366119329180");
        let (_, formatted_results) = parse_formatter(
            test_float,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "-650937839.633862");

        let test_string = "%s";
        test_message[0].message_strings = String::from("The big red dog jumped over the crab");
        let (_, formatted_results) = parse_formatter(
            test_string,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "The big red dog jumped over the crab");

        let test_string = "%.2@";
        test_message[0].message_strings = String::from("aaabbbb");
        let (_, formatted_results) = parse_formatter(
            test_string,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "aa");

        let test_string = "%*s";
        test_message[0].item_size = 10;
        test_message[0].item_type = 0x12;
        let test_data2 = FirehoseItemInfo {
            message_strings: String::from("hi"),
            item_type: 2,
            item_size: 2,
        };
        test_message.push(test_data2);
        let (_, formatted_results) = parse_formatter(
            test_string,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "        hi");
    }

    #[test]
    fn test_parse_type_formatter() {
        let mut test_format = "%{public}s";
        let mut test_message = Vec::new();

        let mut test_data = FirehoseItemInfo {
            message_strings: String::from("test"),
            item_type: 2,
            item_size: 4,
        };
        test_message.push(test_data);

        let item_index = 0;
        let (_, formatted_results) = parse_type_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "test");

        test_format = "%{public, signpost.description:begin_time}llu";
        let mut test_message = Vec::new();

        test_data = FirehoseItemInfo {
            message_strings: String::from("1"),
            item_type: 2,
            item_size: 4,
        };
        test_message.push(test_data);

        let item_index = 0;
        let (_, formatted_results) = parse_type_formatter(
            test_format,
            &test_message,
            test_message[0].item_type,
            item_index,
        )
        .unwrap();
        assert_eq!(formatted_results, "1 (signpost.description:begin_time)");
    }

    #[test]
    fn test_parse_signpost_format() {
        let test_format = "%{public, signpost.description:begin_time";
        let (_, results) = parse_signpost_format(test_format).unwrap();
        assert_eq!(results, "signpost.description:begin_time");
    }

    #[test]
    fn test_format_alignment_left() {
        let test_type = "d";
        let test_width = 4;
        let test_precision = 0;
        let test_format = String::from("2");
        let plus_minus = false;
        let hashtag = false;
        let formatted_results = format_alignment_left(
            test_format,
            test_width,
            test_precision,
            test_type,
            plus_minus,
            hashtag,
        );
        assert_eq!(formatted_results, "2000");
    }

    #[test]
    fn test_format_alignment_right() {
        let test_type = "d";
        let test_width = 4;
        let test_precision = 0;
        let test_format = String::from("2");
        let plus_minus = false;
        let hashtag = false;
        let formatted_results = format_alignment_right(
            test_format,
            test_width,
            test_precision,
            test_type,
            plus_minus,
            hashtag,
        );
        assert_eq!(formatted_results, "0002");
    }

    #[test]
    fn test_format_alignment_left_space() {
        let test_type = "d";
        let test_width = 4;
        let test_precision = 0;
        let test_format = String::from("2");
        let plus_minus = false;
        let hashtag = false;
        let formatted_results = format_alignment_left_space(
            test_format,
            test_width,
            test_precision,
            test_type,
            plus_minus,
            hashtag,
        );
        assert_eq!(formatted_results, "2   ");
    }

    #[test]
    fn test_format_alignment_right_space() {
        let test_type = "d";
        let test_width = 4;
        let test_precision = 0;
        let test_format = String::from("2");
        let plus_minus = false;
        let hashtag = false;
        let formatted_results = format_alignment_right_space(
            test_format,
            test_width,
            test_precision,
            test_type,
            plus_minus,
            hashtag,
        );
        assert_eq!(formatted_results, "   2");
    }

    #[test]
    fn test_format_left() {
        let test_type = "d";
        let test_precision = 0;
        let test_format = String::from("2");
        let plus_minus = false;
        let hashtag = false;
        let formatted_results =
            format_left(test_format, test_precision, test_type, plus_minus, hashtag);
        assert_eq!(formatted_results, "2");
    }

    #[test]
    fn test_format_right() {
        let test_type = "d";
        let test_precision = 0;
        let test_format = String::from("2");
        let plus_minus = false;
        let hashtag = false;
        let formatted_results =
            format_right(test_format, test_precision, test_type, plus_minus, hashtag);
        assert_eq!(formatted_results, "2");
    }

    #[test]
    fn test_parse_float() {
        let value = String::from("4611911198408756429");
        let results = parse_float(value);
        assert_eq!(results, 2.1);
    }

    #[test]
    fn test_parse_int() {
        let value = String::from("2");
        let results = parse_int(value);
        assert_eq!(results, 2);
    }
}
