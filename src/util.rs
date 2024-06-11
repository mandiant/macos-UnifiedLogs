// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use base64::engine::general_purpose;
use base64::DecodeError;
use base64::Engine;
use chrono::SecondsFormat;
use chrono::TimeZone;
use chrono::Utc;
use log::{error, warn};
use nom::bytes::complete::take;
use nom::bytes::complete::take_while;
use std::str::from_utf8;

/// Calculate 8 byte padding
pub(crate) fn padding_size(data: u64) -> u64 {
    let alignment = 8;
    // Calculate padding to achieve 64-bit alignment
    (alignment - (data & (alignment - 1))) & (alignment - 1)
}

/// Calculate 4 byte padding
pub(crate) fn padding_size_four(data: u64) -> u64 {
    let alignment = 4;
    // Calculate padding to achieve 64-bit alignment
    (alignment - (data & (alignment - 1))) & (alignment - 1)
}

/// Extract a size based on provided string size from Firehose string item entries
pub(crate) fn extract_string_size(data: &[u8], message_size: u64) -> nom::IResult<&[u8], String> {
    let null_string = 0;
    if message_size == null_string {
        return Ok((data, String::from("(null)")));
    }

    // If our remaining data is smaller than the message string size just go until the end of the remaining data
    if data.len() < message_size as usize {
        // Get whole string message except end of string (0s)
        let (input, path) = take(data.len())(data)?;
        let path_string = String::from_utf8(path.to_vec());
        match path_string {
            Ok(results) => return Ok((input, results.trim_end_matches(char::from(0)).to_string())),
            Err(err) => error!(
                "[macos-unifiedlogs] Failed to get extract specific string size: {:?}",
                err
            ),
        }
    }

    // Get whole string message except end of string (0s)
    let (input, path) = take(message_size)(data)?;
    let path_string = String::from_utf8(path.to_vec());
    match path_string {
        Ok(results) => return Ok((input, results.trim_end_matches(char::from(0)).to_string())),
        Err(err) => error!(
            "[macos-unifiedlogs] Failed to get specific string: {:?}",
            err
        ),
    }
    Ok((input, String::from("Could not find path string")))
}

/// Extract strings that contain end of string characters
pub(crate) fn extract_string(data: &[u8]) -> nom::IResult<&[u8], String> {
    let last_value = data.last();
    match last_value {
        Some(value) => {
            let has_end_of_string: u8 = 0;

            // If message data does not end with end of string character (0)
            // just grab everything and convert what we have to string
            if value != &has_end_of_string {
                let (input, path) = take(data.len())(data)?;
                let path_string = from_utf8(path);
                match path_string {
                    Ok(results) => return Ok((input, results.to_string())),
                    Err(err) => {
                        warn!(
                            "[macos-unifiedlogs] Failed to extract full string: {:?}",
                            err
                        );
                        return Ok((input, String::from("Could not extract string")));
                    }
                }
            }
        }
        None => {
            error!("[macos-unifiedlogs] Cannot extract string. Empty input.");
            return Ok((data, String::from("Cannot extract string. Empty input.")));
        }
    }

    let (input, path) = take_while(|b: u8| b != 0)(data)?;
    let path_string = from_utf8(path);
    match path_string {
        Ok(results) => {
            return Ok((input, results.to_string()));
        }
        Err(err) => {
            warn!("[macos-unifiedlogs] Failed to get string: {:?}", err);
        }
    }
    Ok((input, String::from("Could not extract string")))
}

/// Clean and format UUIDs to be pretty
pub(crate) fn clean_uuid(uuid_format: &str) -> String {
    uuid_format.replace([',', '[', ']', ' '], "")
}

/// Base64 encode data use the STANDARD engine (alphabet along with "+" and "/")
pub(crate) fn encode_standard(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Base64 decode data use the STANDARD engine (alphabet along with "+" and "/")
pub(crate) fn decode_standard(data: &str) -> Result<Vec<u8>, DecodeError> {
    general_purpose::STANDARD.decode(data)
}

/// Convert `UnixEpoch` time to ISO RFC 3339
pub(crate) fn unixepoch_to_iso(timestamp: &i64) -> String {
    let date_time_result = Utc.timestamp_nanos(*timestamp);
    date_time_result.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

#[cfg(test)]
mod tests {
    use super::{decode_standard, encode_standard, unixepoch_to_iso};
    use crate::util::{extract_string, extract_string_size, padding_size, padding_size_four};

    #[test]
    fn test_padding_size() {
        let data = 8;
        let results = padding_size(data);
        assert_eq!(results, 0);
    }

    #[test]
    fn test_padding_size_four() {
        let data = 4;
        let results = padding_size_four(data);
        assert_eq!(results, 0);
    }

    #[test]
    fn test_extract_string_size() {
        let test_data = [55, 57, 54, 46, 49, 48, 48, 0];
        let test_size = 8;
        let (_, results) = extract_string_size(&test_data, test_size).unwrap();
        assert_eq!(results, "796.100");
    }

    #[test]
    fn test_extract_string() {
        let test_data = [55, 57, 54, 46, 49, 48, 48, 0];
        let (_, results) = extract_string(&test_data).unwrap();
        assert_eq!(results, "796.100");
    }

    #[test]
    fn test_encode_standard() {
        let test = b"Hello word!";
        let result = encode_standard(test);
        assert_eq!(result, "SGVsbG8gd29yZCE=")
    }

    #[test]
    fn test_decode_standard() {
        let test = "SGVsbG8gd29yZCE=";
        let result = decode_standard(test).unwrap();
        assert_eq!(result, b"Hello word!")
    }

    #[test]
    fn test_unixepoch_to_iso() {
        let result = unixepoch_to_iso(&1650767813342574583);
        assert_eq!(result, "2022-04-24T02:36:53.342574583Z");
    }
}
