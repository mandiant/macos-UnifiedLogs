// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::DecoderError;
use chrono::{LocalResult, SecondsFormat, TimeZone, Utc};

/// Parse time data object
pub(crate) fn parse_time(input: &str) -> Result<String, DecoderError<'_>> {
    let timestamp = input.parse::<i64>().map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "parse time",
        message: "Failed to parse timestamp",
    })?;

    // Format to UTC, the log command will format to whatever the local time is for the system
    let date_time_result = Utc.timestamp_opt(timestamp, 0);
    match date_time_result {
        LocalResult::None => Err(DecoderError::Parse {
            input: input.as_bytes(),
            parser_name: "parse time",
            message: "Could not parse time",
        }),
        LocalResult::Single(date_time) => {
            Ok(date_time.to_rfc3339_opts(SecondsFormat::Millis, true))
        }
        LocalResult::Ambiguous(date_time, date_time2) => Ok(format!(
            "Ambiguous time: {} or {}",
            date_time.to_rfc3339_opts(SecondsFormat::Millis, true),
            date_time2.to_rfc3339_opts(SecondsFormat::Millis, true)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_time;

    #[test]
    fn test_parse_time() {
        let test_data = "1642302428";
        let result = parse_time(test_data).unwrap();
        assert_eq!(result, "2022-01-16T03:07:08.000Z")
    }
}
