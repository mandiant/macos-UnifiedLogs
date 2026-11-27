// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::DecoderError;
use jiff::Timestamp;
use std::fmt::Display;

#[derive(Debug)]
pub enum LocalDateTime {
    Single(String),
}

impl Display for LocalDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalDateTime::Single(dt) => {
                write!(f, "{dt}")
            }
        }
    }
}

/// Parse time data object
pub(crate) fn parse_time(input: &str) -> Result<LocalDateTime, DecoderError<'_>> {
    let timestamp = input.parse::<i64>().map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "parse time",
        message: "Failed to parse timestamp",
    })?;

    // Format to UTC, the log command will format to whatever the local time is for the system
    if let Ok(utc) = Timestamp::from_second(timestamp) {
        return Ok(LocalDateTime::Single(utc.to_string()));
    }

    Err(DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "parse time",
        message: "Could not convert timestamp to RFC3339",
    })
}

#[cfg(test)]
mod tests {
    use super::parse_time;
    use crate::decoders::DecoderError;

    #[test]
    fn test_parse_time() {
        let test_data = "1642302428";
        let result = parse_time(test_data).unwrap();
        assert_eq!(result.to_string(), "2022-01-16T03:07:08Z")
    }

    #[test]
    fn test_parse_time_bad_string() {
        let bad_time = "not a timestamp";
        let err = parse_time(bad_time).unwrap_err();
        assert!(
            matches!(err, DecoderError::Parse { message, .. } if message == "Failed to parse timestamp")
        )
    }

    #[test]
    fn test_parse_time_bad_number() {
        let bad_time = "9223372036854775807";
        let err = parse_time(bad_time).unwrap_err();
        assert!(
            matches!(err, DecoderError::Parse { message, .. } if message == "Could not convert timestamp to RFC3339")
        )
    }
}
