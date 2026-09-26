// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::fmt::Display;

use super::DecoderError;
use chrono::{DateTime, LocalResult, SecondsFormat, TimeZone, Utc};

pub enum LocalDateTime {
    Single(DateTime<Utc>),
    Ambiguous(DateTime<Utc>, DateTime<Utc>),
}

impl Display for LocalDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalDateTime::Single(dt) => {
                write!(f, "{}", dt.to_rfc3339_opts(SecondsFormat::Millis, true))
            }
            LocalDateTime::Ambiguous(dt1, dt2) => {
                write!(
                    f,
                    "Ambiguous time: {} or {}",
                    dt1.to_rfc3339_opts(SecondsFormat::Millis, true),
                    dt2.to_rfc3339_opts(SecondsFormat::Millis, true)
                )
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
    let date_time_result = Utc.timestamp_opt(timestamp, 0);
    match date_time_result {
        LocalResult::None => Err(DecoderError::Parse {
            input: input.as_bytes(),
            parser_name: "parse time",
            message: "Could not parse time",
        }),
        LocalResult::Single(date_time) => Ok(LocalDateTime::Single(date_time)),
        LocalResult::Ambiguous(date_time, date_time2) => {
            Ok(LocalDateTime::Ambiguous(date_time, date_time2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_time;

    #[test]
    fn test_parse_time() {
        let test_data = "1642302428";
        let result = parse_time(test_data).unwrap();
        assert_eq!(result.to_string(), "2022-01-16T03:07:08.000Z")
    }
}
