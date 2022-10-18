// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::{SecondsFormat, TimeZone, Utc};
use log::error;

/// Parse time data object
pub(crate) fn parse_time(data: &str) -> String {
    let timestamp_result = data.parse::<i64>();
    let timestamp = match timestamp_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse timestamp {}. Error: {:?}",
                data, err
            );
            return data.to_string();
        }
    };

    // Format to UTC, the log command will format to whatever the local time is for the system
    let date_time = Utc.timestamp(timestamp, 0);
    date_time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::parse_time;

    #[test]
    fn test_parse_time() {
        let test_data = "1642302428";
        let result = parse_time(test_data);
        assert_eq!(result, "2022-01-16T03:07:08.000Z")
    }
}
