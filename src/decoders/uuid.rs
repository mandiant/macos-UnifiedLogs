// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::{clean_uuid, decode_standard};
use log::error;

/// Get UUID string from log object
pub(crate) fn parse_uuid(uuid_data: &str) -> String {
    let decoded_data_result = decode_standard(uuid_data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode uuid data {}, error: {:?}",
                uuid_data, err
            );
            return String::from("Failed to base64 decode UUID details");
        }
    };
    let mut uuid_string = format!("{:02X?}", decoded_data);
    uuid_string = clean_uuid(&uuid_string);
    uuid_string
}

#[cfg(test)]
mod tests {
    use super::parse_uuid;

    #[test]
    fn test_parse_uuid() {
        let test_data = "hZV+HTbETtKGqAZXvN3ikw==";
        let results = parse_uuid(test_data);
        assert_eq!(results, "85957E1D36C44ED286A80657BCDDE293")
    }
}
