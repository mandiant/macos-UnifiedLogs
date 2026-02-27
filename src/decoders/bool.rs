// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

/// Return BOOL value to string
pub(crate) fn uppercase_bool(bool_data: &str) -> &'static str {
    (bool_data == "0").then(|| "NO").unwrap_or("YES")
}

const FALSE_BOOL: u32 = 0;

/// Return false if int is 0, true otherwise
pub(crate) fn bool_from_int(integer: impl Into<u32>) -> bool {
    integer.into() != FALSE_BOOL
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uppercase_bool() {
        let mut test_data = "0";
        let mut results = uppercase_bool(test_data);
        assert_eq!(results, "NO");

        test_data = "1";
        results = uppercase_bool(test_data);
        assert_eq!(results, "YES");
    }

}
