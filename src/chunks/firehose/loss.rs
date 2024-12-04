// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use nom::bytes::complete::take;
use nom::number::complete::le_u64;
use std::mem::size_of;

#[derive(Debug, Clone, Default)]
pub struct FirehoseLoss {
    pub start_time: u64,
    pub end_time: u64,
    pub count: u64,
}

impl FirehoseLoss {
    /// Parse loss Firehose log entry.
    //  Ex: tp 16 + 48: loss
    pub fn parse_firehose_loss(data: &[u8]) -> nom::IResult<&[u8], FirehoseLoss> {
        let mut firehose_loss = FirehoseLoss::default();

        let (input, start_time) = take(size_of::<u64>())(data)?;
        let (input, end_time) = take(size_of::<u64>())(input)?;
        let (input, count) = take(size_of::<u64>())(input)?;

        let (_, firehose_start_time) = le_u64(start_time)?;
        let (_, firehose_end_time) = le_u64(end_time)?;
        let (_, firehose_count) = le_u64(count)?;

        firehose_loss.start_time = firehose_start_time;
        firehose_loss.end_time = firehose_end_time;
        firehose_loss.count = firehose_count;

        Ok((input, firehose_loss))
    }
}

#[cfg(test)]
mod tests {
    use crate::chunks::firehose::loss::FirehoseLoss;

    #[test]
    fn test_parse_firehose_loss_monterey() {
        let test_data = [
            72, 56, 43, 42, 0, 0, 0, 0, 231, 207, 114, 187, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (_, results) = FirehoseLoss::parse_firehose_loss(&test_data).unwrap();
        assert_eq!(results.start_time, 707475528);
        assert_eq!(results.end_time, 3144863719);
        assert_eq!(results.count, 63);
    }
}
