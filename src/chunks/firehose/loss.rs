// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use nom::number::complete::le_u64;

/// Parsed Loss entry body (no lifetime — fully owned).
#[derive(Debug, Clone, Copy)]
pub struct RawLossBody {
    pub start_time: u64,
    pub end_time: u64,
    pub count: u64,
}

impl RawLossBody {
    /// Parse a Loss entry body from raw entry data.
    pub fn parse(data: &[u8]) -> nom::IResult<&[u8], Self> {
        let (input, start_time) = le_u64(data)?;
        let (input, end_time) = le_u64(input)?;
        let (input, count) = le_u64(input)?;
        Ok((
            input,
            Self {
                start_time,
                end_time,
                count,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::body::RawFirehoseBody;
    use super::super::entry::{FirehoseActivityType, FirehoseLogType};
    use super::super::flags::FirehoseFlags;

    #[test]
    fn test_loss_body() -> anyhow::Result<()> {
        // From src/chunks/firehose/loss.rs test_parse_firehose_loss_monterey
        let test_data: &[u8] = &[
            72, 56, 43, 42, 0, 0, 0, 0, 231, 207, 114, 187, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0,
        ];

        let body = RawFirehoseBody::parse(
            test_data,
            FirehoseActivityType::Loss,
            FirehoseFlags::empty(),
            FirehoseLogType::Default,
        )
        .unwrap();
        let loss = match body {
            RawFirehoseBody::Loss(l) => l,
            other => panic!("expected Loss, got {other:?}"),
        };

        assert_eq!(loss.start_time, 707475528);
        assert_eq!(loss.end_time, 3144863719);
        assert_eq!(loss.count, 63);
        Ok(())
    }
}
