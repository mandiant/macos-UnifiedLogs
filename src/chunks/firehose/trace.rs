// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use nom::number::complete::le_u32;

use super::item::{RawFirehoseItem, parse_trace_items};

/// Parsed Trace entry body.
#[derive(Debug, Clone, Copy)]
pub struct RawTraceBody<'a> {
    pub pc_id: u32,
    /// Raw message data — interpretation requires reversal (trace stores data backwards).
    pub items_data: &'a [u8],
}

impl<'a> RawTraceBody<'a> {
    /// Parse items from this trace body's `items_data`.
    pub fn parse_items(&self) -> Vec<RawFirehoseItem<'static>> {
        parse_trace_items(self.items_data)
    }

    /// Parse a Trace entry body from raw entry data.
    pub fn parse(data: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (items_data, pc_id) = le_u32(data)?;
        Ok((&[], Self { pc_id, items_data }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::body::RawFirehoseBody;
    use super::super::entry::{FirehoseActivityType, FirehoseLogType};
    use super::super::flags::FirehoseFlags;

    #[test]
    fn test_trace_body() -> anyhow::Result<()> {
        // From src/chunks/firehose/trace.rs test_parse_firehose_trace
        let test_data: &[u8] = &[106, 139, 3, 0, 0];

        let body = RawFirehoseBody::parse(
            test_data,
            FirehoseActivityType::Trace,
            FirehoseFlags::empty(),
            FirehoseLogType::Default,
        )
        .unwrap();
        let trace = match body {
            RawFirehoseBody::Trace(t) => t,
            other => panic!("expected Trace, got {other:?}"),
        };

        assert_eq!(trace.pc_id, 232298);
        assert_eq!(trace.items_data, &[0]);
        Ok(())
    }
}
