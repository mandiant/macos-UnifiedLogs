//! Compatibility iterator matching the legacy `iterator::UnifiedLogIterator` API.
//!
//! The rewrite parser does not need the legacy per-catalog iterator internally,
//! but examples can keep using the same public shape when built with
//! `rewrite-compat`.

use std::io::Cursor;

use log::error;

use super::parser::parse_log;
use super::unified_log::{HeaderInfo, UnifiedLogData};

#[derive(Debug)]
/// Iterator to loop through parsed tracev3 data.
pub struct UnifiedLogIterator {
    pub data: Vec<u8>,
    pub header: Vec<HeaderInfo>,
    pub evidence: String,
}

impl Iterator for UnifiedLogIterator {
    type Item = UnifiedLogData;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }

        let data = std::mem::take(&mut self.data);
        let evidence = self.evidence.clone();

        match parse_log(Cursor::new(data), &evidence) {
            Ok(mut parsed) => {
                if parsed.header.is_empty() && !self.header.is_empty() {
                    parsed.header = std::mem::take(&mut self.header);
                }
                Some(parsed)
            }
            Err(err) => {
                error!("Failed to parse tracev3 data: {err}");
                None
            }
        }
    }
}
