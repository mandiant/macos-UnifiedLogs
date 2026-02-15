// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::doc_markdown,
    clippy::needless_continue,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::fn_params_excessive_bools,
    clippy::inefficient_to_string,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    rust_2018_idioms,
    future_incompatible
)]
#![deny(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::unnecessary_cast
)]

//! # A library to parse Apple Unified Logs
//! `macos_unifiedlogs` is a small cross platform library to help parse Unified Logs on a system or logarchive.
//! No Apple APIs are used so this library can be used on non-apple platforms.
//!
//! A full example can found on [GitHub](https://github.com/mandiant/macos-UnifiedLogs)
//! ## Example
//! ```rust
//!    use macos_unifiedlogs::filesystem::LiveSystemProvider;
//!    use macos_unifiedlogs::traits::FileProvider;
//!    use macos_unifiedlogs::parser::collect_timesync;
//!    use macos_unifiedlogs::iterator::UnifiedLogIterator;
//!    use macos_unifiedlogs::unified_log::UnifiedLogData;
//!    use macos_unifiedlogs::parser::build_log;
//!
//!    // Run on live macOS system
//!     let mut provider = LiveSystemProvider::default();
//!     let timesync_data = collect_timesync(&provider).unwrap();
//!
//!     // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
//!     let mut oversize_strings = UnifiedLogData {
//!        header: Vec::new(),
//!        catalog_data: Vec::new(),
//!        oversize: Vec::new(),
//!        evidence: String::new(),
//!     };
//!     for mut entry in provider.tracev3_files() {
//!         println!("TraceV3 file: {}", entry.source_path());
//!         let mut buf = Vec::new();
//!         entry.reader().read_to_end(&mut buf);
//!         let log_iterator = UnifiedLogIterator {
//!             data: buf,
//!             header: Vec::new(),
//!             evidence: entry.source_path().to_string(),
//!         };
//!         // If we exclude entries that are missing strings, we may find them in later log files
//!         let exclude = true;
//!         for mut chunk in log_iterator {
//!             chunk.oversize.append(&mut oversize_strings.oversize);
//!             let (results, _missing_logs) = build_log(
//!                 &chunk,
//!                 &mut provider,
//!                 &timesync_data,
//!                 exclude,
//!             );
//!             oversize_strings.oversize = chunk.oversize;
//!             println!("Got {} log entries", results.len());
//!             break;
//!         }
//!         break;
//!     }
//!
//! ```

/// Functions to parse catalog information from tracev3 files
mod catalog;
mod chunks;
mod chunkset;
/// Parsers to extract specific log objects
mod decoders;
/// Functions to parse the shared string cache
pub mod dsc;
mod error;
/// Providers to parse Unified Log data on a live system or a provided logarchive
pub mod filesystem;
mod header;
pub mod iterator;
/// Functions to assemble the log message
mod message;
/// Functions to extract and assemble log entries from the macOS Unified Log
pub mod parser;
mod preamble;
/// Functions to parse time data associated with the Unified Log
pub mod timesync;
pub mod traits;
/// Functions to parse tracev3 files
pub mod unified_log;
mod util;
/// Functions to parse the log string files
pub mod uuidtext;
