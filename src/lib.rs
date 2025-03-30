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
    clippy::match_on_vec_items,
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
    //clippy::cast_possible_truncation, 
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    //clippy::cast_sign_loss,
    clippy::char_lit_as_u8,
    clippy::checked_conversions,
    clippy::unnecessary_cast
)]

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
