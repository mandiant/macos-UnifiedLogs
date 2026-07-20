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

pub use error::*;
use nom::{IResult, Parser};

// pub mod cache; // to be ported to vNext (or other design entirely)
pub mod catalog;
pub mod chunk;
pub mod chunks;
pub mod chunks_reader;
pub mod decoders;
pub mod dsc;
pub mod error;
pub mod filesystem;
pub mod format;
pub mod header;
pub mod helpers;
pub mod log_entry;
pub mod logarchive;
pub mod resolve;
pub mod timesync;
pub mod tracev3;
pub mod traits;
pub mod uuidtext;

/// Byte offset within the data being parsed.
pub type Offset = usize;
