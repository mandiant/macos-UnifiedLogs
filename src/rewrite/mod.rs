pub use error::*;
use nom::{IResult, Parser};

pub mod catalog;
pub mod chunk;
pub mod chunks;
pub mod chunks_reader;
pub mod decoders;
pub mod dsc;
pub mod error;
pub mod format;
pub mod header;
pub mod helpers;
pub mod log_entry;
pub mod logarchive;
pub mod resolve;
pub mod timesync;
pub mod tracev3;
pub mod uuidtext;

/// Byte offset within the data being parsed.
pub type Offset = usize;
