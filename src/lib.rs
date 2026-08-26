//! # A library to parse Apple Unified Logs
//!
//! `macos_unifiedlogs` is a cross-platform library to parse Unified Logs from a
//! `.logarchive` directory or a live macOS system. No Apple APIs are used, so it
//! runs on non-Apple platforms too.
//!
//! The core type is [`log_entry::LogEntry`] — a zero-copy log entry borrowing
//! directly from the parsed file buffers. Messages are formatted lazily on
//! demand via `.message()`, and `UUIDText`/DSC string data is read lazily as
//! entries reference it (see [`cache`]).
//!
//! ## Example
//!
//! ```rust,no_run
//! use macos_unifiedlogs::logarchive::visit_logarchive;
//! use std::path::Path;
//!
//! visit_logarchive(Path::new("system_logs.logarchive"), |entry| {
//!     let timestamp = entry.timestamp().to_rfc3339();
//!     let process = entry.process.unwrap_or("");
//!     let message = entry.message();
//!
//!     println!("{timestamp} [{process}] {message}");
//! })
//! .unwrap();
//! ```
//!
//! Use [`logarchive::visit_live_system`] on a live macOS system, or implement
//! [`traits::FileProvider`] to parse from any other source (mounted image,
//! evidence container, in-memory data — see [`filesystem::InMemoryProvider`])
//! and hand it to [`logarchive::visit_provider`].

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

pub mod cache;
/// Catalog chunk parsing (process/subsystem metadata)
pub mod catalog;
/// Top-level and chunkset chunk readers
pub mod chunk;
/// Individual chunk parsers (firehose, oversize, simpledump, statedump)
pub mod chunks;
/// Streaming reader over the top-level chunks of a tracev3 buffer
pub mod chunks_reader;
/// Decoders for typed log arguments (uuid, dns, location, …)
pub mod decoders;
/// DSC (shared-cache strings) file parsing
pub mod dsc;
/// Error types shared by all parsers
pub mod error;
pub mod filesystem;
pub mod format;
/// Tracev3 header chunk parsing
pub mod header;
pub(crate) mod helpers;
pub mod log_entry;
pub mod logarchive;
/// Format string / library / process path resolution
pub mod resolve;
/// Timesync file parsing and timestamp resolution
pub mod timesync;
pub mod tracev3;
pub mod traits;
/// `UUIDText` string file parsing
pub mod uuidtext;

/// Byte offset within the data being parsed.
pub type Offset = usize;
