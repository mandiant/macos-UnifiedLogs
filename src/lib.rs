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

#[cfg(not(feature =  "rewrite"))]
pub mod legacy;
#[cfg(not(feature =  "rewrite"))]
mod old_prelude {
    pub use super::legacy::*;
}
#[cfg(not(feature =  "rewrite"))]
pub use old_prelude::*;


#[cfg(feature =  "rewrite")]
mod rewrite;
#[cfg(feature =  "rewrite")]
mod rewrite_prelude {
    pub use super::rewrite::*;
}
#[cfg(feature =  "rewrite")]
pub use rewrite_prelude::*;