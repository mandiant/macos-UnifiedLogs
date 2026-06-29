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

#[cfg(all(feature = "legacy", feature = "rewrite"))]
compile_error!(
    "features `legacy` and `rewrite` are mutually exclusive; use `default-features = false` when enabling `rewrite` or `rewrite-compat`"
);

#[cfg(all(feature = "legacy", not(feature = "rewrite")))]
pub mod legacy;
#[cfg(all(feature = "legacy", not(feature = "rewrite")))]
mod old_prelude {
    pub use super::legacy::*;
}
#[cfg(all(feature = "legacy", not(feature = "rewrite")))]
pub use old_prelude::*;

#[cfg(all(feature = "rewrite", not(feature = "legacy")))]
mod rewrite;
#[cfg(all(feature = "rewrite", not(feature = "legacy")))]
mod rewrite_prelude {
    pub use super::rewrite::*;
}
#[cfg(all(feature = "rewrite", not(feature = "legacy")))]
pub use rewrite_prelude::*;

#[cfg(all(feature = "rewrite-compat", not(feature = "legacy")))]
pub mod compat;
#[cfg(all(feature = "rewrite-compat", not(feature = "legacy")))]
mod compat_prelude {
    pub use super::compat::*;
}
#[cfg(all(feature = "rewrite-compat", not(feature = "legacy")))]
pub use compat::filesystem;
#[cfg(all(feature = "rewrite-compat", not(feature = "legacy")))]
pub use compat_prelude::*;

#[cfg(all(feature = "rewrite-compat", not(feature = "legacy")))]
pub mod timesync {
    pub use crate::compat::unified_log::TimesyncBoot;
    pub use crate::rewrite::timesync::*;
}
