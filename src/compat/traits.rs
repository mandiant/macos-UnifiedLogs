//! Minimal `FileProvider` / `SourceFile` traits for the compatibility layer.
//!
//! Only the methods actually exercised by integration tests are required:
//! `tracev3_files()` for iterating log files and `logarchive_base_path()` for
//! loading DSC / `UUIDText` / timesync data from disk.

use std::path::{Path, PathBuf};

/// Trait for providing unified log source files.
pub trait FileProvider {
    /// Iterator over `.tracev3` files in the logarchive.
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;

    /// Root path of the logarchive directory.
    fn logarchive_base_path(&self) -> &Path;

    /// Directory containing `.timesync` files.
    fn timesync_dir(&self) -> PathBuf {
        self.logarchive_base_path().join("timesync")
    }

    /// Root containing UUIDText two-character hex directories.
    fn uuidtext_root(&self) -> PathBuf {
        self.logarchive_base_path().to_path_buf()
    }

    /// Directory containing DSC shared-cache string files.
    fn dsc_dir(&self) -> PathBuf {
        self.logarchive_base_path().join("dsc")
    }

    /// Downcast support for internal caching optimizations.
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}

/// A single source file with path information.
pub trait SourceFile {
    /// A reader for the file contents.
    fn reader(&mut self) -> Box<&mut dyn std::io::Read>;

    /// The source path of the file (used as evidence string).
    fn source_path(&self) -> &str;
}
