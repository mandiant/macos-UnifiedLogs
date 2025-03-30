use std::io::Error;

use crate::{dsc::SharedCacheStrings, uuidtext::UUIDText};

/// Implementing this trait allows library consumers to provide the files required by the parser in
/// arbitrary formats, as long as they are provided as an iterator of items that implement [Read].
///
/// For help mapping files to the correct filetype, see the
/// [`LogFileType`](crate::filesystem::LogFileType) enum's
/// [From]<&[Path](std::path::Path)> implementation.
pub trait FileProvider {
    /// Provides an iterator of `.tracev3` files from the
    /// `/private/var/db/diagnostics/((HighVolume|Signpost|Trace|Special)/`, plus the
    /// `livedata.LogData.tracev3` file if it was collected via `log collect`.
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;

    /// Provides an iterator of `UUIDText` string files from the `/var/db/uuidtext/XX/` directories,
    /// where the `XX` is any two uppercase hex characters, along with the filename (i.e., the
    /// filename from the _source_ file. This should be a 30-character name containing only hex
    /// digits. This should be a 30-character name containing only hex digits. It is important that
    /// this is. accurate, or else strings will not be able to be referenced from the source file.
    fn uuidtext_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;

    /// Reads a provided UUID file at runtime.
    /// The UUID is obtaind by parsing the `tracev3` files. Reads will fail if the UUID does not exist
    /// This avoids having to read all `UUIDText` files into memory.
    fn read_uuidtext(&self, uuid: &str) -> Result<UUIDText, Error>;

    /// Check our cached `UUIDText` data for strings
    fn cached_uuidtext(&self, uuid: &str) -> Option<&UUIDText>;

    /// Update our cached `UUIDText` data
    fn update_uuid(&mut self, uuid: &str, uuid2: &str);

    /// Provides an iterator of shared string files from the `/var/db/uuidtext/dsc` subdirectory,
    /// along with the filename (i.e., the filename from the _source_ file). This should be a
    /// 30-character name containing only hex digits. It is important that this is. accurate, or
    /// else strings will not be able to be referenced from the source file.
    fn dsc_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;

    /// Reads a provided UUID file at runtime.
    /// The UUID is obtaind by parsing the `tracev3` files. Reads will fail if the UUID does not exist
    /// This avoids having to read all `SharedCacheStrings` files into memory.
    fn read_dsc_uuid(&self, uuid: &str) -> Result<SharedCacheStrings, Error>;

    /// Check our cached `SharedCacheStrings` for strings
    fn cached_dsc(&self, uuid: &str) -> Option<&SharedCacheStrings>;

    /// Update our cached `SharedCacheStrings` data
    fn update_dsc(&mut self, uuid: &str, uuid2: &str);

    /// Provides an iterator of `.timesync` files from the `/var/db/diagnostics/timesync` subdirectory.
    fn timesync_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;
}

/// Defines an interface for providing a single unified log file. Parsing unified logs requires the
/// name of the original file in order to reconstruct format strings.
pub trait SourceFile {
    /// A reader for the given source file.
    fn reader(&mut self) -> Box<&mut dyn std::io::Read>;
    /// The source path of the file on the machine from which it was collected, distinct from any
    /// secondary storage location where, for instance, a file backing the `reader` might exist.
    fn source_path(&self) -> &str;
}
