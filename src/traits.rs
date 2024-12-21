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

    /// Provides an iterator of shared string files from the `/var/db/uuidtext/dsc` subdirectory,
    /// along with the filename (i.e., the filename from the _source_ file). This should be a
    /// 30-character name containing only hex digits. It is important that this is. accurate, or
    /// else strings will not be able to be referenced from the source file.
    fn dsc_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;

    /// Provides an iterator of `.timesync` files from the `/var/db/diagnostics/timesync` subdirectory.
    fn timesync_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>>;
}

pub trait SourceFile {
    fn reader(&mut self) -> Box<&mut dyn std::io::Read>;
    fn source_path(&self) -> &str;
}