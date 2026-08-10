//! Consumer-implementable input abstractions.
//!
//! [`FileProvider`] decouples the parser from any on-disk layout: implementors
//! decide where tracev3/timesync files and `UUIDText`/DSC string data come from
//! (a `.logarchive`, a live system, a virtual filesystem, an in-memory store, …).
//!
//! Built-in implementations live in [`crate::filesystem`].

use std::io::{Error, Read};

use uuid::Uuid;

/// Implementing this trait allows library consumers to provide the files required by the parser in
/// arbitrary formats — no real filesystem or specific directory layout is required.
///
/// `UUIDText` and DSC (shared-cache strings) data is requested lazily, by UUID, as tracev3
/// parsing references it. Implementations return the raw file bytes; parsing happens inside
/// the library (see `crate::cache`). The enumeration methods ([`Self::uuidtext_uuids`],
/// [`Self::dsc_uuids`]) are only used for eager preloading and may return nothing if an
/// implementation cannot enumerate its contents.
pub trait FileProvider {
    /// Provides an iterator of `.tracev3` sources in deterministic processing order.
    ///
    /// For the built-in providers this is `HighVolume` -> `Persist` -> `Signpost` ->
    /// `Special` -> `logdata.LiveData.tracev3`, each directory sorted by file name.
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile>;

    /// Provides an iterator of `.timesync` sources.
    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile>;

    /// Reads the raw bytes of the `UUIDText` file for `uuid` at runtime.
    ///
    /// The UUID is obtained by parsing the `tracev3` files. Returns an error (typically
    /// [`std::io::ErrorKind::NotFound`]) if the UUID has no backing file. This avoids
    /// having to read all `UUIDText` files into memory.
    fn read_uuidtext(&self, uuid: &Uuid) -> Result<Vec<u8>, Error>;

    /// Reads the raw bytes of the DSC (shared-cache strings) file for `uuid` at runtime.
    ///
    /// The UUID is obtained by parsing the `tracev3` files. Returns an error (typically
    /// [`std::io::ErrorKind::NotFound`]) if the UUID has no backing file. This avoids
    /// having to read all DSC files into memory.
    fn read_dsc(&self, uuid: &Uuid) -> Result<Vec<u8>, Error>;

    /// Enumerates the UUIDs of all available `UUIDText` files (used for eager preloading).
    fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid>;

    /// Enumerates the UUIDs of all available DSC files (used for eager preloading).
    fn dsc_uuids(&self) -> impl Iterator<Item = Uuid>;
}

/// Defines an interface for providing a single unified log file. Parsing unified logs requires the
/// name of the original file in order to reconstruct format strings.
pub trait SourceFile {
    /// A reader for the given source file.
    fn reader(&mut self) -> impl Read;
    /// The source path of the file on the machine from which it was collected, distinct from any
    /// secondary storage location where, for instance, a file backing the `reader` might exist.
    fn source_path(&self) -> &str;
}

impl<T: FileProvider> FileProvider for &T {
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        (**self).tracev3_files()
    }
    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
        (**self).timesync_files()
    }
    fn read_uuidtext(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        (**self).read_uuidtext(uuid)
    }
    fn read_dsc(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        (**self).read_dsc(uuid)
    }
    fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid> {
        (**self).uuidtext_uuids()
    }
    fn dsc_uuids(&self) -> impl Iterator<Item = Uuid> {
        (**self).dsc_uuids()
    }
}
