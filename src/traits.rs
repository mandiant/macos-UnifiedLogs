//! Consumer-implementable input abstractions.
//!
//! [`FileProvider`] decouples the parser from any on-disk layout: implementors
//! decide where tracev3/timesync files and `UUIDText`/DSC string data come from
//! (a `.logarchive`, a live system, a virtual filesystem, an in-memory store, …).
//!
//! Built-in implementations live in [`crate::filesystem`].

use std::io::{Error, Read};
use std::ops::ControlFlow;

use uuid::Uuid;

mod sealed {
    pub trait Sealed {}
    impl Sealed for () {}
    impl Sealed for std::ops::ControlFlow<()> {}
}

/// Return type accepted from visit callbacks.
///
/// Implemented for `()` (always continue — plain closures work unchanged) and
/// for [`ControlFlow<()>`] (return [`ControlFlow::Break`] to stop the visit
/// early, mid-file included).
///
/// ```no_run
/// use macos_unifiedlogs::logarchive::visit_logarchive;
/// use std::ops::ControlFlow;
/// use std::path::Path;
///
/// // Plain closure: visits everything
/// visit_logarchive(Path::new("archive.logarchive"), |entry| {
///     println!("{}", entry.message());
/// })?;
///
/// // Breaking closure: stops after the first 100 entries
/// let mut count = 0;
/// visit_logarchive(Path::new("archive.logarchive"), |entry| {
///     count += 1;
///     println!("{}", entry.message());
///     if count == 100 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
/// })?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub trait VisitOutcome: sealed::Sealed {
    /// Normalize into a [`ControlFlow`].
    fn into_flow(self) -> ControlFlow<()>;
}

impl VisitOutcome for () {
    #[inline]
    fn into_flow(self) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
}

impl VisitOutcome for ControlFlow<()> {
    #[inline]
    fn into_flow(self) -> ControlFlow<()> {
        self
    }
}

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
    /// The filesystem-backed providers sort files chronologically by each
    /// file's header start time with `logdata.LiveData.tracev3` last, so
    /// oversize payloads are usually seen before the entries referencing them
    /// (falling back to `HighVolume` -> `Persist` -> `Signpost` -> `Special`,
    /// name-sorted, for unreadable headers). [`crate::filesystem::InMemoryProvider`]
    /// yields files in caller-provided order.
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
