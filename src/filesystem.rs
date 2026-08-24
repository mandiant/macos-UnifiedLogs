//! Filesystem providers for parser input layouts.
//!
//! The parser can process the same trace/support-file layout from either
//! a `.logarchive` directory or a live macOS system. Providers expose those
//! sources through the [`crate::traits::FileProvider`] abstraction without
//! changing the lower-level `tracev3` parser. [`InMemoryProvider`] shows that
//! no real filesystem is required at all.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::{Component, Path, PathBuf};

use uuid::Uuid;

use crate::chunks::{ChunkPreamble, ChunkTag, PREAMBLE_SIZE};
use crate::header::{RAW_HEADER_CHUNK_SIZE, RawHeaderChunk};
use crate::traits::SourceFile;

/// A [`SourceFile`] backed by a local file, remembering its original path.
pub struct LocalFile {
    reader: File,
    source: String,
}

impl LocalFile {
    /// Open `path`, keeping it as the source path.
    pub fn new(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            reader: File::open(path)?,
            source: path.as_os_str().to_string_lossy().to_string(),
        })
    }
}

impl SourceFile for LocalFile {
    fn reader(&mut self) -> impl Read {
        &mut self.reader
    }

    fn source_path(&self) -> &str {
        self.source.as_str()
    }
}

/// Classification of a unified-log file by its path shape.
///
/// Useful for custom [`crate::traits::FileProvider`] implementations that walk
/// an arbitrary tree and need to route files by type.
#[derive(Debug, PartialEq, Eq)]
pub enum LogFileType {
    TraceV3,
    UUIDText,
    Dsc,
    Timesync,
    Invalid,
}

fn only_hex_chars(val: &str) -> bool {
    val.chars().all(|c| c.is_ascii_hexdigit())
}

impl From<&Path> for LogFileType {
    fn from(path: &Path) -> Self {
        let components = path.components().collect::<Vec<Component<'_>>>();
        let n = components.len();
        if n < 2 {
            return Self::Invalid;
        }

        if let (Some(&Component::Normal(parent)), Some(&Component::Normal(filename))) =
            (components.get(n - 2), components.get(n - 1))
        {
            let parent_s = parent.to_str().unwrap_or_default();
            let filename_s = filename.to_str().unwrap_or_default();

            if filename_s == "logdata.LiveData.tracev3"
                || (filename_s.ends_with(".tracev3") && TRACE_SUBDIRS.contains(&parent_s))
            {
                return Self::TraceV3;
            }

            if filename_s.len() == 30
                && only_hex_chars(filename_s)
                && parent_s.len() == 2
                && only_hex_chars(parent_s)
            {
                return Self::UUIDText;
            }

            if filename_s.len() == 32 && only_hex_chars(filename_s) && parent_s == "dsc" {
                return Self::Dsc;
            }

            if filename_s.ends_with(".timesync") && parent_s == "timesync" {
                return Self::Timesync;
            }
        }

        Self::Invalid
    }
}

/// Filesystem provider for a `.logarchive` directory.
#[derive(Clone, Debug)]
pub struct LogarchiveProvider {
    base: PathBuf,
}

impl LogarchiveProvider {
    /// Create a provider rooted at a `.logarchive` directory.
    pub fn new(path: &Path) -> Self {
        Self {
            base: path.to_path_buf(),
        }
    }
}

impl crate::traits::FileProvider for LogarchiveProvider {
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        local_files(collect_tracev3_paths(&self.base))
    }
    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
        local_files(collect_timesync_paths(&self.base.join("timesync")))
    }
    fn read_uuidtext(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        std::fs::read(uuidtext_path(&self.base, uuid))
    }
    fn read_dsc(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        std::fs::read(dsc_path(&self.base.join("dsc"), uuid))
    }
    fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid> {
        collect_uuidtext_uuids(&self.base).into_iter()
    }
    fn dsc_uuids(&self) -> impl Iterator<Item = Uuid> {
        collect_dsc_uuids(&self.base.join("dsc")).into_iter()
    }
}

/// Filesystem provider for a live macOS system.
#[derive(Clone, Debug)]
pub struct LiveSystemProvider {
    diagnostics_root: PathBuf,
    uuidtext_root: PathBuf,
}

impl LiveSystemProvider {
    /// Create a provider using the standard live macOS Unified Log paths.
    pub fn new() -> Self {
        Self::with_roots(
            PathBuf::from("/private/var/db/diagnostics"),
            PathBuf::from("/private/var/db/uuidtext"),
        )
    }

    /// Create a provider with custom roots, useful for tests or mounted images.
    pub fn with_roots(diagnostics_root: PathBuf, uuidtext_root: PathBuf) -> Self {
        Self {
            diagnostics_root,
            uuidtext_root,
        }
    }
}

impl Default for LiveSystemProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::FileProvider for LiveSystemProvider {
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        local_files(collect_tracev3_paths(&self.diagnostics_root))
    }
    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
        local_files(collect_timesync_paths(
            &self.diagnostics_root.join("timesync"),
        ))
    }
    fn read_uuidtext(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        std::fs::read(uuidtext_path(&self.uuidtext_root, uuid))
    }
    fn read_dsc(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        std::fs::read(dsc_path(&self.uuidtext_root.join("dsc"), uuid))
    }
    fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid> {
        collect_uuidtext_uuids(&self.uuidtext_root).into_iter()
    }
    fn dsc_uuids(&self) -> impl Iterator<Item = Uuid> {
        collect_dsc_uuids(&self.uuidtext_root.join("dsc")).into_iter()
    }
}

/// A [`crate::traits::FileProvider`] backed entirely by memory.
///
/// Proof that parsing requires no filesystem: fill the maps from any source
/// (an evidence container, a network stream, a zip archive, …) and hand the
/// provider to `crate::logarchive::visit_provider`.
#[derive(Debug, Default, Clone)]
pub struct InMemoryProvider {
    /// Tracev3 buffers as `(source path label, bytes)`, in processing order.
    pub tracev3: Vec<(String, Vec<u8>)>,
    /// Timesync buffers as `(source path label, bytes)`.
    pub timesync: Vec<(String, Vec<u8>)>,
    /// `UUIDText` file bytes keyed by UUID.
    pub uuidtext: HashMap<Uuid, Vec<u8>>,
    /// DSC (shared-cache strings) file bytes keyed by UUID.
    pub dsc: HashMap<Uuid, Vec<u8>>,
}

/// A [`SourceFile`] borrowing an in-memory buffer.
struct MemorySource<'a> {
    name: &'a str,
    data: &'a [u8],
}

impl SourceFile for MemorySource<'_> {
    fn reader(&mut self) -> impl Read {
        self.data
    }
    fn source_path(&self) -> &str {
        self.name
    }
}

impl crate::traits::FileProvider for InMemoryProvider {
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        self.tracev3.iter().map(|(name, data)| MemorySource {
            name,
            data: data.as_slice(),
        })
    }
    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
        self.timesync.iter().map(|(name, data)| MemorySource {
            name,
            data: data.as_slice(),
        })
    }
    fn read_uuidtext(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        self.uuidtext
            .get(uuid)
            .cloned()
            .ok_or_else(|| Error::from(ErrorKind::NotFound))
    }
    fn read_dsc(&self, uuid: &Uuid) -> Result<Vec<u8>, Error> {
        self.dsc
            .get(uuid)
            .cloned()
            .ok_or_else(|| Error::from(ErrorKind::NotFound))
    }
    fn uuidtext_uuids(&self) -> impl Iterator<Item = Uuid> {
        sorted_uuids(self.uuidtext.keys())
    }
    fn dsc_uuids(&self) -> impl Iterator<Item = Uuid> {
        sorted_uuids(self.dsc.keys())
    }
}

/// Sort UUIDs for deterministic preload order.
fn sorted_uuids<'a>(uuids: impl Iterator<Item = &'a Uuid>) -> impl Iterator<Item = Uuid> {
    let mut uuids = uuids.copied().collect::<Vec<_>>();
    uuids.sort();
    uuids.into_iter()
}

// ---------------------------------------------------------------------------
// Path helpers (shared by the filesystem-backed providers)
// ---------------------------------------------------------------------------

const TRACE_SUBDIRS: &[&str] = &["HighVolume", "Persist", "Signpost", "Special"];

/// Collect all tracev3 file paths in processing order.
///
/// The base path may be either a `.logarchive` root or the live macOS diagnostics
/// directory (`/private/var/db/diagnostics`).
///
/// Files are ordered chronologically by each file's header start time so that
/// oversize payloads are usually seen before the entries referencing them,
/// with `logdata.LiveData.tracev3` always last (it holds the newest entries
/// but its header carries an older start time). Files whose header cannot be
/// read fall back to the fixed directory order (`HighVolume` -> `Persist` ->
/// `Signpost` -> `Special`, name-sorted within each directory).
pub fn collect_tracev3_paths(base: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for subdir in TRACE_SUBDIRS {
        let dir = base.join(subdir);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            let dir_paths = sorted_paths(
                entries
                    .filter_map(|entry| entry.ok())
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.extension().and_then(|ext| ext.to_str()) == Some("tracev3")
                    }),
            );
            paths.extend(dir_paths);
        }
    }

    // Stable sort: files with unreadable headers keep their relative
    // fixed-order position at the end.
    paths.sort_by_key(|path| tracev3_sort_key(path).unwrap_or((u64::MAX, u64::MAX)));

    let live_data = base.join("logdata.LiveData.tracev3");
    if live_data.is_file() {
        paths.push(live_data);
    }

    paths
}

/// Chronological sort key for a tracev3 file: `(unknown_time, continous_time)`
/// from its header chunk.
///
/// `unknown_time` is the file's wall-clock start time in Unix epoch seconds;
/// sibling files rotated in the same second are ordered by the mach continuous
/// time. `None` if the file cannot be read or does not start with a header chunk.
pub(crate) fn tracev3_sort_key(path: &Path) -> Option<(u64, u64)> {
    const SIZE: usize = PREAMBLE_SIZE + RAW_HEADER_CHUNK_SIZE;
    let size = u64::try_from(SIZE).ok()?;
    let mut buffer = Vec::new();
    File::open(path)
        .ok()?
        .take(size)
        .read_to_end(&mut buffer)
        .ok()?;
    let (body, preamble) = ChunkPreamble::parse(&buffer).ok()?;
    if preamble.tag != ChunkTag::Header {
        return None;
    }
    let (_, header) = RawHeaderChunk::parse(body).ok()?;
    Some((header.unknown_time, header.continous_time))
}

/// Collect all `.timesync` file paths, sorted by name.
pub fn collect_timesync_paths(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    sorted_paths(
        entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("timesync")),
    )
}

/// Path of the `UUIDText` file for `uuid` under `root`:
/// `{root}/{first 2 hex chars}/{remaining 30 hex chars}` (uppercase).
fn uuidtext_path(root: &Path, uuid: &Uuid) -> PathBuf {
    let mut buffer = Uuid::encode_buffer();
    let hex = uuid.simple().encode_upper(&mut buffer);
    root.join(&hex[..2]).join(&hex[2..])
}

/// Path of the DSC file for `uuid` under `dsc_dir`: `{dsc_dir}/{32 hex chars}` (uppercase).
fn dsc_path(dsc_dir: &Path, uuid: &Uuid) -> PathBuf {
    let mut buffer = Uuid::encode_buffer();
    let hex = uuid.simple().encode_upper(&mut buffer);
    dsc_dir.join(hex)
}

/// Enumerate `UUIDText` UUIDs from 2-char hex directories under `root`.
///
/// Directory layout: `{XX}/{YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY}`
/// Full UUID = `XX` + `YYYYYYYYYYYYYYYYYYYYYYYYYYYYYY` (32 hex chars).
pub fn collect_uuidtext_uuids(root: &Path) -> Vec<Uuid> {
    let mut uuids = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return uuids;
    };
    let dir_paths = sorted_paths(entries.filter_map(|entry| entry.ok().map(|e| e.path())));

    for dir_path in dir_paths {
        let Some(dir_name) = dir_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if dir_name.len() != 2 || !only_hex_chars(dir_name) || !dir_path.is_dir() {
            continue;
        }
        let Ok(file_entries) = std::fs::read_dir(&dir_path) else {
            continue;
        };
        let file_paths =
            sorted_paths(file_entries.filter_map(|entry| entry.ok().map(|e| e.path())));
        for file_path in file_paths {
            if !file_path.is_file() {
                continue;
            }
            let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Ok(uuid) = Uuid::parse_str(&format!("{dir_name}{file_name}")) {
                uuids.push(uuid);
            }
        }
    }
    uuids
}

/// Enumerate DSC UUIDs from files named as 32 hex chars in `dsc_dir`.
pub fn collect_dsc_uuids(dsc_dir: &Path) -> Vec<Uuid> {
    let Ok(entries) = std::fs::read_dir(dsc_dir) else {
        return Vec::new();
    };
    let paths = sorted_paths(entries.filter_map(|entry| entry.ok().map(|e| e.path())));
    paths
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_str()?;
            Uuid::parse_str(name).ok()
        })
        .collect()
}

/// Open paths as [`LocalFile`] sources, skipping (and logging) unreadable files.
fn local_files(paths: Vec<PathBuf>) -> impl Iterator<Item = LocalFile> {
    paths.into_iter().filter_map(|path| {
        LocalFile::new(&path)
            .inspect_err(|e| log::warn!("Failed to open {}: {e}", path.display()))
            .ok()
    })
}

/// Sort paths to keep parser output deterministic across filesystems.
pub(crate) fn sorted_paths(paths: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut paths = paths.collect::<Vec<_>>();
    paths.sort();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::tests::test_data_path;
    use crate::traits::FileProvider as _;

    #[test]
    fn live_provider_with_roots_reads_custom_layout() {
        let root = test_data_path().join("system_logs_tahoe.logarchive");
        let provider = LiveSystemProvider::with_roots(root.clone(), root.clone());

        // diagnostics_root drives tracev3/timesync, uuidtext_root drives strings
        assert_eq!(provider.uuidtext_uuids().count(), 876);
        assert_eq!(provider.dsc_uuids().count(), 1);
    }

    #[test]
    fn collect_tracev3_paths_uses_deterministic_log_order() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");
        let paths = collect_tracev3_paths(&base);

        assert!(!paths.is_empty(), "should find tracev3 files");
        assert!(
            paths
                .iter()
                .all(|path| path.extension().and_then(|ext| ext.to_str()) == Some("tracev3")),
            "collector should only return tracev3 files"
        );

        let first = paths[0].to_string_lossy();
        assert!(
            first.contains("Persist"),
            "first tracev3 should be from Persist/, got: {first}"
        );

        let last = paths.last().unwrap().to_string_lossy();
        assert!(
            last.contains("LiveData"),
            "last tracev3 should be LiveData, got: {last}"
        );

        // All but LiveData (forced last) are chronological by header start time
        let keys: Vec<_> = paths[..paths.len() - 1]
            .iter()
            .map(|p| tracev3_sort_key(p).expect("test archive headers should parse"))
            .collect();
        assert!(
            keys.windows(2).all(|w| w[0] <= w[1]),
            "tracev3 paths should be sorted chronologically, got keys: {keys:?}"
        );
    }

    #[test]
    fn provider_reads_uuidtext_and_dsc_by_uuid() {
        let base = test_data_path().join("system_logs_tahoe.logarchive");
        let provider = LogarchiveProvider::new(&base);

        let uuidtext_uuids: Vec<Uuid> = provider.uuidtext_uuids().collect();
        assert_eq!(uuidtext_uuids.len(), 876);
        let bytes = provider.read_uuidtext(&uuidtext_uuids[0]).unwrap();
        assert!(!bytes.is_empty());

        let dsc_uuids: Vec<Uuid> = provider.dsc_uuids().collect();
        assert_eq!(dsc_uuids.len(), 1);
        let bytes = provider.read_dsc(&dsc_uuids[0]).unwrap();
        assert!(!bytes.is_empty());

        assert!(provider.read_uuidtext(&Uuid::nil()).is_err());
        assert!(provider.read_dsc(&Uuid::nil()).is_err());
    }

    #[test]
    fn provider_lists_tracev3_and_timesync_sources() {
        use crate::traits::SourceFile as _;

        let base = test_data_path().join("system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(&base);

        let tracev3_sources: Vec<String> = provider
            .tracev3_files()
            .map(|s| s.source_path().to_string())
            .collect();
        let expected: Vec<String> = collect_tracev3_paths(&base)
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        assert_eq!(tracev3_sources, expected);

        assert_eq!(provider.timesync_files().count(), 1);
    }

    #[test]
    fn log_file_type_classifies_paths() {
        assert_eq!(
            LogFileType::from(Path::new("/x/Persist/0000000000000001.tracev3")),
            LogFileType::TraceV3
        );
        assert_eq!(
            LogFileType::from(Path::new("/x/logdata.LiveData.tracev3")),
            LogFileType::TraceV3
        );
        assert_eq!(
            LogFileType::from(Path::new("/x/2E/33403A2FF43E3CB4AE8E33B49D0E23")),
            LogFileType::UUIDText
        );
        assert_eq!(
            LogFileType::from(Path::new("/x/dsc/6D6A521B70DF35D8B0A3EBB4C22FB0AE")),
            LogFileType::Dsc
        );
        assert_eq!(
            LogFileType::from(Path::new("/x/timesync/A5D3382D.timesync")),
            LogFileType::Timesync
        );
        assert_eq!(
            LogFileType::from(Path::new("/x/other.txt")),
            LogFileType::Invalid
        );
    }

    #[test]
    fn in_memory_provider_round_trips() {
        use crate::traits::SourceFile as _;

        let uuid = Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let mut provider = InMemoryProvider::default();
        provider
            .tracev3
            .push(("mem://a.tracev3".into(), vec![1, 2, 3]));
        provider.uuidtext.insert(uuid, vec![4, 5]);

        let mut sources: Vec<_> = provider.tracev3_files().collect();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_path(), "mem://a.tracev3");
        let mut data = Vec::new();
        sources[0].reader().read_to_end(&mut data).unwrap();
        assert_eq!(data, vec![1, 2, 3]);

        assert_eq!(provider.read_uuidtext(&uuid).unwrap(), vec![4, 5]);
        assert!(provider.read_dsc(&uuid).is_err());
        assert_eq!(provider.uuidtext_uuids().collect::<Vec<_>>(), vec![uuid]);
    }
}
