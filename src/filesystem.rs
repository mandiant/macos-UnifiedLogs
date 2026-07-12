use crate::dsc::SharedCacheStrings;
use crate::traits::{FileProvider, SourceFile};
use crate::uuidtext::UUIDText;
use std::fs::File;
use std::io::{Error, ErrorKind, Read};
use std::path::{Component, Path, PathBuf};
use tracing::error;
use walkdir::WalkDir;

pub struct LocalFile {
    reader: File,
    source: String,
}

impl LocalFile {
    fn new(path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            reader: File::open(path)?,
            source: path.as_os_str().to_string_lossy().to_string(),
        })
    }
}

impl SourceFile for LocalFile {
    fn reader(&mut self) -> impl std::io::Read {
        &mut self.reader
    }

    fn source_path(&self) -> &str {
        self.source.as_str()
    }
}

/// Provides an implementation of [`FileProvider`] that enumerates the
/// required files at the correct paths on a live macOS system. These files are only present on
/// macOS Sierra (10.12) and above. The implemented methods emit error log messages if any are
/// encountered while enumerating files or creating readers, but are otherwise infallible.
/// # Example
/// ```rust
///    use macos_unifiedlogs::filesystem::LiveSystemProvider;
///    let provider = LiveSystemProvider::default();
/// ```
#[derive(Default, Debug)]
pub struct LiveSystemProvider;

impl LiveSystemProvider {
    pub fn new() -> Self {
        Self
    }
}

static TRACE_FOLDERS: &[&str] = &["HighVolume", "Special", "Signpost", "Persist"];

#[derive(Debug, PartialEq)]
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

        if let (Some(&Component::Normal(parent)), Some(&Component::Normal(filename))) =
            (components.get(n - 2), components.get(n - 1))
        {
            let parent_s = parent.to_str().unwrap_or_default();
            let filename_s = filename.to_str().unwrap_or_default();

            if filename_s == "logdata.LiveData.tracev3"
                || (filename_s.ends_with(".tracev3") && TRACE_FOLDERS.contains(&parent_s))
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

impl FileProvider for LiveSystemProvider {
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        let path = PathBuf::from("/private/var/db/diagnostics");
        sort_files(
            WalkDir::new(path)
                .sort_by(|a, b| a.file_name().cmp(b.file_name()))
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::TraceV3))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }

    fn uuidtext_files(&self) -> impl Iterator<Item = impl SourceFile> {
        let path = PathBuf::from("/private/var/db/uuidtext");
        sort_files(
            WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::UUIDText))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }

    fn read_uuidtext(&self, uuid: &str) -> Result<UUIDText, Error> {
        let uuid_len = 32;
        let uuid = if uuid.len() == uuid_len - 1 {
            &format!("0{uuid}")
        } else if uuid.len() == uuid_len - 2 {
            &format!("00{uuid}")
        } else if uuid.len() == uuid_len {
            uuid
        } else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("uuid length not correct: {uuid}"),
            ));
        };

        let dir_name = format!("{}{}", &uuid[0..1], &uuid[1..2]);
        let filename = &uuid[2..];

        let mut path = PathBuf::from("/private/var/db/uuidtext");
        path.push(dir_name);
        path.push(filename);

        let mut buf = Vec::new();
        let mut file = LocalFile::new(&path)?;
        file.reader().read_to_end(&mut buf)?;

        let uuid_text = match UUIDText::parse_uuidtext(&buf) {
            Ok((_, results)) => results,
            Err(err) => {
                error!(
                    "Failed to parse UUID file {}: {err:?}",
                    path.to_str().unwrap_or_default()
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read: {uuid}"),
                ));
            }
        };

        Ok(uuid_text)
    }

    fn read_dsc_uuid(&self, uuid: &str) -> Result<SharedCacheStrings, Error> {
        let uuid_len = 32;
        let uuid = if uuid.len() == uuid_len - 1 {
            &format!("0{uuid}")
        } else if uuid.len() == uuid_len - 2 {
            &format!("00{uuid}")
        } else if uuid.len() == uuid_len {
            uuid
        } else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("uuid length not correct: {uuid}"),
            ));
        };

        let mut path = PathBuf::from("/private/var/db/uuidtext/dsc");
        path.push(uuid);

        let mut buf = Vec::new();
        let mut file = LocalFile::new(&path)?;
        file.reader().read_to_end(&mut buf)?;

        let uuid_text = match SharedCacheStrings::parse_dsc(&buf) {
            Ok((_, results)) => results,
            Err(err) => {
                error!(
                    "Failed to parse dsc UUID file {}: {err:?}",
                    path.to_str().unwrap_or_default(),
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read: {uuid}"),
                ));
            }
        };

        Ok(uuid_text)
    }

    fn dsc_files(&self) -> impl Iterator<Item = impl SourceFile> {
        let path = PathBuf::from("/private/var/db/uuidtext/dsc");
        sort_files(WalkDir::new(path).into_iter().filter_map(|entry| {
            if !matches!(
                LogFileType::from(entry.as_ref().ok()?.path()),
                LogFileType::Dsc
            ) {
                return None;
            }
            LocalFile::new(entry.ok()?.path()).ok()
        }))
    }

    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
        let path = PathBuf::from("/private/var/db/diagnostics/timesync");
        sort_files(
            WalkDir::new(path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::Timesync))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }
}

/// Provides an implementation of [`FileProvider`] that enumerates the
/// required files at the correct paths on a from a provided logarchive.
/// # Example
/// ```rust
///    use macos_unifiedlogs::filesystem::LogarchiveProvider;
///    use std::path::PathBuf;
///
///    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
///    test_path.push("tests/test_data/system_logs_big_sur.logarchive");
///    let provider = LogarchiveProvider::new(test_path.as_path());
/// ```
pub struct LogarchiveProvider {
    base: PathBuf,
}

impl LogarchiveProvider {
    pub fn new(path: &Path) -> Self {
        Self {
            base: path.to_path_buf(),
        }
    }
}

impl FileProvider for LogarchiveProvider {
    /// Provide iterator for tracev3 files
    /// # Example
    /// ```rust
    ///    use macos_unifiedlogs::filesystem::LogarchiveProvider;
    ///    use macos_unifiedlogs::traits::{FileProvider, SourceFile};
    ///    use macos_unifiedlogs::parser::collect_timesync;
    ///    use std::path::PathBuf;
    ///
    ///    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ///    test_path.push("tests/test_data/system_logs_big_sur.logarchive");
    ///    let provider = LogarchiveProvider::new(test_path.as_path());
    ///    for mut entry in provider.tracev3_files() {
    ///      println!("TraceV3 file: {}", entry.source_path());
    ///    }
    /// ```
    fn tracev3_files(&self) -> impl Iterator<Item = impl SourceFile> {
        Box::new(
            WalkDir::new(&self.base)
                .sort_by(|a, b| a.file_name().cmp(b.file_name()))
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::TraceV3))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }

    fn uuidtext_files(&self) -> impl Iterator<Item = impl SourceFile> {
        sort_files(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::UUIDText))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }

    fn read_uuidtext(&self, uuid: &str) -> Result<UUIDText, Error> {
        let uuid_len = 32;
        let uuid = if uuid.len() == uuid_len - 1 {
            &format!("0{uuid}")
        } else if uuid.len() == uuid_len - 2 {
            &format!("00{uuid}")
        } else if uuid.len() == uuid_len {
            uuid
        } else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("uuid length not correct: {uuid}"),
            ));
        };

        let dir_name = format!("{}{}", &uuid[0..1], &uuid[1..2]);
        let filename = &uuid[2..];

        let mut base = self.base.clone();
        base.push(dir_name);
        base.push(filename);

        let mut buf = Vec::new();
        let mut file = LocalFile::new(&base)?;
        file.reader().read_to_end(&mut buf)?;

        let uuid_text = match UUIDText::parse_uuidtext(&buf) {
            Ok((_, results)) => results,
            Err(err) => {
                error!(
                    "Failed to parse UUID file {}: {err:?}",
                    base.to_str().unwrap_or_default(),
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read: {uuid}"),
                ));
            }
        };

        Ok(uuid_text)
    }

    fn read_dsc_uuid(&self, uuid: &str) -> Result<SharedCacheStrings, Error> {
        let uuid_len = 32;
        let uuid = if uuid.len() == uuid_len - 1 {
            &format!("0{uuid}")
        } else if uuid.len() == uuid_len - 2 {
            &format!("00{uuid}")
        } else if uuid.len() == uuid_len {
            uuid
        } else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("uuid length not correct: {uuid}"),
            ));
        };

        let mut base = self.base.clone();
        base.push("dsc");
        base.push(uuid);

        let mut buf = Vec::new();
        let mut file = LocalFile::new(&base)?;
        file.reader().read_to_end(&mut buf)?;

        let uuid_text = match SharedCacheStrings::parse_dsc(&buf) {
            Ok((_, results)) => results,
            Err(err) => {
                error!(
                    "Failed to parse dsc UUID file {}: {err:?}",
                    base.to_str().unwrap_or_default(),
                );
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("failed to read: {uuid}"),
                ));
            }
        };

        Ok(uuid_text)
    }

    fn dsc_files(&self) -> impl Iterator<Item = impl SourceFile> {
        sort_files(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::Dsc))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }

    fn timesync_files(&self) -> impl Iterator<Item = impl SourceFile> {
        sort_files(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::Timesync))
                .filter_map(|entry| LocalFile::new(entry.path()).ok()),
        )
    }
}

/// Sort files by their source path,
/// in order to have deterministic output of the parser.
/// Not having it would cause parsing differences across systems
/// (macOS does not guarantee order of files returned by the filesystem).
fn sort_files(
    files: impl Iterator<Item = impl SourceFile>,
) -> impl Iterator<Item = impl SourceFile> {
    let mut files = files.collect::<Vec<_>>();
    files.sort_by(|a, b| a.source_path().cmp(b.source_path()));
    Box::new(files.into_iter())
}

#[cfg(test)]
mod tests {
    use super::{LogFileType, LogarchiveProvider};
    use crate::traits::FileProvider;
    use std::path::PathBuf;

    #[test]
    fn test_only_hex() {
        use super::only_hex_chars;

        let cases = vec![
            "A7563E1D7A043ED29587044987205172",
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        ];

        for case in cases {
            assert!(only_hex_chars(case));
        }
    }

    #[test]
    fn test_validate_uuidtext_path() {
        let valid_cases = vec![
            "/private/var/db/uuidtext/dsc/A7563E1D7A043ED29587044987205172",
            "/private/var/db/uuidtext/dsc/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
            "./dsc/A7563E1D7A043ED29587044987B05172",
        ];

        for case in valid_cases {
            let path = PathBuf::from(case);
            let file_type = LogFileType::from(path.as_path());
            assert_eq!(file_type, LogFileType::Dsc);
        }
    }

    #[test]
    fn test_read_uuidtext() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(test_path.as_path());
        let uuid = provider
            .read_uuidtext("25A8CFC3A9C035F19DBDC16F994EA948")
            .unwrap();
        assert_eq!(uuid.entry_descriptors.len(), 2);
        assert_eq!(uuid.uuid, "");
        assert_eq!(uuid.footer_data.len(), 76544);
        assert_eq!(uuid.signature, 1719109785);
        assert_eq!(uuid.major_version, 2);
        assert_eq!(uuid.minor_version, 1);
        assert_eq!(uuid.number_entries, 2);
    }

    #[test]
    fn test_read_dsc_uuid() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(test_path.as_path());
        let uuid = provider
            .read_dsc_uuid("80896B329EB13A10A7C5449B15305DE2")
            .unwrap();
        assert_eq!(uuid.dsc_uuid, "");
        assert_eq!(uuid.major_version, 1);
        assert_eq!(uuid.minor_version, 0);
        assert_eq!(uuid.number_ranges, 2993);
        assert_eq!(uuid.number_uuids, 1976);
        assert_eq!(uuid.ranges.len(), 2993);
        assert_eq!(uuid.uuids.len(), 1976);
        assert_eq!(uuid.signature, 1685283688);
    }

    #[test]
    fn test_validate_dsc_path() {}

    #[test]
    fn test_validate_timesync_path() {}

    #[test]
    fn test_validate_tracev3_path() {}
}
