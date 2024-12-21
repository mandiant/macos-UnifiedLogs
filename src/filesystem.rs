use crate::traits::FileProvider;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

/// Provides an implementation of [`FileProvider`] that enumerates the
/// required files at the correct paths on a live macOS system. These files are only present on
/// macOS Sierra (10.12) and above. The implemented methods emit error log messages if any are
/// encountered while enumerating files or creating readers, but are otherwise infallible.
#[derive(Default, Clone, Debug)]
pub struct LiveSystemProvider {}

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
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn std::io::Read>>> {
        let path = PathBuf::from("/private/var/db/diagnostics");
        Box::new(
            WalkDir::new(path)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::TraceV3))
                .filter_map(|entry| {
                    Some(Box::new(std::fs::File::open(entry.path()).ok()?) as Box<dyn Read>)
                }),
        )
    }

    fn uuidtext_files(&self) -> Box<dyn Iterator<Item = (Box<dyn std::io::Read>, String)>> {
        let path = PathBuf::from("/private/var/db/uuidtext");
        Box::new(
            WalkDir::new(path)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::UUIDText))
                .map(|entry| {
                    (
                        std::fs::File::open(entry.path()),
                        entry
                            .file_name()
                            .to_os_string()
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
                .map(|(handle, file_name)| (handle.ok(), file_name))
                .filter_map(|(handle, file_name)| Some((handle?, file_name)))
                .map(|(handle, file_name)| (Box::new(handle) as Box<dyn Read>, file_name)),
        )
    }

    fn dsc_files(&self) -> Box<dyn Iterator<Item = (Box<dyn std::io::Read>, String)>> {
        let path = PathBuf::from("/private/var/db/uuidtext/dsc");
        Box::new(
            WalkDir::new(path)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .map(|entry| {
                    (
                        std::fs::File::open(entry.path()),
                        entry
                            .file_name()
                            .to_os_string()
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
                .map(|(handle, file_name)| (handle.ok(), file_name))
                .filter_map(|(handle, file_name)| Some((handle?, file_name)))
                .map(|(handle, file_name)| (Box::new(handle) as Box<dyn Read>, file_name)),
        )
    }

    fn timesync_files(&self) -> Box<dyn Iterator<Item = Box<dyn std::io::Read>>> {
        let path = PathBuf::from("/private/var/db/diagnostics/timesync");
        Box::new(
            WalkDir::new(path)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::Timesync))
                .filter_map(|entry| {
                    Some(Box::new(std::fs::File::open(entry.path()).ok()?) as Box<dyn Read>)
                }),
        )
    }
}

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
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn std::io::Read>>> {
        Box::new(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::TraceV3))
                .filter_map(|entry| {
                    Some(Box::new(std::fs::File::open(entry.path()).ok()?) as Box<dyn Read>)
                }),
        )
    }

    fn uuidtext_files(&self) -> Box<dyn Iterator<Item = (Box<dyn std::io::Read>, String)>> {
        Box::new(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::UUIDText))
                .map(|entry| {
                    (
                        std::fs::File::open(entry.path()),
                        entry
                            .file_name()
                            .to_os_string()
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
                .map(|(handle, file_name)| (handle.ok(), file_name))
                .filter_map(|(handle, file_name)| Some((handle?, file_name)))
                .map(|(handle, file_name)| (Box::new(handle) as Box<dyn Read>, file_name)),
        )
    }

    fn dsc_files(&self) -> Box<dyn Iterator<Item = (Box<dyn std::io::Read>, String)>> {
        Box::new(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::Dsc))
                .map(|entry| {
                    (
                        std::fs::File::open(entry.path()),
                        entry
                            .file_name()
                            .to_os_string()
                            .to_string_lossy()
                            .into_owned(),
                    )
                })
                .map(|(handle, file_name)| (handle.ok(), file_name))
                .filter_map(|(handle, file_name)| Some((handle?, file_name)))
                .map(|(handle, file_name)| (Box::new(handle) as Box<dyn Read>, file_name)),
        )
    }

    fn timesync_files(&self) -> Box<dyn Iterator<Item = Box<dyn std::io::Read>>> {
        Box::new(
            WalkDir::new(&self.base)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| matches!(LogFileType::from(entry.path()), LogFileType::Timesync))
                .filter_map(|entry| {
                    Some(Box::new(std::fs::File::open(entry.path()).ok()?) as Box<dyn Read>)
                }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::LogFileType;
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
            println!("{:?}", path.components());
            let file_type = LogFileType::from(path.as_path());
            assert_eq!(file_type, LogFileType::Dsc);
        }
    }

    #[test]
    fn test_validate_dsc_path() {}

    #[test]
    fn test_validate_timesync_path() {}

    #[test]
    fn test_validate_tracev3_path() {}
}
