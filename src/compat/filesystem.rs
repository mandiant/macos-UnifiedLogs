//! Logarchive filesystem provider for the compatibility layer.
//!
//! Walks a `.logarchive` directory to enumerate tracev3 files in the same
//! order as the legacy `LogarchiveProvider`.

use super::traits::{FileProvider, SourceFile};
use std::fs::File;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::rewrite::filesystem::collect_tracev3_paths;
use crate::rewrite::logarchive::{load_file_buffers_by_uuid, load_uuidtext_buffers};

// ---------------------------------------------------------------------------
// LogarchiveProvider
// ---------------------------------------------------------------------------

/// Provides tracev3 files from a logarchive directory on disk.
///
/// Caches DSC and `UUIDText` buffers so they are loaded from disk only once
/// across multiple `build_log` calls.
pub struct LogarchiveProvider {
    base: PathBuf,
    pub(crate) dsc_buffers: Option<Vec<(Uuid, Vec<u8>)>>,
    pub(crate) uuidtext_buffers: Option<Vec<(Uuid, Vec<u8>)>>,
}

impl LogarchiveProvider {
    pub fn new(path: &Path) -> Self {
        Self {
            base: path.to_path_buf(),
            dsc_buffers: None,
            uuidtext_buffers: None,
        }
    }

    /// Get DSC buffers, loading from disk on first call.
    pub(crate) fn dsc_buffers(&mut self) -> &[(Uuid, Vec<u8>)] {
        if self.dsc_buffers.is_none() {
            self.dsc_buffers = Some(load_file_buffers_by_uuid(&self.base.join("dsc")));
        }
        self.dsc_buffers.as_ref().unwrap()
    }

    /// Get `UUIDText` buffers, loading from disk on first call.
    pub(crate) fn uuidtext_buffers(&mut self) -> &[(Uuid, Vec<u8>)] {
        if self.uuidtext_buffers.is_none() {
            self.uuidtext_buffers = Some(load_uuidtext_buffers(&self.base));
        }
        self.uuidtext_buffers.as_ref().unwrap()
    }
}

impl FileProvider for LogarchiveProvider {
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        Box::new(
            collect_tracev3_paths(&self.base)
                .into_iter()
                .filter_map(|path| {
                    Some(Box::new(LocalFile::new(&path).ok()?) as Box<dyn SourceFile>)
                }),
        )
    }

    fn logarchive_base_path(&self) -> &Path {
        &self.base
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------
// LiveSystemProvider
// ---------------------------------------------------------------------------

/// Provides tracev3 files and support files from a live macOS system.
///
/// This preserves the legacy-compatible `filesystem::LiveSystemProvider` API
/// while using the rewrite path collection rules internally.
pub struct LiveSystemProvider {
    diagnostics_root: PathBuf,
    uuidtext_root: PathBuf,
    pub(crate) dsc_buffers: Option<Vec<(Uuid, Vec<u8>)>>,
    pub(crate) uuidtext_buffers: Option<Vec<(Uuid, Vec<u8>)>>,
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
            dsc_buffers: None,
            uuidtext_buffers: None,
        }
    }

    /// Get DSC buffers, loading from disk on first call.
    pub(crate) fn dsc_buffers(&mut self) -> &[(Uuid, Vec<u8>)] {
        if self.dsc_buffers.is_none() {
            self.dsc_buffers = Some(load_file_buffers_by_uuid(&self.dsc_dir()));
        }
        self.dsc_buffers.as_ref().unwrap()
    }

    /// Get `UUIDText` buffers, loading from disk on first call.
    pub(crate) fn uuidtext_buffers(&mut self) -> &[(Uuid, Vec<u8>)] {
        if self.uuidtext_buffers.is_none() {
            self.uuidtext_buffers = Some(load_uuidtext_buffers(&self.uuidtext_root()));
        }
        self.uuidtext_buffers.as_ref().unwrap()
    }
}

impl Default for LiveSystemProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FileProvider for LiveSystemProvider {
    fn tracev3_files(&self) -> Box<dyn Iterator<Item = Box<dyn SourceFile>>> {
        Box::new(
            collect_tracev3_paths(&self.diagnostics_root)
                .into_iter()
                .filter_map(|path| {
                    Some(Box::new(LocalFile::new(&path).ok()?) as Box<dyn SourceFile>)
                }),
        )
    }

    fn logarchive_base_path(&self) -> &Path {
        &self.diagnostics_root
    }

    fn uuidtext_root(&self) -> PathBuf {
        self.uuidtext_root.clone()
    }

    fn dsc_dir(&self) -> PathBuf {
        self.uuidtext_root.join("dsc")
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// ---------------------------------------------------------------------------
// LocalFile
// ---------------------------------------------------------------------------

struct LocalFile {
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
    fn reader(&mut self) -> Box<&mut dyn std::io::Read> {
        Box::new(&mut self.reader)
    }

    fn source_path(&self) -> &str {
        self.source.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::helpers::tests::test_data_path;

    #[test]
    fn live_provider_uses_live_style_support_roots() {
        let diagnostics_root = test_data_path().join("system_logs_big_sur.logarchive");
        let uuidtext_root = test_data_path().join("system_logs_big_sur.logarchive");
        let provider =
            LiveSystemProvider::with_roots(diagnostics_root.clone(), uuidtext_root.clone());

        assert_eq!(provider.logarchive_base_path(), diagnostics_root);
        assert_eq!(provider.timesync_dir(), diagnostics_root.join("timesync"));
        assert_eq!(provider.uuidtext_root(), uuidtext_root);
        assert_eq!(provider.dsc_dir(), provider.uuidtext_root().join("dsc"));
        assert_eq!(
            provider.tracev3_files().count(),
            collect_tracev3_paths(&diagnostics_root).len()
        );
    }
}
