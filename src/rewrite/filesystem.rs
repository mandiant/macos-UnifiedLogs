//! Filesystem providers for rewrite parser input layouts.
//!
//! The rewrite parser can process the same trace/support-file layout from either
//! a `.logarchive` directory or a live macOS system. Providers expose those
//! roots without changing the lower-level `tracev3` parser.

use std::path::{Path, PathBuf};

/// Provides paths required by the rewrite parser.
pub trait RewriteFileProvider {
    /// Tracev3 files in deterministic processing order.
    fn tracev3_paths(&self) -> Vec<PathBuf>;

    /// Directory containing `.timesync` files.
    fn timesync_dir(&self) -> PathBuf;

    /// Root containing UUIDText two-character hex directories.
    fn uuidtext_root(&self) -> PathBuf;

    /// Directory containing DSC shared-cache string files.
    fn dsc_dir(&self) -> PathBuf;
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

impl RewriteFileProvider for LogarchiveProvider {
    fn tracev3_paths(&self) -> Vec<PathBuf> {
        collect_tracev3_paths(&self.base)
    }

    fn timesync_dir(&self) -> PathBuf {
        self.base.join("timesync")
    }

    fn uuidtext_root(&self) -> PathBuf {
        self.base.clone()
    }

    fn dsc_dir(&self) -> PathBuf {
        self.base.join("dsc")
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

impl RewriteFileProvider for LiveSystemProvider {
    fn tracev3_paths(&self) -> Vec<PathBuf> {
        collect_tracev3_paths(&self.diagnostics_root)
    }

    fn timesync_dir(&self) -> PathBuf {
        self.diagnostics_root.join("timesync")
    }

    fn uuidtext_root(&self) -> PathBuf {
        self.uuidtext_root.clone()
    }

    fn dsc_dir(&self) -> PathBuf {
        self.uuidtext_root.join("dsc")
    }
}

/// Collect all tracev3 file paths in processing order.
///
/// The base path may be either a `.logarchive` root or the live macOS diagnostics
/// directory (`/private/var/db/diagnostics`).
///
/// Order: `HighVolume` -> `Persist` -> `Signpost` -> `Special` ->
/// `logdata.LiveData.tracev3`. Within each directory, files are sorted by name.
pub fn collect_tracev3_paths(base: &Path) -> Vec<PathBuf> {
    let subdirs = ["HighVolume", "Persist", "Signpost", "Special"];
    let mut paths = Vec::new();

    for subdir in &subdirs {
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

    let live_data = base.join("logdata.LiveData.tracev3");
    if live_data.is_file() {
        paths.push(live_data);
    }

    paths
}

fn sorted_paths(paths: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut paths = paths.collect::<Vec<_>>();
    paths.sort();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::helpers::tests::test_data_path;

    #[test]
    fn logarchive_provider_uses_archive_layout() {
        let base = test_data_path().join("system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(&base);

        assert_eq!(provider.timesync_dir(), base.join("timesync"));
        assert_eq!(provider.uuidtext_root(), base);
        assert_eq!(provider.dsc_dir(), provider.uuidtext_root().join("dsc"));
        assert_eq!(provider.tracev3_paths(), collect_tracev3_paths(&base));
    }

    #[test]
    fn live_provider_uses_diagnostics_and_uuidtext_roots() {
        let diagnostics_root = test_data_path().join("system_logs_big_sur.logarchive");
        let uuidtext_root = test_data_path().join("system_logs_big_sur.logarchive");
        let provider =
            LiveSystemProvider::with_roots(diagnostics_root.clone(), uuidtext_root.clone());

        assert_eq!(provider.timesync_dir(), diagnostics_root.join("timesync"));
        assert_eq!(provider.uuidtext_root(), uuidtext_root);
        assert_eq!(provider.dsc_dir(), provider.uuidtext_root().join("dsc"));
        assert_eq!(
            provider.tracev3_paths(),
            collect_tracev3_paths(&diagnostics_root)
        );
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
    }
}
