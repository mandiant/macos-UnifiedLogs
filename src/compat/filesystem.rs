//! Logarchive filesystem provider for the compatibility layer.
//!
//! Walks a `.logarchive` directory to enumerate tracev3 files in the same
//! order as the legacy `LogarchiveProvider`.

use super::traits::{FileProvider, SourceFile};
use std::fs::File;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

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
      WalkDir::new(&self.base)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| is_tracev3(entry.path()))
        .filter_map(|entry| Some(Box::new(LocalFile::new(entry.path()).ok()?) as Box<dyn SourceFile>)),
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

// ---------------------------------------------------------------------------
// Path classification (matches legacy LogFileType::TraceV3)
// ---------------------------------------------------------------------------

static TRACE_FOLDERS: &[&str] = &["HighVolume", "Special", "Signpost", "Persist"];

fn is_tracev3(path: &Path) -> bool {
  let components = path.components().collect::<Vec<Component<'_>>>();
  let n = components.len();

  if let (Some(&Component::Normal(parent)), Some(&Component::Normal(filename))) =
    (components.get(n.wrapping_sub(2)), components.get(n.wrapping_sub(1)))
  {
    let parent_s = parent.to_str().unwrap_or_default();
    let filename_s = filename.to_str().unwrap_or_default();

    if filename_s == "logdata.LiveData.tracev3"
      || (filename_s.ends_with(".tracev3") && TRACE_FOLDERS.contains(&parent_s))
    {
      return true;
    }
  }

  false
}
