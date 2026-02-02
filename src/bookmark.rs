// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Bookmark {
    pub last_timestamp: f64,
    pub processed_files: HashMap<String, u64>,
    /// Boot UUID to detect system reboots (resets bookmark if changed)
    /// TODO: Implement boot UUID checking - currently stored but never compared.
    /// Should extract boot UUID from first log entry and compare against current
    /// system boot UUID. If different, reset bookmark since timestamps are only
    /// valid within a single boot session.
    pub boot_uuid: Option<String>,
    pub last_updated: String,
    /// path for archive/file mode, "live" for live mode
    pub source_id: String,
}

impl Bookmark {
    /// Create a new bookmark for a given source
    pub fn new(source_id: String) -> Self {
        Self {
            last_timestamp: 0.0,
            processed_files: HashMap::new(),
            boot_uuid: None,
            last_updated: chrono::Utc::now().to_rfc3339(),
            source_id,
        }
    }

    pub fn load(path: &Path) -> Option<Self> {
        let contents = fs::read_to_string(path).ok()?;
        serde_json::from_str(&contents).ok()
    }

    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = fs::File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn should_process_entry(&self, timestamp: f64) -> bool {
        timestamp > self.last_timestamp
    }

    pub fn update_timestamp(&mut self, timestamp: f64) {
        if timestamp > self.last_timestamp {
            self.last_timestamp = timestamp;
            self.last_updated = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn update_file_offset(&mut self, path: &str, offset: u64) {
        self.processed_files.insert(path.to_string(), offset);
        self.last_updated = chrono::Utc::now().to_rfc3339();
    }

    pub fn default_path(mode: &str) -> PathBuf {
        // Get data directory following XDG Base Directory spec
        // macOS: ~/Library/Application Support/
        // Linux: ~/.local/share/
        let data_dir = if cfg!(target_os = "macos") {
            std::env::var("HOME")
                .map(|home| PathBuf::from(home).join("Library/Application Support"))
                .unwrap_or_else(|_| PathBuf::from("."))
        } else {
            // Linux/Unix fallback
            std::env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    std::env::var("HOME")
                        .map(|home| PathBuf::from(home).join(".local/share"))
                        .unwrap_or_else(|_| PathBuf::from("."))
                })
        };

        let bookmark_dir = data_dir.join("unifiedlog_iterator");

        // Create directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&bookmark_dir) {
            eprintln!(
                "Warning: Failed to create bookmark directory {:?}: {}",
                bookmark_dir, e
            );
        }

        bookmark_dir.join(format!("{}.bookmark", mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bookmark_filter() {
        let mut bookmark = Bookmark::new("test".to_string());
        bookmark.last_timestamp = 1000.0;

        assert!(bookmark.should_process_entry(1001.0));
        assert!(bookmark.should_process_entry(2000.0));
        assert!(!bookmark.should_process_entry(999.0));
        assert!(!bookmark.should_process_entry(1000.0));
    }

    #[test]
    fn test_bookmark_save_load() {
        let mut bookmark = Bookmark::new("test".to_string());
        bookmark.last_timestamp = 1234567890.0;
        bookmark.boot_uuid = Some("ABC123".to_string());
        bookmark.update_file_offset("/test/file.tracev3", 1024);

        // Use a temporary file path in /tmp
        let temp_path = PathBuf::from(format!("/tmp/test_bookmark_{}.json", std::process::id()));
        bookmark.save(&temp_path).unwrap();

        let loaded = Bookmark::load(&temp_path).unwrap();
        assert_eq!(loaded.last_timestamp, bookmark.last_timestamp);
        assert_eq!(loaded.boot_uuid, bookmark.boot_uuid);
        assert_eq!(
            loaded.processed_files.get("/test/file.tracev3"),
            Some(&1024)
        );

        // Cleanup
        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn test_update_timestamp() {
        let mut bookmark = Bookmark::new("test".to_string());
        bookmark.last_timestamp = 100.0;

        bookmark.update_timestamp(50.0); // Older, should not update
        assert_eq!(bookmark.last_timestamp, 100.0);

        bookmark.update_timestamp(150.0); // Newer, should update
        assert_eq!(bookmark.last_timestamp, 150.0);
    }
}
