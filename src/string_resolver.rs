// Copyright 2024 Shindan, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0

//! On-demand string resolution for [`StructuralEntry`].
//!
//! [`StringResolver`] takes a [`StructuralEntry`] and resolves it into a full
//! [`LogData`] by looking up format strings from DSC/UUIDText, resolving oversize
//! entries, and formatting the log message.
//!
//! This is the "slow path" — only called for entries that pass structural filtering.

use regex::Regex;
use uuid::Uuid;

use crate::chunks::oversize::Oversize;
use crate::tracev3_stream::StructuralEntry;
use crate::traits::FileProvider;
use crate::unified_log::{LogData, LogType};
use crate::empty_rc_string;

/// Resolves structural entries into full LogData with strings.
///
/// Caches the compiled regex and provides access to the FileProvider for
/// UUIDText/DSC lookups.
pub struct StringResolver<'a> {
    provider: &'a mut dyn FileProvider,
    message_re: Regex,
}

impl<'a> StringResolver<'a> {
    /// Create a new resolver with access to the file provider.
    pub fn new(provider: &'a mut dyn FileProvider) -> Self {
        Self {
            provider,
            // Same regex as used in unified_log.rs LogIterator
            message_re: Regex::new(
                r"(%\{[^}]*\}(?:[-+0 #]*)(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h{0,2}|l{0,2}|[qLztj])?[@dDiuUxXoOfeEgGcCsSpaAFP%nm]|%(?:[-+0 #]*)(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h{0,2}|l{0,2}|[qLztj])?[@dDiuUxXoOfeEgGcCsSpaAFP%nm])"
            ).expect("Failed to compile message format regex"),
        }
    }

    /// Access the underlying file provider.
    pub fn provider(&self) -> &dyn FileProvider {
        self.provider
    }

    /// Resolve a structural entry into a full LogData.
    ///
    /// This performs the expensive operations:
    /// 1. Parse message items from raw_firehose_data
    /// 2. Look up format string from DSC/UUIDText
    /// 3. Look up oversize strings if needed
    /// 4. Format the log message (printf-style expansion)
    /// 5. Look up subsystem/category from catalog
    ///
    /// Returns None if the entry cannot be resolved (e.g., missing format string).
    pub fn resolve(
        &mut self,
        entry: &StructuralEntry<'_, '_>,
        oversize_cache: &[Oversize],
    ) -> Option<LogData> {
        // For now, this is a placeholder that demonstrates the API.
        // Full implementation would delegate to the existing message.rs / unified_log.rs logic
        // after parsing the raw firehose data on demand.

        // Get subsystem/category
        let (subsystem, category) = if entry.subsystem_value != 0 {
            match entry.catalog.get_subsystem(
                entry.subsystem_value,
                entry.first_proc_id,
                entry.second_proc_id,
            ) {
                Ok((_, info)) => (info.subsystem, info.category),
                Err(_) => (empty_rc_string(), empty_rc_string()),
            }
        } else {
            (empty_rc_string(), empty_rc_string())
        };

        // Get oversize strings if this entry has an oversize reference
        let oversize_items = if entry.has_oversize() {
            Oversize::get_oversize_strings(
                entry.data_ref_value,
                entry.first_proc_id,
                entry.second_proc_id,
                oversize_cache,
            )
        } else {
            &[]
        };

        let _ = oversize_items; // Will be used in full implementation

        Some(LogData {
            subsystem,
            thread_id: entry.thread_id,
            pid: entry.pid,
            euid: entry.euid,
            library: empty_rc_string(),
            library_uuid: Uuid::nil(),
            activity_id: 0,
            time: entry.timestamp,
            category,
            event_type: crate::unified_log::EventType::Log,
            log_type: LogType::Default,
            process: empty_rc_string(),
            process_uuid: Uuid::nil(),
            message: empty_rc_string(),
            raw_message: empty_rc_string(),
            boot_uuid: entry.boot_uuid,
            timezone_name: empty_rc_string(),
            message_entries: Vec::new(),
            timestamp: crate::util::unixepoch_to_datetime(entry.timestamp as i64),
        })
    }
}
