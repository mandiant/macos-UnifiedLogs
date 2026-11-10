// Copyright 2026 European Union. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//! Eager, borrow-free conversion of a `LogEntry` into an owned Python `dict`.
//!
//! The library's `LogEntry<'a, 'b>` is zero-copy and borrow-bound: every string
//! field points into file buffers that are only valid while the visitor callback
//! is running. So each entry is fully materialized into a `Py<PyDict>` here,
//! inside the callback, before it returns. A `Py<PyDict>` is owned and `Send`,
//! so it can cross the thread boundary to the Python iterator.
//!
//! The 22 keys and their formats mirror the hand-written `impl Serialize for
//! LogEntry` in `src/log_entry.rs` (locked by `test_log_entry_json_schema`), with
//! one deliberate exception: `timestamp` is a native Python `datetime.datetime`
//! (UTC) rather than the serde RFC3339 string, since Python pipelines want a real
//! datetime. The full-precision `time` (ns, f64) is unchanged, so no information
//! is lost. Because a `datetime` is not JSON-serializable by default, reproducing
//! the CLI's JSONL requires a custom `json.dumps` encoder (see the README).

use std::collections::HashMap;

use macos_unifiedlogs::log_entry::{EventType, LogEntry, LogType, MessageFlags};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
use uuid::Uuid;

/// Caches `Py<PyString>` for the repeated string fields so identical values reuse
/// one Python `str` instead of allocating a new object per entry. These fields
/// (`subsystem`, `category`, `process`, `library`, `timezone_name`) repeat heavily
/// across a logarchive, so interning cuts allocations substantially.
#[derive(Default)]
pub struct Interner {
    map: HashMap<String, Py<PyString>>,
}

impl Interner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return an interned `Py<PyString>` for `value`, creating it on first sight.
    fn intern(&mut self, py: Python<'_>, value: &str) -> Py<PyString> {
        if let Some(existing) = self.map.get(value) {
            return existing.clone_ref(py);
        }
        let interned: Py<PyString> = PyString::new(py, value).unbind();
        self.map.insert(value.to_owned(), interned.clone_ref(py));
        interned
    }

    /// Intern an optional borrowed field into `Py<PyString> | None`.
    fn intern_opt(&mut self, py: Python<'_>, value: Option<&str>) -> Option<Py<PyString>> {
        value.map(|v| self.intern(py, v))
    }
}

/// serde serializes a fieldless enum as its variant identifier. Reproduce those
/// exact tokens so the dict's `event_type` matches the CLI JSONL.
fn event_type_name(value: EventType) -> &'static str {
    match value {
        EventType::Unknown => "Unknown",
        EventType::Log => "Log",
        EventType::Activity => "Activity",
        EventType::Trace => "Trace",
        EventType::Signpost => "Signpost",
        EventType::Simpledump => "Simpledump",
        EventType::Statedump => "Statedump",
        EventType::Loss => "Loss",
    }
}

fn log_type_name(value: LogType) -> &'static str {
    match value {
        LogType::Debug => "Debug",
        LogType::Info => "Info",
        LogType::Default => "Default",
        LogType::Error => "Error",
        LogType::Fault => "Fault",
        LogType::Create => "Create",
        LogType::Useraction => "Useraction",
        LogType::ProcessSignpostEvent => "ProcessSignpostEvent",
        LogType::ProcessSignpostStart => "ProcessSignpostStart",
        LogType::ProcessSignpostEnd => "ProcessSignpostEnd",
        LogType::SystemSignpostEvent => "SystemSignpostEvent",
        LogType::SystemSignpostStart => "SystemSignpostStart",
        LogType::SystemSignpostEnd => "SystemSignpostEnd",
        LogType::ThreadSignpostEvent => "ThreadSignpostEvent",
        LogType::ThreadSignpostStart => "ThreadSignpostStart",
        LogType::ThreadSignpostEnd => "ThreadSignpostEnd",
        LogType::Simpledump => "Simpledump",
        LogType::Statedump => "Statedump",
        LogType::Loss => "Loss",
    }
}

fn message_flag_name(value: MessageFlags) -> &'static str {
    match value {
        MessageFlags::SharedCache => "SharedCache",
        MessageFlags::MainExe => "MainExe",
        MessageFlags::HasLargeOffset => "HasLargeOffset",
        MessageFlags::LargeSharedCache => "LargeSharedCache",
        MessageFlags::Absolute => "Absolute",
        MessageFlags::UuidRelative => "UuidRelative",
        MessageFlags::MainPlugin => "MainPlugin",
        MessageFlags::PcStyle => "PcStyle",
        MessageFlags::HasUniquePid => "HasUniquePid",
        MessageFlags::HasCurrentAid => "HasCurrentAid",
        MessageFlags::HasOtherAid => "HasOtherAid",
        MessageFlags::HasRules => "HasRules",
        MessageFlags::HasName => "HasName",
        MessageFlags::AltIndex => "AltIndex",
        MessageFlags::Unknown => "Unknown",
        MessageFlags::HasPrivateData => "HasPrivateData",
        MessageFlags::HasOversize => "HasOversize",
        MessageFlags::HasSubsystem => "HasSubsystem",
        MessageFlags::HasPersona => "HasPersona",
    }
}

/// Uppercase bare-hex (32 chars, no hyphens) UUID rendering, identical to the
/// serde impl's `simple().encode_upper(..)`.
fn uuid_hex(uuid: &Uuid) -> String {
    let mut buffer = Uuid::encode_buffer();
    uuid.simple().encode_upper(&mut buffer).to_string()
}

/// Convert a borrowed `LogEntry` into an owned `Py<PyDict>` with all 22 schema
/// keys, eagerly (the pipeline reads every field, so no lazy materialization).
///
/// Key order and formats mirror `impl Serialize for LogEntry`:
/// `subsystem, category, thread_id, pid, euid, persona_id, library, library_uuid,
/// activity_id, parent_activity_id, time, timestamp, event_type, log_type,
/// process, process_uuid, message, format_string, boot_uuid, timezone_name,
/// evidence, message_flags`.
pub fn entry_to_dict(
    py: Python<'_>,
    entry: &LogEntry<'_, '_>,
    interner: &mut Interner,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);

    dict.set_item("subsystem", interner.intern_opt(py, entry.subsystem))?;
    dict.set_item("category", interner.intern_opt(py, entry.category))?;
    dict.set_item("thread_id", entry.thread_id)?;
    dict.set_item("pid", entry.pid)?;
    dict.set_item("euid", entry.euid)?;
    dict.set_item("persona_id", entry.persona_id)?;
    dict.set_item("library", interner.intern_opt(py, entry.library))?;
    dict.set_item("library_uuid", uuid_hex(&entry.library_uuid))?;
    dict.set_item("activity_id", entry.activity_id)?;
    dict.set_item("parent_activity_id", entry.parent_activity_id)?;
    dict.set_item("time", entry.time)?;

    // `timestamp` is a tz-aware Python `datetime.datetime` (UTC), converted from
    // the library's `DateTime<Utc>` via PyO3's `chrono` feature. This departs
    // from the serde impl, which renders `timestamp` as an RFC3339 string: a
    // `datetime` is what Python pipelines actually want, and no information is
    // lost because `time` (ns, f64) remains the full-precision source of truth.
    // Note: Python `datetime` has only microsecond resolution, so sub-microsecond
    // nanoseconds live solely in `time`; and a `datetime` is not JSON-serializable
    // by `json.dumps` without a custom encoder (see the README).
    dict.set_item("timestamp", entry.timestamp())?;

    dict.set_item("event_type", event_type_name(entry.event_type))?;
    dict.set_item("log_type", log_type_name(entry.log_type))?;
    dict.set_item("process", interner.intern_opt(py, entry.process))?;
    dict.set_item("process_uuid", uuid_hex(&entry.process_uuid))?;

    // The single allocation point in the library: format the message on demand.
    let message = entry.message();
    dict.set_item("message", message.as_str())?;

    // The serde impl writes `effective_format_string()`: the real format string
    // when present, else the error fallback text. No Trace special-casing here —
    // that only applies to `raw_message()`, which is not part of the schema.
    let format_string = entry.format_string.or(entry.format_string_error.as_deref());
    dict.set_item("format_string", format_string)?;

    dict.set_item("boot_uuid", uuid_hex(&entry.boot_uuid))?;
    dict.set_item("timezone_name", interner.intern(py, entry.timezone_name))?;
    dict.set_item("evidence", entry.evidence.to_string_lossy().as_ref())?;

    let flags = PyList::new(
        py,
        entry.message_flags.iter().map(|f| message_flag_name(*f)),
    )?;
    dict.set_item("message_flags", flags)?;

    Ok(dict.unbind())
}
