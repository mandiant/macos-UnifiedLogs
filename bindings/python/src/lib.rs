//! Python bindings for the `macos-unifiedlogs` library.
//!
//! Exposes the Unified Log parser to Python as the `macos_unifiedlogs`
//! package, built with [PyO3](https://pyo3.rs) and packaged with
//! [maturin](https://www.maturin.rs). The public surface mirrors the visitor
//! pipeline in [`macos_unifiedlogs::logarchive`]:
//!
//! - [`parse_logarchive`] parses a full `.logarchive` directory (as produced
//!   by `log collect`) into a list of dicts
//! - [`parse_tracev3`] parses a single tracev3 file
//! - [`parse_live_system`] parses the live system (macOS only)
//! - [`LogArchive`] streams entries one at a time, holding only a small
//!   buffer plus the string cache in memory
//!
//! Every log entry is returned as a plain `dict` with the same fields the
//! library serializes to JSON (see the `Serialize` impl on
//! [`LogEntry`]): subsystem, message, process, pid, time, timestamp,
//! event_type, log_type, …
//!
//! The library's visitor API yields zero-copy [`LogEntry`] values that borrow
//! the parse buffers, so the bindings serialize each entry to an owned
//! [`serde_json::Value`] inside the visit callback — pure Rust, no GIL —
//! and convert it to a `dict` only at the Python boundary. The GIL is
//! released while a visit runs, so other Python threads keep executing
//! during long parses. The streaming [`LogArchive`] runs the visit on a
//! worker thread and hands entries back through a channel, so callers can
//! consume a large archive entry-by-entry without buffering it.

#![warn(missing_docs)]

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvError};
use std::sync::Mutex;
use std::thread;

use macos_unifiedlogs::log_entry::LogEntry;
use macos_unifiedlogs::logarchive::{
    visit_live_system, visit_logarchive, visit_logarchive_tracev3_file,
};
use pyo3::create_exception;
use pyo3::exceptions::PyFileNotFoundError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;
use tracing::warn;

/// pyo3 0.30 removed the `PyObject` alias for `Py<PyAny>`; keep using the name
/// internally for readability.
type PyObject = Py<PyAny>;

/// Bounded channel capacity between the visit worker thread and the
/// [`LogArchive`] iterator. Small enough to bound memory, large enough to
/// amortize per-entry wakeups.
const STREAM_CHANNEL_CAPACITY: usize = 64;

// Exception raised to Python when Unified Log data could not be parsed.
//
// Exported as `macos_unifiedlogs.UnifiedLogError`; subclasses `RuntimeError`.
// Missing paths are reported as `FileNotFoundError` instead.
create_exception!(
    macos_unifiedlogs,
    UnifiedLogError,
    pyo3::exceptions::PyRuntimeError,
    "Raised when macOS Unified Log data could not be parsed"
);

/// Convert a [`serde_json::Value`] into the matching Python object.
///
/// `null` becomes `None`, objects become `dict`s and arrays become `list`s.
fn json_to_py<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    use serde_json::Value;
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(b) => Ok((*b).into_py_any(py)?.into_bound(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any())
            } else {
                Ok(n.as_f64().unwrap_or_default().into_pyobject(py)?.into_any())
            }
        }
        Value::String(s) => Ok(s.clone().into_pyobject(py)?.into_any()),
        Value::Array(items) => {
            let elements: Vec<PyObject> = items
                .iter()
                .map(|item| Ok(json_to_py(py, item)?.unbind()))
                .collect::<PyResult<_>>()?;
            Ok(elements.into_pyobject(py)?.into_any())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, val) in map {
                dict.set_item(key.as_str(), json_to_py(py, val)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

/// Convert a serialized log entry (a JSON object) into a plain Python `dict`.
///
/// Non-object values produce an empty `dict`, which cannot occur for
/// serialized log entries.
fn value_to_pydict(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    if let serde_json::Value::Object(map) = value {
        for (key, val) in map {
            dict.set_item(key.as_str(), json_to_py(py, val)?)?;
        }
    }
    Ok(dict.into_any().unbind())
}

/// Serialize a zero-copy [`LogEntry`] to an owned [`serde_json::Value`].
///
/// This is the hand-off point between the borrow-based visitor API
/// ([`macos_unifiedlogs::logarchive`]) and the owned data that can safely
/// cross the GIL/thread boundary.
fn entry_to_value(entry: &LogEntry<'_, '_>) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(entry)
}

/// Map a `std::io::Error` from a visit to the matching Python exception.
///
/// `ErrorKind::NotFound` (a wrong archive path, or the live-system provider
/// on a non-Apple platform yielding no files) becomes `FileNotFoundError`;
/// anything else becomes `UnifiedLogError`.
fn visit_err_to_py(err: std::io::Error) -> PyErr {
    if err.kind() == std::io::ErrorKind::NotFound {
        PyFileNotFoundError::new_err(err.to_string())
    } else {
        UnifiedLogError::new_err(err.to_string())
    }
}

/// Visit callback shared by the eager collectors: serialize the entry or, if
/// serialization fails, skip it with a `tracing` warning — matching the
/// library's behavior of warning and skipping individual bad files.
fn record_callback(
    records: &mut Vec<serde_json::Value>,
) -> impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) + '_ {
    move |entry| match entry_to_value(&entry) {
        Ok(value) => records.push(value),
        Err(err) => warn!("Failed to serialize log entry: {err}"),
    }
}

/// Visit a logarchive directory, collecting every entry as an owned JSON value.
///
/// # Errors
///
/// Returns the visit error as-is: `ErrorKind::NotFound` when the provider
/// yields no tracev3 files at all — a wrong or unreadable path rather than
/// an empty log.
fn collect_archive(path: &Path) -> Result<Vec<serde_json::Value>, std::io::Error> {
    let mut records = Vec::new();
    visit_logarchive(path, record_callback(&mut records))?;
    Ok(records)
}

/// Visit the live system (macOS only), collecting every entry as an owned
/// JSON value.
///
/// # Errors
///
/// Returns the visit error as-is: on a non-Apple platform the live provider
/// yields no tracev3 files and the visit fails with `ErrorKind::NotFound`.
fn collect_live() -> Result<Vec<serde_json::Value>, std::io::Error> {
    let mut records = Vec::new();
    visit_live_system(record_callback(&mut records))?;
    Ok(records)
}

/// Visit a single tracev3 file resolved against a logarchive/base directory,
/// collecting every entry as an owned JSON value.
///
/// `visit_logarchive_tracev3_file` joins the tracev3 path onto `base`, so
/// `file_path` is passed relative to `base`.
///
/// # Errors
///
/// Returns `ErrorKind::InvalidInput` when the file is not inside `base`,
/// and the visit error otherwise.
fn collect_tracev3(
    file_path: &Path,
    base: &Path,
) -> Result<Vec<serde_json::Value>, std::io::Error> {
    let relative = file_path.strip_prefix(base).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("tracev3 file {file_path:?} is not inside logarchive base {base:?}"),
        )
    })?;
    let mut records = Vec::new();
    visit_logarchive_tracev3_file(base, relative, record_callback(&mut records))?;
    Ok(records)
}

/// Convert a batch of owned JSON values into a list of Python `dict`s.
fn values_to_pylist(py: Python<'_>, values: &[serde_json::Value]) -> PyResult<Vec<PyObject>> {
    values
        .iter()
        .map(|value| value_to_pydict(py, value))
        .collect()
}

// ---------------------------------------------------------------------------
// Streaming iterator over a worker-thread visit
// ---------------------------------------------------------------------------

/// Messages handed from the visit worker thread to the [`LogArchive`]
/// iterator.
#[derive(Debug)]
enum StreamMsg {
    /// One serialized log entry.
    Entry(serde_json::Value),
    /// The visit finished. `None` means success; `Some` carries the failure.
    End(Option<std::io::Error>),
}

/// Visit callback shared by the streaming workers: serialize the entry and
/// hand it to the iterator, or skip it with a `tracing` warning. Returns
/// `ControlFlow::Break` when the receiver is gone (the Python iterator was
/// dropped), so early abandonment stops parsing instead of producing the
/// whole archive.
fn stream_callback(
    tx: &mpsc::SyncSender<StreamMsg>,
) -> impl for<'a, 'b> FnMut(LogEntry<'a, 'b>) -> ControlFlow<()> + '_ {
    move |entry| match entry_to_value(&entry) {
        Ok(value) => {
            if tx.send(StreamMsg::Entry(value)).is_err() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        }
        Err(err) => {
            warn!("Failed to serialize log entry: {err}");
            ControlFlow::Continue(())
        }
    }
}

/// Run a visit on a worker thread, streaming serialized entries through a
/// bounded channel. Returns the receiver and join handle used by the
/// [`LogArchive`] pyclass.
///
/// The visit closure must be pure Rust (no GIL, no Python objects); it
/// receives the sending half of the channel. It always terminates by
/// returning, after which the worker sends a final [`StreamMsg::End`] with
/// the visit result.
fn spawn_stream<F>(visit: F) -> (mpsc::Receiver<StreamMsg>, thread::JoinHandle<()>)
where
    F: FnOnce(mpsc::SyncSender<StreamMsg>) -> Result<(), std::io::Error> + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel::<StreamMsg>(STREAM_CHANNEL_CAPACITY);

    let handle = thread::spawn(move || {
        let result = visit(tx.clone());
        // Always send an End so the receiver can stop cleanly. If the receiver
        // is already gone (iterator dropped), sending is a no-op error.
        let end = match result {
            Ok(()) => StreamMsg::End(None),
            Err(err) => StreamMsg::End(Some(err)),
        };
        let _ = tx.send(end);
    });

    (rx, handle)
}

/// Streaming parser for macOS Unified Log data.
///
/// Iterates over fully reconstructed log entries, one `dict` per `next()`.
/// The visit runs on a worker thread and entries are handed back through a
/// bounded channel, so only a small buffer is held in memory at a time —
/// unlike [`parse_logarchive`], which materializes every entry up front.
/// Dropping the iterator early stops the visit.
///
/// Example:
/// ```python
/// from macos_unifiedlogs import LogArchive
///
/// for entry in LogArchive("/path/to/system_logs.logarchive"):
///     print(entry["timestamp"], entry["message"])
/// ```
///
/// With no argument, the live system is parsed (only works on macOS):
/// ```python
/// for entry in LogArchive():
///     print(entry["timestamp"], entry["message"])
/// ```
#[pyclass]
pub struct LogArchive {
    /// Channel receiver for entries serialized by the visit worker thread.
    rx: Mutex<mpsc::Receiver<StreamMsg>>,
    /// Handle to the visit worker thread, joined on abnormal stream end.
    handle: Option<thread::JoinHandle<()>>,
}

#[pymethods]
impl LogArchive {
    /// Create a streaming parser for a logarchive directory (as produced by
    /// `log collect`). When no path is provided, the live system is parsed
    /// (macOS only).
    ///
    /// # Errors
    ///
    /// Raises `FileNotFoundError` when `path` is not a directory.
    #[new]
    #[pyo3(signature = (path=None))]
    fn new(path: Option<&str>) -> PyResult<Self> {
        let (rx, handle) = match path {
            Some(path) => {
                let path = PathBuf::from(path);
                if !path.is_dir() {
                    return Err(PyFileNotFoundError::new_err(format!(
                        "logarchive directory not found: {}",
                        path.display()
                    )));
                }
                spawn_stream(move |tx| visit_logarchive(&path, stream_callback(&tx)))
            }
            None => spawn_stream(move |tx| visit_live_system(stream_callback(&tx))),
        };

        Ok(Self {
            rx: Mutex::new(rx),
            handle: Some(handle),
        })
    }

    /// Return the iterator itself, so `LogArchive` instances are directly
    /// iterable (`for entry in LogArchive(path)`).
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Return the next log entry as a `dict`, or `None` to end iteration
    /// (`StopIteration` in Python).
    ///
    /// # Errors
    ///
    /// Maps the visit result with [`visit_err_to_py`]: `FileNotFoundError`
    /// when no tracev3 files were found (e.g. the live system on a non-Apple
    /// platform), `UnifiedLogError` for any other visit failure or a
    /// worker-thread panic.
    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        // Wait without holding the GIL so other Python threads keep running
        // while the visit produces the next entry.
        let msg = py.detach(|| {
            // Recover from a poisoned lock instead of panicking across the
            // FFI boundary: the lock guards nothing but receiver access, and
            // the stream state lives in the channel.
            self.rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .recv()
        });

        match msg {
            Ok(StreamMsg::Entry(value)) => Ok(Some(value_to_pydict(py, &value)?)),
            Ok(StreamMsg::End(None)) => Ok(None),
            Ok(StreamMsg::End(Some(err))) => Err(visit_err_to_py(err)),
            Err(RecvError) => {
                // The worker always sends `End` before exiting, so a closed
                // channel means it panicked mid-visit.
                match self.handle.take().map(|handle| handle.join()) {
                    Some(Ok(())) => Ok(None),
                    Some(Err(payload)) => {
                        let msg = payload
                            .downcast_ref::<&'static str>()
                            .map(|s| s.to_string())
                            .or_else(|| payload.downcast_ref::<String>().map(String::clone))
                            .unwrap_or_else(|| "visit worker thread panicked".to_string());
                        Err(UnifiedLogError::new_err(msg))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    /// Collect all log entries into a list. Equivalent to
    /// `list(LogArchive(path))`, but the visit runs without holding the GIL
    /// and the entries are converted once it completes.
    ///
    /// # Errors
    ///
    /// Raises `FileNotFoundError` when `path` is not a directory, and
    /// `UnifiedLogError` when the visit fails.
    #[staticmethod]
    #[pyo3(signature = (path=None))]
    fn parse_all(path: Option<&str>) -> PyResult<Vec<PyObject>> {
        Python::attach(|py| {
            let values = match path {
                Some(path) => {
                    let path = PathBuf::from(path);
                    if !path.is_dir() {
                        return Err(PyFileNotFoundError::new_err(format!(
                            "logarchive directory not found: {}",
                            path.display()
                        )));
                    }
                    // Release the GIL while the (potentially long) visit runs.
                    py.detach(|| collect_archive(&path)).map_err(visit_err_to_py)?
                }
                None => py.detach(collect_live).map_err(visit_err_to_py)?,
            };
            values_to_pylist(py, &values)
        })
    }
}

/// Parse a logarchive directory (as produced by `log collect`) and return all
/// reconstructed log entries as a list of dicts.
///
/// Every entry is materialized in memory; for large archives consider the
/// streaming [`LogArchive`] class instead.
///
/// # Errors
///
/// Raises `FileNotFoundError` when `path` is not a directory (or contains no
/// tracev3 files), and `UnifiedLogError` for other visit failures.
#[pyfunction]
pub fn parse_logarchive(path: &str) -> PyResult<Vec<PyObject>> {
    LogArchive::parse_all(Some(path))
}

/// Parse the Unified Logs on the live system (macOS only) and return all
/// reconstructed log entries as a list of dicts.
///
/// Reads tracev3/timesync data from `/private/var/db/diagnostics` and
/// `UUIDText`/DSC support files from `/private/var/db/uuidtext`.
///
/// # Errors
///
/// Raises `FileNotFoundError` on a non-Apple platform (the live provider
/// yields no tracev3 files), and `UnifiedLogError` for other visit failures.
#[pyfunction]
pub fn parse_live_system() -> PyResult<Vec<PyObject>> {
    LogArchive::parse_all(None)
}

/// Parse a single tracev3 file and return all reconstructed log entries as a
/// list of dicts.
///
/// `logarchive` optionally points to the logarchive directory (or extracted
/// archive layout) that contains the `uuidtext`/`dsc`/`timesync` files needed
/// to reconstruct strings and timestamps. When omitted, the parent directory
/// of the tracev3 file is used.
///
/// # Errors
///
/// Raises `FileNotFoundError` when the tracev3 file does not exist, and
/// `UnifiedLogError` when the file lies outside the logarchive base or the
/// visit fails.
#[pyfunction]
#[pyo3(signature = (path, logarchive=None))]
pub fn parse_tracev3(path: &str, logarchive: Option<&str>) -> PyResult<Vec<PyObject>> {
    let file_path = PathBuf::from(path);
    if !file_path.is_file() {
        return Err(PyFileNotFoundError::new_err(format!(
            "tracev3 file not found: {path}"
        )));
    }

    let base = logarchive
        .map(PathBuf::from)
        .unwrap_or_else(|| file_path.parent().map(Path::to_path_buf).unwrap_or_default());

    Python::attach(|py| {
        // Release the GIL while the visit runs.
        let values = py
            .detach(|| collect_tracev3(&file_path, &base))
            .map_err(visit_err_to_py)?;
        values_to_pylist(py, &values)
    })
}

/// Registers the `UnifiedLogError` exception, the [`LogArchive`] class and
/// the `parse_*` functions on the `_macos_unifiedlogs` module.
#[pymodule]
fn _macos_unifiedlogs(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("UnifiedLogError", py.get_type::<UnifiedLogError>())?;
    m.add_class::<LogArchive>()?;
    m.add_function(wrap_pyfunction!(parse_logarchive, m)?)?;
    m.add_function(wrap_pyfunction!(parse_live_system, m)?)?;
    m.add_function(wrap_pyfunction!(parse_tracev3, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_archive_dir_rejected() {
        let err = collect_archive(Path::new("/this/path/does/not/exist")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn tracev3_outside_base_rejected() {
        let err = collect_tracev3(
            Path::new("/this/path/does/not/exist.tracev3"),
            Path::new("/other/base"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn visit_errors_map_to_matching_exceptions() {
        Python::attach(|py| {
            let not_found = visit_err_to_py(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no tracev3 files found",
            ));
            assert!(not_found.is_instance_of::<PyFileNotFoundError>(py));

            let other = visit_err_to_py(std::io::Error::other("disk error"));
            assert!(other.is_instance_of::<UnifiedLogError>(py));
        });
    }

    #[test]
    fn json_to_py_roundtrip() {
        let value: serde_json::Value = serde_json::json!({
            "subsystem": "com.example",
            "pid": 42u64,
            "time": 1.5_f64,
            "active": true,
            "tags": ["a", "b"],
            "missing": serde_json::Value::Null,
        });
        Python::attach(|py| {
            let obj = value_to_pydict(py, &value).unwrap();
            let dict = obj.bind(py).cast::<PyDict>().unwrap();

            let pid = dict.get_item("pid").unwrap().unwrap();
            assert_eq!(pid.extract::<u64>().unwrap(), 42);

            let subsystem = dict.get_item("subsystem").unwrap().unwrap();
            assert_eq!(subsystem.extract::<String>().unwrap(), "com.example");

            let time = dict.get_item("time").unwrap().unwrap();
            assert_eq!(time.extract::<f64>().unwrap(), 1.5);

            assert!(dict.get_item("active").unwrap().unwrap().is_truthy().unwrap());

            let tags = dict.get_item("tags").unwrap().unwrap();
            assert_eq!(tags.extract::<Vec<String>>().unwrap(), ["a", "b"]);

            // JSON null becomes Python None
            assert!(dict.get_item("missing").unwrap().unwrap().is_none());
        });
    }

    #[test]
    fn spawn_stream_forwards_entries_and_end_result() {
        let (rx, handle) = spawn_stream(|tx| {
            tx.send(StreamMsg::Entry(serde_json::json!({"pid": 1})))
                .expect("receiver is alive in this test");
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no tracev3 files found",
            ))
        });

        assert!(matches!(rx.recv(), Ok(StreamMsg::Entry(_))));
        match rx.recv() {
            Ok(StreamMsg::End(Some(err))) => assert_eq!(err.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected End(Some), got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn spawn_stream_ends_with_none_on_success() {
        let (rx, handle) = spawn_stream(|_tx| Ok(()));
        assert!(matches!(rx.recv(), Ok(StreamMsg::End(None))));
        handle.join().unwrap();
    }
}