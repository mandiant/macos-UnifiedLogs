//! Python bindings for the `macos-unifiedlogs` library.
//!
//! Exposes the Unified Log parser to Python as the `macos_unifiedlogs`
//! package, built with [PyO3](https://pyo3.rs) and packaged with
//! [maturin](https://www.maturin.rs). The public surface mirrors the visitor
//! pipeline in [`macos_unifiedlogs::logarchive`]:
//!
//! - [`parse_logarchive`] streams entries from a full `.logarchive` directory
//!   (as produced by `log collect`)
//! - [`parse_tracev3`] streams entries from a single tracev3 file
//! - [`parse_live_system`] streams entries from the live system (macOS only)
//! - [`LogArchive`] is the streaming iterator class all of them return
//!
//! Every log entry is yielded as a plain `dict` with the same fields the
//! library serializes to JSON (see the `Serialize` impl on
//! [`LogEntry`]): subsystem, message, process, pid, time, timestamp,
//! event_type, log_type, … — except `timestamp`, which is handed to Python
//! as a timezone-aware `datetime` (UTC) instead of an RFC 3339 string.
//!
//! # Uniformly streaming, flat memory by construction
//!
//! Every entry point goes through the same bounded channel — there is no way
//! to accidentally materialize the whole archive. A dedicated worker thread
//! drives the library's push-based visitor with the GIL released
//! (`Python::detach`), serializing each zero-copy [`LogEntry`] to an owned
//! [`serde_json::Value`] in pure Rust and converting full batches to
//! `Py<PyDict>` objects under brief GIL re-acquisitions. The batches travel
//! over a bounded `std::sync::mpsc` channel (single producer / single
//! consumer, so no extra dependency is needed): the parse thread blocks once
//! a few batches are queued, keeping memory flat regardless of archive size —
//! measured at ~138 MB peak on a 747k-entry archive — while parsing overlaps
//! with Python-side work. Dropping the iterator closes the receiver, which
//! makes the visit callback return `ControlFlow::Break` and stops parsing
//! early.
//!
//! The library's visitor API yields zero-copy [`LogEntry`] values that borrow
//! the parse buffers, so the bindings serialize each entry inside the visit
//! callback; because the serde schema is walked directly, new or changed
//! entry fields flow through to Python without hand-maintaining a converter.

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
use pyo3::exceptions::{PyFileNotFoundError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;
use tracing::warn;

/// pyo3 0.30 removed the `PyObject` alias for `Py<PyAny>`; keep using the name
/// internally for readability.
type PyObject = Py<PyAny>;

/// Default number of entries converted and shipped per batch, tunable per
/// call via the `batch_size` argument.
///
/// The bounded channel only ever holds [`STREAM_CHANNEL_CAPACITY`] batches,
/// so peak memory stays flat regardless of archive size; the batch size just
/// amortizes the cross-thread hand-off. 512 sits on the measured throughput
/// plateau (256–1024 entries) of the upstream benchmark on a 747,616-entry
/// archive while keeping per-batch GIL re-acquisitions coarse.
const DEFAULT_BATCH_SIZE: usize = 512;

/// Number of batches the bounded channel holds before the parse thread
/// blocks. Small, so at most `STREAM_CHANNEL_CAPACITY * batch_size` live
/// dicts are queued between the parse thread and the Python iterator.
const STREAM_CHANNEL_CAPACITY: usize = 4;

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
/// The `timestamp` field becomes a timezone-aware Python `datetime` (the
/// value is UTC); everything else is converted per [`json_to_py`].
/// Non-object values produce an empty `dict`, which cannot occur for
/// serialized log entries.
fn value_to_pydict(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    if let serde_json::Value::Object(map) = value {
        for (key, val) in map {
            if key == "timestamp" {
                dict.set_item(key.as_str(), timestamp_to_py(py, val)?)?;
            } else {
                dict.set_item(key.as_str(), json_to_py(py, val)?)?;
            }
        }
    }
    Ok(dict.unbind())
}

/// Convert the RFC 3339 `timestamp` field into a timezone-aware Python
/// `datetime` (always UTC). Falls back to the raw string when parsing fails,
/// which cannot occur for values produced by the library.
fn timestamp_to_py<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        serde_json::Value::String(ts) => match chrono::DateTime::parse_from_rfc3339(ts) {
            Ok(dt) => Ok(dt.into_pyobject(py)?.into_any()),
            Err(_) => Ok(ts.clone().into_pyobject(py)?.into_any()),
        },
        _ => json_to_py(py, value),
    }
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

/// Resolve the user-facing `batch_size` argument, rejecting zero.
fn resolve_batch_size(batch_size: Option<usize>) -> PyResult<usize> {
    match batch_size {
        None => Ok(DEFAULT_BATCH_SIZE),
        Some(0) => Err(PyValueError::new_err("batch_size must be greater than 0")),
        Some(n) => Ok(n),
    }
}

/// Which source the streaming worker thread should parse.
#[derive(Debug)]
enum Source {
    /// A `.logarchive` directory (as produced by `log collect`).
    Logarchive(PathBuf),
    /// One tracev3 file, `relative` to the logarchive base directory that
    /// holds the `uuidtext`/`dsc`/`timesync` support files.
    Tracev3 {
        /// Logarchive base directory.
        base: PathBuf,
        /// Tracev3 file path, relative to `base`.
        relative: PathBuf,
    },
    /// The live macOS system (`/private/var/db/diagnostics`).
    LiveSystem,
}

/// Build a [`Source::Tracev3`] for an absolute tracev3 file path inside
/// `base`, rejecting files outside the logarchive base directory.
///
/// `visit_logarchive_tracev3_file` resolves the tracev3 path against `base`,
/// so the containment check happens up front, here.
///
/// # Errors
///
/// Returns `ErrorKind::InvalidInput` when the file is not inside `base`.
fn tracev3_source(file_path: PathBuf, base: PathBuf) -> Result<Source, std::io::Error> {
    let relative = file_path.strip_prefix(&base).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("tracev3 file {file_path:?} is not inside logarchive base {base:?}"),
        )
    })?;
    Ok(Source::Tracev3 {
        base,
        relative: relative.to_path_buf(),
    })
}

// ---------------------------------------------------------------------------
// Streaming worker: visit on a thread, ship batches over a bounded channel
// ---------------------------------------------------------------------------

/// Messages handed from the visit worker thread to the [`LogArchive`]
/// iterator.
#[derive(Debug)]
enum StreamMsg {
    /// A batch of converted log-entry dicts.
    Batch(Vec<Py<PyDict>>),
    /// The visit finished. `None` means success; `Some` carries the failure.
    End(Option<std::io::Error>),
}

/// Convert a full batch of serialized entries into `Py<PyDict>` objects and
/// ship it over the channel in one send.
///
/// Runs on the visit worker thread, so the conversion re-acquires the GIL
/// briefly via `Python::attach` (the visit itself runs detached). Entries
/// that fail to convert are skipped with a `tracing` warning, matching the
/// library's behavior of warning and skipping individual bad files.
///
/// Returns `false` when the receiver is gone (the Python iterator was
/// dropped), signalling the caller to stop parsing via `ControlFlow::Break`.
fn flush_batch(
    batch: &mut Vec<serde_json::Value>,
    tx: &mpsc::SyncSender<StreamMsg>,
) -> bool {
    if batch.is_empty() {
        return true;
    }
    let dicts = Python::attach(|py| {
        batch
            .drain(..)
            .filter_map(|value| match value_to_pydict(py, &value) {
                Ok(dict) => Some(dict),
                Err(err) => {
                    warn!("Failed to convert log entry to a dict: {err}");
                    None
                }
            })
            .collect::<Vec<Py<PyDict>>>()
    });
    tx.send(StreamMsg::Batch(dicts)).is_ok()
}

/// Drive the visitor for `source` on the worker thread, batching serialized
/// entries and shipping converted dicts over the bounded channel.
///
/// The visit runs with the GIL released; the GIL is re-acquired only once
/// per batch, inside [`flush_batch`]. A bad entry is skipped with a
/// `tracing` warning instead of stopping the stream.
///
/// # Errors
///
/// Returns the visit error as-is: `ErrorKind::NotFound` when the provider
/// yields no tracev3 files at all — a wrong or unreadable path rather than an
/// empty log.
fn visit_source(
    source: &Source,
    batch_size: usize,
    tx: &mpsc::SyncSender<StreamMsg>,
) -> Result<(), std::io::Error> {
    let mut batch: Vec<serde_json::Value> = Vec::with_capacity(batch_size);

    let on_entry = |entry: LogEntry<'_, '_>| {
        // Serialize the zero-copy entry in pure Rust, no GIL. A failed
        // serialization skips the entry with a warning.
        match entry_to_value(&entry) {
            Ok(value) => batch.push(value),
            Err(err) => warn!("Failed to serialize log entry: {err}"),
        }

        if batch.len() >= batch_size && !flush_batch(&mut batch, tx) {
            // Receiver gone (iterator dropped): stop parsing early.
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };

    let result = match source {
        Source::Logarchive(path) => visit_logarchive(path, on_entry),
        Source::Tracev3 { base, relative } => {
            visit_logarchive_tracev3_file(base, relative, on_entry)
        }
        Source::LiveSystem => visit_live_system(on_entry),
    };

    // Flush the final partial batch. A failed send is expected when the
    // receiver is gone, so the result is ignored.
    let _ = flush_batch(&mut batch, tx);
    result
}

/// Spawn the visit worker thread for `source`, returning the receiving half
/// of the bounded channel and the join handle used by the [`LogArchive`]
/// pyclass.
///
/// The thread marks itself as a Python user up front (`Python::attach`),
/// then releases the GIL for the whole visit (`Python::detach`) so other
/// Python threads keep running; the GIL is re-acquired per batch inside
/// [`flush_batch`]. The worker always terminates by sending a final
/// [`StreamMsg::End`] with the visit result.
fn spawn_stream(
    source: Source,
    batch_size: usize,
) -> (mpsc::Receiver<StreamMsg>, thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::sync_channel::<StreamMsg>(STREAM_CHANNEL_CAPACITY);

    let handle = thread::spawn(move || {
        Python::attach(|py| {
            py.detach(|| {
                let result = visit_source(&source, batch_size, &tx);
                // Always send an End so the receiver can stop cleanly. If the
                // receiver is already gone (iterator dropped), sending is a
                // no-op error.
                let end = match result {
                    Ok(()) => StreamMsg::End(None),
                    Err(err) => StreamMsg::End(Some(err)),
                };
                let _ = tx.send(end);
            })
        })
    });

    (rx, handle)
}

/// Streaming parser for macOS Unified Log data.
///
/// Iterates over fully reconstructed log entries, one `dict` per `next()`.
/// The visit runs on a worker thread and entries are handed back in batches
/// through a bounded channel, so only a small, fixed number of batches is
/// held in memory at a time — memory stays flat no matter how large the
/// archive is. Every entry point of this module returns a `LogArchive`;
/// materializing the whole archive is only possible by explicitly building
/// a Python list (`list(LogArchive(path))`). Dropping the iterator early
/// stops the visit.
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
    /// Channel receiver for the batches produced by the visit worker
    /// thread. `None` once the stream has finished or been shut down;
    /// dropping it unblocks a full channel so the worker stops parsing.
    rx: Mutex<Option<mpsc::Receiver<StreamMsg>>>,
    /// The batch most recently received from the worker, drained one dict
    /// per `__next__` call.
    current: std::vec::IntoIter<Py<PyDict>>,
    /// Handle to the visit worker thread, joined on stream end and drop.
    handle: Option<thread::JoinHandle<()>>,
}

impl LogArchive {
    /// Build a streaming parser around an already-validated [`Source`].
    fn from_source(source: Source, batch_size: usize) -> Self {
        let (rx, handle) = spawn_stream(source, batch_size);
        Self {
            rx: Mutex::new(Some(rx)),
            current: Vec::new().into_iter(),
            handle: Some(handle),
        }
    }

    /// Build a streaming parser for a logarchive directory, validating the
    /// path up front.
    ///
    /// # Errors
    ///
    /// Raises `FileNotFoundError` when `path` is not a directory, and
    /// `ValueError` for a zero `batch_size`.
    fn from_path(path: &str, batch_size: Option<usize>) -> PyResult<Self> {
        let batch_size = resolve_batch_size(batch_size)?;
        let path = PathBuf::from(path);
        if !path.is_dir() {
            return Err(PyFileNotFoundError::new_err(format!(
                "logarchive directory not found: {}",
                path.display()
            )));
        }
        Ok(Self::from_source(Source::Logarchive(path), batch_size))
    }

    /// Stop the stream: drop the receiver so a blocked worker send fails
    /// (translating to `ControlFlow::Break` in the visit callback), then
    /// join the worker thread.
    ///
    /// The join runs with the GIL released: the worker re-acquires the GIL
    /// to convert batches, so joining while holding it could deadlock.
    /// `Python::attach` is a no-op re-acquisition when the GIL is already
    /// held by the caller.
    fn shutdown(&mut self) {
        // Recover from a poisoned lock instead of panicking across the FFI
        // boundary: the lock guards nothing but receiver access, and the
        // stream state lives in the channel.
        *self.rx.lock().unwrap_or_else(|p| p.into_inner()) = None;
        if let Some(handle) = self.handle.take() {
            Python::attach(|py| {
                py.detach(|| {
                    let _ = handle.join();
                })
            });
        }
    }
}

impl Drop for LogArchive {
    fn drop(&mut self) {
        // Dropping the iterator stops the visit promptly instead of letting
        // the worker parse the whole archive for nobody.
        self.shutdown();
    }
}

#[pymethods]
impl LogArchive {
    /// Create a streaming parser for a logarchive directory (as produced by
    /// `log collect`). When no path is provided, the live system is parsed
    /// (macOS only).
    ///
    /// `batch_size` tunes how many entries are converted and shipped per
    /// channel message (default: 512); the bounded channel keeps memory flat
    /// regardless of the value.
    ///
    /// # Errors
    ///
    /// Raises `FileNotFoundError` when `path` is not a directory, and
    /// `ValueError` when `batch_size` is zero.
    #[new]
    #[pyo3(signature = (path=None, batch_size=None))]
    fn new(path: Option<&str>, batch_size: Option<usize>) -> PyResult<Self> {
        match path {
            Some(path) => Self::from_path(path, batch_size),
            None => Ok(Self::from_source(
                Source::LiveSystem,
                resolve_batch_size(batch_size)?,
            )),
        }
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
    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyDict>>> {
        loop {
            if let Some(dict) = self.current.next() {
                return Ok(Some(dict));
            }

            // Batch drained — block for the next one. Release the GIL while
            // waiting so the worker can re-acquire it to convert the next
            // batch (and other Python threads can run). The receiver is
            // accessed through the mutex guard inside the closure because a
            // bare `&Receiver` is not `Send` and cannot cross `detach`.
            let msg = py.detach(|| {
                self.rx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .as_ref()
                    .map(|rx| rx.recv())
            });

            match msg {
                // Already shut down or finished.
                None => return Ok(None),
                Some(msg) => match msg {
                    Ok(StreamMsg::Batch(dicts)) => {
                        self.current = dicts.into_iter();
                        // Loop around to yield the first item of the new batch.
                    }
                    Ok(StreamMsg::End(None)) => {
                        self.shutdown();
                        return Ok(None);
                    }
                    Ok(StreamMsg::End(Some(err))) => {
                        self.shutdown();
                        return Err(visit_err_to_py(err));
                    }
                    Err(RecvError) => {
                        // The worker always sends `End` before exiting, so a
                        // closed channel means it panicked mid-visit.
                        *self.rx.lock().unwrap_or_else(|p| p.into_inner()) = None;
                        let joined = match self.handle.take() {
                            Some(handle) => {
                                // Join with the GIL released: the worker may
                                // be waiting to acquire it mid-conversion.
                                Python::attach(|py| py.detach(|| handle.join()))
                            }
                            None => Ok(()),
                        };
                        return match joined {
                            // The worker exited without sending End; treat
                            // the stream as finished.
                            Ok(()) => Ok(None),
                            Err(payload) => {
                                let msg = payload
                                    .downcast_ref::<&'static str>()
                                    .map(|s| s.to_string())
                                    .or_else(|| payload.downcast_ref::<String>().cloned())
                                    .unwrap_or_else(|| {
                                        "visit worker thread panicked".to_string()
                                    });
                                Err(UnifiedLogError::new_err(msg))
                            }
                        };
                    }
                },
            }
        }
    }
}

/// Stream every log entry from a `.logarchive` directory (as produced by
/// `log collect`), as a [`LogArchive`] iterator yielding one `dict` per
/// entry.
///
/// The entries flow through a bounded channel from a worker thread, so
/// memory stays flat regardless of archive size; use `list(...)` on the
/// result to deliberately materialize every entry.
///
/// # Errors
///
/// Raises `FileNotFoundError` when `path` is not a directory (or contains no
/// tracev3 files), `UnifiedLogError` for other visit failures, and
/// `ValueError` when `batch_size` is zero.
#[pyfunction]
#[pyo3(signature = (path, batch_size=None))]
pub fn parse_logarchive(path: &str, batch_size: Option<usize>) -> PyResult<LogArchive> {
    LogArchive::from_path(path, batch_size)
}

/// Stream every entry from the Unified Logs on the live system (macOS only)
/// as a [`LogArchive`] iterator yielding one `dict` per entry.
///
/// Reads tracev3/timesync data from `/private/var/db/diagnostics` and
/// `UUIDText`/DSC support files from `/private/var/db/uuidtext`.
///
/// # Errors
///
/// Raises `FileNotFoundError` on a non-Apple platform (the live provider
/// yields no tracev3 files), `UnifiedLogError` for other visit failures, and
/// `ValueError` when `batch_size` is zero.
#[pyfunction]
#[pyo3(signature = (batch_size=None))]
pub fn parse_live_system(batch_size: Option<usize>) -> PyResult<LogArchive> {
    Ok(LogArchive::from_source(
        Source::LiveSystem,
        resolve_batch_size(batch_size)?,
    ))
}

/// Stream every log entry from a single tracev3 file, as a [`LogArchive`]
/// iterator yielding one `dict` per entry.
///
/// `logarchive` optionally points to the logarchive directory (or extracted
/// archive layout) that contains the `uuidtext`/`dsc`/`timesync` files needed
/// to reconstruct strings and timestamps. When omitted, the parent directory
/// of the tracev3 file is used.
///
/// # Errors
///
/// Raises `FileNotFoundError` when the tracev3 file does not exist,
/// `UnifiedLogError` when the file lies outside the logarchive base or the
/// visit fails, and `ValueError` when `batch_size` is zero.
#[pyfunction]
#[pyo3(signature = (path, logarchive=None, batch_size=None))]
pub fn parse_tracev3(
    path: &str,
    logarchive: Option<&str>,
    batch_size: Option<usize>,
) -> PyResult<LogArchive> {
    let batch_size = resolve_batch_size(batch_size)?;

    let file_path = PathBuf::from(path);
    if !file_path.is_file() {
        return Err(PyFileNotFoundError::new_err(format!(
            "tracev3 file not found: {path}"
        )));
    }

    let base = logarchive.map(PathBuf::from).unwrap_or_else(|| {
        file_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    });
    let source = tracev3_source(file_path, base).map_err(visit_err_to_py)?;

    Ok(LogArchive::from_source(source, batch_size))
}

/// Registers the `UnifiedLogError` exception, the [`LogArchive`] class, the
/// streaming `parse_*` functions and `DEFAULT_BATCH_SIZE` on the
/// `_macos_unifiedlogs` module.
#[pymodule]
fn _macos_unifiedlogs(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("UnifiedLogError", py.get_type::<UnifiedLogError>())?;
    m.add("DEFAULT_BATCH_SIZE", DEFAULT_BATCH_SIZE)?;
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
    fn tracev3_outside_base_rejected() {
        let err = tracev3_source(
            PathBuf::from("/this/path/does/not/exist.tracev3"),
            PathBuf::from("/other/base"),
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn tracev3_inside_base_resolved_relative() {
        let source = tracev3_source(
            PathBuf::from("/archive/Persist/0000000000000002.tracev3"),
            PathBuf::from("/archive"),
        )
        .unwrap();
        match source {
            Source::Tracev3 { base, relative } => {
                assert_eq!(base, Path::new("/archive"));
                assert_eq!(relative, Path::new("Persist/0000000000000002.tracev3"));
            }
            other => panic!("expected Source::Tracev3, got {other:?}"),
        }
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
    fn timestamp_becomes_timezone_aware_datetime() {
        use chrono::{Datelike, TimeZone};

        let value: serde_json::Value = serde_json::json!({
            "pid": 1u64,
            "timestamp": "2024-05-01T12:00:00.123456789Z",
        });
        Python::attach(|py| {
            let obj = value_to_pydict(py, &value).unwrap();
            let dict = obj.bind(py).cast::<PyDict>().unwrap();

            // A timezone-aware datetime in UTC, not a plain string
            let ts = dict.get_item("timestamp").unwrap().unwrap();
            let dt = ts.extract::<chrono::DateTime<chrono::FixedOffset>>().unwrap();
            assert_eq!(dt.year(), 2024);
            assert_eq!(dt.month(), 5);
            assert_eq!(chrono::Utc.from_utc_datetime(&dt.naive_utc()), dt);

            // Other fields still convert normally
            let pid = dict.get_item("pid").unwrap().unwrap();
            assert_eq!(pid.extract::<u64>().unwrap(), 1);
        });
    }

    #[test]
    fn batch_size_resolution() {
        assert_eq!(resolve_batch_size(None).unwrap(), DEFAULT_BATCH_SIZE);
        assert_eq!(resolve_batch_size(Some(1)).unwrap(), 1);
        Python::attach(|py| {
            let err = resolve_batch_size(Some(0)).unwrap_err();
            assert!(err.is_instance_of::<PyValueError>(py));
        });
    }

    #[test]
    fn missing_archive_dir_surfaces_not_found_at_stream_end() {
        let (rx, handle) = spawn_stream(
            Source::Logarchive(PathBuf::from("/this/path/does/not/exist")),
            16,
        );
        match rx.recv() {
            Ok(StreamMsg::End(Some(err))) => assert_eq!(err.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected End(Some(NotFound)), got {other:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn dropping_receiver_does_not_hang_the_worker() {
        let (rx, handle) = spawn_stream(
            Source::Logarchive(PathBuf::from("/this/path/does/not/exist")),
            16,
        );
        drop(rx);
        // The worker notices the gone receiver and exits instead of
        // blocking on a full channel forever.
        handle.join().unwrap();
    }

    #[test]
    fn logarchive_next_maps_visit_error_to_file_not_found() {
        Python::attach(|py| {
            let mut archive = LogArchive::from_source(
                Source::Logarchive(PathBuf::from("/this/path/does/not/exist")),
                16,
            );
            let err = archive.__next__(py).unwrap_err();
            assert!(err.is_instance_of::<PyFileNotFoundError>(py));
        });
    }

    #[test]
    fn batch_flush_converts_values_and_reports_closed_channel() {
        let (tx, rx) = mpsc::sync_channel::<StreamMsg>(STREAM_CHANNEL_CAPACITY);
        let mut batch = vec![serde_json::json!({"pid": 1u64}), serde_json::json!({"pid": 2u64})];

        Python::attach(|py| {
            assert!(flush_batch(&mut batch, &tx));
            assert!(batch.is_empty());
            match rx.recv() {
                Ok(StreamMsg::Batch(dicts)) => {
                    assert_eq!(dicts.len(), 2);
                    let pid = dicts[0]
                        .bind(py)
                        .get_item("pid")
                        .unwrap()
                        .unwrap()
                        .extract::<u64>()
                        .unwrap();
                    assert_eq!(pid, 1);
                }
                other => panic!("expected Batch, got {other:?}"),
            }

            // With the receiver gone the flush reports failure so the visit
            // can stop early.
            drop(rx);
            let mut batch = vec![serde_json::json!({"pid": 3u64})];
            assert!(!flush_batch(&mut batch, &tx));
        });
    }
}
