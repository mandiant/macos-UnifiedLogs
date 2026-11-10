// Copyright 2026 European Union. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//! `unifiedlogs` — a Python binding over the `macos-unifiedlogs` library.
//!
//! Streams every parsed `LogEntry` from a `.logarchive` into Python as a plain
//! `dict`. The keys and formats mirror the library's serde schema, with one
//! deliberate exception: `timestamp` is a native `datetime.datetime` rather than
//! an RFC3339 string (see `convert.rs`). Because of that, reproducing the CLI's
//! JSONL requires a `json.dumps(dict, default=str)` encoder. Business logic and
//! serialization stay in Python; Rust only parses and hands over dicts.
//!
//! # Architecture
//!
//! The library exposes a *push-based* visitor (`visit_logarchive`,
//! `visit_logarchive_tracev3_file`). Python wants a *pull-based* iterator. The
//! bridge is a dedicated background OS thread that runs the visitor with the GIL
//! released (`Python::detach`), re-acquiring the GIL only briefly to convert a
//! batch of entries into `Py<PyDict>` objects and sending the batch over a
//! **bounded** channel. The Python-side iterator drains one dict at a time.
//!
//! The bounded channel gives backpressure: the parse thread blocks once a few
//! batches are queued, so memory stays flat even on 5M+ entry archives, and
//! parsing overlaps with Python-side work. Dropping the Python iterator closes
//! the receiver, which makes the callback return `ControlFlow::Break` and stops
//! parsing early.
//!
//! Channel choice: `std::sync::mpsc::sync_channel`. This is a single-producer
//! (parse thread) / single-consumer (Python iterator) hand-off, which std's
//! bounded channel covers directly; staying std-only keeps the dependency tree
//! clean for `cargo deny`. crossbeam would add a dependency for no benefit here.

mod convert;

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

use pyo3::exceptions::{PyFileNotFoundError, PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

use macos_unifiedlogs::logarchive::{visit_logarchive, visit_logarchive_tracev3_file};

use convert::{Interner, entry_to_dict};

/// Default number of entries converted and shipped per batch, tunable per-call
/// via the `batch_size` argument and benchmarked by `benchmarks/bench_iter.py`.
///
/// Throughput plateaus across 256–512 and regresses for larger batches (coarser
/// cross-thread wakeups reduce the parse/consume overlap); peak memory is
/// governed by the bounded channel, not the batch size, so it stays flat up to
/// 1024. Measured on `system_logs_big_sur.logarchive` (747,616 entries):
/// 256 ≈ 278k entries/s, 512 ≈ 275k, 1024 ≈ 252k, 2048 ≈ 207k, all at ~138 MB
/// peak. 512 sits on the plateau and is the larger of the two plateau values.
/// See the README for the full table.
const DEFAULT_BATCH_SIZE: usize = 512;

/// Number of batches the bounded channel holds before the parse thread blocks.
/// Small, so peak memory is bounded to roughly `CHANNEL_CAPACITY * batch_size`
/// live dicts regardless of archive size.
const CHANNEL_CAPACITY: usize = 4;

/// Which visitor the parse thread should drive.
enum Source {
    Logarchive(PathBuf),
    Tracev3 {
        logarchive: PathBuf,
        tracev3: PathBuf,
    },
}

/// A batch of converted entries, or a terminal error from the parse thread.
enum Message {
    Batch(Vec<Py<PyDict>>),
    Err(std::io::Error),
}

/// Pull-based Python iterator over converted log-entry dicts.
///
/// Holds the receiving end of the bounded channel, the current batch and a
/// cursor into it, and the parse-thread handle. Dropping it closes the receiver,
/// signalling the parse thread to stop.
// `unsendable`: the iterator holds an mpsc `Receiver` (Send but !Sync) and is
// created/consumed on a single Python thread. PyO3 otherwise requires pyclasses
// to be Send + Sync; `unsendable` enforces single-thread ownership at runtime
// instead. The parse thread and the per-entry `Py<PyDict>` hand-off remain Send.
#[pyclass(module = "unifiedlogs", unsendable)]
struct LogEntryIterator {
    receiver: Option<Receiver<Message>>,
    current: std::vec::IntoIter<Py<PyDict>>,
    handle: Option<JoinHandle<()>>,
}

impl LogEntryIterator {
    fn spawn(source: Source, batch_size: usize) -> Self {
        let (sender, receiver) = sync_channel::<Message>(CHANNEL_CAPACITY);

        let handle = std::thread::spawn(move || {
            run_parse(source, batch_size, sender);
        });

        LogEntryIterator {
            receiver: Some(receiver),
            current: Vec::new().into_iter(),
            handle: Some(handle),
        }
    }

    /// Join the parse thread, dropping the receiver first so the parse thread's
    /// `send` fails and it stops (translating to `ControlFlow::Break`).
    ///
    /// The join runs with the GIL released: the parse thread converts entries
    /// under `Python::attach`, so if we joined while holding the GIL and the
    /// parse thread were mid-conversion waiting to acquire it, we would deadlock.
    /// `Python::attach(|py| py.detach(..))` releases the GIL for the join whether
    /// or not the caller already holds it (attach is a no-op when already held).
    fn shutdown(&mut self) {
        self.receiver = None;
        if let Some(handle) = self.handle.take() {
            Python::attach(|py| {
                py.detach(|| {
                    let _ = handle.join();
                });
            });
        }
    }
}

#[pymethods]
impl LogEntryIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<Py<PyDict>>> {
        loop {
            if let Some(item) = self.current.next() {
                return Ok(Some(item));
            }

            // Current batch drained — block for the next one. Release the GIL
            // while waiting so the parse thread can re-acquire it to convert the
            // next batch (and other Python threads can run). The receiver is
            // moved into the detached closure and back out because `&Receiver`
            // is not `Send`; `Receiver` itself is.
            let Some(receiver) = self.receiver.take() else {
                return Ok(None);
            };

            let (receiver, next) = py.detach(move || {
                let result = receiver.recv();
                (receiver, result)
            });
            self.receiver = Some(receiver);

            match next {
                Ok(Message::Batch(batch)) => {
                    self.current = batch.into_iter();
                    // Loop around to yield the first item of the new batch.
                }
                Ok(Message::Err(err)) => {
                    self.shutdown();
                    return Err(io_error_to_py(err));
                }
                Err(_) => {
                    // Channel closed: parse finished (or thread gone). Join and
                    // signal StopIteration.
                    self.shutdown();
                    return Ok(None);
                }
            }
        }
    }
}

impl Drop for LogEntryIterator {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Run the appropriate visitor on the parse thread, converting entries into
/// batches of `Py<PyDict>` and sending them over the bounded channel.
///
/// The visitor runs with the GIL released (`Python::detach`). Entries are
/// borrow-bound and cannot outlive the callback, so each entry is converted to a
/// `Py<PyDict>` under a brief `Python::attach` and accumulated into a batch; the
/// whole batch is then shipped over the channel in one send. Batching keeps the
/// cross-thread hand-off (and the Python `__next__` wakeups) coarse-grained while
/// the bounded channel bounds memory. When the receiver is gone (iterator
/// dropped), the callback returns `ControlFlow::Break` to stop parsing promptly.
fn run_parse(source: Source, batch_size: usize, sender: SyncSender<Message>) {
    Python::attach(|py| {
        py.detach(|| {
            let mut batch: Vec<Py<PyDict>> = Vec::with_capacity(batch_size);
            let mut interner = Interner::new();
            let mut send_failed = false;

            // Convert one entry into the batch; flush when full. Returns a
            // ControlFlow so a failed send (dropped receiver) stops the visit.
            let mut on_entry = |entry: macos_unifiedlogs::log_entry::LogEntry<'_, '_>| {
                // Re-acquire the GIL only to build the dict, then release again.
                let converted = Python::attach(|py| entry_to_dict(py, &entry, &mut interner));
                let dict = match converted {
                    Ok(dict) => dict,
                    Err(err) => {
                        // Convert a PyErr into an io error channel message and stop.
                        let io = std::io::Error::other(format!("conversion failed: {err}"));
                        let _ = sender.send(Message::Err(io));
                        send_failed = true;
                        return ControlFlow::Break(());
                    }
                };
                batch.push(dict);

                if batch.len() >= batch_size {
                    let full = std::mem::replace(&mut batch, Vec::with_capacity(batch_size));
                    if sender.send(Message::Batch(full)).is_err() {
                        send_failed = true;
                        return ControlFlow::Break(());
                    }
                }
                ControlFlow::Continue(())
            };

            let result = match &source {
                Source::Logarchive(path) => visit_logarchive(path, &mut on_entry),
                Source::Tracev3 {
                    logarchive,
                    tracev3,
                } => visit_logarchive_tracev3_file(logarchive, tracev3, &mut on_entry),
            };

            // Propagate a visitor-level error (e.g. NotFound) unless we are
            // already shutting down because the receiver went away.
            if let Err(err) = result {
                if !send_failed {
                    let _ = sender.send(Message::Err(err));
                }
                return;
            }

            // Flush the final partial batch (if the receiver is still there).
            if !send_failed && !batch.is_empty() {
                let _ = sender.send(Message::Batch(batch));
            }
            // Dropping `sender` here closes the channel → StopIteration.
        });
    });
}

/// Map a std::io::Error to the closest Python exception.
fn io_error_to_py(err: std::io::Error) -> PyErr {
    match err.kind() {
        std::io::ErrorKind::NotFound => PyFileNotFoundError::new_err(err.to_string()),
        _ => PyIOError::new_err(err.to_string()),
    }
}

fn resolve_batch_size(batch_size: Option<usize>) -> PyResult<usize> {
    match batch_size {
        None => Ok(DEFAULT_BATCH_SIZE),
        Some(0) => Err(PyValueError::new_err("batch_size must be greater than 0")),
        Some(n) => Ok(n),
    }
}

/// Stream every entry from a `.logarchive` directory as dicts.
///
/// ```python
/// import unifiedlogs
/// for entry in unifiedlogs.iter_logarchive("system_logs.logarchive"):
///     ...  # entry is a dict with the 22 schema keys
/// ```
#[pyfunction]
#[pyo3(signature = (path, batch_size=None))]
fn iter_logarchive(path: PathBuf, batch_size: Option<usize>) -> PyResult<LogEntryIterator> {
    let batch_size = resolve_batch_size(batch_size)?;
    Ok(LogEntryIterator::spawn(
        Source::Logarchive(path),
        batch_size,
    ))
}

/// Stream every entry from a single tracev3 file within a `.logarchive`.
///
/// A thin sibling of `iter_logarchive` sharing the same machinery — useful for
/// testing against a small, deterministic input.
#[pyfunction]
#[pyo3(signature = (logarchive_path, tracev3_path, batch_size=None))]
fn iter_tracev3(
    logarchive_path: PathBuf,
    tracev3_path: PathBuf,
    batch_size: Option<usize>,
) -> PyResult<LogEntryIterator> {
    let batch_size = resolve_batch_size(batch_size)?;
    Ok(LogEntryIterator::spawn(
        Source::Tracev3 {
            logarchive: logarchive_path,
            tracev3: tracev3_path,
        },
        batch_size,
    ))
}

#[pymodule]
fn unifiedlogs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__doc__", "Streaming Python binding for macOS UnifiedLogs.")?;
    m.add("DEFAULT_BATCH_SIZE", DEFAULT_BATCH_SIZE)?;
    m.add_class::<LogEntryIterator>()?;
    m.add_function(wrap_pyfunction!(iter_logarchive, m)?)?;
    m.add_function(wrap_pyfunction!(iter_tracev3, m)?)?;
    Ok(())
}
