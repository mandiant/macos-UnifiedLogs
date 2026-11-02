# macos-unifiedlogs (Python)

Python bindings for the [macos-unifiedlogs](https://github.com/mandiant/macos-UnifiedLogs)
Rust library, which parses Apple Unified Logs from `.logarchive` directories,
individual `tracev3` files, or a live macOS system. The parser uses no Apple
APIs, so logs can be examined on Linux and Windows as well as macOS - useful
for offline forensics of acquisitions collected from macOS and iOS devices.

The bindings are built with [PyO3](https://pyo3.rs) and packaged with
[maturin](https://www.maturin.rs). They expose the same log entry fields the
library serializes to JSON.

## Installation

A Rust toolchain and Python development headers are required to build from
source.

```bash
pip install maturin
pip install ./bindings/python
```

For development (builds and installs into the active virtual environment):

```bash
cd bindings/python
maturin develop
```

## API

| Symbol | Description |
| --- | --- |
| `parse_logarchive(path)` | Parse a full `.logarchive` directory; returns `list[dict]`. |
| `parse_tracev3(path, logarchive=None)` | Parse a single `tracev3` file; returns `list[dict]`. |
| `parse_live_system()` | Parse the live system (macOS only); returns `list[dict]`. |
| `LogArchive(path=None)` | Streaming iterator yielding one `dict` per entry. `path=None` parses the live system (macOS only). |
| `LogArchive.parse_all(path=None)` | Bulk equivalent of iterating `LogArchive`; returns `list[dict]`. |
| `UnifiedLogError` | `RuntimeError` subclass raised on parse failures. |

### Log entry fields

Each entry is a plain `dict` containing:

`timestamp`, `time`, `message`, `format_string`, `process`, `process_uuid`,
`subsystem`, `category`, `pid`, `euid`, `persona_id`, `thread_id`,
`event_type`, `log_type`, `library`, `library_uuid`, `activity_id`,
`parent_activity_id`, `boot_uuid`, `timezone_name`, `evidence`,
`message_flags`.

`timestamp` is a timezone-aware `datetime` (UTC); `time` is the same instant
as Unix nanoseconds (float). Serialize datetime values back to JSON with
`json.dumps(entry, default=str)`. `event_type` and `log_type` are strings
(`"Log"`, `"Signpost"`, `"Default"`, …). `message_flags` is a list of
strings.

## Usage

### Parse a logarchive

```python
import macos_unifiedlogs

for entry in macos_unifiedlogs.parse_logarchive("/path/to/system_logs.logarchive"):
    print(entry["timestamp"], entry["process"], entry["message"])
```

### Parse a single tracev3 file

```python
entries = macos_unifiedlogs.parse_tracev3(
    "/path/to/Persist/0000000000000002.tracev3",
    logarchive="/path/to/system_logs.logarchive",
)
```

`logarchive` is the directory containing the `uuidtext` / `dsc` / `timesync`
support files used to reconstruct strings and timestamps. If omitted, the
parent directory of the `tracev3` file is used.

### Stream a large archive

`parse_logarchive` materializes every entry in memory. For large archives,
iterate with `LogArchive`, which yields entries one at a time and holds only a
small buffer plus the string cache:

```python
import json

from macos_unifiedlogs import LogArchive

with open("out.jsonl", "w") as fh:
    for entry in LogArchive("/path/to/system_logs.logarchive"):
        fh.write(json.dumps(entry, default=str) + "\n")
```

### Parse the live system (macOS only)

```python
for entry in macos_unifiedlogs.LogArchive():
    print(entry["timestamp"], entry["message"])
```

### Error handling

Missing paths raise `FileNotFoundError`; parse failures raise
`UnifiedLogError` (a `RuntimeError` subclass):

```python
import macos_unifiedlogs

try:
    macos_unifiedlogs.parse_logarchive("/nonexistent.logarchive")
except FileNotFoundError:
    ...
except macos_unifiedlogs.UnifiedLogError as err:
    ...
```

## Testing

The Python tests need a real logarchive. Point
`MACOS_UNIFIEDLOGS_TEST_ARCHIVE` at one (e.g. the
`system_logs_big_sur.logarchive` test data downloadable from the project's
GitHub releases), or set it to `live` to parse the current macOS system.

```bash
cd bindings/python
pip install pytest
MACOS_UNIFIEDLOGS_TEST_ARCHIVE=/path/to/system_logs_big_sur.logarchive \
    python -m pytest tests
```

The Rust unit tests do not require an archive:

```bash
cargo test
```

## Implementation notes

- The binding crate is a standalone workspace (`bindings/python`) with a path
  dependency on the library, so building or testing the Rust library is
  unaffected by the Python dependencies.
- The GIL is released while parsing runs, so other Python threads keep
  executing during long parses.
- The compiled extension is `_macos_unifiedlogs`; import the wrapper package
  `macos_unifiedlogs` instead.
- Build release wheels with `maturin build --release`, or across supported
  platforms with `cibuildwheel` in CI.