"""Python bindings for the macos-unifiedlogs library.

Parse macOS Unified Log data (tracev3 files / logarchives) from Python,
on any platform (no Apple APIs are used).

Every entry point returns a streaming `LogArchive` iterator: entries are
produced on a worker thread and handed back in batches through a bounded
channel, so memory stays flat no matter how large the archive is. Pass the
iterator to `list(...)` only when a fully materialized list is deliberately
wanted.
"""

from ._macos_unifiedlogs import (
    DEFAULT_BATCH_SIZE,
    LogArchive,
    UnifiedLogError,
    parse_logarchive,
    parse_live_system,
    parse_tracev3,
)

__version__ = "0.8.0"

__all__ = [
    "DEFAULT_BATCH_SIZE",
    "LogArchive",
    "UnifiedLogError",
    "parse_logarchive",
    "parse_live_system",
    "parse_tracev3",
]