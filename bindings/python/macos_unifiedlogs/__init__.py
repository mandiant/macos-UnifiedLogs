"""Python bindings for the macos-unifiedlogs library.

Parse macOS Unified Log data (tracev3 files / logarchives) from Python,
on any platform (no Apple APIs are used).
"""

from ._macos_unifiedlogs import (
    LogArchive,
    UnifiedLogError,
    parse_logarchive,
    parse_live_system,
    parse_tracev3,
)

__version__ = "0.8.0"

__all__ = [
    "LogArchive",
    "UnifiedLogError",
    "parse_logarchive",
    "parse_live_system",
    "parse_tracev3",
]