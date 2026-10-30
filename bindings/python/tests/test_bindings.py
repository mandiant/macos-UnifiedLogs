"""Tests for the macos_unifiedlogs Python bindings.

Most tests require a real logarchive to parse. Point the
``MACOS_UNIFIEDLOGS_TEST_ARCHIVE`` environment variable at a directory created
with ``log collect`` (e.g. the ``system_logs_big_sur.logarchive`` test data
used by the Rust tests, downloadable from the project's GitHub releases), or
run on a live macOS system to use ``MACOS_UNIFIEDLOGS_TEST_ARCHIVE=live``.
"""

import os

import pytest

import macos_unifiedlogs

ARCHIVE = os.environ.get("MACOS_UNIFIEDLOGS_TEST_ARCHIVE")
HAVE_ARCHIVE = ARCHIVE is not None and ARCHIVE != "live" and os.path.isdir(ARCHIVE)


def _expected_fields():
    return [
        "subsystem",
        "thread_id",
        "pid",
        "euid",
        "persona_id",
        "library",
        "library_uuid",
        "activity_id",
        "parent_activity_id",
        "time",
        "category",
        "event_type",
        "log_type",
        "process",
        "process_uuid",
        "message",
        "format_string",
        "boot_uuid",
        "timezone_name",
        "timestamp",
        "evidence",
        "message_flags",
    ]


def test_exceptions_and_exports():
    assert macos_unifiedlogs.UnifiedLogError.__name__ == "UnifiedLogError"
    for name in macos_unifiedlogs.__all__:
        assert hasattr(macos_unifiedlogs, name)


def test_missing_archive_raises():
    with pytest.raises(FileNotFoundError):
        macos_unifiedlogs.parse_logarchive("/this/path/does/not/exist")


def test_missing_tracev3_raises():
    with pytest.raises(FileNotFoundError):
        macos_unifiedlogs.parse_tracev3("/this/path/does/not/exist.tracev3")


def test_streaming_missing_archive_raises():
    with pytest.raises(FileNotFoundError):
        macos_unifiedlogs.LogArchive("/this/path/does/not/exist")


def test_streaming_empty_archive_raises_on_first_next(tmp_path):
    # A directory with no tracev3 files passes the constructor check but the
    # visit fails with NotFound, surfaced on the first next() call.
    parser = macos_unifiedlogs.LogArchive(str(tmp_path))
    with pytest.raises(FileNotFoundError):
        next(parser)


@pytest.mark.skipif(
    not HAVE_ARCHIVE,
    reason="set MACOS_UNIFIEDLOGS_TEST_ARCHIVE to a logarchive directory",
)
class TestLogarchive:
    def test_parse_logarchive(self):
        records = macos_unifiedlogs.parse_logarchive(ARCHIVE)
        assert len(records) > 0
        for record in records[:50]:
            assert isinstance(record, dict)
            for field in _expected_fields():
                assert field in record, f"missing field: {field}"

    def test_streaming_matches_bulk(self):
        streamed = list(macos_unifiedlogs.LogArchive(ARCHIVE))
        bulk = macos_unifiedlogs.parse_logarchive(ARCHIVE)
        assert len(streamed) == len(bulk)
        assert streamed[0]["message"] == bulk[0]["message"]

    def test_iterator_is_stoppable_and_repeatable(self):
        parser = macos_unifiedlogs.LogArchive(ARCHIVE)
        first = next(iter(parser))
        assert "message" in first
        # A fresh instance starts over from the beginning
        again = next(iter(macos_unifiedlogs.LogArchive(ARCHIVE)))
        assert again["message"] == first["message"]

    def test_single_tracev3_file(self):
        # Parse one tracev3 file from within the archive
        tracev3 = None
        for root, _dirs, files in os.walk(ARCHIVE):
            for name in files:
                if name.endswith(".tracev3") and not name.startswith("._"):
                    tracev3 = os.path.join(root, name)
                    break
            if tracev3:
                break

        assert tracev3 is not None, "no tracev3 file found in archive"
        records = macos_unifiedlogs.parse_tracev3(tracev3, ARCHIVE)
        assert len(records) > 0
        for record in records[:50]:
            assert "message" in record