# Copyright 2026 European Union. All Rights Reserved
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""End-to-end smoke test for the `unifiedlogs` Python binding.

Streams real entries from the downloaded Big Sur logarchive and asserts the dict
shape matches the library's 22-field serde schema (the same schema the CLI emits
as JSONL, locked by `test_log_entry_json_schema` in `src/logarchive.rs`).

Run with: `python -m pytest bindings/python/tests/test_smoke.py -q`
or directly:  `python bindings/python/tests/test_smoke.py`
"""

import datetime
import json
import os

import unifiedlogs

# The 22 keys in the exact order of `impl Serialize for LogEntry`.
EXPECTED_KEYS = [
    "subsystem",
    "category",
    "thread_id",
    "pid",
    "euid",
    "persona_id",
    "library",
    "library_uuid",
    "activity_id",
    "parent_activity_id",
    "time",
    "timestamp",
    "event_type",
    "log_type",
    "process",
    "process_uuid",
    "message",
    "format_string",
    "boot_uuid",
    "timezone_name",
    "evidence",
    "message_flags",
]

# tests/test_data/system_logs_big_sur.logarchive relative to the repo root.
_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
ARCHIVE = os.path.join(
    _REPO_ROOT, "tests", "test_data", "system_logs_big_sur.logarchive"
)
TRACEV3 = "Persist/0000000000000001.tracev3"


def _require_archive():
    if not os.path.isdir(ARCHIVE):
        raise SystemExit(
            f"test data not found at {ARCHIVE}; download it per BUILDING.md"
        )


def test_tracev3_dict_shape():
    _require_archive()
    it = unifiedlogs.iter_tracev3(ARCHIVE, TRACEV3)
    first = next(iter(it))

    # Exactly the 22 schema keys, no more, no less.
    assert set(first.keys()) == set(EXPECTED_KEYS), set(first.keys()) ^ set(
        EXPECTED_KEYS
    )
    assert len(first) == 22

    # UUIDs: 32-char uppercase bare hex.
    for field in ("library_uuid", "process_uuid", "boot_uuid"):
        value = first[field]
        assert isinstance(value, str)
        assert len(value) == 32, f"{field}={value!r}"
        assert all(c.isdigit() or (c.isupper() and c.isalpha()) for c in value), (
            f"{field}={value!r}"
        )

    # timestamp is a tz-aware datetime (UTC) consistent with `time` (ns). Python
    # datetime is microsecond-resolution, so allow up to 1us vs the ns `time`.
    ts = first["timestamp"]
    assert isinstance(ts, datetime.datetime)
    assert ts.tzinfo is not None
    delta_ns = abs(ts.timestamp() * 1e9 - first["time"])
    assert delta_ns < 1_000.0, (ts, first["time"])

    # Types match the schema.
    assert isinstance(first["time"], float)
    assert isinstance(first["thread_id"], int)
    assert isinstance(first["pid"], int)
    assert isinstance(first["euid"], int)
    assert isinstance(first["event_type"], str)
    assert isinstance(first["log_type"], str)
    assert isinstance(first["message"], str)
    assert isinstance(first["message_flags"], list)

    # `timestamp` is a datetime, so a bare json.dumps raises; it needs an
    # encoder. `default=str` renders the datetime as its ISO string.
    try:
        json.dumps(first)
    except TypeError:
        pass
    else:
        raise AssertionError("datetime timestamp should need a json encoder")

    encoded = json.dumps(first, default=str)
    decoded = json.loads(encoded)
    assert decoded["boot_uuid"] == first["boot_uuid"]
    assert decoded["timestamp"] == str(first["timestamp"])


def test_tracev3_boot_uuid_matches_schema_test():
    # Cross-check: the library's test_log_entry_json_schema asserts the first
    # entry's boot_uuid for this exact tracev3 file.
    _require_archive()
    first = next(iter(unifiedlogs.iter_tracev3(ARCHIVE, TRACEV3)))
    assert first["boot_uuid"] == "9A6A3124274A44B29ABF2BC9E4599B3B"


def test_logarchive_streams_many():
    _require_archive()
    count = 0
    for entry in unifiedlogs.iter_logarchive(ARCHIVE):
        count += 1
        if count >= 2000:
            break
    assert count >= 2000


def test_early_break_stops_promptly():
    # Dropping the iterator after one entry must not hang (ControlFlow::Break).
    _require_archive()
    it = unifiedlogs.iter_logarchive(ARCHIVE)
    first = next(iter(it))
    assert set(first.keys()) == set(EXPECTED_KEYS)
    del it  # triggers shutdown/join of the parse thread


def test_batch_size_validation():
    _require_archive()
    try:
        unifiedlogs.iter_logarchive(ARCHIVE, batch_size=0)
    except ValueError:
        pass
    else:
        raise AssertionError("batch_size=0 should raise ValueError")


def test_bad_path_raises():
    try:
        next(iter(unifiedlogs.iter_logarchive("/nonexistent/path.logarchive")))
    except (FileNotFoundError, OSError):
        pass
    else:
        raise AssertionError("missing archive should raise")


if __name__ == "__main__":
    test_tracev3_dict_shape()
    test_tracev3_boot_uuid_matches_schema_test()
    test_logarchive_streams_many()
    test_early_break_stops_promptly()
    test_batch_size_validation()
    test_bad_path_raises()
    print("all smoke tests passed")
