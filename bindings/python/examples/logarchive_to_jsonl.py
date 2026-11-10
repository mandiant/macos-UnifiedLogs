# Copyright 2026 European Union. All Rights Reserved
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Minimal Python port of the `unifiedlog_iterator` CLI's basic mode.

Takes a folder containing the binary unified logs (a `.logarchive` directory)
and writes one JSON object per line (JSONL) — one line per parsed log entry —
to an output file (or stdout). This mirrors the default `log-archive` +
`jsonl` behavior of the Rust `unifiedlog_iterator` example, using the
`unifiedlogs` Python binding.

Install the binding first (from `bindings/python/`):

    python -m venv .venv && . .venv/bin/activate
    pip install maturin
    maturin develop --release

Then run:

    # write to a file
    python examples/logarchive_to_jsonl.py path/to/system_logs.logarchive -o out.jsonl

    # or stream to stdout
    python examples/logarchive_to_jsonl.py path/to/system_logs.logarchive
"""

import argparse
import contextlib
import json
import os
import sys
import time

import unifiedlogs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        help="path to a .logarchive folder containing the binary unified logs",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="output JSONL file (default: stdout)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help=(
            "entries converted per cross-thread batch "
            f"(default: {unifiedlogs.DEFAULT_BATCH_SIZE})"
        ),
    )
    args = parser.parse_args()

    count = 0
    start = time.perf_counter()
    # Open the output sink via ExitStack so a file is closed on exit, while
    # stdout is used as-is and never closed.
    with contextlib.ExitStack() as stack:
        if args.output:
            out = stack.enter_context(open(args.output, "w", encoding="utf-8"))
        else:
            out = sys.stdout

        try:
            for entry in unifiedlogs.iter_logarchive(
                args.input, batch_size=args.batch_size
            ):
                # `entry` is a plain dict with the 22 schema keys; dump it as one
                # compact JSON line. This is where real tooling would run its own
                # business logic on the record before writing. The `timestamp`
                # value is a datetime, so `default=str` renders it as an ISO
                # string (the `time` field keeps full nanosecond precision).
                out.write(json.dumps(entry, default=str))
                out.write("\n")
                count += 1
        except BrokenPipeError:
            # A downstream reader (e.g. `| head`) closed the pipe early — a
            # normal stop, not a failure. Redirect stdout to devnull so the
            # interpreter's shutdown flush does not re-raise on the dead pipe.
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            return 0
        except (FileNotFoundError, OSError) as err:
            print(f"error: {err}", file=sys.stderr)
            return 1

    elapsed = time.perf_counter() - start
    rate = count / elapsed if elapsed > 0 else float("nan")
    print(
        f"wrote {count} records in {elapsed:.2f}s ({rate:.0f} entries/sec)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
