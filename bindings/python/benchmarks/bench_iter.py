# Copyright 2026 European Union. All Rights Reserved
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Benchmark `unifiedlogs.iter_logarchive`, parameterized by batch size.

Streams the full archive for each batch size, consuming every dict (and touching
a field so the loop is not optimized away — mirroring the real pipeline, which
reads every field), and reports entries/sec and peak RSS so the batch size can be
tuned against real numbers.

Usage:
    python bench_iter.py --path <archive.logarchive> \\
        --batch-size 256 --batch-size 512 --batch-size 1024
"""

import argparse
import resource
import time

import unifiedlogs


def peak_rss_mb() -> float:
    # ru_maxrss is kilobytes on Linux, bytes on macOS.
    kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    import sys

    if sys.platform == "darwin":
        return kb / (1024 * 1024)
    return kb / 1024


def run_counted(path: str, batch_size: int):
    count = 0
    start = time.perf_counter()
    for entry in unifiedlogs.iter_logarchive(path, batch_size=batch_size):
        # Touch fields to mimic a real pipeline reading the record.
        _ = entry["pid"]
        _ = entry["message"]
        count += 1
    elapsed = time.perf_counter() - start
    return count, elapsed, peak_rss_mb()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, help="path to a .logarchive")
    parser.add_argument(
        "--batch-size",
        type=int,
        action="append",
        default=None,
        help="batch size to test (repeatable; default: 256 512 1024)",
    )
    args = parser.parse_args()

    batch_sizes = args.batch_size or [256, 512, 1024]

    print(f"archive: {args.path}")
    print(
        f"{'batch_size':>10}  {'entries':>10}  {'seconds':>9}  "
        f"{'entries/sec':>13}  {'peak_MB':>9}"
    )
    for bs in batch_sizes:
        count, elapsed, peak = run_counted(args.path, bs)
        rate = count / elapsed if elapsed > 0 else float("nan")
        print(
            f"{bs:>10}  {count:>10}  {elapsed:>9.3f}  {rate:>13.0f}  {peak:>9.1f}"
        )


if __name__ == "__main__":
    main()
