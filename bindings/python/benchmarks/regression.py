# Copyright 2026 European Union. All Rights Reserved
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Baseline / regression gate for `unifiedlogs.iter_logarchive`.

`bench_iter.py` prints a one-shot table — useful for tuning, but it cannot tell
you whether a change *regressed*. This script adds the baseline-diffing the
project's perf culture implies (the Rust side gates with `criterion`; there was
no Python equivalent): it measures the same way `bench_iter.py` does (stream the
whole archive, touch `pid`/`message` per entry, record entries/sec via
`time.perf_counter` and peak RSS via `ru_maxrss`), then either saves that run as
a baseline or compares a fresh run against a saved baseline and exits non-zero on
regression.

Two subcommands:

    # Measure and write a committed baseline (annotated with this machine).
    python regression.py baseline \\
        --path <archive.logarchive> --batch-size 256 \\
        --out baselines/big_sur.json

    # Measure again and fail (exit 1) if throughput drops or memory grows
    # beyond tolerance relative to the baseline.
    python regression.py compare \\
        --path <archive.logarchive> \\
        --baseline baselines/big_sur.json

Noise handling. Throughput is noisy: the same machine/batch_size has been seen
at ~278k vs ~275k entries/s, and different machines differ more. To damp that,
each measurement runs `--repeats` times (default 3) and reports the *best*
entries/sec (the run least perturbed by scheduler noise) and the *max* peak RSS
(the worst case the bounded channel allowed). Defaults: throughput may fall up
to 15% below baseline, peak memory may grow up to 10% above baseline. 15% on
throughput comfortably covers the observed run-to-run spread with headroom;
memory is governed by the bounded channel (flat at ~138 MB across batch sizes in
the README table), so a tighter 10% is a meaningful signal. Both are overridable
via `--throughput-tolerance` / `--memory-tolerance` (percent).

Baselines are machine-specific (CPU, memory bandwidth, Python build all move the
numbers), so a committed baseline records the machine it was taken on. CI should
compare only against a baseline it regenerated on its own runner — treat the
committed sample as documentation of the shape, not an absolute target to beat on
other hardware.
"""

import argparse
import json
import platform
import resource
import sys
import time

import unifiedlogs


def peak_rss_mb() -> float:
    # ru_maxrss is kilobytes on Linux, bytes on macOS.
    kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return kb / (1024 * 1024)
    return kb / 1024


def run_counted(path: str, batch_size: int):
    """Stream the whole archive once, touching fields like the real pipeline."""
    count = 0
    start = time.perf_counter()
    for entry in unifiedlogs.iter_logarchive(path, batch_size=batch_size):
        _ = entry["pid"]
        _ = entry["message"]
        count += 1
    elapsed = time.perf_counter() - start
    return count, elapsed, peak_rss_mb()


def measure(path: str, batch_size: int, repeats: int) -> dict:
    """Measure `repeats` streams and reduce to best-throughput / max-memory.

    peak RSS is process-wide and monotonic (`ru_maxrss` is a high-water mark), so
    the max across repeats is simply the final reading; we keep the max explicitly
    for clarity.
    """
    best_rate = 0.0
    peak_mb = 0.0
    entries = 0
    for _ in range(repeats):
        count, elapsed, peak = run_counted(path, batch_size)
        rate = count / elapsed if elapsed > 0 else float("nan")
        best_rate = max(best_rate, rate)
        peak_mb = max(peak_mb, peak)
        entries = count
    return {
        "entries": entries,
        "batch_size": batch_size,
        "repeats": repeats,
        "entries_per_sec": best_rate,
        "peak_mb": peak_mb,
    }


def machine_info() -> dict:
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def cmd_baseline(args: argparse.Namespace) -> int:
    result = measure(args.path, args.batch_size, args.repeats)
    baseline = {
        "archive": args.path,
        "machine": machine_info(),
        "result": result,
        "note": (
            "Machine-specific baseline. Regenerate on the target machine "
            "(e.g. CI runner) before comparing; absolute numbers are not "
            "portable across hardware or Python builds."
        ),
    }
    text = json.dumps(baseline, indent=2, sort_keys=True) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"wrote baseline to {args.out}")
    _print_result("baseline", result)
    return 0


def _print_result(label: str, result: dict) -> None:
    print(
        f"{label}: batch_size={result['batch_size']} "
        f"entries={result['entries']} "
        f"entries/sec={result['entries_per_sec']:.0f} "
        f"peak_MB={result['peak_mb']:.1f} "
        f"(best of {result['repeats']})"
    )


def cmd_compare(args: argparse.Namespace) -> int:
    with open(args.baseline, "r", encoding="utf-8") as handle:
        baseline = json.load(handle)
    base = baseline["result"]

    # Measure at the baseline's batch size unless overridden, so the comparison
    # is like-for-like by default.
    batch_size = args.batch_size if args.batch_size is not None else base["batch_size"]
    fresh = measure(args.path, batch_size, args.repeats)

    _print_result("baseline", base)
    _print_result("current ", fresh)

    base_machine = baseline.get("machine", {})
    cur_machine = machine_info()
    if base_machine.get("platform") != cur_machine.get("platform"):
        print(
            "warning: baseline machine differs from this machine; "
            f"baseline={base_machine.get('platform')!r} "
            f"current={cur_machine.get('platform')!r}. "
            "Absolute numbers are not portable; regenerate the baseline here.",
            file=sys.stderr,
        )

    throughput_tol = args.throughput_tolerance / 100.0
    memory_tol = args.memory_tolerance / 100.0

    min_rate = base["entries_per_sec"] * (1.0 - throughput_tol)
    max_mem = base["peak_mb"] * (1.0 + memory_tol)

    failures = []
    rate_drop = (
        (base["entries_per_sec"] - fresh["entries_per_sec"])
        / base["entries_per_sec"]
        * 100.0
        if base["entries_per_sec"] > 0
        else 0.0
    )
    mem_growth = (
        (fresh["peak_mb"] - base["peak_mb"]) / base["peak_mb"] * 100.0
        if base["peak_mb"] > 0
        else 0.0
    )

    print(
        f"throughput: {fresh['entries_per_sec']:.0f} vs baseline "
        f"{base['entries_per_sec']:.0f} "
        f"({rate_drop:+.1f}% change; floor {min_rate:.0f}, "
        f"tolerance {args.throughput_tolerance:g}%)"
    )
    print(
        f"peak_MB:    {fresh['peak_mb']:.1f} vs baseline {base['peak_mb']:.1f} "
        f"({mem_growth:+.1f}% change; ceiling {max_mem:.1f}, "
        f"tolerance {args.memory_tolerance:g}%)"
    )

    if fresh["entries_per_sec"] < min_rate:
        failures.append(
            f"throughput regressed: {fresh['entries_per_sec']:.0f} < "
            f"floor {min_rate:.0f} entries/sec"
        )
    if fresh["peak_mb"] > max_mem:
        failures.append(
            f"peak memory grew: {fresh['peak_mb']:.1f} > ceiling {max_mem:.1f} MB"
        )

    if failures:
        for failure in failures:
            print(f"REGRESSION: {failure}", file=sys.stderr)
        return 1
    print("OK: within tolerance")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--path", required=True, help="path to a .logarchive")
    common.add_argument(
        "--repeats",
        type=int,
        default=3,
        help="streams per measurement; best throughput / max memory is kept "
        "(default: 3)",
    )

    p_baseline = sub.add_parser(
        "baseline", parents=[common], help="measure and write a baseline file"
    )
    p_baseline.add_argument(
        "--batch-size",
        type=int,
        default=unifiedlogs.DEFAULT_BATCH_SIZE,
        help=f"batch size (default: {unifiedlogs.DEFAULT_BATCH_SIZE})",
    )
    p_baseline.add_argument(
        "--out",
        default="-",
        help="baseline JSON output path ('-' for stdout; default: stdout)",
    )
    p_baseline.set_defaults(func=cmd_baseline)

    p_compare = sub.add_parser(
        "compare", parents=[common], help="measure and gate against a baseline"
    )
    p_compare.add_argument(
        "--baseline", required=True, help="baseline JSON to compare against"
    )
    p_compare.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help="batch size to measure (default: the baseline's batch size)",
    )
    p_compare.add_argument(
        "--throughput-tolerance",
        type=float,
        default=15.0,
        help="max allowed throughput drop, percent (default: 15)",
    )
    p_compare.add_argument(
        "--memory-tolerance",
        type=float,
        default=10.0,
        help="max allowed peak-memory growth, percent (default: 10)",
    )
    p_compare.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
