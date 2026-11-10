# unifiedlogs — Python binding

A PyO3 + maturin binding over the [`macos-unifiedlogs`](../../) Rust library.
It streams every parsed log entry from a `.logarchive` into Python as a plain
`dict`, so your Python code can run business logic on each record and serialize
it however it likes (the library intentionally does **not** serialize in Rust).

Each emitted `dict` has the 22 keys of the library's serde schema, in the same
formats the `unifiedlog_iterator` CLI emits as JSONL, with **one exception**:
`timestamp` is a tz-aware Python `datetime.datetime` (UTC), not an RFC3339
string. Python pipelines usually want a real datetime, and nothing is lost —
the `time` field (nanoseconds since the Unix epoch, `float`) remains the
full-precision source of truth, while a `datetime` is microsecond-resolution.
Because a `datetime` is not JSON-serializable by default, reproducing the CLI's
JSONL needs an encoder, e.g. `json.dumps(entry, default=str)`.

## Build

This crate is a standalone cargo workspace (it does not perturb the published
library). Build the Python module with [maturin](https://www.maturin.rs/):

```bash
cd bindings/python
python -m venv .venv && . .venv/bin/activate
pip install maturin
maturin develop --release        # builds and installs into the active venv
python -c "import unifiedlogs; print(unifiedlogs.DEFAULT_BATCH_SIZE)"
```

To build a wheel instead of installing in place:

```bash
maturin build --release --out dist
```

The wheel is an abi3 wheel (`abi3-py39`), loadable on CPython 3.9+.

## Usage

```python
import json
import unifiedlogs

# Stream an entire .logarchive directory.
for entry in unifiedlogs.iter_logarchive("system_logs.logarchive"):
    # entry is a mutable dict with the 22 schema keys. `entry["timestamp"]`
    # is a datetime.datetime; `entry["time"]` is ns since the epoch (float).
    entry["my_field"] = do_business_logic(entry)
    # `timestamp` is a datetime, so pass an encoder to serialize it.
    print(json.dumps(entry, default=str))

# Stream a single tracev3 file within an archive (handy for tests / small inputs).
for entry in unifiedlogs.iter_tracev3(
    "system_logs.logarchive", "Persist/0000000000000001.tracev3"
):
    ...
```

Both functions accept an optional `batch_size` (default
`unifiedlogs.DEFAULT_BATCH_SIZE`) that tunes how many entries the background
parse thread converts per cross-thread hand-off. See `benchmarks/bench_iter.py`
to measure throughput and peak memory across batch sizes.

### Example script

`examples/logarchive_to_jsonl.py` is a small, dependency-free command-line tool
that mirrors the basic behavior of the `unifiedlog_iterator` Rust example: point
it at a `.logarchive` folder and it writes one JSON object per line (JSONL) to a
file or stdout.

```bash
# write to a file
python examples/logarchive_to_jsonl.py system_logs.logarchive -o out.jsonl

# or stream to stdout
python examples/logarchive_to_jsonl.py system_logs.logarchive
```

## Benchmarks and regression gating

`benchmarks/bench_iter.py` prints a one-shot table of entries/sec and peak RSS
per batch size — use it to tune. `benchmarks/regression.py` adds a
baseline/regression gate so a change that slows throughput or grows memory is
caught (the Rust side gates with `criterion`; this is the Python equivalent):

```bash
# Save a baseline (annotated with this machine) at a batch size.
python benchmarks/regression.py baseline \
    --path ../../tests/test_data/system_logs_big_sur.logarchive \
    --batch-size 256 --out benchmarks/baselines/big_sur.json

# Measure again and fail (exit 1) if throughput drops >15% or peak memory
# grows >10% versus the baseline (both tolerances overridable).
python benchmarks/regression.py compare \
    --path ../../tests/test_data/system_logs_big_sur.logarchive \
    --baseline benchmarks/baselines/big_sur.json
```

Each measurement runs `--repeats` streams (default 3) and keeps the best
throughput and max peak RSS to damp scheduler noise. The default 15% throughput
tolerance covers the observed run-to-run spread (~275k–278k entries/sec on the
same machine/batch size) with headroom; peak memory is bounded by the channel
(flat ~138 MB across batch sizes above), so a tighter 10% is a meaningful
signal.

`benchmarks/baselines/big_sur.json` is a committed **sample** baseline, taken on
the machine recorded inside it (`machine.platform`). Absolute numbers are
hardware- and interpreter-specific, so CI should regenerate its own baseline on
its runner and compare against that — treat the committed file as documentation
of the expected shape, not an absolute target to beat on other hardware.

## Design notes

- A dedicated background OS thread runs the Rust visitor with the GIL released
  (`Python::detach`), converting entries to dicts under brief GIL re-acquisitions
  and shipping them in batches over a bounded channel. The bounded channel gives
  backpressure, so memory stays flat on multi-million-entry archives and parsing
  overlaps with Python-side work.
- Dropping the iterator early (a Python `break`) closes the channel, which stops
  the parse promptly (`ControlFlow::Break`).
- Repeated string fields (`subsystem`, `category`, `process`, `library`,
  `timezone_name`) are interned so identical values reuse one Python `str`.

### Why a `dict`, not a `LogEntry` object

Entries are yielded as plain `dict`s rather than a `#[pyclass]` wrapper. The
primary consumer reads every field, mutates the record (adds/edits keys), and
serializes it to JSONL. A `dict` is the natural fit for that: it is mutable in
place and `json.dumps(entry, default=str)` works directly, whereas a class would
need an `as_dict()` copy to mutate and serialize. Lazy per-field access (a class
feature) buys nothing when the consumer reads all fields anyway. A typed
`LogEntry` object would mainly help a different, exploratory audience (attribute
access and autocomplete, no serialization); if that need arises it should be
added as an optional second API, not as a replacement for the dict stream.

### Why `DEFAULT_BATCH_SIZE = 512`

Measured with `benchmarks/bench_iter.py` on the `system_logs_big_sur.logarchive`
test archive (747,616 entries), consuming every dict and touching fields:

| batch_size | entries/sec | peak MB |
|-----------:|------------:|--------:|
| 128        | ~270k       | ~138    |
| 256        | ~278k       | ~138    |
| 512        | ~275k       | ~138    |
| 1024       | ~252k       | ~139    |
| 2048       | ~207k       | ~142    |

Throughput plateaus across 256–512 and falls off for larger batches (coarser
cross-thread wakeups reduce the parse/consume overlap). Peak memory is governed
by the bounded channel, not the batch size, so it stays flat (~138 MB) up to
1024. 512 sits on the throughput plateau and is the larger of the two plateau
values, giving slightly coarser hand-offs at the same speed; it is a sensible
default. `batch_size` is tunable per call — re-run the benchmark on your own
workload if your per-entry Python work is heavier than this read-only loop.
