# Library architecture

This document provides a very high level overview of the macos-unifiedlogs design
architecture.


## Parsing pipeline

1. **Timesync** — Parse timesync files for timestamp boot/offset data
2. **TraceV3** — Parse tracev3 binary files into chunks (header, catalog, firehose, oversize, simpledump, statedump)
3. **Resolve** — Look up format strings from UUIDText files and DSC (shared string cache)
4. **Format** — Apply printf-style formatting with decoded message items
5. **Emit** — Deliver `LogEntry` via callback with resolved process/library names, timestamps, subsystem/category

```
                        visit_logarchive(path, callback)
                                      │
          ┌───────────────────────────┼──────────────────────────┐
          │                           │                          │
    ┌─────┴──────┐  ┌────────────────┴────────────────┐  ┌─────┴──────────┐
    │ timesync/  │  │ Persist/ Special/ HighVolume/ … │  │ dsc/ UUIDText/ │
    └─────┬──────┘  │         .tracev3 files          │  └─────┬──────────┘
          │         └────────────────┬────────────────┘        │
          ▼                          │                          ▼
  TimestampResolver                  │              SharedCacheStrings (DSC)
                                     │              UUIDText files
                                     ▼
                       ┌──────────────────────────┐
                       │       ChunksReader       │  per .tracev3
                       └────────────┬─────────────┘
               ┌────────────────────┼────────────────────┐
               ▼                    ▼                    ▼
           Header              Catalog              Chunkset
                                                       │
                                                LZ4 decompress
                                                  (bv41/bv4-)
                                                       │
                                                       ▼
                                           ┌───────────────────┐
                                           │   ChunkSetReader  │
                                           └─────────┬─────────┘
                        ┌──────────┬─────────────────┼──────────┐
                        ▼          ▼                 ▼          ▼
                    Firehose    Oversize         Simpledump  Statedump
                        │     (→ cache)
                        ▼
                 entry iterator
          ┌─────┬──────┼──────┬──────┐
          ▼     ▼      ▼      ▼      ▼
      Activity Non-  Signpost Trace  Loss
             Activity
                        │
                        ▼
             resolve_strings() ◄── DSC + UUIDText + Oversize cache
                        │
                        ▼
              LogEntry<'a,'b>   zero-copy, borrows from buffers
                        │
                        │  .message()  lazy, allocated on demand
                        ▼
             format_message()   printf-style parser
                        │
                        │  %{annotation} specifiers → custom decoders
                        ▼
             ┌── decode_annotation() ──────────────────────────┐
             │ DNS · network · location · time · UUID           │
             │ OpenDirectory · Darwin · bool · config           │
             └──────────────────────────────────────────────────┘
```

## Format strings and message formatting

Log messages are assembled from two separate components stored in the tracev3 binary:

### Format strings (shared, dictionary-based)

Each firehose entry stores a **4-byte offset** (`format_string_location`) pointing into a shared string table — either a **DSC** (shared cache, for system libraries) or a **UUIDText** file (for individual executables). The format string itself (e.g. `"User %s with ID %d logged in"`) is never duplicated per entry; thousands of log lines from the same `os_log()` call site all reference the same offset.

### Items (unique per entry, inline binary)

Each entry carries its own packed `items_data` — a compact binary array of typed values (integers, strings, raw bytes). Items are consumed **positionally, left to right** by the format specifiers:

```
Format string:  "User %s with ID %d logged in"
                       ^^            ^^
                       │              └── items[1] = Int(42)
                       └───────────────── items[0] = String("alice")

→ "User alice with ID 42 logged in"
```

### Format specifier syntax

Apple extends standard printf with privacy annotations and custom type decoders:

```
%[flags][width][.precision][length]<conversion>      standard printf
%{annotation}[flags][width][.precision][length]<conversion>   Apple extension
```

**Privacy annotations** control redaction in logs:
- `%{public}s` — visible in collected logs
- `%{private}d` — always redacted as `<private>`
- `%s` — redacted by default in non-debug contexts

**Common conversions:**
- `%s` — C string, `%d`/`%u` — integers, `%f` — float, `%x` — hex
- `%@` — Objective-C object description (Apple-specific, calls `[object description]`)

**Custom type decoders** via annotations:
- `%{time_t}d` — Unix timestamp → human-readable date
- `%{uuid_t}.*P` — raw bytes → UUID string
- `%{network:in_addr}d` — integer → IPv4 address
- `%{darwin.errno}d` — errno → error name
- `%{bool}d` — 0/1 → `"true"`/`"false"`

**Dynamic width/precision** consume extra items: `%*d` uses one item for the width and the next for the value.

**Special case — dynamic strings:** When bit 31 of `format_string_location` is set (`0x80000000`), the format string becomes `"%s"` and the actual text is carried inline in the items.
