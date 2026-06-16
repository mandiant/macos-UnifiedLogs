# WIP: Dump Parity Reduction

Generated with:

```bash
just dump_all_and_compare
```

Fixture:

```text
tests/test_data/system_logs_big_sur_private_enabled.logarchive
```

All three dumps currently contain `887890` entries, so entry count and ordering are aligned. The remaining work is field/value parity.

## Difference Summary

### Legacy vs Compat

Total differing entries: `530`.

- `530` `message`: mostly formatter/decoder edge cases:
  - OpenDirectory `ODError...` strings are truncated by one or more trailing characters in compat.
  - Some long object/private strings differ by truncation or masking.
  - One install-phase plist/object string is truncated.
  - Four DNS Configuration statedump entries still differ in object formatting.

### Compat vs Rewrite

Total differing entries: `0`.

Compat and rewrite now produce identical normalized dumps for all `887890` entries in the Big Sur private-enabled fixture.

## Reduction Plan

- [x] Mask the high-bit sentinel in rewrite `activity_id` and `parent_activity_id` for normal rewrite output, not only under `rewrite-compat`.
  - Expected impact: about `339558` compat/rewrite entries.
  - Start in `src/rewrite/tracev3.rs::combine_activity_id`.
  - Result: `compat vs rewrite` diff count dropped from `432418` to `92859`; `activity_id` and `parent_activity_id` no longer appear in the structural diff.

- [x] Decide whether rewrite should intentionally match compat/legacy signpost and backtrace prefixes.
  - If yes, remove the `rewrite-compat` gating in `src/rewrite/log_entry.rs::apply_parity_prefix`.
  - Expected impact: about `67481` message entries.
  - Result: signpost and backtrace prefix buckets disappeared; `compat vs rewrite` diff count dropped from `92859` to `25686`.

- [x] Normalize null pointer formatting.
  - Decide target behavior: compat/legacy `(null)` or rewrite empty string.
  - Expected impact: about `24600` message entries.
  - Search in rewrite item formatting and string/object decoding paths.
  - Result: null-rendering bucket disappeared; `compat vs rewrite` diff count dropped from `25686` to `863`.

- [x] Fix `%s%.*s` precision/string assembly in rewrite.
  - Example raw message: `%s%.*s`.
  - Expected impact: about `267` message entries.
  - Start in `src/rewrite/format.rs`.
  - Result: `%s%.*s` empty-message bucket disappeared; `compat vs rewrite` diff count dropped from `863` to `592`.

- [x] Use compat invalid-offset error text in rewrite when format-string lookup fails.
  - Expected impact: `60` entries.
  - Start in `src/rewrite/tracev3.rs::format_string_error_message` and `src/rewrite/log_entry.rs::effective_format_string`.
  - Result: invalid-format bucket disappeared; `raw_message` no longer appears in the structural diff, and `compat vs rewrite` diff count dropped from `592` to `531`.

- [x] Investigate float and large-number precision formatting.
  - Expected impact at the checkpoint: `525` entries.
  - Compare legacy `src/legacy/message.rs` to rewrite `src/rewrite/format.rs`.
  - Result: natural float formatting now matches the old pipeline behavior; the original float bucket disappeared.

- [x] Decide whether loss entries should have an empty message or rewrite's explicit lost-entry message.
  - Expected impact: `6` entries.
  - Result: rewrite loss messages now match compat/legacy's empty message behavior.

- [x] Align private-data parsing and firehose entry padding between rewrite and compat.
  - Result: the object/private string bucket dropped from `458` entries to `181`.
  - Changes were in private-data fill, adjusted private-data slices, and firehose entry padding.

- [x] Align formatter edge cases between rewrite and compat.
  - Result: malformed Apple annotations such as `%{public}.s`, missing-item placeholders, base64 byte formatting, and alternate hex padding now use one shared behavior.

- [x] Normalize statedump protobuf map ordering.
  - Result: protobuf statedump JSON output is stable in both rewrite flavors.

- [x] Make dump examples use archive-level oversize context consistently.
  - Result: legacy and compat examples now merge oversize entries before building per-file logs, matching rewrite's archive walker behavior.
  - Final result: `compat vs rewrite` structural diff count is `0`.

- [x] Match legacy mDNS DNS-header comma/newline whitespace in compat/rewrite.
  - Expected impact: `2856` `message` entries.
  - Change was in `src/rewrite/decoders/dns.rs::DnsFlags::fmt`.
  - Result: `legacy vs compat` diff count dropped from `3872` to `1016`; `compat vs rewrite` stayed at `0`.

- [x] Normalize statedump nil UUIDs to legacy empty strings in compat/dump output.
  - Expected impact: `480` UUID-only entries plus UUID parts of four statedump message entries.
  - Compat `LogData` can represent this as an empty string; native rewrite still uses typed `Uuid::nil()`.
  - Result: `legacy vs compat` diff count dropped from `1016` to `536`; `compat vs rewrite` stayed at `0`.

- [x] Normalize loss attribution to legacy empty strings in compat/dump output.
  - Expected impact: `6` entries over `library`, `library_uuid`, `process`, and `process_uuid`.
  - Native rewrite still keeps resolved `/kernel` metadata for loss entries.
  - Result: `legacy vs compat` diff count dropped from `536` to `530`; `compat vs rewrite` stayed at `0`.

- [ ] Bring compat closer to legacy for low-volume differences after rewrite parity is stable.
  - OpenDirectory decoder truncation.
  - DNS Configuration statedump formatting.

## Validation Loop

After each fix:

```bash
just dump_all_and_compare > /tmp/macos-unifiedlogs-dump-compare.out 2>&1
wc -l dump_legacy.txt dump_compat.txt dump_rewrite.txt
grep -n "^--- dump_\\|^+++ dump_" /tmp/macos-unifiedlogs-dump-compare.out
```

Then rerun the structural diff grouping before checking off the corresponding task.
