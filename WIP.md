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

Total differing entries: `3872`.

- `2856` `message`: mDNS DNS-header decoder whitespace. Legacy keeps a space before newline after commas, compat/rewrite do not.
- `526` `message`: mostly formatter/decoder edge cases:
  - OpenDirectory `ODError...` strings are truncated by one or more trailing characters in compat.
  - Some long object/private strings differ by truncation or masking.
  - One install-phase plist/object string is truncated.
- `480` `library_uuid`, `process_uuid`: statedump entries use empty UUIDs in legacy and zero UUIDs in compat.
- `6` `library`, `library_uuid`, `process`, `process_uuid`: loss entries are unattributed in legacy but attributed to `/kernel` in compat.
- `4` statedump entries combine zero UUID differences with DNS Configuration decoder formatting differences.

### Compat vs Rewrite

Current differing entries after the activity-id fix: `92859`.

- `66696` `message`: rewrite omits the compat/legacy signpost prefix (`Signpost ID: ... - Signpost Name: ...`).
- `24402` `message`: compat renders null pointers as `(null)`, rewrite renders an empty string.
- `785` `message`: rewrite omits compat backtrace prefix formatting.
- `267` `message`: rewrite returns empty strings for `%s%.*s` style messages that compat resolves, for example CAML warnings.
- `60` `message`, `raw_message`: invalid format-string offsets use compat error text, while rewrite emits `<missing format string>`.
- `7` `message`: very large floating/decimal values lose precision in rewrite output.
- `6` `message`: loss entries include a rewrite-only "Lost N log entries..." message.
- `636` `message`: remaining formatter/object rendering differences that need further bucketing.

## Reduction Plan

- [x] Mask the high-bit sentinel in rewrite `activity_id` and `parent_activity_id` for normal rewrite output, not only under `rewrite-compat`.
  - Expected impact: about `339558` compat/rewrite entries.
  - Start in `src/rewrite/tracev3.rs::combine_activity_id`.
  - Result: `compat vs rewrite` diff count dropped from `432418` to `92859`; `activity_id` and `parent_activity_id` no longer appear in the structural diff.

- [ ] Decide whether rewrite should intentionally match compat/legacy signpost and backtrace prefixes.
  - If yes, remove the `rewrite-compat` gating in `src/rewrite/log_entry.rs::apply_parity_prefix`.
  - Expected impact: about `67481` message entries.

- [ ] Normalize null pointer formatting.
  - Decide target behavior: compat/legacy `(null)` or rewrite empty string.
  - Expected impact: about `24600` message entries.
  - Search in rewrite item formatting and string/object decoding paths.

- [ ] Fix `%s%.*s` precision/string assembly in rewrite.
  - Example raw message: `%s%.*s`.
  - Expected impact: about `267` message entries.
  - Start in `src/rewrite/format.rs`.

- [ ] Use compat invalid-offset error text in rewrite when format-string lookup fails.
  - Expected impact: `60` entries.
  - Start in `src/rewrite/tracev3.rs::format_string_error_message` and `src/rewrite/log_entry.rs::effective_format_string`.

- [ ] Investigate large-number precision formatting.
  - Expected impact: `8` entries.
  - Compare legacy `src/legacy/message.rs` to rewrite `src/rewrite/format.rs`.

- [ ] Decide whether loss entries should have an empty message or rewrite's explicit lost-entry message.
  - Expected impact: `6` entries.

- [ ] Bring compat closer to legacy for low-volume differences after rewrite parity is stable.
  - mDNS DNS-header comma/newline whitespace.
  - OpenDirectory decoder truncation.
  - Statedump empty UUID vs zero UUID representation.
  - Loss attribution to `/kernel`.
  - DNS Configuration statedump formatting.

## Validation Loop

After each fix:

```bash
just dump_all_and_compare > /tmp/macos-unifiedlogs-dump-compare.out 2>&1
wc -l dump_legacy.txt dump_compat.txt dump_rewrite.txt
grep -n "^--- dump_\\|^+++ dump_" /tmp/macos-unifiedlogs-dump-compare.out
```

Then rerun the structural diff grouping before checking off the corresponding task.
