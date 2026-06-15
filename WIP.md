# WIP: Port `main` Into `rewrite3`

Comparison used:

- Current branch: `rewrite3` at `14253f8` (`agents init`)
- Target source: `main` at `27ff665` (`Sort all fileproviders outputs (#121)`)
- Merge base: `6603050` (`Update #104 to new release (#105)`)
- Command basis: `git log --reverse rewrite3..main`

`main` now uses the flat legacy layout (`src/*.rs`, `src/chunks/...`). This branch moved code under `src/legacy/`, added `src/rewrite/`, and added `src/compat/`. Do not cherry-pick blindly; port each behavior into the relevant legacy, rewrite, and compatibility paths.

## Per-Commit Porting Workflow

For each unchecked commit below:

1. Cherry-pick or manually apply the original diff onto the legacy implementation, reconciling the flat `main` paths with `src/legacy/...`.
2. Preserve the original commit message text for the eventual commit.
3. Implement the corresponding feature, increment, or fix in the rewrite implementation when the change is not purely common infrastructure.
4. Update the compatibility layer when public API or output shape changes.
5. Run the checks/tests needed for the touched feature flavors, normally:
   - `just test_legacy`
   - `just test_rewrite`
   - `just test_compat`
   - targeted tests such as `just compare_big_sur` when ordering or parser parity is affected
   - `cd examples && cargo build --release` when example code changes
6. Check the matching checkbox in this file only after the port and validation are done.
7. Pause for human review. The user will create the commit manually.

## Commit Checklist

- [x] `bf5bb3d` - `feat(unified_log): add support for parent activity ID (#109)`
  - Main files: `src/unified_log.rs`, `examples/unifiedlog_iterator/src/main.rs`
  - Port note: add parent activity output through legacy structs, rewrite `LogEntry`/format path if applicable, compat API, and the example binary.
  - Commit message to use: `feat(unified_log): add support for parent activity ID (#109)`

- [x] `bcd444d` - `Test and dependency updates (#110)`
  - Main files: `Cargo.toml`, `examples/unifiedlog_iterator/Cargo.toml`, `tests/big_sur_tests.rs`
  - Port note: review dependency changes and test fixture expectations before applying.
  - Commit message to use: `Test and dependency updates (#110)`

- [x] `c43f3f4` - `Minor update to nom parsing (#111)`
  - Main files: `src/chunks/{oversize,simpledump,statedump}.rs`, `src/chunkset.rs`, `src/{dsc,header,timesync,uuidtext}.rs`, docs/CI
  - Port note: apply parser changes to `src/legacy/...`; audit equivalent rewrite parsers.
  - Commit message to use: `Minor update to nom parsing (#111)`

- [x] `2cf2760` - `Further nom updates and additional error code lookup (#112)`
  - Main files: firehose parsers, `simpledump`, `statedump`, decoders, `message`, `unified_log`, `util`, tests
  - Port note: important behavior change. Port decoder error lookup and parser updates to both parser implementations.
  - Commit message to use: `Further nom updates and additional error code lookup (#112)`

- [x] `0e31c7d` - `Minor code cleanup (#113)`
  - Main files: firehose, `oversize`, `dsc`, `filesystem`, `parser`, `timesync`, `unified_log`, `uuidtext`
  - Port note: review for behavioral cleanup versus style-only churn; avoid undoing rewrite-specific structure.
  - Commit message to use: `Minor code cleanup (#113)`

- [x] `26644e7` - `Code cleanup and fixes (#114)`
  - Main files: dependencies, example, firehose `activity`, `flags`, `message`, `nonactivity`, `signpost`, `trace`
  - Port note: likely overlaps heavily with moved firehose code. Apply after prior nom/firehose commits.
  - Commit message to use: `Code cleanup and fixes (#114)`

- [x] `359aac4` - `Fix for has_large_offset flag and more tests (#115)`
  - Main files: `src/chunks/firehose/message.rs`, `tests/tahoe_tests.rs`
  - Port note: high-priority correctness fix; add Tahoe fixture tests if test data is available.
  - Commit message to use: `Fix for has_large_offset flag and more tests (#115)`

- [x] `b2eadea` - `Added enums for firehose items (#116)`
  - Main files: `firehose_log`, `message`, `trace`, `oversize`, decoder trait, `message`, `unified_log`, Tahoe tests
  - Port note: port enum model carefully into rewrite item/message types, not just legacy structures.
  - Commit message to use: `Added enums for firehose items (#116)`

- [x] `fb9bec5` - `Updates to message assembly (#117)`
  - Main files: `src/message.rs`
  - Port note: legacy message assembly refactor ported; rewrite formatter updated so plain octal formatting no longer forces alternate `0o` output in compat mode.
  - Commit message to use: `Updates to message assembly (#117)`

- [ ] `9c54de4` - `Add message flags to output (#118)`
  - Main files: firehose parsers and `src/unified_log.rs`
  - Port note: expose flags consistently through legacy, rewrite `LogEntry`, and compat output.

- [ ] `cea3d79` - `Dependency Updates (#119)`
  - Main files: root and example `Cargo.toml`
  - Port note: apply after code ports so dependency-driven API changes are easier to isolate.

- [ ] `868d56a` - `Prep Changelog for next release (#120)`
  - Main files: `.changes/v0.6.0.md`, `CHANGELOG.md`
  - Port note: release bookkeeping only; probably port after functional commits, or skip until this branch is release-ready.

- [ ] `27ff665` - `Sort all fileproviders outputs (#121)`
  - Main files: `src/filesystem.rs`, `src/parser.rs`
  - Port note: port ordering behavior to `src/legacy/filesystem.rs`, `src/legacy/parser.rs`, and any rewrite logarchive/file provider traversal.

## Suggested Port Order

1. Dependencies and low-risk parser compatibility: `bcd444d`, `c43f3f4`, `cea3d79`.
2. Firehose and message behavior: `2cf2760`, `26644e7`, `359aac4`, `b2eadea`, `fb9bec5`, `9c54de4`.
3. Public output/API updates: `bf5bb3d`, then re-check compat exports.
4. File ordering behavior: `27ff665`.
5. Release notes: `868d56a` only when the functional port is stable.

## Validation Targets

- `just test_legacy`
- `just test_rewrite`
- `just test_compat`
- `just compare_big_sur`
- `cd examples && cargo build --release`
