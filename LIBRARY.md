# Parsing the log data
There two (2) ways to parse log data using `macos-unifiedlogs`
1. Running on a live system
2. Providing a custom directory

Once you have added the library to `Cargo.toml` five (5) functions are used to parse the log data.
## Live System
1. `collect_strings_system()` Returns a `Result<Vec<UUIDText>, ParserError>` which is a vector structure containing UUID data
2. `collect_shared_strings_system()` Returns a `Result<Vec<SharedCacheStrings>, ParserError>` which is a vector structure containing UUID cached data
3. `collect_timesync_system()` Returns a `Result<Vec<TimesyncBoot>, ParserError>` which is a vector structure containing timesync data

The above three (3) functions should be called first and load the results in memory. This will allow for fast lookups when building the  logs. The UUID, UUID cache, and timesync files are very small and should not be impactful on memory usage.

After getting the UUID, UUID cache, and timesync data we need the full path to a `tracev3` file we want to parse to `parse_log()`.
1. `parse_log(&str)` Returns a `Result<UnifiedLogData, ParserError>` which is a structure containing the parsed Unified Log data

Now we have all data needed to construct the Unified Log entries.
Before building the logs, the caller will need to decide how to deal with log data that is stored in a different `tracev3` file.  
Sometimes a `tracev3` will reference log data in another `tracev3` file, specifically the log data may reference `Oversize` data in different `tracev3` file.  
The function to construct the Unified Log data `build_log()` can be leveraged to both construct the logs and help track which logs may have data in a different `tracev3` files  
`build_log()` expects: `&UnifiedLogData, &[UUIDText], &[SharedCacheStrings], &[TimesyncBoot], bool`

1. `build_log(&UnifiedLogData, &[UUIDText], &[SharedCacheStrings], &[TimesyncBoot], exclude_missing: bool)` Returns a `(Vec<LogData>, UnifiedLogData)`

Passing a `true` bool to `build_log()` will cause it to exclude all `UnifiedLogData` entries from `Vec<LogData>`, if it fails to find the correct `Oversize` data in the provided `UnifiedLogData`.  
By tracking the excluded data separately you can parse each `tracev3` files and collect any entries that failed to build. Once all `tracev3` files are parsed you take a Vector of excluded `UnifiedLogData` and call `build_log` one more time to build any logs that had `Oversize` data in another `tracev3` file. Since all `tracev3` files are now parsed we have all the `Oversize` data and should be able to find all log entries that had data in another file.  
The example projects `unifiedlog_parser` and `unifiedlog_parse_json` both pass `true` to `build_log()`

Passing `false` bool to `build_log()` will cause it include all `UnifiedLogData` entries in `Vec<LogData>` EVEN IF IT FAILED to find `Oversize` data in the parsed `tracev3` file. Any log entries that reference a different `tracev3` file will have data labeled `<Missing message data>`

Once `build_log()` has constructed the Unified Log entries you should immediantly output or upload the returned `Vec<LogData>` before parsing other `tracev3` files. Parsing all `tracev3` files and appending the results to single Vector will increase total memory usage extremely fast.  
The example files `unifiedlog_parser` and `unifiedlog_parse_json` both output `Vec<LogData>` to a file and discards the results before parsing the next `tracev3` file

The example projects `unifiedlog_parser` and `unifiedlog_parse_json` both support parsing on a live system if run with no arguements.

## Custom paths
Similar to `parse_log()` you can also provide custom paths for the UUID, UUID cache, and Timesync files:  
1. `collect_shared_strings(&str)` Expects a path containing UUID Cache files (ex: `/private/var/db/uuidtext/dsc`)
2. `collect_timesync(&str)` Expects a path containing timesync files (ex: `/private/var/db/diagnostics/timesync`)  
Both functions return the same values as `collect_shared_strings_system() and collect_timesync_system()`

3. `collect_strings(&str)` Expects a path containing one (1) or more, two (2) character subdirectories that contain UUID files (ex: `/private/var/db/uuidtext`). Each subdirectory should contain the UUID file(s). This function returns the same value as `collect_strings_system()`

Parsing the `tracev3` files then follows the same process as mentioned in parsing on a `Live System`

The example projects `unifiedlog_parser` and `unifiedlog_parse_json` both support parsing custom paths that follow the same structure as a `logarchive`
```
./unifiedlog_parser system.logarchive/
```
