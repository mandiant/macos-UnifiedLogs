# macos-unifiedlogs

A simple Rust library that can help parse the macOS Unified Log files.

Unified Logs were introduced in macOS version 10.12 (Sierra, 2016). Part of
Apple's goal to create a unified log format for all Apple products. They exist
on macOS, iOS, watchOS, tvOS. The Unified Logs replace many of the old log
formats Apple used. This library can be used to parse these log files.\
Data that is currently extracted includes:

- Process ID
- Thread ID
- Activity ID
- Log Message
- Timestamp (Intel and ARM supported)
- Effective User ID (EUID)
- Log Type
- Event Type
- Library
- Subsystem
- Category
- Process
- Raw message - Message extracted from UUID file
- Message entries - Message parts from tracev3 file. Combines with Raw message
  to get the Log Message
- Library UUID
- Process UUID
- Boot UUID
- Timezone

## Running

An example binary is available to download

- `unifiedlog_iterator` - Can parse a logarchive into a JSOL or CSV file. It can also parse the logs
  on a live system. The output file will be quite large

## Limitations

Its been tested against millions of log entries. However, due the complexity of
the Unified Log format there are some limitations:

1. No printf style error code lookup support. This library does not do any error
   code lookups for log messages. The native `log` command on macOS supports
   error code lookups when it encounters printf style `%m` messages.\
   For example the log message: 'Failed to open file, error: %m'\
   a. This Library outputs:
   ```
   Failed to open file, error: 1
   ```
   b. The macOS Log command outputs:
   ```
   Failed to open file, error: no such file or directory
   ```

2. This library supports most custom objects in log messages. However, unsupported objects will be base64 encoded

# References

- https://github.com/ydkhatri/UnifiedLogReader
- https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc
- https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how
- https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response
