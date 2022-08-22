# macos-unifiedlogs
A simple Rust library that can help parse the macOS Unified Log files.  

Unified Logs were introduced in macOS version 10.12 (Sierra, 2016). Part of Apple's goal to create a unified log format for all Apple products. They exist on macOS, iOS, watchOS, tvOS.
The Unified Logs replace many of the old log formats Apple used. This simple library can be used to parse files.  
Data that is currently extracted includes:
* Process ID
* Thread ID
* Activity ID
* Log Message
* Timestamp (Intel and ARM supported)
* Effective User ID (EUID)
* Log Type
* Event Type
* Library
* Subsystem
* Category
* Process
* Raw message - Message extracted from UUID file
* Message entries - Message parts from tracev3 file. Combines with Raw message to get the Log Message
* Library UUID
* Process UUID
* Boot UUID
* Timezone

## Running
Three (3) simple example binaries are available in `examples`.  
* `unifiedlog_parser` - Can parse all logs into a single CSV file. It can also be run on a live system. The resulting CSV file will likely be quite large 
* `unifiedlog_parser_json` - Can parse all logs into JSON files. It can also be run on a live system. Each log file (tracev3 file) will correspond to a single JSON file. Depending on the logs, hundreds of JSON files may get created
* `parse_tracev3` - Can parse a single tracev3 file without any timesync or uuidtext files, to a JSON file. However, without the uuidtext or timesync files the resulting JSON file will be heavily incomplete.  

See `RUNNING.md` for overview of running the example binaries
## Using as Library
If you want to import this project into a Rust application add the following to you `Cargo.toml` file
```
macos-unifiedlogs = {git = "https://github.com/mandiant/macos-UnifiedLogs"}
```
If you want to pin to a specific commit
```
macos-unifiedlogs = {git = "https://github.com/mandiant/macos-UnifiedLogs", rev = "commit hash"}
```
See `Library.md` for overview of how to use the library. Simple example projects are also available to review and use
## Status
This library has been heavily tested on log data from macOS Sierra (10.12.5) to Monterey (12).  
Its been tested against 100+ million log entries. However, due the complexity of the Unified Log format there are some limitations:
1. No printf style error code lookup support. This library does not do any error code lookups for log messages. The native `log` command on macOS supports error code lookups when it encounters printf style `%m` messages.  
    An example base log messsage: 'Failed to open file, error: %m'  
    a. This Library outputs:
    ```
      Failed to open file, error: 1
    ```
    b. The macOS Log command outputs:
    ```
      Failed to open file, error: no such file or directory
    ```
    Here the error code 1 gets translated to the error string message

2. No support for custom object decoders. The Unified Log format allows a developer to log abrirtary data to the logs. Apple also includes a handful of custom objects that developer can use to log raw data. An example list can be found in `man os_log`. However, it is not a complete list.
```
man os_log
...
     To format a log message, use a printf(3) format string.  You may also use the "%@" format specifier for use with Obj-C/CF/Swift objects, and %.*P which can be used to decode arbitrary binary data.  The logging system also supports custom decoding of values by denoting value types inline in the format %{value_type}d.  The built-in value type decoders are:

     Value type      Custom specifier         Example output
     BOOL            %{BOOL}d                 YES
     bool            %{bool}d                 true
     darwin.errno    %{darwin.errno}d         [32: Broken pipe]
     darwin.mode     %{darwin.mode}d          drwxr-xr-x
     darwin.signal   %{darwin.signal}d        [sigsegv: Segmentation Fault]
     time_t          %{time_t}d               2016-01-12 19:41:37
     timeval         %{timeval}.*P            2016-01-12 19:41:37.774236
     timespec        %{timespec}.*P           2016-01-12 19:41:37.2382382823
     bytes           %{bytes}d                4.72 kB
     iec-bytes       %{iec-bytes}d            4.61 KiB
     bitrate         %{bitrate}d              123 kbps
     iec-bitrate     %{iec-bitrate}d          118 Kibps
     uuid_t          %{uuid_t}.16P            10742E39-0657-41F8-AB99-878C5EC2DCAA
     sockaddr        %{network:sockaddr}.*P   fe80::f:86ff:fee9:5c16
     in_addr         %{network:in_addr}d      127.0.0.1
     in6_addr        %{network:in6_addr}.16P  fe80::f:86ff:fee9:5c16
```
Currently when the library encounters log messages that contain arbitrary binary data, it will base64 the data as a string.
Support for custom decoders will hopefully be added in version 2 of the library.

3. No support for log messages that have custom object structures or protocol buffer data. 
   Some logs contain binary plist files, custom object structures, or protocol buffer data. This library currently supports parsing binary plist data, but it does not support custom object structures, or protocol buffer data.
   The custom object structures are similar to the custom decoders mentioned above. But there is no list of decoders  
   Support for custom object structures will hopefully be added in version 2 of the library

# References
https://github.com/ydkhatri/UnifiedLogReader  
https://github.com/libyal/dtformats/blob/main/documentation/Apple%20Unified%20Logging%20and%20Activity%20Tracing%20formats.asciidoc  
https://eclecticlight.co/2018/03/19/macos-unified-log-1-why-what-and-how/  
https://www.crowdstrike.com/blog/how-to-leverage-apple-unified-log-for-incident-response/
