# Example binaries
Precompiled binaries are available in GitHub releases, they can also be built following the steps under `BUILDING.md`.  
`unifiedlog_parser` and `unifiedlog_parser_json` can run on a live macOS system or a `logarchive`.  To run on a live system execute `unifiedlog_parser` or `unifiedlog_parser_json` with the arguements `-l true`.  
To run on a `logarchive` provide the full path to the `logarchive` as an arguement to `unifiedlog_parser` or `unifiedlog_parser_json`.  
- Ex: `unifiedlog_parser -i <path/to/file.logarchive>`  

By default the example binaries will output to the directory where run from. To change the output path pass the arguement `-o <path to output>`  
Full exmample: 
```
./unifiedlog_parser -i system_logs.logarchive -o build/output.csv
Starting Unified Log parser...
Parsing: system_logs.logarchive/Persist/0000000000000462.tracev3
Parsing: system_logs.logarchive/Persist/0000000000000454.tracev3
...
```

A very simple help menu is provided via the `-h` option for both `unifiedlog_parser` and `unifiedlog_parser_json`
```
./unifiedlog_parser_json -h
Starting Unified Log parser...
unifiedlog_parser_json 0.1.0

USAGE:
    unifiedlog_parser_json [OPTIONS]

OPTIONS:
    -h, --help               Print help information
    -i, --input <INPUT>      Path to logarchive formatted directory [default: ]
    -l, --live <LIVE>        Run on live system [default: false]
    -o, --output <OUTPUT>    Path to output directory. Any directories must already exist [default:.]
    -V, --version            Print version information
```


To create an `logarchive`, execute `sudo log collect`. If you cannot execute the `log` command, you can manually create a `logarchive`.  
The example binary `parse_tracev3` can parse a single `tracev3`.  
- Ex: `parse_tracev3 <path/to/file.tracev3>`  

## Manually create logarchive
1. Create a directory. Ex: `mkdir output`
2. Copy all contents from `/private/var/db/uuidtext` to created directory
3. Copy all contents from `/private/var/db/diagnostics` to created directory
4. Execute `unifiedlog_parser` or `unifiedlog_parser_json` with path to created directory
- Ex: `unifiedlog_parser -i <path/to/output>`

# Possible Issues when running
Due to the complexity and size of the Unified Logs, some warnings may be encountered when running `unifiedlog_parser` or the other example binaries. Any errors or crashes should be reported.  
Example of running `unifiedlog_parser` on a live system
```
./unifiedlog_parser -l true
Starting Unified Log parser...
Parsing: /var/db/diagnostics/Persist/00000000000005c8.tracev3
21:55:02 [WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"
Parsing: /var/db/diagnostics/Persist/00000000000005b8.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a7.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b1.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c1.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005ba.tracev3
Parsing: /var/db/diagnostics/Persist/000000000000059e.tracev3
21:56:46 [WARN] Failed to get message string from alternative UUIDText file: "9C2D765DAEE334BFA507FDC05EFA7019"
Parsing: /var/db/diagnostics/Persist/00000000000005c0.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b0.tracev3
21:57:44 [WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"
21:57:44 [WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"
21:57:44 [WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"
Parsing: /var/db/diagnostics/Persist/000000000000059d.tracev3
21:57:50 [WARN] Failed to get message string from alternative UUIDText file: "9C2D765DAEE334BFA507FDC05EFA7019"
21:57:50 [WARN] Failed to get message string from alternative UUIDText file: "9C2D765DAEE334BFA507FDC05EFA7019"
Parsing: /var/db/diagnostics/Persist/00000000000005b9.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c9.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005af.tracev3
21:58:53 [WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"
Parsing: /var/db/diagnostics/Persist/00000000000005a6.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b2.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c2.tracev3
Parsing: /var/db/diagnostics/Persist/000000000000059f.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005bb.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005ad.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a4.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005ae.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a5.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c3.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b3.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005bc.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a9.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005bf.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b6.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c6.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a0.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a1.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005aa.tracev3
Parsing: /var/db/diagnostics/Persist/000000000000059c.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a8.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c7.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b7.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a3.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005ac.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005be.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b5.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005c5.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005bd.tracev3
22:07:02 [WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"
Parsing: /var/db/diagnostics/Persist/00000000000005c4.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005b4.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005a2.tracev3
Parsing: /var/db/diagnostics/Persist/00000000000005ab.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000167.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000166.tracev3
22:08:12 [WARN] Failed to get string: Utf8Error { valid_up_to: 0, error_len: Some(1) }
22:08:12 [WARN] Failed to get string: Utf8Error { valid_up_to: 0, error_len: None }
22:08:12 [WARN] Failed to get string: Utf8Error { valid_up_to: 2, error_len: Some(1) }
Parsing: /var/db/diagnostics/Special/000000000000016f.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000174.tracev3
Parsing: /var/db/diagnostics/Special/000000000000016d.tracev3
22:08:20 [WARN] Failed to get string: Utf8Error { valid_up_to: 2, error_len: Some(1) }
Parsing: /var/db/diagnostics/Special/000000000000016e.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000170.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000169.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000168.tracev3
Parsing: /var/db/diagnostics/Special/000000000000016a.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000171.tracev3
22:08:33 [WARN] Failed to get string: Utf8Error { valid_up_to: 2, error_len: Some(1) }
Parsing: /var/db/diagnostics/Special/000000000000016c.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000173.tracev3
22:08:38 [WARN] Failed to get string: Utf8Error { valid_up_to: 2, error_len: Some(1) }
Parsing: /var/db/diagnostics/Special/000000000000016b.tracev3
Parsing: /var/db/diagnostics/Special/0000000000000172.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000baf.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb9.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc9.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b79.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba6.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc0.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb0.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be2.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd2.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b84.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b94.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b8d.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b9d.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000beb.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bdb.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb1.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc1.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b95.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b85.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd3.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be3.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b7a.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bdc.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bec.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b9e.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b8e.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bba.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bca.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc8.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb8.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba7.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b78.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b7c.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be1.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd1.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b87.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b97.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc3.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb3.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bcc.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bbc.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bea.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bda.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd8.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be8.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bae.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba5.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bad.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be9.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd9.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba4.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b7b.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b96.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b86.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd0.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be0.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb2.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc2.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bbb.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bcb.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b9f.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b8f.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bee.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bde.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b8c.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b9c.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba8.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b83.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b93.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be5.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd5.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc7.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb7.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba1.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bf3.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000baa.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba0.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bf2.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bbf.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bcf.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba9.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b9b.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b8b.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bdd.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bed.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd4.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be4.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b92.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b82.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b7f.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb6.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc6.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bf0.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba2.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b99.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b89.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bab.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bef.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bdf.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bcd.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bbd.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc4.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb4.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b7d.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b80.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b90.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be6.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd6.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b9a.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b8a.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bbe.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bce.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bb5.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bc5.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b7e.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bd7.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000be7.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b91.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b81.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bf1.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000ba3.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000bac.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b88.tracev3
Parsing: /var/db/diagnostics/Signpost/0000000000000b98.tracev3

Finished parsing Unified Log data. Saved results to: output.csv
```

* Breakdown of warnings
  * `[WARN] Failed to get message string from alternative UUIDText file: "8151CEAA69AF3C059474AAE3403C91A7"` 
     * The parser failed to extract the base log message string from the designated UUIDText file (UUID file).  
       macOS `log` command would report the error as `error: ~~> Invalid image <8151CEAA-69AF-3C05-9474-AAE3403C91A7>`
  * `[WARN] Failed to get string: Utf8Error { valid_up_to: 0, error_len: Some(1) }`
     * The parser failed to extract string metadata from a log message. This is commonly happens with log files in the `Special` directory. The parser currently attempts to extract strings associated with metdata on the log entry. Sometimes the metadata cannot be represented as a string

`<Missing message data>` in output. Sometimes log data may get deleted or not recorded, if the parser fails to find all the data associated with the log entries it will use `<Missing message data>` when attempting to build the logs.  
macOS `log` command would report the missing data as `<decode: missing data>`   
This sometimes occurs when a `tracev3` file references data in a deleted `tracev3` file. 

## Reviewing Unified Logs
The logs typically retain 30 days worth of information.  
Some possible starting points when reviewing log data:  
https://github.com/jamf/jamfprotect/tree/main/unified_log_filters
