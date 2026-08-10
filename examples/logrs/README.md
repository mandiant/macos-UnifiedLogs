# logrs

A simple example binary that uses the `macos-unifiedlogs` library to parse Apple Unified Logs. Its goals:

1. Help troubleshoot Unified Log format changes
2. Provide a CLI similar to the `log` command. log + Rust (rs) = `logrs`
3. Exercise the library's zero-copy, lazy-message API
