// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::LevelFilter;
use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::filesystem::{LiveSystemProvider, LogarchiveProvider};
use macos_unifiedlogs::parser::{
    build_log, collect_shared_strings, collect_strings, collect_timesync, parse_log,
};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};
use macos_unifiedlogs::uuidtext::UUIDText;
use simplelog::{Config, SimpleLogger};
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Run on live system
    #[clap(short, long)]
    live: bool,

    /// Path to logarchive formatted directory
    #[clap(short, long, default_value = "")]
    input: Option<PathBuf>,

    /// Path to output directory. Any directories must already exist
    #[clap(short, long)]
    output: Option<PathBuf>,
}

fn main() {
    println!("Starting Unified Log parser...");
    // Set logging level to warning
    SimpleLogger::init(LevelFilter::Warn, Config::default())
        .expect("Failed to initialize simple logger");

    let args = Args::parse();

    if let Some(input) = args.input {
        parse_log_archive(&input);
    } else if args.live {
        parse_live_system();
    }
}

// Parse a provided directory path. Currently expect the path to follow macOS log collect structure
fn parse_log_archive(path: &Path) {
    let provider = LogarchiveProvider::new(path);

    // Parse all UUID files which contain strings and other metadata
    let string_results = collect_strings(&provider).unwrap();
    // Parse UUID cache files which also contain strings and other metadata
    let shared_strings_results = collect_shared_strings(&provider).unwrap();
    // Parse all timesync files
    let timesync_data = collect_timesync(&provider).unwrap();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    parse_trace_file(
        &string_results,
        &shared_strings_results,
        &timesync_data,
        &provider,
    );

    println!("\nFinished parsing Unified Log data. Saved results to json files");
}

// Parse a live macOS system
fn parse_live_system() {
    let provider = LiveSystemProvider::default();
    let strings = collect_strings(&provider).unwrap();
    let shared_strings = collect_shared_strings(&provider).unwrap();
    let timesync_data = collect_timesync(&provider).unwrap();

    parse_trace_file(&strings, &shared_strings, &timesync_data, &provider);

    println!("\nFinished parsing Unified Log data. Saved results to json files");
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
// Currently expect the path to follow macOS log collect structure
fn parse_trace_file(
    string_results: &[UUIDText],
    shared_strings_results: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    provider: &dyn FileProvider,
) {
    // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
    // Some log entries have Oversize strings located in different tracev3 files.
    // This is very rare. Seen in ~20 log entries out of ~700,000. Seen in ~700 out of ~18 million
    let mut oversize_strings = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
    };

    // Exclude missing data from returned output. Keep separate until we parse all oversize entries.
    // Then at end, go through all missing data and check all parsed oversize entries again
    let mut exclude_missing = true;
    let mut missing_data: Vec<UnifiedLogData> = Vec::new();
    let mut log_count = 0;

    for (i, mut source) in provider.tracev3_files().enumerate() {
        let log_data = parse_log(source.reader()).unwrap();

        // Get all constructed logs and any log data that failed to get constrcuted (exclude_missing = true)
        let (results, missing_logs) = build_log(
            &log_data,
            string_results,
            shared_strings_results,
            timesync_data,
            exclude_missing,
        );
        // Take all Oversize entries and add to tracker
        oversize_strings
            .oversize
            .append(&mut log_data.oversize.clone());

        // Add log entries that failed to find strings to missing tracker
        // We will try parsing them again at the end once we have all Oversize entries
        missing_data.push(missing_logs);
        log_count += results.len();
        output(&results, &format!("persist_{}", i)).unwrap();
    }

    // Include all log entries now, if any logs are missing data its because the data has rolled
    exclude_missing = false;
    for mut leftover_data in missing_data {
        // Add all of our previous oversize data to logs for lookups
        leftover_data
            .oversize
            .append(&mut oversize_strings.oversize.clone());

        // Exclude_missing = false
        // If we fail to find any missing data its probably due to the logs rolling
        // Ex: tracev3A rolls, tracev3B references Oversize entry in tracev3A will trigger missing data since tracev3A is gone
        let (results, _) = build_log(
            &leftover_data,
            string_results,
            shared_strings_results,
            timesync_data,
            exclude_missing,
        );
        log_count += results.len();

        output(&results, "dataFoundInMultipleLogFiles").unwrap();
    }
    println!("Parsed {} log entries", log_count);
}

// Create JSON files in JSONL format
fn output(results: &Vec<LogData>, output_name: &str) -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let mut filepath = args.output.unwrap_or(PathBuf::from("."));
    filepath.push(output_name);
    filepath.set_extension("jsonl");

    let mut json_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(filepath)?;

    for log_data in results.iter() {
        let serde_data = serde_json::to_string(log_data)?;
        json_file.write_all(serde_data.as_bytes())?;
        json_file.write_all(b"\n")?; // Add a newline after each JSON entry
    }

    Ok(())
}
