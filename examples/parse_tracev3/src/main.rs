// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::LevelFilter;
use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::parser::{build_log, parse_log};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::unified_log::LogData;
use macos_unifiedlogs::uuidtext::UUIDText;

use simplelog::{Config, SimpleLogger};
use std::env;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("Starting Unified Log parser...");
    // Set logging to Error only, since we are parsing only a tracev3, we wont have enough data to build the whole log
    SimpleLogger::init(LevelFilter::Error, Config::default())
        .expect("Failed to initialize simple logger");

    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let archive_path = &args[1];
        parse_trace_file(archive_path);
    } else {
        println!("Expected an argument for a tracev3 file")
    }
}

// Parse single tracev3 file
fn parse_trace_file(path: &str) {
    let log_data = parse_log(path).unwrap();
    let filename = Path::new(path);
    // Pass empty UUID, UUID cache, timesync files
    let string_results: Vec<UUIDText> = Vec::new();
    let shared_strings_results: Vec<SharedCacheStrings> = Vec::new();
    let timesync_data: Vec<TimesyncBoot> = Vec::new();
    let exclude_missing = false;

    // We only get minimal data since we dont have the log metadata
    let (results, _) = build_log(
        &log_data,
        &string_results,
        &shared_strings_results,
        &timesync_data,
        exclude_missing,
    );
    output(&results, filename.file_name().unwrap().to_str().unwrap()).unwrap();
    println!(
        "\nParsed file: {} to {}.json",
        path,
        filename.file_name().unwrap().to_str().unwrap()
    )
}

// Create JSON file
fn output(results: &Vec<LogData>, output_name: &str) -> Result<(), Box<dyn Error>> {
    let mut json_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{}.json", output_name))?;

    let serde_data = serde_json::to_string(&results)?;

    json_file.write_all(serde_data.as_bytes())?;

    Ok(())
}
