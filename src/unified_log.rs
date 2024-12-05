// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

//! Parse macOS Unified Log data
//!
//! Provides a simple library to parse the macOS Unified Log format.

use crate::catalog::CatalogChunk;
use crate::chunks::firehose::activity::FirehoseActivity;
use crate::chunks::firehose::firehose_log::{Firehose, FirehoseItemInfo, FirehosePreamble};
use crate::chunks::firehose::nonactivity::FirehoseNonActivity;
use crate::chunks::firehose::signpost::FirehoseSignpost;
use crate::chunks::firehose::trace::FirehoseTrace;
use crate::chunks::oversize::Oversize;
use crate::chunks::simpledump::SimpleDump;
use crate::chunks::statedump::Statedump;
use crate::chunkset::ChunksetChunk;
use crate::dsc::SharedCacheStrings;
use crate::header::HeaderChunk;
use crate::message::format_firehose_log_message;
use crate::preamble::LogPreamble;
use crate::timesync::TimesyncBoot;
use crate::util::{extract_string, padding_size, unixepoch_to_iso};
use crate::uuidtext::UUIDText;
use log::{error, warn};
use nom::bytes::complete::take;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct UnifiedLogData {
    pub header: Vec<HeaderChunk>,
    pub catalog_data: Vec<UnifiedLogCatalogData>,
    pub oversize: Vec<Oversize>, // Keep a global cache of oversize string
}

#[derive(Debug, Clone, Default)]
pub struct UnifiedLogCatalogData {
    pub catalog: CatalogChunk,
    pub firehose: Vec<FirehosePreamble>,
    pub simpledump: Vec<SimpleDump>,
    pub statedump: Vec<Statedump>,
    pub oversize: Vec<Oversize>,
}

struct LogIterator<'a> {
    unified_log_data: &'a UnifiedLogData,
    strings_data: &'a [UUIDText],
    shared_strings: &'a [SharedCacheStrings],
    timesync_data: &'a [TimesyncBoot],
    exclude_missing: bool,
    message_re: Regex,
    catalog_data_iterator_index: usize,
}
impl<'a> LogIterator<'a> {
    fn new(
        unified_log_data: &'a UnifiedLogData,
        strings_data: &'a [UUIDText],
        shared_strings: &'a [SharedCacheStrings],
        timesync_data: &'a [TimesyncBoot],
        exclude_missing: bool,
    ) -> Result<Self, regex::Error> {
        /*
        Crazy Regex to try to get all log message formatters
        Formatters are based off of printf formatters with additional Apple values
        (                                 # start of capture group 1
        %                                 # literal "%"
        (?:                               # first option

        (?:{[^}]+}?)                      # Get String formatters with %{<variable>}<variable> values. Ex: %{public}#llx with team ID %{public}@
        (?:[-+0#]{0,5})                   # optional flags
        (?:\d+|\*)?                       # width
        (?:\.(?:\d+|\*))?                 # precision
        (?:h|hh|l|ll|t|q|w|I|z|I32|I64)?  # size
        [cCdiouxXeEfgGaAnpsSZPm@}]       # type

        |                                 # OR get regular string formatters, ex: %s, %d

        (?:[-+0 #]{0,5})                  # optional flags
        (?:\d+|\*)?                       # width
        (?:\.(?:\d+|\*))?                 # precision
        (?:h|hh|l|ll|w|I|t|q|z|I32|I64)?  # size
        [cCdiouxXeEfgGaAnpsSZPm@%]        # type
        ))
        */
        let message_re_result = Regex::new(
            r"(%(?:(?:\{[^}]+}?)(?:[-+0#]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l|ll|w|I|z|t|q|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@}]|(?:[-+0 #]{0,5})(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:h|hh|l||q|t|ll|w|I|z|I32|I64)?[cmCdiouxXeEfgGaAnpsSZP@%]))",
        );
        let message_re = match message_re_result {
            Ok(message_re) => message_re,
            Err(err) => {
                error!(
                    "Failed to compile regex for printf format parsing: {:?}",
                    err
                );
                return Err(err);
            }
        };

        Ok(LogIterator {
            unified_log_data,
            strings_data,
            shared_strings,
            timesync_data,
            exclude_missing,
            message_re,
            catalog_data_iterator_index: 0,
        })
    }
}

impl Iterator for LogIterator<'_> {
    type Item = (Vec<LogData>, UnifiedLogData);

    // catalog_data_index == 0
    fn next(&mut self) -> Option<Self::Item> {
        let catalog_data = self
            .unified_log_data
            .catalog_data
            .get(self.catalog_data_iterator_index)?;
        let mut log_data_vec: Vec<LogData> = Vec::new();
        // Need to keep track of any log entries that fail to find Oversize strings (sometimes the strings may be in other log files that have not been parsed yet)
        let mut missing_unified_log_data_vec = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        for (preamble_index, preamble) in catalog_data.firehose.iter().enumerate() {
            for (firehose_index, firehose) in preamble.public_data.iter().enumerate() {
                // The continous time is actually 6 bytes long. Combining 4 bytes and 2 bytes
                let firehose_log_entry_continous_time = u64::from(firehose.continous_time_delta)
                    | ((u64::from(firehose.continous_time_delta_upper)) << 32);

                let continous_time =
                    preamble.base_continous_time + firehose_log_entry_continous_time;

                // Calculate the timestamp for the log entry
                let timestamp = TimesyncBoot::get_timestamp(
                    self.timesync_data,
                    &self.unified_log_data.header[0].boot_uuid,
                    continous_time,
                    preamble.base_continous_time,
                );

                // Our struct format to hold and show the log data
                let mut log_data = LogData {
                    subsystem: String::new(),
                    thread_id: firehose.thread_id,
                    pid: CatalogChunk::get_pid(
                        &preamble.first_number_proc_id,
                        &preamble.second_number_proc_id,
                        &catalog_data.catalog,
                    ),
                    library: String::new(),
                    activity_id: 0,
                    time: timestamp,
                    timestamp: unixepoch_to_iso(&(timestamp as i64)),
                    category: String::new(),
                    log_type: LogData::get_log_type(
                        &firehose.unknown_log_type,
                        &firehose.unknown_log_activity_type,
                    ),
                    process: String::new(),
                    message: String::new(),
                    event_type: LogData::get_event_type(&firehose.unknown_log_activity_type),
                    euid: CatalogChunk::get_euid(
                        &preamble.first_number_proc_id,
                        &preamble.second_number_proc_id,
                        &catalog_data.catalog,
                    ),
                    boot_uuid: self.unified_log_data.header[0].boot_uuid.to_owned(),
                    timezone_name: self.unified_log_data.header[0]
                        .timezone_path
                        .split('/')
                        .last()
                        .unwrap_or("Unknown Timezone Name")
                        .to_string(),
                    library_uuid: String::new(),
                    process_uuid: String::new(),
                    raw_message: String::new(),
                    message_entries: firehose.message.item_info.to_owned(),
                };

                // 0x4 - Non-activity log entry. Ex: log default, log error, etc
                // 0x2 - Activity log entry. Ex: activity create
                // 0x7 - Loss log entry. Ex: loss
                // 0x6 - Signpost entry. Ex: process signpost, thread signpost, system signpost
                // 0x3 - Trace log entry. Ex: trace default
                match firehose.unknown_log_activity_type {
                    0x4 => {
                        log_data.activity_id =
                            u64::from(firehose.firehose_non_activity.unknown_activity_id);
                        let message_data = FirehoseNonActivity::get_firehose_nonactivity_strings(
                            &firehose.firehose_non_activity,
                            self.strings_data,
                            self.shared_strings,
                            u64::from(firehose.format_string_location),
                            &preamble.first_number_proc_id,
                            &preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        );

                        match message_data {
                            Ok((_, results)) => {
                                log_data.library = results.library;
                                log_data.library_uuid = results.library_uuid;
                                log_data.process = results.process;
                                log_data.process_uuid = results.process_uuid;
                                results.format_string.clone_into(&mut log_data.raw_message);

                                // If the non-activity log entry has a data ref value then the message strings are stored in an oversize log entry
                                let log_message =
                                    if firehose.firehose_non_activity.data_ref_value != 0 {
                                        let oversize_strings = Oversize::get_oversize_strings(
                                            firehose.firehose_non_activity.data_ref_value,
                                            preamble.first_number_proc_id,
                                            preamble.second_number_proc_id,
                                            &self.unified_log_data.oversize,
                                        );
                                        // Format and map the log strings with the message format string found UUIDText or shared string file
                                        format_firehose_log_message(
                                            results.format_string,
                                            &oversize_strings,
                                            &self.message_re,
                                        )
                                    } else {
                                        // Format and map the log strings with the message format string found UUIDText or shared string file
                                        format_firehose_log_message(
                                            results.format_string,
                                            &firehose.message.item_info,
                                            &self.message_re,
                                        )
                                    };
                                // If we are tracking missing data (due to it being stored in another log file). Add missing data to vec to track and parse again once we got all data
                                if self.exclude_missing
                                    && log_message.contains("<Missing message data>")
                                {
                                    LogData::add_missing(
                                        catalog_data,
                                        preamble_index,
                                        firehose_index,
                                        &self.unified_log_data.header,
                                        &mut missing_unified_log_data_vec,
                                        preamble,
                                    );
                                    continue;
                                }

                                if !firehose.message.backtrace_strings.is_empty() {
                                    log_data.message = format!(
                                        "Backtrace:\n{:}\n{:}",
                                        firehose.message.backtrace_strings.join("\n"),
                                        log_message
                                    );
                                } else {
                                    log_data.message = log_message;
                                }
                            }
                            Err(err) => {
                                warn!("[macos-unifiedlogs] Failed to get message string data for firehose non-activity log entry: {:?}", err);
                            }
                        }

                        if firehose.firehose_non_activity.subsystem_value != 0 {
                            let results = CatalogChunk::get_subsystem(
                                &firehose.firehose_non_activity.subsystem_value,
                                &preamble.first_number_proc_id,
                                &preamble.second_number_proc_id,
                                &catalog_data.catalog,
                            );
                            match results {
                                Ok((_, subsystem)) => {
                                    log_data.subsystem = subsystem.subsystem;
                                    log_data.category = subsystem.category;
                                }
                                Err(err) => {
                                    warn!("[macos-unifiedlogs] Failed to get subsystem: {:?}", err)
                                }
                            }
                        }
                    }
                    0x7 => {
                        // No message data in loss entries
                        log_data.log_type = String::new();
                    }
                    0x2 => {
                        log_data.activity_id =
                            u64::from(firehose.firehose_activity.unknown_activity_id);
                        let message_data = FirehoseActivity::get_firehose_activity_strings(
                            &firehose.firehose_activity,
                            self.strings_data,
                            self.shared_strings,
                            u64::from(firehose.format_string_location),
                            &preamble.first_number_proc_id,
                            &preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        );
                        match message_data {
                            Ok((_, results)) => {
                                log_data.library = results.library;
                                log_data.library_uuid = results.library_uuid;
                                log_data.process = results.process;
                                log_data.process_uuid = results.process_uuid;
                                results.format_string.clone_into(&mut log_data.raw_message);

                                let log_message = format_firehose_log_message(
                                    results.format_string,
                                    &firehose.message.item_info,
                                    &self.message_re,
                                );

                                if self.exclude_missing
                                    && log_message.contains("<Missing message data>")
                                {
                                    LogData::add_missing(
                                        catalog_data,
                                        preamble_index,
                                        firehose_index,
                                        &self.unified_log_data.header,
                                        &mut missing_unified_log_data_vec,
                                        preamble,
                                    );
                                    continue;
                                }
                                if !firehose.message.backtrace_strings.is_empty() {
                                    log_data.message = format!(
                                        "Backtrace:\n{:}\n{:}",
                                        firehose.message.backtrace_strings.join("\n"),
                                        log_message
                                    );
                                } else {
                                    log_data.message = log_message;
                                }
                            }
                            Err(err) => {
                                warn!("[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: {:?}", err);
                            }
                        }
                    }
                    0x6 => {
                        log_data.activity_id =
                            u64::from(firehose.firehose_signpost.unknown_activity_id);
                        let message_data = FirehoseSignpost::get_firehose_signpost(
                            &firehose.firehose_signpost,
                            self.strings_data,
                            self.shared_strings,
                            u64::from(firehose.format_string_location),
                            &preamble.first_number_proc_id,
                            &preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        );
                        match message_data {
                            Ok((_, results)) => {
                                log_data.library = results.library;
                                log_data.library_uuid = results.library_uuid;
                                log_data.process = results.process;
                                log_data.process_uuid = results.process_uuid;
                                results.format_string.clone_into(&mut log_data.raw_message);

                                let mut log_message =
                                    if firehose.firehose_non_activity.data_ref_value != 0 {
                                        let oversize_strings = Oversize::get_oversize_strings(
                                            firehose.firehose_non_activity.data_ref_value,
                                            preamble.first_number_proc_id,
                                            preamble.second_number_proc_id,
                                            &self.unified_log_data.oversize,
                                        );
                                        // Format and map the log strings with the message format string found UUIDText or shared string file
                                        format_firehose_log_message(
                                            results.format_string,
                                            &oversize_strings,
                                            &self.message_re,
                                        )
                                    } else {
                                        // Format and map the log strings with the message format string found UUIDText or shared string file
                                        format_firehose_log_message(
                                            results.format_string,
                                            &firehose.message.item_info,
                                            &self.message_re,
                                        )
                                    };
                                if self.exclude_missing
                                    && log_message.contains("<Missing message data>")
                                {
                                    LogData::add_missing(
                                        catalog_data,
                                        preamble_index,
                                        firehose_index,
                                        &self.unified_log_data.header,
                                        &mut missing_unified_log_data_vec,
                                        preamble,
                                    );
                                    continue;
                                }

                                log_message = format!(
                                    "Signpost ID: {:X} - Signpost Name: {:X}\n {}",
                                    firehose.firehose_signpost.signpost_id,
                                    firehose.firehose_signpost.signpost_name,
                                    log_message
                                );

                                if !firehose.message.backtrace_strings.is_empty() {
                                    log_data.message = format!(
                                        "Backtrace:\n{:}\n{:}",
                                        firehose.message.backtrace_strings.join("\n"),
                                        log_message
                                    );
                                } else {
                                    log_data.message = log_message;
                                }
                            }
                            Err(err) => {
                                warn!("[macos-unifiedlogs] Failed to get message string data for firehose signpost log entry: {:?}", err);
                            }
                        }
                        if firehose.firehose_signpost.subsystem != 0 {
                            let results = CatalogChunk::get_subsystem(
                                &firehose.firehose_signpost.subsystem,
                                &preamble.first_number_proc_id,
                                &preamble.second_number_proc_id,
                                &catalog_data.catalog,
                            );
                            match results {
                                Ok((_, subsystem)) => {
                                    log_data.subsystem = subsystem.subsystem;
                                    log_data.category = subsystem.category;
                                }
                                Err(err) => {
                                    warn!("[macos-unifiedlogs] Failed to get subsystem: {:?}", err)
                                }
                            }
                        }
                    }
                    0x3 => {
                        let message_data = FirehoseTrace::get_firehose_trace_strings(
                            self.strings_data,
                            u64::from(firehose.format_string_location),
                            &preamble.first_number_proc_id,
                            &preamble.second_number_proc_id,
                            &catalog_data.catalog,
                        );
                        match message_data {
                            Ok((_, results)) => {
                                log_data.library = results.library;
                                log_data.library_uuid = results.library_uuid;
                                log_data.process = results.process;
                                log_data.process_uuid = results.process_uuid;

                                let log_message = format_firehose_log_message(
                                    results.format_string,
                                    &firehose.message.item_info,
                                    &self.message_re,
                                );

                                if self.exclude_missing
                                    && log_message.contains("<Missing message data>")
                                {
                                    LogData::add_missing(
                                        catalog_data,
                                        preamble_index,
                                        firehose_index,
                                        &self.unified_log_data.header,
                                        &mut missing_unified_log_data_vec,
                                        preamble,
                                    );
                                    continue;
                                }
                                if !firehose.message.backtrace_strings.is_empty() {
                                    log_data.message = format!(
                                        "Backtrace:\n{:}\n{:}",
                                        firehose.message.backtrace_strings.join("\n"),
                                        log_message
                                    );
                                } else {
                                    log_data.message = log_message;
                                }
                            }
                            Err(err) => {
                                warn!("[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: {:?}", err);
                            }
                        }
                    }
                    _ => error!(
                        "[macos-unifiedlogs] Parsed unknown log firehose data: {:?}",
                        firehose
                    ),
                }
                log_data_vec.push(log_data);
            }
        }

        for simpledump in &catalog_data.simpledump {
            let no_firehose_preamble = 1;
            let timestamp = TimesyncBoot::get_timestamp(
                self.timesync_data,
                &self.unified_log_data.header[0].boot_uuid,
                simpledump.continous_time,
                no_firehose_preamble,
            );
            let log_data = LogData {
                subsystem: simpledump.subsystem.to_owned(),
                thread_id: simpledump.thread_id,
                pid: simpledump.first_proc_id,
                library: String::new(),
                activity_id: 0,
                time: timestamp,
                timestamp: unixepoch_to_iso(&(timestamp as i64)),
                category: String::new(),
                log_type: String::new(),
                process: String::new(),
                message: simpledump.message_string.to_owned(),
                event_type: String::from("Simpledump"),
                euid: 0,
                boot_uuid: self.unified_log_data.header[0].boot_uuid.to_owned(),
                timezone_name: self.unified_log_data.header[0]
                    .timezone_path
                    .split('/')
                    .last()
                    .unwrap_or("Unknown Timezone Name")
                    .to_string(),
                library_uuid: simpledump.sender_uuid.to_owned(),
                process_uuid: simpledump.dsc_uuid.to_owned(),
                raw_message: String::new(),
                message_entries: Vec::new(),
            };
            log_data_vec.push(log_data);
        }

        for statedump in &catalog_data.statedump {
            let no_firehose_preamble = 1;

            let data_string = match statedump.unknown_data_type {
                0x1 => Statedump::parse_statedump_plist(&statedump.statedump_data),
                0x2 => String::from("Statedump Protocol Buffer"),
                0x3 => Statedump::parse_statedump_object(
                    &statedump.statedump_data,
                    &statedump.title_name,
                ),
                _ => {
                    warn!(
                        "Unknown statedump data type: {}",
                        statedump.unknown_data_type
                    );
                    let results = extract_string(&statedump.statedump_data);
                    match results {
                        Ok((_, string_data)) => string_data,
                        Err(err) => {
                            error!(
                                "[macos-unifiedlogs] Failed to extract string from statedump: {:?}",
                                err
                            );
                            String::from("Failed to extract string from statedump")
                        }
                    }
                }
            };
            let timestamp = TimesyncBoot::get_timestamp(
                self.timesync_data,
                &self.unified_log_data.header[0].boot_uuid,
                statedump.continuous_time,
                no_firehose_preamble,
            );
            let log_data = LogData {
                subsystem: String::new(),
                thread_id: 0,
                pid: statedump.first_proc_id,
                library: String::new(),
                activity_id: statedump.activity_id,
                time: timestamp,
                timestamp: unixepoch_to_iso(&(timestamp as i64)),
                category: String::new(),
                event_type: String::from("Statedump"),
                process: String::new(),
                message: format!(
                    "title: {:?}\nObject Type: {:?}\n Object Type: {:?}\n{:?}",
                    statedump.title_name,
                    statedump.decoder_library,
                    statedump.decoder_type,
                    data_string
                ),
                log_type: String::new(),
                euid: 0,
                boot_uuid: self.unified_log_data.header[0].boot_uuid.to_owned(),
                timezone_name: self.unified_log_data.header[0]
                    .timezone_path
                    .split('/')
                    .last()
                    .unwrap_or("Unknown Timezone Name")
                    .to_string(),
                library_uuid: String::new(),
                process_uuid: String::new(),
                raw_message: String::new(),
                message_entries: Vec::new(),
            };
            log_data_vec.push(log_data);
        }

        self.catalog_data_iterator_index += 1;
        Some((log_data_vec, missing_unified_log_data_vec))
    }
}

#[derive(Debug, Serialize)]
pub struct LogData {
    pub subsystem: String,
    pub thread_id: u64,
    pub pid: u64,
    pub euid: u32,
    pub library: String,
    pub library_uuid: String,
    pub activity_id: u64,
    pub time: f64,
    pub category: String,
    pub event_type: String,
    pub log_type: String,
    pub process: String,
    pub process_uuid: String,
    pub message: String,
    pub raw_message: String,
    pub boot_uuid: String,
    pub timezone_name: String,
    pub message_entries: Vec<FirehoseItemInfo>,
    pub timestamp: String,
}

impl LogData {
    /// Parse the Unified log data read from a tracev3 file
    pub fn parse_unified_log(data: &[u8]) -> nom::IResult<&[u8], UnifiedLogData> {
        let mut unified_log_data_true = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        let mut catalog_data = UnifiedLogCatalogData::default();

        let mut input = data;
        let chunk_preamble_size = 16; // Include preamble size in total chunk size

        let header_chunk = 0x1000;
        let catalog_chunk = 0x600b;
        let chunkset_chunk = 0x600d;
        // Loop through traceV3 file until all file contents are read
        while !input.is_empty() {
            let (_, preamble) = LogPreamble::detect_preamble(input)?;
            let chunk_size = preamble.chunk_data_size;

            // Grab all data associated with Unified Log entry (chunk)
            let (data, chunk_data) = take(chunk_size + chunk_preamble_size)(input)?;

            if preamble.chunk_tag == header_chunk {
                LogData::get_header_data(chunk_data, &mut unified_log_data_true);
            } else if preamble.chunk_tag == catalog_chunk {
                if catalog_data.catalog.chunk_tag != 0 {
                    unified_log_data_true.catalog_data.push(catalog_data);
                }
                catalog_data = UnifiedLogCatalogData::default();

                LogData::get_catalog_data(chunk_data, &mut catalog_data);
            } else if preamble.chunk_tag == chunkset_chunk {
                LogData::get_chunkset_data(
                    chunk_data,
                    &mut catalog_data,
                    &mut unified_log_data_true,
                );
            } else {
                error!(
                    "[macos-unifiedlogs] Unknown chunk type: {:?}",
                    preamble.chunk_tag
                );
            }

            let padding_size = padding_size(preamble.chunk_data_size);
            if data.len() < padding_size as usize {
                break;
            }
            let (data, _) = take(padding_size)(data)?;
            if data.is_empty() {
                break;
            }
            input = data;
            if input.len() < chunk_preamble_size as usize {
                warn!(
                    "Not enough data for preamble header, needed 16 bytes. Got: {:?}",
                    input.len()
                );
                break;
            }
        }
        // Make sure to get the last catalog
        if catalog_data.catalog.chunk_tag != 0 {
            unified_log_data_true.catalog_data.push(catalog_data);
        }
        Ok((input, unified_log_data_true))
    }

    /// Parse the Unified log data and return an iterator
    pub fn iter_log<'a>(
        unified_log_data: &'a UnifiedLogData,
        strings_data: &'a [UUIDText],
        shared_strings: &'a [SharedCacheStrings],
        timesync_data: &'a [TimesyncBoot],
        exclude_missing: bool,
    ) -> Result<impl Iterator<Item = (Vec<LogData>, UnifiedLogData)> + 'a, regex::Error> {
        LogIterator::new(
            unified_log_data,
            strings_data,
            shared_strings,
            timesync_data,
            exclude_missing,
        )
    }

    /// Reconstruct Unified Log entries using the binary strings data, cached strings data, timesync data, and unified log. Provide bool to ignore log entries that are not able to be recontructed (additional tracev3 files needed)
    /// Return a reconstructed log entries and any leftover Unified Log entries that could not be reconstructed (data may be stored in other tracev3 files)
    pub fn build_log(
        unified_log_data: &UnifiedLogData,
        strings_data: &[UUIDText],
        shared_strings: &[SharedCacheStrings],
        timesync_data: &[TimesyncBoot],
        exclude_missing: bool,
    ) -> (Vec<LogData>, UnifiedLogData) {
        let mut log_data_vec: Vec<LogData> = Vec::new();
        // Need to keep track of any log entries that fail to find Oversize strings (sometimes the strings may be in other log files that have not been parsed yet)
        let mut missing_unified_log_data_vec = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        let Ok(log_iterator) = LogIterator::new(
            unified_log_data,
            strings_data,
            shared_strings,
            timesync_data,
            exclude_missing,
        ) else {
            return (log_data_vec, missing_unified_log_data_vec);
        };
        for (mut log_data, mut missing_unified_log) in log_iterator {
            log_data_vec.append(&mut log_data);
            missing_unified_log_data_vec
                .header
                .append(&mut missing_unified_log.header);
            missing_unified_log_data_vec
                .catalog_data
                .append(&mut missing_unified_log.catalog_data);
            missing_unified_log_data_vec
                .oversize
                .append(&mut missing_unified_log.oversize);
        }

        (log_data_vec, missing_unified_log_data_vec)
    }

    /// Return log type based on parsed log data
    fn get_log_type(log_type: &u8, activity_type: &u8) -> String {
        match log_type {
            0x1 => {
                let activity = 2;
                if activity_type == &activity {
                    String::from("Create")
                } else {
                    String::from("Info")
                }
            }
            0x2 => String::from("Debug"),
            0x3 => String::from("Useraction"),
            0x10 => String::from("Error"),
            0x11 => String::from("Fault"),
            0x80 => String::from("Process Signpost Event"),
            0x81 => String::from("Process Signpost Start"),
            0x82 => String::from("Process Signpost End"),
            0xc0 => String::from("System Signpost Event"), // Not seen but may exist?
            0xc1 => String::from("System Signpost Start"),
            0xc2 => String::from("System Signpost End"),
            0x40 => String::from("Thread Signpost Event"), // Not seen but may exist?
            0x41 => String::from("Thread Signpost Start"),
            0x42 => String::from("Thread Signpost End"),
            _ => String::from("Default"),
        }
    }

    /// Return the log event type based on parsed log data
    fn get_event_type(event_type: &u8) -> String {
        match event_type {
            0x4 => String::from("Log"),
            0x2 => String::from("Activity"),
            0x3 => String::from("Trace"),
            0x6 => String::from("Signpost"),
            0x7 => String::from("Loss"),
            _ => String::from("Unknown"),
        }
    }

    /// Get the header of the Unified Log data (tracev3 file)
    pub(crate) fn get_header_data(data: &[u8], unified_log_data: &mut UnifiedLogData) {
        let header_results = HeaderChunk::parse_header(data);
        match header_results {
            Ok((_, header_data)) => unified_log_data.header.push(header_data),
            Err(err) => error!("[macos-unifiedlogs] Failed to parse header data: {:?}", err),
        }
    }

    /// Get the Catalog of the Unified Log data (tracev3 file)
    pub(crate) fn get_catalog_data(data: &[u8], unified_log_data: &mut UnifiedLogCatalogData) {
        let catalog_results = CatalogChunk::parse_catalog(data);
        match catalog_results {
            Ok((_, catalog_data)) => unified_log_data.catalog = catalog_data,
            Err(err) => error!(
                "[macos-unifiedlogs] Failed to parse catalog data: {:?}",
                err
            ),
        }
    }

    /// Get the Chunkset of the Unified Log data (tracev3)
    pub(crate) fn get_chunkset_data(
        data: &[u8],
        catalog_data: &mut UnifiedLogCatalogData,
        unified_log_data: &mut UnifiedLogData,
    ) {
        // Parse and decompress the chunkset entries
        let chunkset_data_results = ChunksetChunk::parse_chunkset(data);
        match chunkset_data_results {
            Ok((_, chunkset_data)) => {
                // Parse the decompressed data which contains the log data
                let _result = ChunksetChunk::parse_chunkset_data(
                    &chunkset_data.decompressed_data,
                    catalog_data,
                );
                unified_log_data.oversize.append(&mut catalog_data.oversize);
            }
            Err(err) => error!(
                "[macos-unifiedlogs] Failed to parse chunkset data: {:?}",
                err
            ),
        }
    }

    /// Track log entries that are missing data that could in another tracev3 file
    fn track_missing(
        first_proc_id: u64,
        second_proc_id: u32,
        time: u64,
        firehose: Firehose,
    ) -> FirehosePreamble {
        FirehosePreamble {
            chunk_tag: 0,
            chunk_sub_tag: 0,
            chunk_data_size: 0,
            first_number_proc_id: first_proc_id,
            second_number_proc_id: second_proc_id,
            collapsed: 0,
            unknown: Vec::new(),
            public_data_size: 0,
            private_data_virtual_offset: 0,
            unkonwn2: 0,
            unknown3: 0,
            base_continous_time: time,
            public_data: vec![firehose],
            ttl: 0,
        }
    }

    /// Add all missing log entries to log data tracker. Log data may be in another file. Mainly related to logs with that have Oversize data
    fn add_missing(
        catalog_data: &UnifiedLogCatalogData,
        preamble_index: usize,
        firehose_index: usize,
        header: &[HeaderChunk],
        missing_unified_log_data_vec: &mut UnifiedLogData,
        preamble: &FirehosePreamble,
    ) {
        let missing_firehose = LogData::track_missing(
            catalog_data.firehose[preamble_index].first_number_proc_id,
            catalog_data.firehose[preamble_index].second_number_proc_id,
            catalog_data.firehose[preamble_index].base_continous_time,
            preamble.public_data[firehose_index].to_owned(),
        );
        let mut missing_unified_log_data = UnifiedLogCatalogData {
            catalog: catalog_data.catalog.to_owned(),
            firehose: Vec::new(),
            simpledump: Vec::new(),
            statedump: Vec::new(),
            oversize: Vec::new(),
        };

        missing_unified_log_data.firehose.push(missing_firehose);
        header.clone_into(&mut missing_unified_log_data_vec.header);

        missing_unified_log_data_vec
            .catalog_data
            .push(missing_unified_log_data);
    }
}

#[cfg(test)]
mod tests {
    use super::{LogData, UnifiedLogData};

    use crate::{
        chunks::firehose::firehose_log::Firehose,
        parser::{collect_shared_strings, collect_strings, collect_timesync, iter_log, parse_log},
        unified_log::UnifiedLogCatalogData,
    };
    use std::{fs, path::PathBuf};

    #[test]
    fn test_parse_unified_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3",
        );

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = LogData::parse_unified_log(&buffer).unwrap();
        assert_eq!(results.catalog_data.len(), 56);
        assert_eq!(results.header.len(), 1);
        assert_eq!(results.oversize.len(), 12);
    }

    #[test]
    fn test_iter_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3",
        );

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = LogData::parse_unified_log(&buffer).unwrap();
        let iter = iter_log(&results, &[], &[], &[], false).unwrap();
        for (entry, remaining) in iter {
            assert!(entry.len() > 1000);
            assert!(remaining.catalog_data.is_empty());
            assert!(remaining.header.is_empty());
            assert!(remaining.oversize.is_empty());
        }
    }

    #[test]
    fn test_bad_log_header() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/TraceV3/Bad_header_0000000000000005.tracev3");

        let buffer = fs::read(test_path).unwrap();
        let (_, results) = LogData::parse_unified_log(&buffer).unwrap();
        assert_eq!(results.catalog_data.len(), 36);
        assert_eq!(results.header.len(), 0);
        assert_eq!(results.oversize.len(), 28);
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_log_content() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/TraceV3/Bad_content_0000000000000005.tracev3");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = LogData::parse_unified_log(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Eof")]
    fn test_bad_log_file() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/TraceV3/00.tracev3");

        let buffer = fs::read(test_path).unwrap();
        let (_, _) = LogData::parse_unified_log(&buffer).unwrap();
    }

    #[test]
    fn test_build_log() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let string_results = collect_strings(&test_path.display().to_string()).unwrap();

        test_path.push("dsc");
        let shared_strings_results =
            collect_shared_strings(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("timesync");
        let timesync_data = collect_timesync(&test_path.display().to_string()).unwrap();
        test_path.pop();

        test_path.push("Persist/0000000000000002.tracev3");

        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        let exclude_missing = false;
        let (results, _) = LogData::build_log(
            &log_data,
            &string_results,
            &shared_strings_results,
            &timesync_data,
            exclude_missing,
        );
        assert_eq!(results.len(), 207366);
        assert_eq!(results[0].process, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results[0].subsystem, "com.apple.lom");
        assert_eq!(results[0].time, 1642302326434850732.0);
        assert_eq!(results[0].activity_id, 0);
        assert_eq!(results[0].library, "/usr/libexec/lightsoutmanagementd");
        assert_eq!(results[0].library_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
        assert_eq!(results[0].process_uuid, "6C3ADF991F033C1C96C4ADFAA12D8CED");
        assert_eq!(results[0].message, "LOMD Start");
        assert_eq!(results[0].pid, 45);
        assert_eq!(results[0].thread_id, 588);
        assert_eq!(results[0].category, "device");
        assert_eq!(results[0].log_type, "Default");
        assert_eq!(results[0].event_type, "Log");
        assert_eq!(results[0].euid, 0);
        assert_eq!(results[0].boot_uuid, "80D194AF56A34C54867449D2130D41BB");
        assert_eq!(results[0].timezone_name, "Pacific");
        assert_eq!(results[0].raw_message, "LOMD Start");
        assert_eq!(results[0].timestamp, "2022-01-16T03:05:26.434850816Z")
    }

    #[test]
    fn test_get_log_type() {
        let mut log_type = 0x2;
        let activity_type = 0x2;

        let mut log_string = LogData::get_log_type(&log_type, &activity_type);
        assert_eq!(log_string, "Debug");
        log_type = 0x1;
        log_string = LogData::get_log_type(&log_type, &activity_type);
        assert_eq!(log_string, "Create");
    }

    #[test]
    fn test_get_event_type() {
        let event_type = 0x2;
        let event_string = LogData::get_event_type(&event_type);
        assert_eq!(event_string, "Activity");
    }

    #[test]
    fn test_get_header_data() {
        let test_chunk_header = [
            0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 15, 105,
            217, 162, 204, 126, 0, 0, 48, 215, 18, 98, 0, 0, 0, 0, 203, 138, 9, 0, 44, 1, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 97, 0, 0, 8, 0, 0, 0, 6, 112, 124, 198, 169, 153, 1, 0, 1, 97,
            0, 0, 56, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 50, 49, 65, 53, 53, 57, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 77, 97, 99, 66, 111, 111, 107, 80, 114, 111, 49, 54, 44, 49, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 97, 0, 0, 24, 0, 0, 0, 195, 32, 184, 206, 151,
            250, 77, 165, 159, 49, 125, 57, 46, 56, 156, 234, 85, 0, 0, 0, 0, 0, 0, 0, 3, 97, 0, 0,
            48, 0, 0, 0, 47, 118, 97, 114, 47, 100, 98, 47, 116, 105, 109, 101, 122, 111, 110, 101,
            47, 122, 111, 110, 101, 105, 110, 102, 111, 47, 65, 109, 101, 114, 105, 99, 97, 47, 78,
            101, 119, 95, 89, 111, 114, 107, 0, 0, 0, 0, 0, 0,
        ];
        let mut data = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };

        LogData::get_header_data(&test_chunk_header, &mut data);
        assert_eq!(data.header.len(), 1);
    }

    #[test]
    fn test_get_catalog_data() {
        let test_chunk_catalog = [
            11, 96, 0, 0, 17, 0, 0, 0, 208, 1, 0, 0, 0, 0, 0, 0, 32, 0, 96, 0, 1, 0, 160, 0, 7, 0,
            0, 0, 0, 0, 0, 0, 20, 165, 44, 35, 253, 233, 2, 0, 43, 239, 210, 12, 24, 236, 56, 56,
            129, 79, 43, 78, 90, 243, 188, 236, 61, 5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54,
            231, 114, 172, 1, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105,
            103, 104, 116, 0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110,
            115, 116, 114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99,
            105, 110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 158,
            0, 0, 0, 0, 0, 0, 0, 55, 1, 0, 0, 158, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 19, 0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0,
            246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 1,
            0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
            99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0,
            0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
            0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87,
            79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107,
            20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
            0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255,
            0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57,
            68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
        ];
        let mut data = UnifiedLogCatalogData::default();

        LogData::get_catalog_data(&test_chunk_catalog, &mut data);
        assert_eq!(data.catalog.chunk_tag, 0x600b);
        assert_eq!(data.catalog.chunk_sub_tag, 17);
        assert_eq!(data.catalog.chunk_data_size, 464);
        assert_eq!(data.catalog.catalog_subsystem_strings_offset, 32);
        assert_eq!(data.catalog.catalog_process_info_entries_offset, 96);
        assert_eq!(data.catalog.number_process_information_entries, 1);
        assert_eq!(data.catalog.catalog_offset_sub_chunks, 160);
        assert_eq!(data.catalog.number_sub_chunks, 7);
        assert_eq!(data.catalog.unknown, [0, 0, 0, 0, 0, 0]);
        assert_eq!(data.catalog.earliest_firehose_timestamp, 820223379547412);
        assert_eq!(
            data.catalog.catalog_uuids,
            [
                "2BEFD20C18EC3838814F2B4E5AF3BCEC",
                "3D05845F3F65358F9EBF2236E772AC01"
            ]
        );
        assert_eq!(
            data.catalog.catalog_subsystem_strings,
            [
                99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105, 103, 104, 116,
                0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116,
                114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105,
                110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0
            ]
        );
        assert_eq!(data.catalog.catalog_process_info_entries.len(), 1);
        assert_eq!(
            data.catalog.catalog_process_info_entries[0].main_uuid,
            "2BEFD20C18EC3838814F2B4E5AF3BCEC"
        );
        assert_eq!(
            data.catalog.catalog_process_info_entries[0].dsc_uuid,
            "3D05845F3F65358F9EBF2236E772AC01"
        );

        assert_eq!(data.catalog.catalog_subchunks.len(), 7)
    }

    #[test]
    fn test_get_chunkset_data() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Chunkset Tests/high_sierra_compressed_chunkset.raw");

        let buffer = fs::read(test_path).unwrap();

        let mut unified_log = UnifiedLogCatalogData::default();

        let mut log_data = UnifiedLogData::default();

        LogData::get_chunkset_data(&buffer, &mut unified_log, &mut log_data);
        assert_eq!(unified_log.catalog.chunk_tag, 0);
        assert_eq!(unified_log.firehose.len(), 21);
        assert_eq!(unified_log.statedump.len(), 0);
        assert_eq!(unified_log.simpledump.len(), 0);
        assert_eq!(unified_log.oversize.len(), 0);

        assert_eq!(
            unified_log.firehose[0].public_data[0].message.item_info[0].message_strings,
            "483.700"
        );
        assert_eq!(unified_log.firehose[0].base_continous_time, 0);
        assert_eq!(unified_log.firehose[0].first_number_proc_id, 70);
        assert_eq!(unified_log.firehose[0].second_number_proc_id, 71);
        assert_eq!(unified_log.firehose[0].public_data_size, 4040);
        assert_eq!(unified_log.firehose[0].private_data_virtual_offset, 4096);
    }

    #[test]
    fn test_track_missing() {
        let first_proc_id = 1;
        let second_proc_id = 2;
        let time = 11;
        let test_firehose = Firehose::default();

        let missing_firehose =
            LogData::track_missing(first_proc_id, second_proc_id, time, test_firehose);
        assert_eq!(missing_firehose.first_number_proc_id, first_proc_id);
        assert_eq!(missing_firehose.second_number_proc_id, second_proc_id);
        assert_eq!(missing_firehose.base_continous_time, time);
    }

    #[test]
    fn test_add_missing() {
        let mut missing_unified_log_data_vec = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3",
        );

        let log_data = parse_log(&test_path.display().to_string()).unwrap();

        LogData::add_missing(
            &log_data.catalog_data[0],
            0,
            0,
            &log_data.header,
            &mut missing_unified_log_data_vec,
            &log_data.catalog_data[0].firehose[0],
        );
        assert_eq!(missing_unified_log_data_vec.header.len(), 1);
        assert_eq!(
            missing_unified_log_data_vec.header[0].boot_uuid,
            "80D194AF56A34C54867449D2130D41BB"
        );
        assert_eq!(missing_unified_log_data_vec.header[0].logd_pid, 42);
        assert_eq!(missing_unified_log_data_vec.catalog_data.len(), 1);
        assert_eq!(
            missing_unified_log_data_vec.catalog_data[0]
                .catalog
                .catalog_subsystem_strings_offset,
            848
        );
        assert_eq!(
            missing_unified_log_data_vec.catalog_data[0].firehose.len(),
            1
        );
        assert_eq!(
            missing_unified_log_data_vec.catalog_data[0].firehose[0].first_number_proc_id,
            45
        );
        assert_eq!(
            missing_unified_log_data_vec.catalog_data[0].firehose[0].second_number_proc_id,
            188
        );
    }
}
