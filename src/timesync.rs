// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::error;
use nom::Needed;
use nom::bytes::complete::take;
use nom::number::complete::{be_u128, le_i64, le_u16, le_u32, le_u64};
use serde::{Deserialize, Serialize};
use std::mem::size_of;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct TimesyncBoot {
    pub signature: u16,
    pub header_size: u16,
    pub unknown: u32,
    pub boot_uuid: String,
    pub timebase_numerator: u32,
    pub timebase_denominator: u32,
    pub boot_time: i64, // Number of nanoseconds since UNIXEPOCH
    pub timezone_offset_mins: u32,
    pub daylight_savings: u32, // 0 is no DST, 1 is DST
    pub timesync: Vec<Timesync>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Timesync {
    // Timestamps are in UTC
    pub signature: u32,
    pub unknown_flags: u32,
    pub kernel_time: u64, // Mach continuous timestamp
    pub walltime: i64,    // Number of nanoseconds since UNIXEPOCH
    pub timezone: u32,
    pub daylight_savings: u32, // 0 is no DST, 1 is DST
}

impl TimesyncBoot {
    /// Parse the Unified Log timesync files
    pub fn parse_timesync_data(data: &[u8]) -> nom::IResult<&[u8], Vec<TimesyncBoot>> {
        let mut timesync_data: Vec<TimesyncBoot> = Vec::new();
        let mut input = data;

        let mut timesync_boot = TimesyncBoot::default();

        while !input.is_empty() {
            let (_, signature) = take(size_of::<u32>())(input)?;
            let (_, timesync_signature) = le_u32(signature)?;

            let timesync_sig: u32 = 0x207354;
            if timesync_signature == timesync_sig {
                let (timesync_input, timesync) = TimesyncBoot::parse_timesync(input)?;
                timesync_boot.timesync.push(timesync);
                input = timesync_input;
            } else {
                if timesync_boot.signature != 0 {
                    timesync_data.push(timesync_boot);
                }
                let (timesync_input, timesync_boot_data) =
                    TimesyncBoot::parse_timesync_boot(input)?;
                timesync_boot = timesync_boot_data;
                input = timesync_input;
            }
        }
        timesync_data.push(timesync_boot);

        Ok((input, timesync_data))
    }

    fn parse_timesync_boot(data: &[u8]) -> nom::IResult<&[u8], TimesyncBoot> {
        let (input, signature) = take(size_of::<u16>())(data)?;
        let (_, timesync_signature) = le_u16(signature)?;

        let expected_boot_signature = 0xbbb0;
        if expected_boot_signature != timesync_signature {
            error!(
                "[macos-unifiedlogs] Incorrect Timesync boot header signature. Expected {}. Got: {}",
                expected_boot_signature, timesync_signature
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let (input, header_size) = take(size_of::<u16>())(input)?;
        let (input, unknown) = take(size_of::<u32>())(input)?;
        let (input, boot_uuid) = take(size_of::<u128>())(input)?;
        let (input, timebase_numerator) = take(size_of::<u32>())(input)?;
        let (input, timebase_denominator) = take(size_of::<u32>())(input)?;
        let (input, boot_time) = take(size_of::<i64>())(input)?;
        let (input, timezone_offset_mins) = take(size_of::<u32>())(input)?;
        let (input, daylight_savings) = take(size_of::<u32>())(input)?;

        let (_, timesync_header_size) = le_u16(header_size)?;
        let (_, timesync_unknown) = le_u32(unknown)?;
        let (_, timesync_boot_uuid) = be_u128(boot_uuid)?;
        let (_, timesync_timebase_numerator) = le_u32(timebase_numerator)?;
        let (_, timesync_timebase_denominator) = le_u32(timebase_denominator)?;
        let (_, timesync_boot_time) = le_i64(boot_time)?;
        let (_, timesync_timezone_offset_mins) = le_u32(timezone_offset_mins)?;
        let (_, timesync_daylight_savings) = le_u32(daylight_savings)?;

        let timesync_boot = TimesyncBoot {
            signature: timesync_signature,
            header_size: timesync_header_size,
            unknown: timesync_unknown,
            boot_uuid: format!("{:X}", timesync_boot_uuid),
            timebase_numerator: timesync_timebase_numerator,
            timebase_denominator: timesync_timebase_denominator,
            boot_time: timesync_boot_time,
            timezone_offset_mins: timesync_timezone_offset_mins,
            daylight_savings: timesync_daylight_savings,
            timesync: Vec::new(),
        };
        Ok((input, timesync_boot))
    }

    fn parse_timesync(data: &[u8]) -> nom::IResult<&[u8], Timesync> {
        let mut timesync = Timesync {
            signature: 0,
            unknown_flags: 0,
            kernel_time: 0,
            walltime: 0,
            timezone: 0,
            daylight_savings: 0,
        };
        let (input, signature) = take(size_of::<u32>())(data)?;
        let (_, timesync_signature) = le_u32(signature)?;

        let expected_record_signature = 0x207354;
        if expected_record_signature != timesync_signature {
            error!(
                "[macos-unifiedlogs] Incorrect Timesync record header signature. Expected {}. Got: {}",
                expected_record_signature, timesync_signature
            );
            return Err(nom::Err::Incomplete(Needed::Unknown));
        }

        let (input, unknown_flags) = take(size_of::<u32>())(input)?;
        let (input, kernel_time) = take(size_of::<u64>())(input)?;
        let (input, walltime) = take(size_of::<i64>())(input)?;
        let (input, timezone) = take(size_of::<u32>())(input)?;
        let (input, daylight_savings) = take(size_of::<u32>())(input)?;

        let (_, timesync_unknown_flags) = le_u32(unknown_flags)?;
        let (_, timesync_kernel_time) = le_u64(kernel_time)?;
        let (_, timesync_walltime) = le_i64(walltime)?;
        let (_, timesync_timezone) = le_u32(timezone)?;
        let (_, timesync_daylight_savings) = le_u32(daylight_savings)?;

        timesync.signature = timesync_signature;
        timesync.unknown_flags = timesync_unknown_flags;
        timesync.kernel_time = timesync_kernel_time;
        timesync.walltime = timesync_walltime;
        timesync.timezone = timesync_timezone;
        timesync.daylight_savings = timesync_daylight_savings;

        Ok((input, timesync))
    }

    /// Calculate timestamp for firehose log entry
    pub fn get_timestamp(
        timesync_data: &[TimesyncBoot],
        boot_uuid: &str,
        firehose_log_delta_time: u64,
        firehose_preamble_time: u64,
    ) -> f64 {
        /*  Timestamp calculation logic:
            Firehose Log entry timestamp is calculated by using firehose_preamble_time, firehose.continous_time_delta, and timesync timestamps
            Firehose log header/preample contains a base timestamp
              Ex: Firehose header base time is 2022-01-01 00:00:00
            All log entries following the header are continous from that base. EXCEPT when the base time is zero. If the base time is zero the TimeSync boot record boot time is used (boot time)
              Ex: Firehose log entry time is +60 seconds
            Timestamp would be 2022-01-01 00:01:00

            (firehose_log_entry_continous_time = firehose.continous_time_delta | ((firehose.continous_time_delta_upper) << 32))
            firehose_log_delta_time = firehose_preamble_time + firehose_log_entry_continous_time

            Get all timesync boot records if timesync uuid equals boot uuid in tracev3 header data

            Loop through all timesync records from matching boot uuid until timesync cont_time/kernel time is greater than firehose_preamble_time
            If firehose_header_time equals zero. Then the Timesync header walltime is used (the Timesync header cont_time/kernel time is then always zero)
            Subtract timesync_cont_time/kernel time from firehose_log_delta_time
            IF APPLE SILICON (ARM) is the architecture, then we need to mupltiple timesync_cont_time and firehose_log_delta_time by the timebase 125.0/3.0 to get the nanocsecond representation

           Add results to timesync_walltime (unix epoch in nanoseconds)
           Final results is unix epoch timestamp in nano seconds
        */

        let mut timesync_continous_time = 0;
        let mut timesync_walltime = 0;

        let mut larger_time = false;

        // Apple Intel uses 1/1 as the timebase
        let mut timebase_adjustment = 1.0;
        for timesync in timesync_data {
            if boot_uuid != timesync.boot_uuid {
                continue;
            }

            if timesync.timebase_numerator == 125 && timesync.timebase_denominator == 3 {
                // For Apple Silicon (ARM) we need to adjust the mach time by multiplying by 125.0/3.0 to get the accurate nanosecond count
                timebase_adjustment = 125.0 / 3.0;
            }

            // A preamble time of 0 means we need to use the timesync header boot time as our minimum value.
            // We also set the timesync_continous_time to  zero
            if firehose_preamble_time == 0 {
                timesync_continous_time = 0;
                timesync_walltime = timesync.boot_time;
            }
            for timesync_record in &timesync.timesync {
                if timesync_record.kernel_time > firehose_log_delta_time {
                    if timesync_continous_time == 0 && timesync_walltime == 0 {
                        timesync_continous_time = timesync_record.kernel_time;
                        timesync_walltime = timesync_record.walltime;
                    }
                    larger_time = true;
                    break;
                }

                timesync_continous_time = timesync_record.kernel_time;
                timesync_walltime = timesync_record.walltime;
            }
            // We should only break once we encountered a timesync_record.kernel_time greater than the firehose_log_delta_time
            if larger_time {
                break;
            }
        }

        let continous_time = (firehose_log_delta_time as f64).mul_add(
            timebase_adjustment,
            -(timesync_continous_time as f64) * timebase_adjustment,
        );
        continous_time + timesync_walltime as f64
    }
}

#[cfg(test)]
mod tests {
    use crate::filesystem::LogarchiveProvider;
    use crate::parser::collect_timesync;
    use crate::timesync::TimesyncBoot;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn test_parse_timesync_data() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(
            "tests/test_data/system_logs_big_sur.logarchive/timesync/0000000000000002.timesync",
        );

        let mut open = File::open(test_path).unwrap();
        let mut buffer = Vec::new();
        open.read_to_end(&mut buffer).unwrap();

        let (_, timesync_data) = TimesyncBoot::parse_timesync_data(&buffer).unwrap();
        assert_eq!(timesync_data.len(), 5);
        assert_eq!(timesync_data[0].timesync.len(), 5);
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_timesync_bad_boot_header() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/Bad Data/Timesync/Bad_Boot_header_0000000000000002.timesync");

        let mut open = File::open(test_path).unwrap();
        let mut buffer = Vec::new();
        open.read_to_end(&mut buffer).unwrap();

        let (_, _) = TimesyncBoot::parse_timesync_data(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_timesync_bad_record_header() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path
            .push("tests/test_data/Bad Data/Timesync/Bad_Record_header_0000000000000002.timesync");

        let mut open = File::open(test_path).unwrap();
        let mut buffer = Vec::new();
        open.read_to_end(&mut buffer).unwrap();

        let (_, _) = TimesyncBoot::parse_timesync_data(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_timesync_bad_content() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/Timesync/Bad_content_0000000000000002.timesync");

        let mut open = File::open(test_path).unwrap();
        let mut buffer = Vec::new();
        open.read_to_end(&mut buffer).unwrap();

        let (_, _) = TimesyncBoot::parse_timesync_data(&buffer).unwrap();
    }

    #[test]
    #[should_panic(expected = "Incomplete(Unknown)")]
    fn test_timesync_bad_file() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/Bad Data/Timesync/BadFile.timesync");

        let mut open = File::open(test_path).unwrap();
        let mut buffer = Vec::new();
        open.read_to_end(&mut buffer).unwrap();

        let (_, _) = TimesyncBoot::parse_timesync_data(&buffer).unwrap();
    }

    #[test]
    fn test_timesync() {
        let test_data = [
            84, 115, 32, 0, 0, 0, 0, 0, 165, 196, 104, 252, 1, 0, 0, 0, 216, 189, 100, 108, 116,
            158, 131, 22, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (_, timesync) = TimesyncBoot::parse_timesync(&test_data).unwrap();
        assert_eq!(timesync.signature, 0x207354);
        assert_eq!(timesync.unknown_flags, 0);
        assert_eq!(timesync.kernel_time, 8529691813);
        assert_eq!(timesync.walltime, 1622314513655447000);
        assert_eq!(timesync.timezone, 0);
        assert_eq!(timesync.daylight_savings, 0);
    }

    #[test]
    fn test_timesync_boot() {
        let test_data = [
            176, 187, 48, 0, 0, 0, 0, 0, 132, 91, 13, 213, 1, 96, 69, 62, 172, 224, 56, 118, 12,
            123, 92, 29, 1, 0, 0, 0, 1, 0, 0, 0, 168, 167, 19, 176, 114, 158, 131, 22, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let (_, timesync_boot) = TimesyncBoot::parse_timesync_boot(&test_data).unwrap();
        assert_eq!(timesync_boot.signature, 0xbbb0);
        assert_eq!(timesync_boot.header_size, 48);
        assert_eq!(timesync_boot.unknown, 0);
        assert_eq!(timesync_boot.boot_uuid, "845B0DD50160453EACE038760C7B5C1D");
        assert_eq!(timesync_boot.timebase_numerator, 1);
        assert_eq!(timesync_boot.timebase_denominator, 1);
        assert_eq!(timesync_boot.boot_time, 1622314506201049000);
        assert_eq!(timesync_boot.timezone_offset_mins, 0);
        assert_eq!(timesync_boot.daylight_savings, 0);
    }

    #[test]
    fn test_get_timestamp() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_big_sur.logarchive");
        let provider = LogarchiveProvider::new(test_path.as_path());

        let timesync_data = collect_timesync(&provider).unwrap();

        let boot_uuid = "A2A9017676CF421C84DC9BBD6263FEE7";
        let firehose_preamble_continous_time = 2818326118;

        let results = TimesyncBoot::get_timestamp(
            &timesync_data,
            boot_uuid,
            firehose_preamble_continous_time,
            1,
        );
        assert_eq!(results, 1_642_304_803_060_379_000.0);
    }

    #[test]
    fn test_get_arm_timestamp() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_monterey.logarchive");
        let provider = LogarchiveProvider::new(test_path.as_path());

        let timesync_data = collect_timesync(&provider).unwrap();

        let boot_uuid = "3E12B435814B4C62918CEBC0826F06B8";
        let firehose_preamble_continous_time = 2818326118;

        let results = TimesyncBoot::get_timestamp(
            &timesync_data,
            boot_uuid,
            firehose_preamble_continous_time,
            1,
        );
        assert_eq!(results, 1650767519086487000.0);
    }

    #[test]
    fn test_get_arm_timestamp_use_boot_time() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/system_logs_monterey.logarchive/timesync");

        let provider = LogarchiveProvider::new(test_path.as_path());

        let timesync_data = collect_timesync(&provider).unwrap();

        let boot_uuid = "3E12B435814B4C62918CEBC0826F06B8";
        let firehose_preamble_continous_time = 9898326118;

        let results = TimesyncBoot::get_timestamp(
            &timesync_data,
            boot_uuid,
            firehose_preamble_continous_time,
            0,
        );
        assert_eq!(results, 1_650_767_813_342_574_600.0);
    }
}
