use nom::number::complete::{be_u128, le_i64, le_u16, le_u32, le_u64};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

const TIMESYNC_BOOT_SIGNATURE: u16 = 0xbbb0;
const TIMESYNC_RECORD_SIGNATURE: u32 = 0x0020_7354;

/// A single timesync calibration record (40 bytes on disk).
///
/// Maps Mach continuous timestamps to wall-clock time (nanoseconds since UNIX epoch).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RawTimesyncRecord {
    pub kernel_time: u64,
    pub walltime: i64,
    pub timezone: u32,
    pub daylight_savings: u32,
}

impl RawTimesyncRecord {
    /// Parse a single 40-byte timesync record.
    ///
    /// Validates the 4-byte signature (`0x0020_7354`), skips the 4-byte unknown flags,
    /// then reads the time fields.
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Self> {
        let (input, signature) = le_u32(input)?;
        if signature != TIMESYNC_RECORD_SIGNATURE {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
        let (input, _unknown_flags) = le_u32(input)?;
        let (input, kernel_time) = le_u64(input)?;
        let (input, walltime) = le_i64(input)?;
        let (input, timezone) = le_u32(input)?;
        let (input, daylight_savings) = le_u32(input)?;

        Ok((
            input,
            RawTimesyncRecord {
                kernel_time,
                walltime,
                timezone,
                daylight_savings,
            },
        ))
    }
}

/// A boot session header with its associated timesync records.
#[derive(Debug, Clone, Serialize)]
pub struct RawTimesyncBoot {
    pub boot_uuid: Uuid,
    pub timebase_numerator: u32,
    pub timebase_denominator: u32,
    pub boot_time: i64,
    pub timezone_offset_mins: u32,
    pub daylight_savings: u32,
    pub records: Vec<RawTimesyncRecord>,
}

impl RawTimesyncBoot {
    /// Parse a 48-byte boot session header.
    ///
    /// Validates the 2-byte signature (`0xbbb0`), skips header size and unknown fields,
    /// then reads the boot session fields.
    /// The `records` vec starts empty — records are appended by [`parse_timesync_file`].
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], Self> {
        let (input, signature) = le_u16(input)?;
        if signature != TIMESYNC_BOOT_SIGNATURE {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
        let (input, _header_size) = le_u16(input)?;
        let (input, _unknown) = le_u32(input)?;
        let (input, boot_uuid_raw) = be_u128(input)?;
        let (input, timebase_numerator) = le_u32(input)?;
        let (input, timebase_denominator) = le_u32(input)?;
        let (input, boot_time) = le_i64(input)?;
        let (input, timezone_offset_mins) = le_u32(input)?;
        let (input, daylight_savings) = le_u32(input)?;

        Ok((
            input,
            RawTimesyncBoot {
                boot_uuid: Uuid::from_u128(boot_uuid_raw),
                timebase_numerator,
                timebase_denominator,
                boot_time,
                timezone_offset_mins,
                daylight_savings,
                records: Vec::new(),
            },
        ))
    }
}

/// Parse an entire timesync file into a map of boot UUID → boot session.
///
/// A timesync file is a sequence of boot headers interleaved with records.
/// Multiple boots can share a UUID — records are merged in that case.
pub fn parse_timesync_file(data: &[u8]) -> nom::IResult<&[u8], HashMap<Uuid, RawTimesyncBoot>> {
    let mut result: HashMap<Uuid, RawTimesyncBoot> = HashMap::new();
    let mut input = data;
    let mut current_boot = RawTimesyncBoot {
        boot_uuid: Uuid::nil(),
        timebase_numerator: 0,
        timebase_denominator: 0,
        boot_time: 0,
        timezone_offset_mins: 0,
        daylight_savings: 0,
        records: Vec::new(),
    };
    let mut has_boot = false;

    while !input.is_empty() {
        // Peek at the first 4 bytes to distinguish record vs boot header.
        // Record signature is a u32; boot signature is a u16 in the first 2 bytes.
        let (_, peek_u32) = le_u32(input)?;

        if peek_u32 == TIMESYNC_RECORD_SIGNATURE {
            let (remaining, record) = RawTimesyncRecord::parse(input)?;
            current_boot.records.push(record);
            input = remaining;
        } else {
            // Flush current boot before starting a new one
            if has_boot {
                if let Some(existing) = result.get_mut(&current_boot.boot_uuid) {
                    existing.records.append(&mut current_boot.records);
                } else {
                    result.insert(current_boot.boot_uuid, current_boot);
                }
            }
            let (remaining, boot) = RawTimesyncBoot::parse(input)?;
            current_boot = boot;
            has_boot = true;
            input = remaining;
        }
    }

    // Flush the last boot
    if has_boot {
        if let Some(existing) = result.get_mut(&current_boot.boot_uuid) {
            existing.records.append(&mut current_boot.records);
        } else {
            result.insert(current_boot.boot_uuid, current_boot);
        }
    }

    Ok((input, result))
}

/// Resolves continuous timestamps to wall-clock nanoseconds.
///
/// Wraps a `HashMap<Uuid, RawTimesyncBoot>` and provides the same
/// calculation as `TimesyncBoot::get_timestamp()`.
pub struct TimestampResolver {
    timesync_data: HashMap<Uuid, RawTimesyncBoot>,
}

impl TimestampResolver {
    pub fn new(timesync_data: HashMap<Uuid, RawTimesyncBoot>) -> Self {
        Self { timesync_data }
    }

    /// Convert an absolute continuous time to wall-clock nanoseconds (f64).
    ///
    /// - `boot_uuid`: from the tracev3 header
    /// - `absolute_continuous_time`: firehose base + entry delta
    /// - `preamble_time`: firehose chunk's `base_continuous_time` (0 = use boot time)
    pub fn resolve(
        &self,
        boot_uuid: &Uuid,
        absolute_continuous_time: u64,
        preamble_time: u64,
    ) -> f64 {
        let mut timesync_continuous_time: u64 = 0;
        let mut timesync_walltime: i64 = 0;
        let mut timebase_adjustment: f64 = 1.0;

        if let Some(boot) = self.timesync_data.get(boot_uuid) {
            if boot.timebase_numerator == 125 && boot.timebase_denominator == 3 {
                timebase_adjustment = 125.0 / 3.0;
            }

            if preamble_time == 0 {
                timesync_continuous_time = 0;
                timesync_walltime = boot.boot_time;
            }

            for record in &boot.records {
                if record.kernel_time > absolute_continuous_time {
                    if timesync_continuous_time == 0 && timesync_walltime == 0 {
                        timesync_continuous_time = record.kernel_time;
                        timesync_walltime = record.walltime;
                    }
                    break;
                }
                timesync_continuous_time = record.kernel_time;
                timesync_walltime = record.walltime;
            }
        }

        let continuous_time = (absolute_continuous_time as f64).mul_add(
            timebase_adjustment,
            -(timesync_continuous_time as f64) * timebase_adjustment,
        );
        continuous_time + timesync_walltime as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::helpers::tests::test_data_path;

    #[test]
    fn test_parse_timesync_record() -> anyhow::Result<()> {
        let test_data: [u8; 32] = [
            84, 115, 32, 0, 0, 0, 0, 0, 165, 196, 104, 252, 1, 0, 0, 0, 216, 189, 100, 108, 116,
            158, 131, 22, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (remaining, record) = RawTimesyncRecord::parse(&test_data).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(record.kernel_time, 8529691813);
        assert_eq!(record.walltime, 1622314513655447000);
        assert_eq!(record.timezone, 0);
        assert_eq!(record.daylight_savings, 0);
        Ok(())
    }

    #[test]
    fn test_parse_timesync_boot() -> anyhow::Result<()> {
        let test_data: [u8; 48] = [
            176, 187, 48, 0, 0, 0, 0, 0, 132, 91, 13, 213, 1, 96, 69, 62, 172, 224, 56, 118, 12,
            123, 92, 29, 1, 0, 0, 0, 1, 0, 0, 0, 168, 167, 19, 176, 114, 158, 131, 22, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        let (remaining, boot) = RawTimesyncBoot::parse(&test_data).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(
            boot.boot_uuid,
            Uuid::parse_str("845B0DD50160453EACE038760C7B5C1D")?
        );
        assert_eq!(boot.timebase_numerator, 1);
        assert_eq!(boot.timebase_denominator, 1);
        assert_eq!(boot.boot_time, 1622314506201049000);
        assert_eq!(boot.timezone_offset_mins, 0);
        assert_eq!(boot.daylight_savings, 0);
        assert!(boot.records.is_empty());
        Ok(())
    }

    #[test]
    fn test_parse_timesync_file() -> anyhow::Result<()> {
        let test_path = test_data_path()
            .join("system_logs_big_sur.logarchive/timesync/0000000000000002.timesync");
        let buffer = std::fs::read(test_path)?;

        let (_, timesync_data) = parse_timesync_file(&buffer).unwrap();
        assert_eq!(timesync_data.len(), 5);
        assert_eq!(
            timesync_data
                .get(&Uuid::parse_str("9A6A3124274A44B29ABF2BC9E4599B3B")?)
                .unwrap()
                .records
                .len(),
            5
        );
        Ok(())
    }

    /// Helper: collect timesync data from all .timesync files in a logarchive directory.
    fn collect_timesync_data(logarchive_path: &std::path::Path) -> HashMap<Uuid, RawTimesyncBoot> {
        let timesync_dir = logarchive_path.join("timesync");
        let mut all_data: HashMap<Uuid, RawTimesyncBoot> = HashMap::new();

        for entry in std::fs::read_dir(&timesync_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("timesync") {
                let buffer = std::fs::read(&path).unwrap();
                let (_, file_data) = parse_timesync_file(&buffer).unwrap();
                for (uuid, mut boot) in file_data {
                    if let Some(existing) = all_data.get_mut(&uuid) {
                        existing.records.append(&mut boot.records);
                    } else {
                        all_data.insert(uuid, boot);
                    }
                }
            }
        }
        all_data
    }

    #[test]
    fn test_resolve_timestamp() -> anyhow::Result<()> {
        let test_path = test_data_path().join("system_logs_big_sur.logarchive");
        let timesync_data = collect_timesync_data(&test_path);
        let resolver = TimestampResolver::new(timesync_data);

        let boot_uuid = Uuid::parse_str("A2A9017676CF421C84DC9BBD6263FEE7")?;
        let result = resolver.resolve(&boot_uuid, 2818326118, 1);
        assert_eq!(result, 1_642_304_803_060_379_000.0);
        Ok(())
    }

    #[test]
    fn test_resolve_arm_timestamp() -> anyhow::Result<()> {
        let test_path = test_data_path().join("system_logs_monterey.logarchive");
        let timesync_data = collect_timesync_data(&test_path);
        let resolver = TimestampResolver::new(timesync_data);

        let boot_uuid = Uuid::parse_str("3E12B435814B4C62918CEBC0826F06B8")?;
        let result = resolver.resolve(&boot_uuid, 2818326118, 1);
        assert_eq!(result, 1650767519086487000.0);
        Ok(())
    }

    #[test]
    fn test_resolve_arm_boot_time() -> anyhow::Result<()> {
        let test_path = test_data_path().join("system_logs_monterey.logarchive");
        let timesync_data = collect_timesync_data(&test_path);
        let resolver = TimestampResolver::new(timesync_data);

        let boot_uuid = Uuid::parse_str("3E12B435814B4C62918CEBC0826F06B8")?;
        let result = resolver.resolve(&boot_uuid, 9898326118, 0);
        assert_eq!(result, 1_650_767_813_342_574_600.0);
        Ok(())
    }
}
