use super::entry::{FirehoseActivityType, FirehoseLogType};
use super::flags::FirehoseFlags;
use super::item::{RawFirehoseItemData, parse_items_data, parse_trace_items};

// Re-export body types for convenience.
pub use super::activity::RawActivityBody;
pub use super::flags::RawFormatterFlags;
pub use super::loss::RawLossBody;
pub use super::nonactivity::RawNonActivityBody;
pub use super::signpost::RawSignpostBody;
pub use super::trace::RawTraceBody;

/// Dispatch enum for parsed firehose entry bodies.
#[derive(Debug, Clone, Copy)]
pub enum RawFirehoseBody<'a> {
    Activity(RawActivityBody<'a>),
    NonActivity(RawNonActivityBody<'a>),
    Signpost(RawSignpostBody<'a>),
    Trace(RawTraceBody<'a>),
    Loss(RawLossBody),
    Unknown(&'a [u8]),
}

impl<'a> RawFirehoseBody<'a> {
    /// Parse a firehose entry body by dispatching on the activity type.
    pub fn parse(
        data: &'a [u8],
        log_activity_type: FirehoseActivityType,
        flags: FirehoseFlags,
        log_type: FirehoseLogType,
    ) -> Result<Self, nom::Err<nom::error::Error<&'a [u8]>>> {
        match log_activity_type {
            FirehoseActivityType::Activity => {
                let (_, body) = RawActivityBody::parse(data, flags, log_type)?;
                Ok(Self::Activity(body))
            }
            FirehoseActivityType::NonActivity => {
                let (_, body) = RawNonActivityBody::parse(data, flags)?;
                Ok(Self::NonActivity(body))
            }
            FirehoseActivityType::Signpost => {
                let (_, body) = RawSignpostBody::parse(data, flags)?;
                Ok(Self::Signpost(body))
            }
            FirehoseActivityType::Trace => {
                let (_, body) = RawTraceBody::parse(data)?;
                Ok(Self::Trace(body))
            }
            FirehoseActivityType::Loss => {
                let (_, body) = RawLossBody::parse(data)?;
                Ok(Self::Loss(body))
            }
            FirehoseActivityType::Unknown => Ok(Self::Unknown(data)),
        }
    }

    /// Get `items_data` from standard (non-trace) body types.
    pub(crate) fn standard_items_data(&self) -> Option<&'a [u8]> {
        match self {
            Self::Activity(b) => Some(b.items_data),
            Self::NonActivity(b) => Some(b.items_data),
            Self::Signpost(b) => Some(b.items_data),
            _ => None,
        }
    }

    /// Parse items from this body, dispatching to the appropriate parser.
    ///
    /// - Activity / `NonActivity` / Signpost → standard item parsing
    /// - Trace → reversed big-endian numeric parsing
    /// - Loss / Unknown → `None`
    pub fn parse_items(&self, flags: FirehoseFlags) -> Option<RawFirehoseItemData<'a>> {
        if let Some(items_data) = self.standard_items_data() {
            return Some(
                parse_items_data(items_data, flags)
                    .map(|(_, data)| data)
                    .unwrap_or_else(|_| RawFirehoseItemData {
                        unknown_item: 0,
                        items: Vec::new(),
                        backtrace_data: None,
                    }),
            );
        }
        match self {
            Self::Trace(b) => Some(RawFirehoseItemData {
                unknown_item: 0,
                items: parse_trace_items(b.items_data),
                backtrace_data: None,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::RawFirehose;
    use super::*;

    #[test]
    fn test_activity_body_from_entry_test_data() -> anyhow::Result<()> {
        // Same test data as entry.rs test_iterate_entries: 3 Activity entries with flags=4.
        let test_data: &[u8] = &[
            1, 96, 0, 0, 0, 0, 0, 0, 152, 0, 0, 0, 0, 0, 0, 0, 133, 16, 0, 0, 0, 0, 0, 0, 157, 38,
            0, 0, 0, 0, 0, 0, 136, 0, 0, 16, 0, 0, 0, 2, 42, 188, 25, 14, 104, 4, 0, 0, 2, 1, 4, 0,
            240, 243, 53, 0, 176, 232, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 12, 0, 176, 249, 0, 0,
            0, 0, 0, 128, 163, 133, 51, 0, 0, 0, 0, 0, 2, 1, 4, 0, 32, 250, 53, 0, 177, 232, 0, 0,
            0, 0, 0, 0, 209, 67, 85, 0, 16, 0, 12, 0, 177, 249, 0, 0, 0, 0, 0, 128, 237, 115, 51,
            0, 0, 0, 0, 0, 2, 1, 4, 0, 48, 57, 126, 0, 179, 232, 0, 0, 0, 0, 0, 0, 40, 101, 197, 1,
            16, 0, 12, 0, 178, 249, 0, 0, 0, 0, 0, 128, 105, 67, 61, 0, 0, 0, 0, 0,
        ];

        // Skip 16-byte preamble, parse firehose
        let data = &test_data[16..];
        let (_, fh) = RawFirehose::parse(data).unwrap();
        let entries: Vec<_> = fh.entries().collect();
        assert_eq!(entries.len(), 3);

        for entry in &entries {
            let body = entry.parse_body().unwrap();
            let activity = match body {
                RawFirehoseBody::Activity(a) => a,
                other => panic!("expected Activity, got {other:?}"),
            };

            // flags=4, log_type=Info(0x01)
            // Not Useraction → activity_id present
            assert_eq!(activity.activity_id.unwrap().1, 0x80000000);
            // flags & 0x10 = 0 → no pid
            assert_eq!(activity.pid, None);
            // flags & 0x01 = 0 → no current_aid
            assert_eq!(activity.current_aid, None);
            // flags & 0x200 = 0 → no other_aid
            assert_eq!(activity.other_aid, None);
            // flags & 0xE = 0x4 = SHARED_CACHE
            assert!(activity.formatter.shared_cache);
            assert!(activity.items_data.is_empty());
        }

        // First entry specifics
        let first = match entries[0].parse_body().unwrap() {
            RawFirehoseBody::Activity(a) => a,
            _ => unreachable!(),
        };
        assert_eq!(first.activity_id, Some((63920, 0x80000000)));
        assert_eq!(first.pc_id, 0x003385A3);
        Ok(())
    }
}
