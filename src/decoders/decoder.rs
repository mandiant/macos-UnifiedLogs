// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::fmt;
use std::net::IpAddr;

use crate::{
    RcString,
    chunks::firehose::firehose_log::FirehoseItemInfo,
    decoders::{
        DecoderError,
        darwin::{Errno, errno_codes, format_permission, permission},
        dns::{
            DnsAcceptable, DnsAddRmv, DnsCounts, DnsDomainName, DnsHeader, DnsIdFlags, DnsMacAddr,
            DnsProtocol, DnsReason, DnsRecordType, DnsSvcbRecord, DnsYesNo, dns_acceptable,
            dns_addrmv, dns_counts, dns_getaddrinfo_opts, dns_idflags, dns_ip_addr, dns_protocol,
            dns_reason, dns_records, dns_yes_no, get_dns_mac_addr, get_domain_name,
            get_service_binding, parse_dns_header,
        },
        location::{
            ClientAuthorizationStatus, DaemonStatusType, LocationStateTrackerData,
            LocationTrackerState, SqliteError, SubharvesterIdentifier, client_authorization_status,
            client_manager_state_tracker_state, daemon_status_type, io_message,
            location_manager_state_tracker_state, sqlite_location, subharvester_identifier,
        },
        network::{SockaddrData, ipv_four, ipv_six, sockaddr},
        opendirectory::{
            MemberDetails, MemberIdType, OdError, SidDetails, errors, member_details,
            member_id_type, sid_details,
        },
        time::{LocalDateTime, parse_time},
        uuid::parse_uuid,
    },
    rc_string,
    util::format_uuid,
};
use uuid::Uuid;

pub enum Decoded {
    Error(RcString),
    Masked(RcString),
    UpBool(bool),
    LoBool(bool),
    Uuid(Uuid),
    Errno(Errno),
    OdError(OdError),
    MemberIdType(MemberIdType),
    MemberDetails(MemberDetails),
    SidDetails(SidDetails),
    ClientAuthorizationStatus(ClientAuthorizationStatus),
    DaemonStatusType(DaemonStatusType),
    SubharvesterIdentifier(SubharvesterIdentifier),
    SqliteError(SqliteError),
    LocationStateTrackerData(LocationStateTrackerData),
    LocationTrackerState(LocationTrackerState),
    IpAddr(IpAddr),
    SockaddrData(SockaddrData),
    LocalDateTime(LocalDateTime),
    DnsIdFlags(DnsIdFlags),
    DnsHeader(DnsHeader),
    DnsRecordType(DnsRecordType),
    DnsReason(DnsReason),
    DnsProtocol(DnsProtocol),
    DnsCounts(DnsCounts),
    DnsAddRmv(DnsAddRmv),
    DnsYesNo(DnsYesNo),
    DnsAcceptable(DnsAcceptable),
    IoMessage(&'static str),
    DnsGetAddrInfoOpts(&'static str),
    DnsDomainName(DnsDomainName),
    DnsMacAddr(DnsMacAddr),
    DnsSvcbRecord(DnsSvcbRecord),
    Permission(u8, u8, u8),
}

impl fmt::Display for Decoded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(value) | Self::Masked(value) => f.write_str(value.as_str()),
            Self::UpBool(value) => f.write_str(if *value { "NO" } else { "YES" }),
            Self::LoBool(value) => f.write_str(if *value { "false" } else { "true" }),
            Self::Uuid(value) => f.write_str(&format_uuid(*value)),
            Self::Errno(value) => write!(f, "{value}"),
            Self::OdError(value) => write!(f, "{value}"),
            Self::MemberIdType(value) => write!(f, "{value}"),
            Self::MemberDetails(value) => write!(f, "{value}"),
            Self::SidDetails(value) => write!(f, "{value}"),
            Self::ClientAuthorizationStatus(value) => write!(f, "{value}"),
            Self::DaemonStatusType(value) => write!(f, "{value}"),
            Self::SubharvesterIdentifier(value) => write!(f, "{value}"),
            Self::SqliteError(value) => write!(f, "{value}"),
            Self::LocationStateTrackerData(value) => write!(f, "{value}"),
            Self::LocationTrackerState(value) => write!(f, "{value}"),
            Self::IpAddr(value) => write!(f, "{value}"),
            Self::SockaddrData(value) => write!(f, "{value}"),
            Self::LocalDateTime(value) => write!(f, "{value}"),
            Self::DnsIdFlags(value) => write!(f, "{value}"),
            Self::DnsHeader(value) => write!(f, "{value}"),
            Self::DnsRecordType(value) => write!(f, "{value}"),
            Self::DnsReason(value) => write!(f, "{value}"),
            Self::DnsProtocol(value) => write!(f, "{value}"),
            Self::DnsCounts(value) => write!(f, "{value}"),
            Self::DnsAddRmv(value) => write!(f, "{value}"),
            Self::DnsYesNo(value) => write!(f, "{value}"),
            Self::DnsAcceptable(value) => write!(f, "{value}"),
            Self::IoMessage(value) | Self::DnsGetAddrInfoOpts(value) => f.write_str(value),
            Self::DnsDomainName(value) => write!(f, "{value}"),
            Self::DnsMacAddr(value) => write!(f, "{value}"),
            Self::DnsSvcbRecord(value) => write!(f, "{value}"),
            Self::Permission(user, owner, group) => {
                f.write_str(&format_permission(*user, *owner, *group))
            }
        }
    }
}

impl Decoded {
    pub fn to_rc_string(&self) -> RcString {
        rc_string!(self.to_string())
    }
}

/// Check if we support one of Apple's custom logging objects.
/// Returns `None` if no decoder matched (the common case for plain `%d`/`%s`).
pub(crate) fn check_objects(
    format_string: &str,
    message_values: &[FirehoseItemInfo],
    item_type: u8,
    item_index: usize,
) -> Option<Decoded> {
    let mut index = item_index;
    const PRECISION_ITEM: u8 = 0x12;

    // Increment index get the actual firehose item data
    if item_type == PRECISION_ITEM {
        index += 1;
        if index > message_values.len() {
            return Some(Decoded::Error(rc_string!(format!(
                "Index out of bounds for FirehoseItemInfo Vec. Got adjusted index {}, Vec size is {}. This should not have happened",
                index,
                message_values.len()
            ))));
        }
    }

    const MASKED_HASH_TYPE: u8 = 0xf2;
    // Check if the log value is hashed or marked private
    let message_cow = message_values[index].message_strings.as_cow();
    if (format_string.contains("mask.hash") && message_values[index].item_type == MASKED_HASH_TYPE)
        || message_cow.as_ref() == "<private>"
    {
        return Some(Decoded::Masked(
            message_values[index].message_strings.to_rc_string(),
        ));
    }

    let message_strings = message_cow.as_ref();

    // Check if log value contains one the supported decoders
    let message_value = to_decoded_value(format_string, message_strings);

    match message_value {
        Ok(Some(value)) => Some(value),
        Ok(None) => None,
        Err(e) => {
            log::error!("[macos-unifiedlogs] Failed to decode log object. Error: {e:?}");
            Some(Decoded::Error(rc_string!(format!("Decoder error: {e:?}"))))
        }
    }
}

fn to_decoded_value<'a>(
    format_string: &'a str,
    message_strings: &'a str,
) -> Result<Option<Decoded>, DecoderError<'a>> {
    let decoded = if format_string.contains("BOOL") {
        Decoded::UpBool(message_strings == "0")
    } else if format_string.contains("bool") {
        Decoded::LoBool(message_strings == "0")
    } else if format_string.contains("uuid_t") {
        Decoded::Uuid(parse_uuid(&message_strings)?)
    } else if format_string.contains("darwin.errno") {
        Decoded::Errno(errno_codes(&message_strings))
    } else if format_string.contains("darwin.mode") {
        permission(&message_strings)
    } else if format_string.contains("odtypes:ODError") {
        Decoded::OdError(errors(&message_strings))
    } else if format_string.contains("odtypes:mbridtype") {
        Decoded::MemberIdType(member_id_type(&message_strings))
    } else if format_string.contains("odtypes:mbr_details") {
        Decoded::MemberDetails(member_details(&message_strings)?)
    } else if format_string.contains("odtypes:nt_sid_t") {
        Decoded::SidDetails(sid_details(&message_strings)?)
    } else if format_string.contains("location:CLClientAuthorizationStatus") {
        Decoded::ClientAuthorizationStatus(client_authorization_status(&message_strings)?)
    } else if format_string.contains("location:CLDaemonStatus_Type::Reachability") {
        Decoded::DaemonStatusType(daemon_status_type(&message_strings)?)
    } else if format_string.contains("location:CLSubHarvesterIdentifier") {
        Decoded::SubharvesterIdentifier(subharvester_identifier(&message_strings)?)
    } else if format_string.contains("location:SqliteResult") {
        Decoded::SqliteError(sqlite_location(&message_strings)?)
    } else if format_string.contains("location:_CLClientManagerStateTrackerState") {
        Decoded::LocationStateTrackerData(client_manager_state_tracker_state(&message_strings)?)
    } else if format_string.contains("location:_CLLocationManagerStateTrackerState") {
        Decoded::LocationTrackerState(location_manager_state_tracker_state(&message_strings)?)
    } else if format_string.contains("network:in6_addr") {
        Decoded::IpAddr(ipv_six(&message_strings)?.into())
    } else if format_string.contains("network:in_addr") {
        Decoded::IpAddr(ipv_four(&message_strings)?.into())
    } else if format_string.contains("network:sockaddr") {
        Decoded::SockaddrData(sockaddr(&message_strings)?)
    } else if format_string.contains("time_t") {
        Decoded::LocalDateTime(parse_time(&message_strings)?)
    } else if format_string.contains("mdns:dns.idflags") {
        Decoded::DnsIdFlags(dns_idflags(&message_strings)?)
    } else if format_string.contains("mdns:dnshdr") {
        Decoded::DnsHeader(parse_dns_header(&message_strings)?)
    } else if format_string.contains("mdns:rrtype") {
        Decoded::DnsRecordType(dns_records(&message_strings)?)
    } else if format_string.contains("mdns:nreason") {
        Decoded::DnsReason(dns_reason(&message_strings)?)
    } else if format_string.contains("mdns:protocol") {
        Decoded::DnsProtocol(dns_protocol(&message_strings)?)
    } else if format_string.contains("mdns:dns.counts") {
        Decoded::DnsCounts(dns_counts(&message_strings)?)
    } else if format_string.contains("mdns:addrmv") {
        Decoded::DnsAddRmv(dns_addrmv(&message_strings))
    } else if format_string.contains("mdns:yesno") {
        Decoded::DnsYesNo(dns_yes_no(&message_strings))
    } else if format_string.contains("mdns:acceptable") {
        Decoded::DnsAcceptable(dns_acceptable(&message_strings))
    } else if format_string.contains("location:IOMessage") {
        Decoded::IoMessage(io_message(&message_strings)?)
    } else if format_string.contains("mdns:gaiopts") {
        Decoded::DnsGetAddrInfoOpts(dns_getaddrinfo_opts(&message_strings)?)
    } else if format_string.contains("mdnsresponder:domain_name") {
        Decoded::DnsDomainName(get_domain_name(&message_strings)?)
    } else if format_string.contains("mdnsresponder:mac_addr") {
        Decoded::DnsMacAddr(get_dns_mac_addr(&message_strings)?)
    } else if format_string.contains("mdnsresponder:ip_addr") {
        Decoded::IpAddr(dns_ip_addr(&message_strings)?)
    } else if format_string.contains("mdns:rd.svcb") {
        Decoded::DnsSvcbRecord(get_service_binding(&message_strings)?)
    } else {
        return Ok(None);
    };

    Ok(Some(decoded))
}

#[cfg(test)]
mod tests {
    use super::check_objects;
    use super::*;
    use crate::chunks::firehose::firehose_log::{FirehoseItemInfo, FirehoseItemValue};

    #[test]
    fn test_check_objects_lowercase_bool() {
        let test_format = "%{bool}d";
        let test_item_info = FirehoseItemInfo {
            message_strings: FirehoseItemValue::Str(rc_string!("1")),
            item_type: 0,
            item_size: 4,
        };
        let test_type = 0;
        let test_index = 0;

        let results = check_objects(test_format, &[test_item_info], test_type, test_index);
        assert_eq!(results.unwrap().to_rc_string().as_str(), "true")
    }

    #[test]
    fn test_check_objects_uppercase_bool() {
        let test_format = "%{BOOL}d";
        let test_item_info = FirehoseItemInfo {
            message_strings: FirehoseItemValue::Str(rc_string!("1")),
            item_type: 0,
            item_size: 4,
        };
        let test_type = 0;
        let test_index = 0;

        let results = check_objects(test_format, &[test_item_info], test_type, test_index);
        assert_eq!(results.unwrap().to_rc_string().as_str(), "YES")
    }

    #[test]
    fn test_odtypes() {
        let test_format = "%{odtypes:mbr_details}d";
        let test_item_info = FirehoseItemInfo {
            message_strings: FirehoseItemValue::Str(rc_string!("I/7///8vTG9jYWwvRGVmYXVsdAA=")),
            item_type: 50,
            item_size: 0,
        };
        let test_type = 50; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &[test_item_info], test_type, test_index);
        assert_eq!(
            results.unwrap().to_rc_string().as_str(),
            "user: -2@/Local/Default"
        );
    }

    #[test]
    fn test_check_objects_uuid() {
        let test_format = "%{public,uuid_t}.16P";
        let test_item_info = FirehoseItemInfo {
            message_strings: FirehoseItemValue::Str(rc_string!("hZV+HTbETtKGqAZXvN3ikw==")),
            item_type: 50,
            item_size: 16,
        };
        let test_type = 50; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &[test_item_info], test_type, test_index);
        assert_eq!(
            results.unwrap().to_rc_string().as_str(),
            "85957E1D36C44ED286A80657BCDDE293"
        )
    }

    #[test]
    fn test_private() {
        let test_format = "%{public,uuid_t}.16P";
        let test_item_info = FirehoseItemInfo {
            message_strings: FirehoseItemValue::Str(rc_string!("<private>")),
            item_type: 50,
            item_size: 16,
        };
        let test_type = 50; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &[test_item_info], test_type, test_index);
        assert_eq!(results.unwrap().to_rc_string().as_str(), "<private>")
    }

    #[test]
    fn test_hash() {
        let test_format = "%{public,mask.hash}.16P";
        let test_item_info = FirehoseItemInfo {
            message_strings: FirehoseItemValue::Str(rc_string!("hash")),
            item_type: 242,
            item_size: 16,
        };
        let test_type = 242; // 0x32
        let test_index = 0;

        let results = check_objects(test_format, &[test_item_info], test_type, test_index);
        assert_eq!(results.unwrap().to_rc_string().as_str(), "hash")
    }
}
