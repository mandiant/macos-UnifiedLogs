// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use std::fmt;
use std::net::IpAddr;

use super::{
  DecoderError,
  darwin::{Errno, errno_codes, format_permission, permission},
  dns::{
    DnsAcceptable, DnsAddRmv, DnsCounts, DnsDomainName, DnsHeader, DnsIdFlags, DnsMacAddr, DnsProtocol, DnsReason, DnsRecordType,
    DnsSvcbRecord, DnsYesNo, dns_acceptable, dns_addrmv, dns_counts, dns_getaddrinfo_opts, dns_idflags, dns_ip_addr, dns_protocol,
    dns_reason, dns_records, dns_yes_no, get_dns_mac_addr, get_domain_name, get_service_binding, parse_dns_header,
  },
  location::{
    ClientAuthorizationStatus, DaemonStatusType, LocationStateTrackerData, LocationTrackerState, SqliteError, SubharvesterIdentifier,
    client_authorization_status, client_manager_state_tracker_state, daemon_status_type, io_message, location_manager_state_tracker_state,
    sqlite_location, subharvester_identifier,
  },
  network::{SockaddrData, ipv_four, ipv_six, sockaddr},
  opendirectory::{MemberDetails, MemberIdType, OdError, SidDetails, errors, member_details, member_id_type, sid_details},
  time::{LocalDateTime, parse_time},
  uuid::parse_uuid,
};
use crate::rewrite::helpers::format_uuid;
use uuid::Uuid;

pub enum Decoded {
  Error(String),
  Masked(String),
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
      Self::Error(value) | Self::Masked(value) => f.write_str(value),
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
      Self::Permission(user, owner, group) => f.write_str(&format_permission(*user, *owner, *group)),
    }
  }
}

pub(crate) fn to_decoded_value<'a>(format_string: &'a str, message_strings: &'a str) -> Result<Option<Decoded>, DecoderError<'a>> {
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
