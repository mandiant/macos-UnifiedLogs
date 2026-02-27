// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::{
    DecoderError,
    network::{get_ip_four, get_ip_six},
};
use crate::util::{decode_standard, extract_string, extract_string_size};
use byteorder::{BigEndian, WriteBytesExt};
use log::error;
use nom::{
    IResult, Parser,
    bytes::complete::take,
    combinator::{iterator, map, map_parser, verify},
    error::ErrorKind,
    multi::fold_many0,
    number::complete::{be_u8, be_u16, be_u32, be_u128, le_u32},
};
use std::{
    fmt::{Display, Write},
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// Parse the DNS header
pub(crate) fn parse_dns_header(data: &str) -> Result<DnsHeader, DecoderError<'_>> {
    let decoded_data = decode_standard(data).map_err(|_| DecoderError::Parse {
        input: data.as_bytes(),
        parser_name: "dns header",
        message: "Failed to base64 decode DNS header details",
    })?;

    let (_, message) = get_dns_header(&decoded_data).map_err(|_| DecoderError::Parse {
        input: data.as_bytes(),
        parser_name: "dns header",
        message: "Failed to parse DNS header details",
    })?;

    Ok(message)
}

fn remove_err_offset(
    error_with_offset: nom::Err<nom::error::Error<(&[u8], usize)>>,
) -> nom::Err<nom::error::Error<&[u8]>> {
    use nom::Err;
    match error_with_offset {
        Err::Error(e) => Err::Error(nom::error::Error {
            input: e.input.0,
            code: e.code,
        }),
        Err::Failure(e) => Err::Failure(nom::error::Error {
            input: e.input.0,
            code: e.code,
        }),
        Err::Incomplete(e) => Err::Incomplete(e),
    }
}

pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub decoded_flags: DnsFlags,
    pub counts: DnsCounts,
}

impl Display for DnsHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Query ID: {:#X?}, Flags: {:#X?} {}, {}",
            self.id, self.flags, self.decoded_flags, self.counts
        )
    }
}

/// Get the DNS header data
fn get_dns_header(input: &[u8]) -> IResult<&[u8], DnsHeader> {
    let (input, id) = be_u16(input)?;

    let (input, flag_data) = take(size_of::<u16>())(input)?;
    let ((_, _), decoded_flags) = get_dns_flags(flag_data).map_err(remove_err_offset)?;
    let (_, flags) = be_u16(flag_data)?;

    let (input, counts) = parse_counts(input)?;

    Ok((
        input,
        DnsHeader {
            id,
            flags,
            decoded_flags,
            counts,
        },
    ))
}

pub struct DnsFlags {
    pub query: u8,
    pub opcode: u8,
    pub authoritative_flag: u8,
    pub truncation_flag: u8,
    pub recursion_desired: u8,
    pub recursion_available: u8,
    pub _reserved: u8,
    pub response_code: u8,
}

impl Display for DnsFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opcode_message = match self.opcode {
            0 => "QUERY",
            1 => "IQUERY",
            2 => "STATUS",
            3 => "RESERVED",
            4 => "NOTIFY",
            5 => "UPDATE",
            _ => "UNKNOWN OPCODE",
        };

        let response_message = match self.response_code {
            0 => "No Error",
            1 => "Format Error",
            2 => "Server Failure",
            3 => "NX Domain",
            4 => "Not Implemented",
            5 => "Refused",
            6 => "YX Domain",
            7 => "YX RR Set",
            8 => "NX RR Set",
            9 => "Not Auth",
            10 => "Not Zone",
            _ => "Unknown Response Code",
        };

        let Self {
            query,
            authoritative_flag,
            truncation_flag,
            recursion_desired,
            recursion_available,
            ..
        } = self;

        write!(
            f,
            "Opcode: {opcode_message},\n    Query Type: {query},\n    Authoritative Answer Flag: {authoritative_flag},\n    Truncation Flag: {truncation_flag},\n    Recursion Desired: {recursion_desired},\n    Recursion Available: {recursion_available},\n    Response Code: {response_message}",
        )
    }
}

/// Parse the DNS bit flags
fn get_dns_flags(input: &[u8]) -> IResult<(&[u8], usize), DnsFlags> {
    // https://en.wikipedia.org/wiki/Domain_Name_System#DNS_message_format
    const QR: usize = 1;
    const OPCODE: usize = 4;
    const AA: usize = 1;
    const TC: usize = 1;
    const RD: usize = 1;
    const RA: usize = 1;
    const Z: usize = 3;
    const RCODE: usize = 4;

    type Ret<'a> = ((&'a [u8], usize), u8);
    use nom::bits::complete::take as bits;
    // Have to work with bits instead of bytes for the DNS flags
    let ((input, offset), query): Ret<'_> = bits(QR)((input, 0))?;
    let ((input, offset), opcode): Ret<'_> = bits(OPCODE)((input, offset))?;
    let ((input, offset), authoritative_flag): Ret<'_> = bits(AA)((input, offset))?;
    let ((input, offset), truncation_flag): Ret<'_> = bits(TC)((input, offset))?;
    let ((input, offset), recursion_desired): Ret<'_> = bits(RD)((input, offset))?;
    let ((input, offset), recursion_available): Ret<'_> = bits(RA)((input, offset))?;
    let ((input, offset), _reserved): Ret<'_> = bits(Z)((input, offset))?;
    let ((input, _), response_code): Ret<'_> = bits(RCODE)((input, offset))?;

    let flags = DnsFlags {
        query,
        opcode,
        authoritative_flag,
        truncation_flag,
        recursion_desired,
        recursion_available,
        _reserved,
        response_code,
    };

    // why 0 ?? to be able to throw with `?` in the previous lines
    Ok(((input, 0), flags))
}

pub struct DnsDomainName(pub String);

impl Display for DnsDomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Base64 decode the domain name. This is normally masked, but may be shown if private data is enabled
pub(crate) fn get_domain_name(input: &str) -> Result<DnsDomainName, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns domain name",
        message: "Failed to base64 decode DNS name details",
    })?;

    let (_, results) = extract_string(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns domain name",
        message: "Failed to extract domain name from logs",
    })?;

    let mut clean_domain = String::new();
    let non_domain_chars = ['\n', '\t', '\r'];
    for unicode in results.chars() {
        // skip non-domain characters and replace with '.'
        if non_domain_chars.contains(&unicode) || format!("{unicode:?}").contains("\\u{") {
            clean_domain.push('.');
            continue;
        }
        clean_domain.push_str(&String::from(unicode));
    }
    Ok(DnsDomainName(clean_domain))
}

pub enum DnsSvcbRecord {
    Url(String),
    Rdata {
        id: u16,
        alpn: DnsSvcbAlpn,
        ip_hints: DnsSvcbIpHints,
    },
}

impl Display for DnsSvcbRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(url) => f.write_str(url),
            Self::Rdata { id, alpn, ip_hints } => {
                write!(f, "rdata: {id} . {alpn} {ip_hints}")
            }
        }
    }
}

pub struct DnsSvcbAlpn(pub Vec<String>);

impl Display for DnsSvcbAlpn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("alpn=")?;
        for entry in &self.0 {
            write!(f, "{entry},")?;
        }
        Ok(())
    }
}

pub struct DnsSvcbIpHints {
    pub ipv4s: Vec<Ipv4Addr>,
    pub ipv6s: Vec<Ipv6Addr>,
}

impl Display for DnsSvcbIpHints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ipv4 hint:")?;
        for (i, ip) in self.ipv4s.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{ip}")?;
        }
        f.write_str(", ipv6 hint:")?;
        for (i, ip) in self.ipv6s.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            write!(f, "{ip}")?;
        }
        Ok(())
    }
}

/// Parse DNS Service Binding record type
pub(crate) fn get_service_binding(input: &str) -> Result<DnsSvcbRecord, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns service binding",
        message: "Failed to base64 decode DNS svcb details",
    })?;

    let (_, result) = parse_svcb(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns service binding",
        message: "Failed to parse DNS Service Binding data",
    })?;

    Ok(result)
}

/// Parse DNS SVC Binding record
fn parse_svcb(input: &[u8]) -> nom::IResult<&[u8], DnsSvcbRecord> {
    // Format/documentation found at https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00/?include_text=1
    let (input, id) = be_u16(input)?;
    let (input, unknown_type) = be_u32(input)?;

    const DNS_OVER_HTTPS: u32 = 0x800000;
    if unknown_type == DNS_OVER_HTTPS {
        let (input, url_size) = be_u8(input)?;
        let (input, url) = extract_string_size(input, url_size.into())?;
        return Ok((input, DnsSvcbRecord::Url(url)));
    }

    // ALPN = Application Layer Protocol Negotation
    let (input, alpn_size) = be_u8(input)?;
    let (input, alpn) = map_parser(take(alpn_size), parse_svcb_alpn).parse(input)?;
    let (input, ip_hints) = parse_svcb_ip(input)?;

    Ok((input, DnsSvcbRecord::Rdata { id, alpn, ip_hints }))
}

/// Parse the Application Layer Protocol Negotation
fn parse_svcb_alpn(mut input: &[u8]) -> nom::IResult<&[u8], DnsSvcbAlpn> {
    let mut entries = Vec::new();
    while !input.is_empty() {
        let (i, alpn_entry_size) = be_u8(input)?;
        let (i, alpn_entry) = take(alpn_entry_size)(i)?;
        let (_, alpn_name) = extract_string(alpn_entry)?;
        input = i;
        entries.push(alpn_name.to_string());
    }
    Ok((input, DnsSvcbAlpn(entries)))
}

/// Parse the IPs
fn parse_svcb_ip(mut input: &[u8]) -> nom::IResult<&[u8], DnsSvcbIpHints> {
    const IPV4: u16 = 4;
    const IPV6: u16 = 6;

    let ipv4_parser = || map(be_u32, Ipv4Addr::from);
    let ipv6_parser = || map(be_u128, Ipv6Addr::from);

    let mut ipv4s = Vec::new();
    let mut ipv6s = Vec::new();

    // IPs can either be IPv4 or/and IPv6
    while !input.is_empty() {
        let (i, ip_version) = verify(be_u16, |val| *val == IPV4 || *val == IPV6).parse(input)?;
        let (i, ip_size) = be_u16(i)?;
        let (i, ip_data) = take(ip_size)(i)?;
        input = i;

        if ip_version == IPV4 {
            let mut iter = iterator(ip_data, ipv4_parser());
            for ip in iter.by_ref() {
                ipv4s.push(ip);
            }
            iter.finish()?;
        } else if ip_version == IPV6 {
            let mut iter = iterator(ip_data, ipv6_parser());
            for ip in iter.by_ref() {
                ipv6s.push(ip);
            }
            iter.finish()?;
        }
    }

    Ok((input, DnsSvcbIpHints { ipv4s, ipv6s }))
}

pub struct DnsMacAddr(pub String);

impl Display for DnsMacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Get the MAC Address from the log data
pub(crate) fn get_dns_mac_addr(input: &str) -> Result<DnsMacAddr, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns mac address",
        message: "Failed to base64 decode DNS mac address details",
    })?;

    let (_, message_results) = parse_mac_addr(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns mac address",
        message: "Failed to parse DNS mac address data",
    })?;

    Ok(DnsMacAddr(message_results))
}

/// Parse the MAC Address
fn parse_mac_addr(input: &[u8]) -> nom::IResult<&[u8], String> {
    fold_many0(
        be_u8,
        || String::with_capacity(input.len() * 3), // This buffer will not have to reallocate/grow
        |mut acc, item| {
            if !acc.is_empty() {
                acc.push(':');
            }
            write!(&mut acc, "{item:02X?}").ok(); // ignore errors on write in String
            acc
        },
    )
    .parse(input)
}

/// Get IP Address info from log data
pub(crate) fn dns_ip_addr(input: &str) -> Result<IpAddr, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns ip address",
        message: "Failed to base64 decode DNS ip address details",
    })?;

    let (_, results) = parse_dns_ip_addr(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns ip address",
        message: "Failed to parse DNS ip address data",
    })?;

    Ok(results)
}

/// Parse IP Address data
fn parse_dns_ip_addr(data: &[u8]) -> nom::IResult<&[u8], IpAddr> {
    let (data, ip_version) = le_u32(data)?;
    const IPV4: u32 = 4;
    const IPV6: u32 = 6;
    if ip_version == IPV4 {
        get_ip_four(data).map(|(data, result)| (data, IpAddr::from(result)))
    } else if ip_version == IPV6 {
        get_ip_six(data).map(|(data, result)| (data, IpAddr::from(result)))
    } else {
        Err(nom::Err::Error(nom::error::Error {
            input: data,
            code: ErrorKind::Fail,
        }))
    }
}

#[derive(Debug, PartialEq, strum::Display)]
pub enum DnsAddRmv {
    #[strum(to_string = "add")]
    Add,
    #[strum(to_string = "rmv")]
    Rmv,
}

/// Translate DNS add/rmv log values
pub(crate) fn dns_addrmv(data: &str) -> DnsAddRmv {
    if data == "1" {
        return DnsAddRmv::Add;
    }
    DnsAddRmv::Rmv
}

#[derive(Debug, PartialEq, strum::Display)]
pub enum DnsRecordType {
    #[strum(to_string = "A")]
    A,
    #[strum(to_string = "NS")]
    NS,
    #[strum(to_string = "CNAME")]
    CNAME,
    #[strum(to_string = "SOA")]
    SOA,
    #[strum(to_string = "NULL")]
    NULL,
    #[strum(to_string = "PTR")]
    PTR,
    #[strum(to_string = "HINFO")]
    HINFO,
    #[strum(to_string = "MX")]
    MX,
    #[strum(to_string = "TXT")]
    TXT,
    #[strum(to_string = "RP")]
    RP,
    #[strum(to_string = "AFSDB")]
    AFSDB,
    #[strum(to_string = "SIG")]
    SIG,
    #[strum(to_string = "KEY")]
    KEY,
    #[strum(to_string = "AAAA")]
    AAAA,
    #[strum(to_string = "LOC")]
    LOC,
    #[strum(to_string = "SRV")]
    SRV,
    #[strum(to_string = "NAPTR")]
    NAPTR,
    #[strum(to_string = "KX")]
    KX,
    #[strum(to_string = "CERT")]
    CERT,
    #[strum(to_string = "DNAME")]
    DNAME,
    #[strum(to_string = "APL")]
    APL,
    #[strum(to_string = "DS")]
    DS,
    #[strum(to_string = "SSHFP")]
    SSHFP,
    #[strum(to_string = "IPSECKEY")]
    IPSECKEY,
    #[strum(to_string = "RRSIG")]
    RRSIG,
    #[strum(to_string = "NSEC")]
    NSEC,
    #[strum(to_string = "DNSKEY")]
    DNSKEY,
    #[strum(to_string = "DHCID")]
    DHCID,
    #[strum(to_string = "NSEC3")]
    NSEC3,
    #[strum(to_string = "NSEC3PARAM")]
    NSEC3PARAM,
    #[strum(to_string = "TLSA")]
    TLSA,
    #[strum(to_string = "SMIMEA")]
    SMIMEA,
    #[strum(to_string = "HIP")]
    HIP,
    #[strum(to_string = "CDS")]
    CDS,
    #[strum(to_string = "CDNSKEY")]
    CDNSKEY,
    #[strum(to_string = "OPENPGPKEY")]
    OPENPGPKEY,
    #[strum(to_string = "CSYNC")]
    CSYNC,
    #[strum(to_string = "ZONEMD")]
    ZONEMD,
    #[strum(to_string = "SVCB")]
    SVCB,
    #[strum(to_string = "HTTPS")]
    HTTPS,
    #[strum(to_string = "EUI48")]
    EUI48,
    #[strum(to_string = "EUI64")]
    EUI64,
    #[strum(to_string = "TKEY")]
    TKEY,
    #[strum(to_string = "TSIG")]
    TSIG,
    #[strum(to_string = "ANY")]
    ANY,
    #[strum(to_string = "URI")]
    URI,
    #[strum(to_string = "CAA")]
    CAA,
    #[strum(to_string = "TA")]
    TA,
    #[strum(to_string = "DLV")]
    DLV,
}

/// Translate DNS records to string
pub(crate) fn dns_records(data: &str) -> Result<DnsRecordType, DecoderError<'_>> {
    // Found at https://en.wikipedia.org/wiki/List_of_DNS_record_types
    Ok(match data {
        "1" => DnsRecordType::A,
        "2" => DnsRecordType::NS,
        "5" => DnsRecordType::CNAME,
        "6" => DnsRecordType::SOA,
        "10" => DnsRecordType::NULL,
        "12" => DnsRecordType::PTR,
        "13" => DnsRecordType::HINFO,
        "15" => DnsRecordType::MX,
        "16" => DnsRecordType::TXT,
        "17" => DnsRecordType::RP,
        "18" => DnsRecordType::AFSDB,
        "24" => DnsRecordType::SIG,
        "25" => DnsRecordType::KEY,
        "28" => DnsRecordType::AAAA,
        "29" => DnsRecordType::LOC,
        "33" => DnsRecordType::SRV,
        "35" => DnsRecordType::NAPTR,
        "36" => DnsRecordType::KX,
        "37" => DnsRecordType::CERT,
        "39" => DnsRecordType::DNAME,
        "42" => DnsRecordType::APL,
        "43" => DnsRecordType::DS,
        "44" => DnsRecordType::SSHFP,
        "45" => DnsRecordType::IPSECKEY,
        "46" => DnsRecordType::RRSIG,
        "47" => DnsRecordType::NSEC,
        "48" => DnsRecordType::DNSKEY,
        "49" => DnsRecordType::DHCID,
        "50" => DnsRecordType::NSEC3,
        "51" => DnsRecordType::NSEC3PARAM,
        "52" => DnsRecordType::TLSA,
        "53" => DnsRecordType::SMIMEA,
        "55" => DnsRecordType::HIP,
        "59" => DnsRecordType::CDS,
        "60" => DnsRecordType::CDNSKEY,
        "61" => DnsRecordType::OPENPGPKEY,
        "62" => DnsRecordType::CSYNC,
        "63" => DnsRecordType::ZONEMD,
        "64" => DnsRecordType::SVCB,
        "65" => DnsRecordType::HTTPS,
        "108" => DnsRecordType::EUI48,
        "109" => DnsRecordType::EUI64,
        "249" => DnsRecordType::TKEY,
        "250" => DnsRecordType::TSIG,
        "255" => DnsRecordType::ANY,
        "256" => DnsRecordType::URI,
        "257" => DnsRecordType::CAA,
        "32768" => DnsRecordType::TA,
        "32769" => DnsRecordType::DLV,
        _ => {
            return Err(DecoderError::Parse {
                input: data.as_bytes(),
                parser_name: "dns records",
                message: "Unknown DNS Resource Record Type",
            });
        }
    })
}

#[derive(Debug, PartialEq, strum::Display)]
pub enum DnsReason {
    #[strum(to_string = "no-data")]
    NoData,
    #[strum(to_string = "query-suppressed")]
    QuerySuppressed,
    #[strum(to_string = "no-dns-service")]
    NoDnsService,
    #[strum(to_string = "nxdomain")]
    Nxdomain,
    #[strum(to_string = "server error")]
    ServerError,
}

/// Translate DNS response/reason? to string
pub(crate) fn dns_reason(data: &str) -> Result<DnsReason, DecoderError<'_>> {
    let message = match data {
        "1" => DnsReason::NoData,
        "4" => DnsReason::QuerySuppressed,
        "3" => DnsReason::NoDnsService,
        "2" => DnsReason::Nxdomain,
        "5" => DnsReason::ServerError,
        _ => {
            return Err(DecoderError::Parse {
                input: data.as_bytes(),
                parser_name: "dns reason",
                message: "Unknown DNS Reason",
            });
        }
    };
    Ok(message)
}

#[derive(Debug, PartialEq, strum::Display)]
pub enum DnsProtocol {
    #[strum(to_string = "UDP")]
    UDP,
    #[strum(to_string = "TCP")]
    TCP,
    #[strum(to_string = "HTTPS")]
    HTTPS,
}

/// Translate the DNS protocol used
pub(crate) fn dns_protocol(data: &str) -> Result<DnsProtocol, DecoderError<'_>> {
    let message = match data {
        "1" => DnsProtocol::UDP,
        "2" => DnsProtocol::TCP,
        //"3" => "HTTP",??
        "4" => DnsProtocol::HTTPS,
        _ => {
            return Err(DecoderError::Parse {
                input: data.as_bytes(),
                parser_name: "dns protocol",
                message: "Unknown DNS Protocol",
            });
        }
    };
    Ok(message)
}

/// Get just the DNS flags associated with the DNS header
pub(crate) fn dns_idflags(input: &str) -> Result<DnsIdFlags, DecoderError<'_>> {
    let flags = input.parse::<u32>().map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns id flags",
        message: "Failed to convert ID Flags to int",
    })?;

    let mut bytes = [0u8; size_of::<u32>()];
    bytes
        .as_mut()
        .write_u32::<BigEndian>(flags)
        .map_err(|_| DecoderError::Parse {
            input: input.as_bytes(),
            parser_name: "dns id flags",
            message: "Failed to convert ID Flags to bytes",
        })?;

    let (_, result) = parse_idflags(&bytes).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns id flags",
        message: "Failed to get ID Flags",
    })?;

    Ok(result)
}

pub struct DnsIdFlags {
    pub id: u16,
    pub flags: u16,
    pub decoded_flags: Option<DnsFlags>,
}

impl Display for DnsIdFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(decoded_flags) = &self.decoded_flags {
            write!(
                f,
                "id: {:#X?}, flags: {:#X?} {decoded_flags}",
                self.id, self.flags
            )
        } else {
            write!(
                f,
                "id: {:#X?}, flags: {:#X?} Failed to parse ID Flags",
                self.id, self.flags
            )
        }
    }
}

/// Parse just the DNS flags associated with the DNS header
fn parse_idflags(input: &[u8]) -> nom::IResult<&[u8], DnsIdFlags> {
    let (input, id) = be_u16(input)?;
    let flag_results = get_dns_flags(input)
        .inspect_err(|err| {
            error!("[macos-unifiedlogs] Failed to parse ID Flags: {err:?}");
        })
        .ok();

    // todo: should be the `get_dns_flags` parser that output what can be used as `flags`
    // the responsibility for the `dns_data` format knowledge should not be shared into multiple functions
    let (_, flags) = be_u16(input)?;
    Ok((
        input,
        DnsIdFlags {
            id,
            flags,
            decoded_flags: flag_results.map(|(_, flags)| flags),
        },
    ))
}

/// Get just the DNS count data associated with the DNS header
pub(crate) fn dns_counts(input: &str) -> Result<DnsCounts, DecoderError<'_>> {
    let flags = input.parse::<u64>().map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns counts",
        message: "Failed to convert counts to int",
    })?;

    let mut bytes = [0u8; size_of::<u64>()];
    bytes
        .as_mut()
        .write_u64::<BigEndian>(flags)
        .map_err(|_| DecoderError::Parse {
            input: input.as_bytes(),
            parser_name: "dns counts",
            message: "Failed to convert counts to bytes",
        })?;

    let (_, counts) = parse_counts(&bytes).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "dns counts",
        message: "Failed to get counts",
    })?;

    Ok(counts)
}

#[derive(Debug, PartialEq)]
pub struct DnsCounts {
    question: u16,
    answer: u16,
    authority: u16,
    additional: u16,
}

impl std::fmt::Display for DnsCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Question Count: {}, Answer Record Count: {}, Authority Record Count: {}, Additional Record Count: {}",
            self.question, self.answer, self.authority, self.additional
        )
    }
}

/// parse just the DNS count data associated with the DNS header
fn parse_counts(data: &[u8]) -> nom::IResult<&[u8], DnsCounts> {
    let mut tup = (be_u16, be_u16, be_u16, be_u16);
    let (input, (question, answer, authority, additional)) = tup.parse(data)?;

    Ok((
        input,
        DnsCounts {
            question,
            answer,
            authority,
            additional,
        },
    ))
}

#[derive(Debug, PartialEq, strum::Display)]
pub enum DnsYesNo {
    #[strum(to_string = "yes")]
    Yes,
    #[strum(to_string = "no")]
    No,
}

/// Translate DNS yes/no log values
pub(crate) fn dns_yes_no(data: &str) -> DnsYesNo {
    if data == "0" {
        return DnsYesNo::No;
    }
    DnsYesNo::Yes
}

#[derive(Debug, PartialEq, strum::Display)]
pub enum DnsAcceptable {
    #[strum(to_string = "acceptable")]
    Acceptable,
    #[strum(to_string = "unacceptable")]
    Unacceptable,
}

/// Translate DNS acceptable log values
pub(crate) fn dns_acceptable(data: &str) -> DnsAcceptable {
    if data == "0" {
        return DnsAcceptable::Unacceptable;
    }
    DnsAcceptable::Acceptable
}

/// Translate DNS getaddrinfo log values
pub(crate) fn dns_getaddrinfo_opts(data: &str) -> Result<&'static str, DecoderError<'_>> {
    let message = match data {
        "0" => "0x0 {}",
        "8" => "0x8 {use-failover}",
        "12" => "0xC {in-app-browser, use-failover}",
        "24" => "0x18 {use-failover, prohibit-encrypted-dns}",
        _ => {
            return Err(DecoderError::Parse {
                input: data.as_bytes(),
                parser_name: "dns getaddrinfo opts",
                message: "Unknown DNS getaddrinfo options",
            });
        }
    };
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::decode_standard;

    #[test]
    fn test_parse_dns_header() {
        let test_data = "uXMBAAABAAAAAAAA";
        let result = parse_dns_header(test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY,\n    Query Type: 0,\n    Authoritative Answer Flag: 0,\n    Truncation Flag: 0,\n    Recursion Desired: 1,\n    Recursion Available: 0,\n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0"
        );
    }

    #[test]
    fn test_get_dns_flags() {
        let test_data = [185, 115, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let (_, result) = get_dns_header(&test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY,\n    Query Type: 0,\n    Authoritative Answer Flag: 0,\n    Truncation Flag: 0,\n    Recursion Desired: 1,\n    Recursion Available: 0,\n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0"
        );
    }

    #[test]
    fn test_get_dns_header() {
        let test_data = [1, 0];
        let (_, result) = get_dns_flags(&test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "Opcode: QUERY,\n    Query Type: 0,\n    Authoritative Answer Flag: 0,\n    Truncation Flag: 0,\n    Recursion Desired: 1,\n    Recursion Available: 0,\n    Response Code: No Error"
        );
    }

    #[test]
    fn test_get_domain_name() {
        let test_data = "AzE0NAMxMDEDMTY4AzE5Mgdpbi1hZGRyBGFycGEA";
        let result = get_domain_name(test_data).unwrap();
        assert_eq!(result.to_string(), ".144.101.168.192.in-addr.arpa");
    }

    #[test]
    fn test_get_service_binding() {
        let test_data =
            "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA==";
        let result = get_service_binding(test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
        );
    }

    #[test]
    fn test_parse_svcb() {
        let test_data =
            "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = parse_svcb(&decoded_data_result).unwrap();
        assert_eq!(
            result.to_string(),
            "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
        );
    }

    #[test]
    fn test_parse_svcb_alpn() {
        let test_data = [2, 104, 50];

        let (_, result) = parse_svcb_alpn(&test_data).unwrap();
        assert_eq!(result.to_string(), "alpn=h2,");
    }

    #[test]
    fn test_parse_svcb_ip() {
        let test_data = [
            0, 4, 0, 8, 104, 16, 148, 64, 104, 16, 149, 64, 0, 6, 0, 32, 38, 6, 71, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 104, 16, 148, 64, 38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 149, 64,
        ];

        let (_, result) = parse_svcb_ip(&test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
        );
    }

    #[test]
    fn test_parse_svcb_ip_should_not_infine_loop() {
        let test_data = [
            // 104.16.148.64
            0, 4, 0, 4, 104, 16, 148, 64, //
            // 2606:4700::6810:9440
            0, 6, 0, 16, 38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 148, 64,
            // [invalid data] infinite loop (consuming too much) in the previous version
            0, 42, 0, 0,
        ];

        let result = parse_svcb_ip(&test_data);
        assert!(result.is_err());

        // // Previous version would have this behavior :
        // let (rest, result) = parse_svcb_ip(&test_data).unwrap();
        // assert_eq!(rest, &[] as &[u8]);
        // assert_eq!(result, "ipv4 hint:104.16.148.64, ipv6 hint:2606:4700::6810:9440,");
    }

    #[test]
    fn test_get_dns_mac_addr() {
        let test_data = "AAAAAAAA";

        let result = get_dns_mac_addr(test_data).unwrap();
        assert_eq!(result.to_string(), "00:00:00:00:00:00");
    }

    #[test]
    fn test_parse_mac_addr() {
        let test_data = [0, 0, 0, 0, 0, 0];

        let (_, result) = parse_mac_addr(&test_data).unwrap();
        assert_eq!(result, "00:00:00:00:00:00");
    }

    #[test]
    fn test_dns_ip_addr() {
        let test_data = "BAAAAMCoZZAAAAAAAAAAAAAAAAA=";

        let result = dns_ip_addr(test_data).unwrap();
        assert_eq!(result.to_string(), "192.168.101.144");
    }

    #[test]
    fn test_parse_dns_ip_addr() {
        let test_data = [
            4, 0, 0, 0, 192, 168, 101, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (_, result) = parse_dns_ip_addr(&test_data).unwrap();
        assert_eq!(result.to_string(), "192.168.101.144");
    }

    #[test]
    fn test_dns_addrmv() {
        let test_data = "1";

        let result = dns_addrmv(test_data);
        assert_eq!(result, DnsAddRmv::Add);
    }

    #[test]
    fn test_dns_records() {
        let test_data = "65";

        let result = dns_records(test_data).unwrap();
        assert_eq!(result, DnsRecordType::HTTPS);
    }

    #[test]
    fn test_dns_reason() {
        let test_data = "1";

        let result = dns_reason(test_data).unwrap();
        assert_eq!(result, DnsReason::NoData);
    }

    #[test]
    fn test_dns_protocol() {
        let test_data = "1";

        let result = dns_protocol(test_data).unwrap();
        assert_eq!(result, DnsProtocol::UDP);
    }

    #[test]
    fn test_dns_idflags() {
        let test_data = "2126119168";

        let result = dns_idflags(test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "id: 0x7EBA, flags: 0x100 Opcode: QUERY,\n    Query Type: 0,\n    Authoritative Answer Flag: 0,\n    Truncation Flag: 0,\n    Recursion Desired: 1,\n    Recursion Available: 0,\n    Response Code: No Error"
        );
    }

    #[test]
    fn test_parse_idflags() {
        let test_data = vec![0x7e, 0xba, 0x1, 0];

        let (_, result) = parse_idflags(&test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "id: 0x7EBA, flags: 0x100 Opcode: QUERY,\n    Query Type: 0,\n    Authoritative Answer Flag: 0,\n    Truncation Flag: 0,\n    Recursion Desired: 1,\n    Recursion Available: 0,\n    Response Code: No Error"
        );
    }

    #[test]
    fn test_dns_counts() {
        let test_data = "281474976710656";

        let result = dns_counts(test_data).unwrap();
        let expected = DnsCounts {
            question: 1,
            answer: 0,
            authority: 0,
            additional: 0,
        };

        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_counts() {
        let test_data = vec![0, 1, 0, 0, 0, 0, 0, 0];

        let (_, result) = parse_counts(&test_data).unwrap();
        assert_eq!(
            result,
            DnsCounts {
                question: 1,
                answer: 0,
                authority: 0,
                additional: 0
            }
        );
    }

    #[test]
    fn test_dns_yes_no() {
        let test_data = "0";

        let result = dns_yes_no(test_data);
        assert_eq!(result, DnsYesNo::No);
    }

    #[test]
    fn test_dns_acceptable() {
        let test_data = "0";

        let result = dns_acceptable(test_data);
        assert_eq!(result, DnsAcceptable::Unacceptable);
    }

    #[test]
    fn test_dns_getaddrinfo_opts() {
        let test_data = "8";

        let result = dns_getaddrinfo_opts(test_data).unwrap();
        assert_eq!(result, "0x8 {use-failover}");
    }
}
