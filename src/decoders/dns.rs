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
    fmt::Write,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Parse the DNS header
pub(crate) fn parse_dns_header(data: &str) -> Result<String, DecoderError<'_>> {
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

/// Get the DNS header data
fn get_dns_header(input: &[u8]) -> IResult<&[u8], String> {
    let (input, id) = be_u16(input)?;

    let (input, flag_data) = take(size_of::<u16>())(input)?;
    let ((_, _), message) = get_dns_flags(flag_data).map_err(remove_err_offset)?;
    let (_, flags) = be_u16(flag_data)?;

    let (input, count_message) = parse_counts(input)?;

    let header_message = format!(
        "Query ID: {:#X?}, Flags: {:#X?} {}, {}",
        id, flags, message, count_message
    );

    Ok((input, header_message))
}

/// Parse the DNS bit flags
fn get_dns_flags(input: &[u8]) -> IResult<(&[u8], usize), String> {
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

    let opcode_message = match opcode {
        0 => "QUERY",
        1 => "IQUERY",
        2 => "STATUS",
        3 => "RESERVED",
        4 => "NOTIFY",
        5 => "UPDATE",
        _ => "UNKNOWN OPCODE",
    };

    let response_message = match response_code {
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

    let message = format!(
        "Opcode: {}, 
    Query Type: {},
    Authoritative Answer Flag: {}, 
    Truncation Flag: {}, 
    Recursion Desired: {}, 
    Recursion Available: {}, 
    Response Code: {}",
        opcode_message,
        query,
        authoritative_flag,
        truncation_flag,
        recursion_desired,
        recursion_available,
        response_message
    );

    Ok(((input, 0), message))
}

/// Base64 decode the domain name. This is normally masked, but may be shown if private data is enabled
pub(crate) fn get_domain_name(input: &str) -> Result<String, DecoderError<'_>> {
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
        if non_domain_chars.contains(&unicode) || format!("{:?}", unicode).contains("\\u{") {
            clean_domain.push('.');
            continue;
        }
        clean_domain.push_str(&String::from(unicode));
    }
    Ok(clean_domain)
}

/// Parse DNS Service Binding record type
pub(crate) fn get_service_binding(input: &str) -> Result<String, DecoderError<'_>> {
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
fn parse_svcb(input: &[u8]) -> nom::IResult<&[u8], String> {
    // Format/documentation found at https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00/?include_text=1
    let (input, id) = be_u16(input)?;
    let (input, unknown_type) = be_u32(input)?;

    const DNS_OVER_HTTPS: u32 = 0x800000;
    if unknown_type == DNS_OVER_HTTPS {
        let (input, url_size) = be_u8(input)?;
        return extract_string_size(input, url_size.into());
    }

    // ALPN = Application Layer Protocol Negotation
    let (input, alpn_size) = be_u8(input)?;
    let (input, alpn_message) = map_parser(take(alpn_size), parse_svcb_alpn).parse(input)?;
    let (input, ip_message) = parse_svcb_ip(input)?;

    let message = format!("rdata: {} . {} {}", id, alpn_message, ip_message);
    Ok((input, message))
}

/// Parse the Application Layer Protocol Negotation
fn parse_svcb_alpn(mut input: &[u8]) -> nom::IResult<&[u8], String> {
    let mut message = String::from("alpn=");
    while !input.is_empty() {
        let (i, alpn_entry_size) = be_u8(input)?;
        let (i, alpn_entry) = take(alpn_entry_size)(i)?;
        let (_, alpn_name) = extract_string(alpn_entry)?;
        input = i;
        message.push_str(&alpn_name);
        message.push(',')
    }
    Ok((input, message))
}

/// Parse the IPs
fn parse_svcb_ip(mut input: &[u8]) -> nom::IResult<&[u8], String> {
    const IPV4: u16 = 4;
    const IPV6: u16 = 6;

    let ipv4_parser = || map(be_u32, Ipv4Addr::from);
    let ipv6_parser = || map(be_u128, Ipv6Addr::from);

    let mut ipv4s = String::with_capacity(2 * 16); // let's reserve max space for 2 IPV4 addresses
    let mut ipv6s = String::with_capacity(2 * 40); // let's reserve max space for 2 IPV6 addresses

    // IPs can either be IPv4 or/and IPv6
    while !input.is_empty() {
        let (i, ip_version) = verify(be_u16, |val| *val == IPV4 || *val == IPV6).parse(input)?;
        let (i, ip_size) = be_u16(i)?;
        let (i, ip_data) = take(ip_size)(i)?;
        input = i;

        if ip_version == IPV4 {
            let mut iter = iterator(ip_data, ipv4_parser());
            for ip in iter.by_ref() {
                if !ipv4s.is_empty() {
                    ipv4s.push(',');
                }
                write!(ipv4s, "{}", ip).ok(); // ignore errors on write in String
            }
            iter.finish()?;
        } else if ip_version == IPV6 {
            let mut iter = iterator(ip_data, ipv6_parser());
            for ip in iter.by_ref() {
                if !ipv6s.is_empty() {
                    ipv6s.push(',');
                }
                write!(ipv6s, "{}", ip).ok(); // ignore errors on write in String
            }
            iter.finish()?;
        }
    }

    let message = format!("ipv4 hint:{ipv4s}, ipv6 hint:{ipv6s}");
    Ok((input, message))
}

/// Get the MAC Address from the log data
pub(crate) fn get_dns_mac_addr(input: &str) -> Result<String, DecoderError<'_>> {
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

    Ok(message_results)
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
            write!(&mut acc, "{:02X?}", item).ok(); // ignore errors on write in String
            acc
        },
    )
    .parse(input)
}

/// Get IP Address info from log data
pub(crate) fn dns_ip_addr(input: &str) -> Result<String, DecoderError<'_>> {
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
fn parse_dns_ip_addr(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (data, ip_version) = le_u32(data)?;
    const IPV4: u32 = 4;
    const IPV6: u32 = 6;
    if ip_version == IPV4 {
        get_ip_four(data).map(|(data, result)| (data, result.to_string()))
    } else if ip_version == IPV6 {
        get_ip_six(data).map(|(data, result)| (data, result.to_string()))
    } else {
        Err(nom::Err::Error(nom::error::Error {
            input: data,
            code: ErrorKind::Fail,
        }))
    }
}

/// Translate DNS add/rmv log values
pub(crate) fn dns_addrmv(data: &str) -> String {
    if data == "1" {
        return String::from("add");
    }
    String::from("rmv")
}

/// Translate DNS records to string
pub(crate) fn dns_records(data: &str) -> Result<&'static str, DecoderError<'_>> {
    // Found at https://en.wikipedia.org/wiki/List_of_DNS_record_types
    let message = match data {
        "1" => "A",
        "2" => "NS",
        "5" => "CNAME",
        "6" => "SOA",
        "10" => "NULL",
        "12" => "PTR",
        "13" => "HINFO",
        "15" => "MX",
        "16" => "TXT",
        "17" => "RP",
        "18" => "AFSDB",
        "24" => "SIG",
        "25" => "KEY",
        "28" => "AAAA",
        "29" => "LOC",
        "33" => "SRV",
        "35" => "NAPTR",
        "36" => "KX",
        "37" => "CERT",
        "39" => "DNAME",
        "42" => "APL",
        "43" => "DS",
        "44" => "SSHFP",
        "45" => "IPSECKEY",
        "46" => "RRSIG",
        "47" => "NSEC",
        "48" => "DNSKEY",
        "49" => "DHCID",
        "50" => "NSEC3",
        "51" => "NSEC3PARAM",
        "52" => "TLSA",
        "53" => "SMIMEA",
        "55" => "HIP",
        "59" => "CDS",
        "60" => "CDNSKEY",
        "61" => "OPENPGPKEY",
        "62" => "CSYNC",
        "63" => "ZONEMD",
        "64" => "SVCB",
        "65" => "HTTPS",
        "108" => "EUI48",
        "109" => "EUI64",
        "249" => "TKEY",
        "250" => "TSIG",
        "255" => "ANY",
        "256" => "URI",
        "257" => "CAA",
        "32768" => "TA",
        "32769" => "DLV",
        _ => {
            return Err(DecoderError::Parse {
                input: data.as_bytes(),
                parser_name: "dns records",
                message: "Unknown DNS Resource Record Type",
            });
        }
    };
    Ok(message)
}

/// Translate DNS response/reason? to string
pub(crate) fn dns_reason(data: &str) -> Result<&'static str, DecoderError<'_>> {
    let message = match data {
        "1" => "no-data",
        "4" => "query-suppressed",
        "3" => "no-dns-service",
        "2" => "nxdomain",
        "5" => "server error",
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

/// Translate the DNS protocol used
pub(crate) fn dns_protocol(data: &str) -> Result<&'static str, DecoderError<'_>> {
    let message = match data {
        "1" => "UDP",
        "2" => "TCP",
        //"3" => "HTTP",??
        "4" => "HTTPS",
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
pub(crate) fn dns_idflags(input: &str) -> Result<String, DecoderError<'_>> {
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

/// Parse just the DNS flags associated with the DNS header
fn parse_idflags(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (dns_data, id) = be_u16(data)?;
    let flag_results = get_dns_flags(dns_data);

    let message = match flag_results {
        Ok((_, result)) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to parse ID Flags: {:?}", err);
            String::from("Failed to parse ID Flags")
        }
    };

    // todo: should be the `get_dns_flags` parser that output what can be used as `flags`
    // the responsibility for the `dns_data` format knowledge should not be shared into multiple functions
    let (_, flags) = be_u16(dns_data)?;
    Ok((
        dns_data,
        format!("id: {:#X?}, flags: {:#X?} {}", id, flags, message),
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
pub(crate) struct DnsCounts {
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

/// Translate DNS yes/no log values
pub(crate) fn dns_yes_no(data: &str) -> String {
    if data == "0" {
        return String::from("no");
    }
    String::from("yes")
}

/// Translate DNS acceptable log values
pub(crate) fn dns_acceptable(data: &str) -> String {
    if data == "0" {
        return String::from("unacceptable");
    }
    String::from("acceptable")
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
            result,
            "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0"
        );
    }

    #[test]
    fn test_get_dns_flags() {
        let test_data = [185, 115, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let (_, result) = get_dns_header(&test_data).unwrap();
        assert_eq!(
            result,
            "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0"
        );
    }

    #[test]
    fn test_get_dns_header() {
        let test_data = [1, 0];
        let (_, result) = get_dns_flags(&test_data).unwrap();
        assert_eq!(
            result,
            "Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error"
        );
    }

    #[test]
    fn test_get_domain_name() {
        let test_data = "AzE0NAMxMDEDMTY4AzE5Mgdpbi1hZGRyBGFycGEA";
        let result = get_domain_name(test_data).unwrap();
        assert_eq!(result, ".144.101.168.192.in-addr.arpa");
    }

    #[test]
    fn test_get_service_binding() {
        let test_data =
            "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA==";
        let result = get_service_binding(test_data).unwrap();
        assert_eq!(
            result,
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
            result,
            "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
        );
    }

    #[test]
    fn test_parse_svcb_alpn() {
        let test_data = [2, 104, 50];

        let (_, result) = parse_svcb_alpn(&test_data).unwrap();
        assert_eq!(result, "alpn=h2,");
    }

    #[test]
    fn test_parse_svcb_ip() {
        let test_data = [
            0, 4, 0, 8, 104, 16, 148, 64, 104, 16, 149, 64, 0, 6, 0, 32, 38, 6, 71, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 104, 16, 148, 64, 38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 149, 64,
        ];

        let (_, result) = parse_svcb_ip(&test_data).unwrap();
        assert_eq!(
            result,
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
        assert_eq!(result, "00:00:00:00:00:00");
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
        assert_eq!(result, "192.168.101.144");
    }

    #[test]
    fn test_parse_dns_ip_addr() {
        let test_data = [
            4, 0, 0, 0, 192, 168, 101, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (_, result) = parse_dns_ip_addr(&test_data).unwrap();
        assert_eq!(result, "192.168.101.144");
    }

    #[test]
    fn test_dns_addrmv() {
        let test_data = "1";

        let result = dns_addrmv(test_data);
        assert_eq!(result, "add");
    }

    #[test]
    fn test_dns_records() {
        let test_data = "65";

        let result = dns_records(test_data).unwrap();
        assert_eq!(result, "HTTPS");
    }

    #[test]
    fn test_dns_reason() {
        let test_data = "1";

        let result = dns_reason(test_data).unwrap();
        assert_eq!(result, "no-data");
    }

    #[test]
    fn test_dns_protocol() {
        let test_data = "1";

        let result = dns_protocol(test_data).unwrap();
        assert_eq!(result, "UDP");
    }

    #[test]
    fn test_dns_idflags() {
        let test_data = "2126119168";

        let result = dns_idflags(test_data).unwrap();
        assert_eq!(
            result,
            "id: 0x7EBA, flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error"
        );
    }

    #[test]
    fn test_parse_idflags() {
        let test_data = vec![0x7e, 0xba, 0x1, 0];

        let (_, result) = parse_idflags(&test_data).unwrap();
        assert_eq!(
            result,
            "id: 0x7EBA, flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error"
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
        assert_eq!(result, "no");
    }

    #[test]
    fn test_dns_acceptable() {
        let test_data = "0";

        let result = dns_acceptable(test_data);
        assert_eq!(result, "unacceptable");
    }

    #[test]
    fn test_dns_getaddrinfo_opts() {
        let test_data = "8";

        let result = dns_getaddrinfo_opts(test_data).unwrap();
        assert_eq!(result, "0x8 {use-failover}");
    }
}
