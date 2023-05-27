// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::network::{get_ip_four, get_ip_six};
use crate::util::{decode_standard, extract_string, extract_string_size};
use byteorder::{BigEndian, WriteBytesExt};
use log::{error, warn};
use nom::{
    bits,
    bytes::complete::take,
    number::complete::{be_u128, be_u16, be_u32, be_u8, le_u32},
};
use std::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
};

/// Parse the DNS header
pub(crate) fn parse_dns_header(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode dns header data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode DNS header details");
        }
    };

    let message_result = get_dns_header(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get dns header structure: {:?}",
                err
            );
            format!("Failed to get dns header: {}", data)
        }
    }
}

/// Get the DNS header data
fn get_dns_header(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (dns_data, id_data) = take(size_of::<u16>())(data)?;
    let (dns_data, flag_data) = take(size_of::<u16>())(dns_data)?;

    let (_, id) = be_u16(id_data)?;

    let message_result = get_dns_flags(flag_data);
    let message = match message_result {
        Ok(result) => result.1,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse DNS header flags. Error: {:?}",
                err
            );
            String::from("Failed to parse DNS header")
        }
    };

    let message_result = parse_counts(dns_data);
    let count_message = match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse DNS header counts. Error: {:?}",
                err
            );
            String::from("Failed to parse DNS header counts")
        }
    };

    let (_, flags) = be_u16(flag_data)?;

    let header_message = format!(
        "Query ID: {:#X?}, Flags: {:#X?} {}, {}",
        id, flags, message, count_message
    );

    Ok((dns_data, header_message))
}

/// Parse the DNS bit flags
fn get_dns_flags(data: &[u8]) -> nom::IResult<(&[u8], usize), String> {
    // Have to work with bits instead of bytes for the DNS flags
    let ((flag_data, offset), query_flag): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u8>())((data, 0))?;
    let ((flag_data, offset), opcode): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u32>())((flag_data, offset))?;
    let ((flag_data, offset), authoritative_flag): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u8>())((flag_data, offset))?;
    let ((flag_data, offset), truncation_flag): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u8>())((flag_data, offset))?;

    let ((flag_data, offset), recursion_desired): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u8>())((flag_data, offset))?;
    let ((flag_data, offset), recursion_available): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u8>())((flag_data, offset))?;

    let reserved_size: usize = 3;
    let ((flag_data, offset), _reserved): ((&[u8], usize), u8) =
        bits::complete::take(reserved_size)((flag_data, offset))?;
    let ((flag_data, _), response_code): ((&[u8], usize), u8) =
        bits::complete::take(size_of::<u32>())((flag_data, offset))?;

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
        query_flag,
        authoritative_flag,
        truncation_flag,
        recursion_desired,
        recursion_available,
        response_message
    );

    Ok(((flag_data, 0), message))
}

/// Base64 decode the domain name. This is normally masked, but may be shown if private data is enabled
pub(crate) fn get_domain_name(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode dns name data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode DNS name details");
        }
    };

    let domain_results = extract_string(&decoded_data);
    match domain_results {
        Ok((_, results)) => {
            let mut clean_domain = String::new();
            let non_domain_chars: Vec<char> = vec!['\n', '\t', '\r'];
            for unicode in results.chars() {
                // skip non-domain characters and replace with '.'
                if non_domain_chars.contains(&unicode) || format!("{:?}", unicode).contains("\\u{")
                {
                    clean_domain.push('.');
                    continue;
                }
                clean_domain.push_str(&String::from(unicode));
            }
            clean_domain
        }
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to extract domain name from logs: {:?}",
                err
            );
            String::from("Failed to extract domain name from logs")
        }
    }
}

/// Parse DNS Service Binding record type
pub(crate) fn get_service_binding(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode dns svcb data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode DNS svcb details");
        }
    };

    let message_results = parse_svcb(&decoded_data);
    match message_results {
        Ok((_, results)) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse DNS Service Binding data: {:?}",
                err
            );
            String::from("Failed to parse DNS Service Binding data")
        }
    }
}

/// Parse DNS SVC Binding record
fn parse_svcb(data: &[u8]) -> nom::IResult<&[u8], String> {
    // Format/documentation found at https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00/?include_text=1
    let (dns_data, id_data) = take(size_of::<u16>())(data)?;
    let (dns_data, unknown_type_data) = take(size_of::<u32>())(dns_data)?;

    let (_, unknown_type) = be_u32(unknown_type_data)?;
    let dns_over_https = 8388608; // 0x800000
    if unknown_type == dns_over_https {
        let (dns_data, url_entry_size) = take(size_of::<u8>())(dns_data)?;
        let (_, url_size) = be_u8(url_entry_size)?;
        return extract_string_size(dns_data, url_size.into());
    }

    // ALPN = Application Layer Protocol Negotation
    let (dns_data, alpn_total_size) = take(size_of::<u8>())(dns_data)?;

    let (_, id) = be_u16(id_data)?;
    let (_, alpn_size) = be_u8(alpn_total_size)?;

    let (dns_data, alpn_data) = take(alpn_size)(dns_data)?;
    let (_, alpn_message) = parse_svcb_alpn(alpn_data)?;

    let (dns_data, ip_message) = parse_svcb_ip(dns_data)?;

    let message = format!("rdata: {} . {} {}", id, alpn_message, ip_message);
    Ok((dns_data, message))
}

/// Parse the Application Layer Protocol Negotation
fn parse_svcb_alpn(dns_data: &[u8]) -> nom::IResult<&[u8], String> {
    let mut data = dns_data;
    let mut message = String::from("alpn=");
    while !data.is_empty() {
        let (alpn_data, entry_size) = take(size_of::<u8>())(data)?;
        let (_, entry) = be_u8(entry_size)?;
        let (alpn_data, alpn_entry) = take(entry)(alpn_data)?;
        data = alpn_data;
        let (_, alpn_name) = extract_string(alpn_entry)?;
        message = format!("{}{},", message, alpn_name);
    }
    Ok((data, message))
}

/// Parse the IPs
fn parse_svcb_ip(data: &[u8]) -> nom::IResult<&[u8], String> {
    let mut dns_data = data;
    let mut ipv4_hint = String::from("ipv4 hint:");
    let mut ipv6_hint = String::from("ipv6 hint:");

    // IPs can either be IPv4 or/and IPv6
    while !dns_data.is_empty() {
        let (remaining_dns_data, ip_type) = take(size_of::<u16>())(dns_data)?;
        let (_, ip_version) = be_u16(ip_type)?;

        let (remaining_dns_data, total_ip_size) = take(size_of::<u16>())(remaining_dns_data)?;
        let (_, ip_size) = be_u16(total_ip_size)?;

        let (remaining_dns_data, mut ip_data) = take(ip_size)(remaining_dns_data)?;
        dns_data = remaining_dns_data;
        let ipv4 = 4;
        let ipv6 = 6;
        // There can be multiple IPs
        while !ip_data.is_empty() {
            if ip_version == ipv4 {
                let (remaining_ip_data, ipv4_data) = take(size_of::<u32>())(ip_data)?;
                ip_data = remaining_ip_data;

                let (_, ip) = be_u32(ipv4_data)?;
                let ip_addr = Ipv4Addr::from(ip);
                ipv4_hint = format!("{}{},", ipv4_hint, ip_addr);
            } else if ip_version == ipv6 {
                let (remaining_ip_data, ipv6_data) = take(size_of::<u128>())(ip_data)?;
                ip_data = remaining_ip_data;

                let (_, ip) = be_u128(ipv6_data)?;
                let ip_addr = Ipv6Addr::from(ip);
                ipv6_hint = format!("{}{},", ipv6_hint, ip_addr);
            }
        }
    }
    let message = format!("{} {}", ipv4_hint, ipv6_hint);
    Ok((dns_data, message))
}

/// Get the MAC Address from the log data
pub(crate) fn get_dns_mac_addr(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode dns mac address data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode DNS mac address details");
        }
    };

    let message_results = parse_mac_addr(&decoded_data);
    match message_results {
        Ok((_, results)) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse DNS mac address data: {:?}",
                err
            );
            String::from("Failed to parse DNS mac address data")
        }
    }
}

/// Parse the MAC Address
fn parse_mac_addr(dns_data: &[u8]) -> nom::IResult<&[u8], String> {
    let mut mac_data: Vec<String> = Vec::new();
    let mut data = dns_data;

    while !data.is_empty() {
        let (remaining_data, addr) = take(size_of::<u8>())(data)?;
        data = remaining_data;

        let (_, mac_addr) = be_u8(addr)?;
        mac_data.push(format!("{:02X?}", mac_addr));
    }
    Ok((data, mac_data.join(":")))
}

/// Get IP Address info from log data
pub(crate) fn dns_ip_addr(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode dns ip address data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode DNS ip address details");
        }
    };
    let message_results = parse_dns_ip_addr(&decoded_data);
    match message_results {
        Ok((_, results)) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to parse DNS ip address data: {:?}",
                err
            );
            String::from("Failed to parse DNS mac address data")
        }
    }
}

/// Parse IP Address data
fn parse_dns_ip_addr(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (data, ip_type) = take(size_of::<u32>())(data)?;
    let (_, ip) = le_u32(ip_type)?;
    let ipv4 = 4;
    let ipv6 = 6;
    if ip == ipv4 {
        return get_ip_four(data);
    } else if ip == ipv6 {
        return get_ip_six(data);
    }
    warn!("[macos-unifiedlogs] Unknown DNS IP Addr type: {}", ip);
    Ok((data, format!("Unknown DNS IP Addr type: {}", ip)))
}

/// Translate DNS add/rmv log values
pub(crate) fn dns_addrmv(data: &str) -> String {
    if data == "1" {
        return String::from("add");
    }
    String::from("rmv")
}

/// Translate DNS records to string
pub(crate) fn dns_records(data: &str) -> String {
    // Found at https://en.wikipedia.org/wiki/List_of_DNS_record_types
    let message = match data {
        "1" => "A",
        "2" => "NS",
        "5" => "CNAME",
        "6" => "SOA",
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
            warn!(
                "[macos-unifiedlogs] Unknown DNS Resource Record Type: {}",
                data
            );
            data
        }
    };
    message.to_string()
}

/// Translate DNS response/reason? to string
pub(crate) fn dns_reason(data: &str) -> String {
    let message = match data {
        "1" => "no-data",
        "4" => "query-suppressed",
        "3" => "no-dns-service",
        "2" => "nxdomain",
        "5" => "server error",
        _ => {
            warn!("[macos-unifiedlogs] Unknown DNS Reason: {}", data);
            data
        }
    };
    message.to_string()
}

/// Translate the DNS protocol used
pub(crate) fn dns_protocol(data: &str) -> String {
    let message = match data {
        "1" => "UDP",
        "2" => "TCP",
        //"3" => "HTTP",??
        "4" => "HTTPS",
        _ => {
            warn!("[macos-unifiedlogs] Unknown DNS Protocol: {}", data);
            data
        }
    };
    message.to_string()
}

/// Get just the DNS flags associated with the DNS header
pub(crate) fn dns_idflags(data: &str) -> String {
    let flags_results = data.parse::<u32>();
    let flags: u32 = match flags_results {
        Ok(results) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to convert ID Flags to int: {:?}",
                err
            );
            return data.to_string();
        }
    };

    let mut bytes = [0u8; size_of::<u32>()];
    let result = bytes.as_mut().write_u32::<BigEndian>(flags);
    match result {
        Ok(_) => {}
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to convert ID Flags to bytes: {:?}",
                err
            );
            return data.to_string();
        }
    }

    let message_result = parse_idflags(&bytes);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to get ID Flags: {:?}", err);
            data.to_string()
        }
    }
}

/// Parse just the DNS flags associated with the DNS header
fn parse_idflags(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (dns_data, id_data) = take(size_of::<u16>())(data)?;
    let flag_results = get_dns_flags(dns_data);

    let (_, id) = be_u16(id_data)?;

    let message = match flag_results {
        Ok((_, result)) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to parse ID Flags: {:?}", err);
            String::from("Failed to parse ID Flags")
        }
    };

    let (_, flags) = be_u16(dns_data)?;
    Ok((
        dns_data,
        format!("id: {:#X?}, flags: {:#X?} {}", id, flags, message),
    ))
}

/// Get just the DNS count data associated with the DNS header
pub(crate) fn dns_counts(data: &str) -> String {
    let flags_results = data.parse::<u64>();
    let flags: u64 = match flags_results {
        Ok(results) => results,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to convert counts to int: {:?}",
                err
            );
            return data.to_string();
        }
    };

    let mut bytes = [0u8; size_of::<u64>()];
    let result = bytes.as_mut().write_u64::<BigEndian>(flags);
    match result {
        Ok(_) => {}
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to convert counts to bytes: {:?}",
                err
            );
            return data.to_string();
        }
    }

    let message_result = parse_counts(&bytes);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to get counts: {:?}", err);
            data.to_string()
        }
    }
}

/// parse just the DNS count data associated with the DNS header
fn parse_counts(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (dns_data, question_data) = take(size_of::<u16>())(data)?;
    let (dns_data, answer_data) = take(size_of::<u16>())(dns_data)?;
    let (dns_data, authority_data) = take(size_of::<u16>())(dns_data)?;
    let (dns_data, additional_data) = take(size_of::<u16>())(dns_data)?;

    let (_, question) = be_u16(question_data)?;
    let (_, answer) = be_u16(answer_data)?;
    let (_, authority) = be_u16(authority_data)?;
    let (_, additional) = be_u16(additional_data)?;

    let header_message = format!(
        "Question Count: {}, Answer Record Count: {}, Authority Record Count: {}, Additional Record Count: {}",
        question,
        answer,
        authority,
        additional);

    Ok((dns_data, header_message))
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
pub(crate) fn dns_getaddrinfo_opts(data: &str) -> String {
    let message = match data {
        "8" => "0x8 {use-failover}",
        "12" => "0xC {in-app-browser, use-failover}",
        _ => {
            warn!("[macos-unifiedlogs] Unknown getaddrinfo options: {}", data);
            data
        }
    };
    message.to_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        decoders::dns::{
            dns_acceptable, dns_addrmv, dns_counts, dns_getaddrinfo_opts, dns_idflags, dns_ip_addr,
            dns_protocol, dns_reason, dns_records, dns_yes_no, get_dns_flags, get_dns_header,
            get_dns_mac_addr, get_domain_name, get_service_binding, parse_counts, parse_dns_header,
            parse_dns_ip_addr, parse_idflags, parse_mac_addr, parse_svcb, parse_svcb_alpn,
            parse_svcb_ip,
        },
        util::decode_standard,
    };

    #[test]
    fn test_parse_dns_header() {
        let test_data = "uXMBAAABAAAAAAAA";
        let result = parse_dns_header(test_data);
        assert_eq!(result, "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0");
    }

    #[test]
    fn test_get_dns_flags() {
        let test_data = [185, 115, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let (_, result) = get_dns_header(&test_data).unwrap();
        assert_eq!(result, "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0");
    }

    #[test]
    fn test_get_dns_header() {
        let test_data = [1, 0];
        let (_, result) = get_dns_flags(&test_data).unwrap();
        assert_eq!(result, "Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error");
    }

    #[test]
    fn test_get_domain_name() {
        let test_data = "AzE0NAMxMDEDMTY4AzE5Mgdpbi1hZGRyBGFycGEA";
        let result = get_domain_name(&test_data);
        assert_eq!(result, ".144.101.168.192.in-addr.arpa");
    }

    #[test]
    fn test_get_service_binding() {
        let test_data =
            "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA==";
        let result = get_service_binding(&test_data);
        assert_eq!(result, "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540,");
    }

    #[test]
    fn test_parse_svcb() {
        let test_data =
            "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = parse_svcb(&decoded_data_result).unwrap();
        assert_eq!(result, "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540,");
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
        assert_eq!(result, "ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540,");
    }

    #[test]
    fn test_get_dns_mac_addr() {
        let test_data = "AAAAAAAA";

        let result = get_dns_mac_addr(&test_data);
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

        let result = dns_ip_addr(&test_data);
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

        let result = dns_addrmv(&test_data);
        assert_eq!(result, "add");
    }

    #[test]
    fn test_dns_records() {
        let test_data = "65";

        let result = dns_records(&test_data);
        assert_eq!(result, "HTTPS");
    }

    #[test]
    fn test_dns_reason() {
        let test_data = "1";

        let result = dns_reason(&test_data);
        assert_eq!(result, "no-data");
    }

    #[test]
    fn test_dns_protocol() {
        let test_data = "1";

        let result = dns_protocol(&test_data);
        assert_eq!(result, "UDP");
    }

    #[test]
    fn test_dns_idflags() {
        let test_data = "2126119168";

        let result = dns_idflags(&test_data);
        assert_eq!(result, "id: 0x7EBA, flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error");
    }

    #[test]
    fn test_parse_idflags() {
        let test_data = vec![0x7e, 0xba, 0x1, 0];

        let (_, result) = parse_idflags(&test_data).unwrap();
        assert_eq!(result, "id: 0x7EBA, flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error");
    }

    #[test]
    fn test_dns_counts() {
        let test_data = "281474976710656";

        let result = dns_counts(&test_data);
        assert_eq!(result, "Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0");
    }

    #[test]
    fn test_parse_counts() {
        let test_data = vec![0, 1, 0, 0, 0, 0, 0, 0];

        let (_, result) = parse_counts(&test_data).unwrap();
        assert_eq!(result, "Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0");
    }

    #[test]
    fn test_dns_yes_no() {
        let test_data = "0";

        let result = dns_yes_no(&test_data);
        assert_eq!(result, "no");
    }

    #[test]
    fn test_dns_acceptable() {
        let test_data = "0";

        let result = dns_acceptable(&test_data);
        assert_eq!(result, "unacceptable");
    }

    #[test]
    fn test_dns_getaddrinfo_opts() {
        let test_data = "8";

        let result = dns_getaddrinfo_opts(&test_data);
        assert_eq!(result, "0x8 {use-failover}");
    }
}