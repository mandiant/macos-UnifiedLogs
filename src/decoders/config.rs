// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::network::{get_ip_four, get_ip_six};
use crate::util::{encode_standard, extract_string};
use log::warn;
use nom::{
    bytes::complete::take,
    number::complete::{be_u32, be_u64},
};

/// Parse DNS configuration. Can view live data with macOS command `scutil --dns`. This info is also logged to the Unified Log
pub(crate) fn get_dns_config(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (input, resolver_count) = be_u32(data)?;

    // Seen only zero
    let (input, _unknown) = take(8_u8)(input)?;
    let (input, scope_count) = be_u32(input)?;
    // Seen only zero
    let (input, _unknown) = take(8_u8)(input)?;

    // Seen 0x5D8D7152
    let (input, _unknown) = take(4_u8)(input)?;
    // Seen 0x0
    let (input, _unknown) = take(16_u8)(input)?;

    // Seen 0x85C73301
    let (input, _unknown) = take(4_u8)(input)?;

    // Seen 0x000005EC. Maybe a size?
    let (input, _unknown) = take(4_u8)(input)?;

    // Seen 0x00000070. Maybe a size?
    let (input, _unknown) = take(4_u8)(input)?;

    let total_count = resolver_count + scope_count;
    let (_, message) = parse_dns_config(input, &total_count)?;

    Ok((input, message))
}

/// Parse the DNS config data and assemble message
fn parse_dns_config<'a>(
    data: &'a [u8],
    resolver_scope_count: &u32,
) -> nom::IResult<&'a [u8], String> {
    let mut count = 0;
    let mut remaining = data;
    let mut resolvers = Vec::new();
    let mut scopes = Vec::new();
    while count < *resolver_scope_count {
        // 1 = DNS Resolver. 2 = DNS Scope. Both appear to have same format
        let (input, resolver_or_scope) = be_u32(remaining)?;
        let (input, size) = be_u32(input)?;

        let adjust = 8;
        if adjust > size {
            break;
        }
        // Size includes `resolver_or_scope` amd `size` value
        let (input, config_data) = take(size - adjust)(input)?;
        remaining = input;

        match resolver_or_scope {
            1 => resolvers.push(parse_dns_resolver(config_data)?.1),
            2 => scopes.push(parse_dns_resolver(config_data)?.1),
            _ => {
                warn!(
                    "[macos-unifiedlogs] Unknown DNS config type. Neither resolver or scope: {resolver_or_scope}"
                );
                return Ok((
                    remaining,
                    format!(
                        "Unknown DNS config type. Neither resolver or scope: {resolver_or_scope}: {}",
                        encode_standard(data)
                    ),
                ));
            }
        };
        count += 1;
    }

    // Now assemble our message!
    let mut message = String::from("DNS Configuration\n");
    message += &assemble_message(&message, &resolvers);

    message += "DNS configuration (for scoped queries)\n\n";
    message += &assemble_message(&message, &scopes);

    Ok((remaining, message))
}

/// Combine our `DnsConfigs` into single message
fn assemble_message(log_message: &str, configs: &[DnsConfig]) -> String {
    let mut message = log_message.to_string();
    for (key, entry) in configs.iter().enumerate() {
        let mut resolver_message = format!("resolver #{key}\n");
        for (index, value) in entry.search_domains.iter().enumerate() {
            resolver_message += &format!("  search domain[{index}] : {value}\n");
        }
        for (index, value) in entry.nameservers.iter().enumerate() {
            resolver_message += &format!("  nameserver[{index}] : {value}\n");
        }

        if entry.if_index != 0 && !entry.if_index_value.is_empty() {
            resolver_message += &format!(
                "  if_index : {} ({})\n",
                entry.if_index, entry.if_index_value
            );
        }

        if !entry.domain.is_empty() {
            resolver_message += &format!("  domain   : {}\n", entry.domain);
        }
        if !entry.options.is_empty() {
            resolver_message += &format!("  options  : {}\n", entry.options);
        }
        if entry.timeout != 0 {
            resolver_message += &format!("  timeout  : {}\n", entry.timeout);
        }

        resolver_message += &format!(
            "  flags    : {:#010x?} {}\n",
            entry.dns_flags, entry.dns_flags_string
        );
        resolver_message += &format!(
            "  reach    : {:#010x?} {}\n",
            entry.reach, entry.reach_string
        );
        if entry.order != 0 {
            resolver_message += &format!("  order    : {}\n", entry.order);
        }
        resolver_message += &format!("  config id: {}\n\n", entry.config_id);

        message += &resolver_message;
    }

    message
}

#[derive(Debug, Default)]
struct DnsConfig {
    nameservers: Vec<String>,
    search_domains: Vec<String>,
    timeout: u32,
    order: u32,
    if_index: u32,
    if_index_value: String,
    dns_flags: u32,
    dns_flags_string: String,
    reach: u32,
    reach_string: String,
    config_id: String,
    options: String,
    domain: String,
    unknown: String,
}

/// Parse DNS resolver data
fn parse_dns_resolver(data: &[u8]) -> nom::IResult<&[u8], DnsConfig> {
    // Seen 0x0
    let (input, _unknown) = take(8_u8)(data)?;
    let (input, _nameserver_count) = be_u32(input)?;

    // Seen 0x0. 3 flags? (each 4 bytes?)
    let (input, _unknown) = take(12_u8)(input)?;
    let (input, _search_domain_count) = be_u32(input)?;

    // Seen 0x0. More flags?
    let (input, _unknown) = take(28_u8)(input)?;

    let (input, timeout) = be_u32(input)?;
    let (input, order) = be_u32(input)?;
    let (input, if_index) = be_u32(input)?;
    let (input, dns_flags) = be_u32(input)?;
    let (input, reach) = be_u32(input)?;

    // Seen 0x0. More flags?
    let (input, _unknown) = take(20_u8)(input)?;
    // Size for remaining bytes
    let (input, _size) = be_u32(input)?;

    // remaining bytes is variety of config options
    let min_size = 10;
    let mut remaining = input;
    let mut config = DnsConfig {
        timeout,
        order,
        if_index,
        dns_flags,
        reach,
        ..Default::default()
    };
    if dns_flags == 6 {
        config.dns_flags_string = String::from("(Request A records, Request AAAA records)");
    }
    if reach == 0 {
        config.reach_string = String::from("(Not Reachable)")
    } else if reach == 0x00020002 {
        config.reach_string = String::from("(Reachable, Directly Reachable Address)")
    }
    while remaining.len() > min_size {
        // Option types:
        // 0xc - search domain
        // 0xb - nameserver
        // 0x10 - if_index value
        // 0xa - domain
        // 0xe - options
        // 0xf - config id
        let (input, option_type) = be_u32(remaining)?;
        let (input, option_size) = be_u32(input)?;
        let adjust: u32 = 8;
        if adjust > option_size {
            break;
        }

        // `option_size` includes `option_type` and `option_size`
        let (input, option_data) = take(option_size - adjust)(input)?;
        remaining = input;
        match option_type {
            0xc => config.search_domains.push(extract_string(option_data)?.1),
            0x10 => config.if_index_value = extract_string(option_data)?.1,
            0xb => config.nameservers.push(parse_nameserver(option_data)?.1),
            0xf => config.config_id = extract_string(option_data)?.1,
            0xa => config.domain = extract_string(option_data)?.1,
            0xe => config.options = extract_string(option_data)?.1,
            _ => {
                warn!("[macos-unifiedlogs] Unknown DNS option type: {option_type}");
                config.unknown = format!(
                    "Unknown DNS option type: {option_type}: {}",
                    encode_standard(data)
                );
                return Ok((remaining, config));
            }
        }
    }

    Ok((input, config))
}

/// Parse nameserver IPv4 or IPv6
fn parse_nameserver(data: &[u8]) -> nom::IResult<&[u8], String> {
    let ipv4 = 16;
    let ipv6 = 28;
    let (input, value) = if data.len() == ipv4 {
        // Flags?
        let (input, _unknown) = be_u32(data)?;
        let (input, ip) = get_ip_four(input)?;
        (input, ip.to_string())
    } else if data.len() == ipv6 {
        // Flags?
        let (input, _unknown) = be_u64(data)?;
        let (input, ip) = get_ip_six(input)?;
        (input, ip.to_string())
    } else {
        warn!("[macos-unifiedlogs] Unknown nameserver data type");
        (
            data,
            format!("Unknown nameserver data type: {}", encode_standard(data)),
        )
    };

    Ok((input, value))
}

#[cfg(test)]
mod tests {
    use super::{get_dns_config, parse_dns_config, parse_dns_resolver, parse_nameserver};

    #[test]
    fn test_get_dns_config() {
        let test_data = [
            0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 93, 141, 113,
            82, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 133, 199, 51, 1, 0, 0, 5, 236, 0,
            0, 0, 112, 0, 0, 0, 1, 0, 0, 0, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 6, 0, 2, 0,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0,
            12, 0, 0, 0, 12, 108, 97, 110, 0, 0, 0, 0, 16, 0, 0, 0, 12, 101, 110, 48, 0, 0, 0, 0,
            11, 0, 0, 0, 24, 16, 2, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0,
            0, 0, 36, 28, 30, 0, 0, 0, 0, 0, 0, 253, 169, 223, 235, 210, 116, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 20, 68, 101, 102, 97, 117, 108, 116, 58, 32,
            48, 0, 0, 0, 0, 0, 2, 0, 0, 0, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 16, 6, 0, 2,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 0, 0,
            0, 12, 0, 0, 0, 12, 108, 97, 110, 0, 0, 0, 0, 16, 0, 0, 0, 12, 101, 110, 48, 0, 0, 0,
            0, 11, 0, 0, 0, 24, 16, 2, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11,
            0, 0, 0, 36, 28, 30, 0, 0, 0, 0, 0, 0, 253, 169, 223, 235, 210, 116, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 56, 83, 99, 111, 112, 101, 100, 58, 32,
            52, 52, 70, 56, 67, 67, 50, 68, 45, 67, 65, 66, 51, 45, 52, 57, 69, 65, 45, 66, 50, 67,
            48, 45, 69, 66, 51, 51, 68, 57, 50, 57, 53, 67, 67, 65, 32, 48, 0, 0, 0, 0, 0, 1, 0, 0,
            0, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 5, 0, 4, 147, 224, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 10, 0, 0, 0, 16, 108, 111,
            99, 97, 108, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0,
            0, 15, 0, 0, 0, 28, 77, 117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32,
            48, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 148, 168, 0, 0, 0, 0, 0, 0, 0, 6,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 0,
            0, 0, 10, 0, 0, 0, 32, 50, 53, 52, 46, 49, 54, 57, 46, 105, 110, 45, 97, 100, 100, 114,
            46, 97, 114, 112, 97, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0,
            0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77, 117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78,
            83, 58, 32, 49, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 149, 112, 0, 0, 0, 0,
            0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 68, 0, 0, 0, 10, 0, 0, 0, 24, 56, 46, 101, 46, 102, 46, 105, 112, 54, 46, 97,
            114, 112, 97, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0,
            15, 0, 0, 0, 28, 77, 117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 50,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 150, 56, 0, 0, 0, 0, 0, 0, 0, 6, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0,
            0, 10, 0, 0, 0, 24, 57, 46, 101, 46, 102, 46, 105, 112, 54, 46, 97, 114, 112, 97, 0, 0,
            0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77,
            117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 51, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 151, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 10, 0, 0, 0, 24,
            97, 46, 101, 46, 102, 46, 105, 112, 54, 46, 97, 114, 112, 97, 0, 0, 0, 0, 0, 14, 0, 0,
            0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77, 117, 108, 116,
            105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 52, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 5, 0, 4, 151, 200, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 10, 0, 0, 0, 24, 98, 46, 101,
            46, 102, 46, 105, 112, 54, 46, 97, 114, 112, 97, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109,
            100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77, 117, 108, 116, 105, 99, 97,
            115, 116, 32, 68, 78, 83, 58, 32, 53, 0, 0, 0, 0,
        ];

        let (_, result) = get_dns_config(&test_data).unwrap();
        assert!(result.contains("  domain   : 254.169.in-addr.arpa\n"));
        assert!(result.contains("config id: Scoped: 44F8CC2D-CAB3-49EA-B2C0-EB33D9295CCA 0"))
    }

    #[test]
    fn test_parse_nameserver() {
        let test_data = [16, 2, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let (_, result) = parse_nameserver(&test_data).unwrap();
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_parse_dns_resolver() {
        let test_data = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 6, 0, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 12, 0, 0, 0, 12, 108, 97, 110, 0, 0,
            0, 0, 16, 0, 0, 0, 12, 101, 110, 48, 0, 0, 0, 0, 11, 0, 0, 0, 24, 16, 2, 0, 0, 192,
            168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 36, 28, 30, 0, 0, 0, 0, 0, 0,
            253, 169, 223, 235, 210, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 15, 0,
            0, 0, 20, 68, 101, 102, 97, 117, 108, 116, 58, 32, 48, 0, 0,
        ];

        let (_, result) = parse_dns_resolver(&test_data).unwrap();
        assert_eq!(result.nameservers.len(), 2);
        assert_eq!(result.search_domains[0], "lan");
        assert_eq!(result.config_id, "Default: 0");
    }

    #[test]
    fn test_parse_dns_config() {
        let test_data = [
            0, 0, 0, 1, 0, 0, 0, 212, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 6, 0, 2, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 0, 0, 0, 12, 0, 0,
            0, 12, 108, 97, 110, 0, 0, 0, 0, 16, 0, 0, 0, 12, 101, 110, 48, 0, 0, 0, 0, 11, 0, 0,
            0, 24, 16, 2, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 36,
            28, 30, 0, 0, 0, 0, 0, 0, 253, 169, 223, 235, 210, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 20, 68, 101, 102, 97, 117, 108, 116, 58, 32, 48, 0,
            0, 0, 0, 0, 2, 0, 0, 0, 248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 16, 6, 0, 2, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 140, 0, 0, 0, 12,
            0, 0, 0, 12, 108, 97, 110, 0, 0, 0, 0, 16, 0, 0, 0, 12, 101, 110, 48, 0, 0, 0, 0, 11,
            0, 0, 0, 24, 16, 2, 0, 0, 192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0,
            36, 28, 30, 0, 0, 0, 0, 0, 0, 253, 169, 223, 235, 210, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 56, 83, 99, 111, 112, 101, 100, 58, 32, 52, 52,
            70, 56, 67, 67, 50, 68, 45, 67, 65, 66, 51, 45, 52, 57, 69, 65, 45, 66, 50, 67, 48, 45,
            69, 66, 51, 51, 68, 57, 50, 57, 53, 67, 67, 65, 32, 48, 0, 0, 0, 0, 0, 1, 0, 0, 0, 168,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 5, 0, 4, 147, 224, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 10, 0, 0, 0, 16, 108, 111, 99, 97,
            108, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0,
            0, 0, 28, 77, 117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 48, 0, 0,
            0, 0, 0, 0, 0, 1, 0, 0, 0, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 148, 168, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 0, 0, 0,
            10, 0, 0, 0, 32, 50, 53, 52, 46, 49, 54, 57, 46, 105, 110, 45, 97, 100, 100, 114, 46,
            97, 114, 112, 97, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0,
            0, 0, 0, 15, 0, 0, 0, 28, 77, 117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58,
            32, 49, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 149, 112, 0, 0, 0, 0, 0, 0, 0,
            6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68,
            0, 0, 0, 10, 0, 0, 0, 24, 56, 46, 101, 46, 102, 46, 105, 112, 54, 46, 97, 114, 112, 97,
            0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0,
            28, 77, 117, 108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 50, 0, 0, 0, 0,
            0, 0, 0, 1, 0, 0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 4, 150, 56, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 10, 0,
            0, 0, 24, 57, 46, 101, 46, 102, 46, 105, 112, 54, 46, 97, 114, 112, 97, 0, 0, 0, 0, 0,
            14, 0, 0, 0, 16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77, 117,
            108, 116, 105, 99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 51, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 0, 176, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 5, 0, 4, 151, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 10, 0, 0, 0, 24, 97,
            46, 101, 46, 102, 46, 105, 112, 54, 46, 97, 114, 112, 97, 0, 0, 0, 0, 0, 14, 0, 0, 0,
            16, 109, 100, 110, 115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77, 117, 108, 116, 105,
            99, 97, 115, 116, 32, 68, 78, 83, 58, 32, 52, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 176, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            5, 0, 4, 151, 200, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 68, 0, 0, 0, 10, 0, 0, 0, 24, 98, 46, 101, 46, 102,
            46, 105, 112, 54, 46, 97, 114, 112, 97, 0, 0, 0, 0, 0, 14, 0, 0, 0, 16, 109, 100, 110,
            115, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 28, 77, 117, 108, 116, 105, 99, 97, 115, 116,
            32, 68, 78, 83, 58, 32, 53, 0, 0, 0, 0,
        ];

        let count = 8;
        let (_, result) = parse_dns_config(&test_data, &count).unwrap();
        assert!(result.contains("  order    : 300800"))
    }
}
