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
    number::complete::{be_u32, be_u64, le_i32, le_u32, le_u64},
};
use std::collections::HashSet;

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

/// Parse `Network Interface` structures. The format is open source at <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_state_information_priv.h>
pub(crate) fn get_network_interface(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (input, _version) = le_u32(data)?;

    // Max number of IPv4 and IPv6 that that can be in the interface list
    let (input, max_protocol_count) = le_u32(input)?;
    let (input, ipv4_count) = le_u32(input)?;
    let (input, ipv6_count) = le_u32(input)?;
    let (input, _list_count) = le_u32(input)?;

    let (input, _ref_count) = le_u32(input)?;
    let (input, _reach_flags_v4) = le_u32(input)?;
    let (input, _reach_flags_v6) = le_u32(input)?;

    let (input, generation_count) = le_u64(input)?;

    // Each interface size seems to be 112 bytes
    let interface_size = 112;
    let (input, ip4_interface_data) = take(interface_size * max_protocol_count)(input)?;
    let (_, ip4_interfaces) = parse_interface(ip4_interface_data, &ipv4_count)?;

    let (input, ip6_interface_data) = take(interface_size * max_protocol_count)(input)?;
    let (_, ip6_interfaces) = parse_interface(ip6_interface_data, &ipv6_count)?;

    let message = assemble_network_interface(
        &ip4_interfaces,
        &ip6_interfaces,
        &generation_count,
        &data.len(),
    );

    Ok((input, message))
}

#[derive(Debug)]
struct NetworkInterface {
    name: String,
    ip: String,
    rank: u32,
    rank_flag: RankFlag,
    rank_position: u32,
    reach: u32,
    reach_flags: Vec<ReachFlags>,
    signature: String,
    generation: u64,
    flag: u64,
    alias_offset: i32,
}

/// Parse interface data
fn parse_interface<'a>(
    data: &'a [u8],
    interface_count: &u32,
) -> nom::IResult<&'a [u8], Vec<NetworkInterface>> {
    let mut remaining = data;
    let mut count = 0;

    let min_size = 112;
    let mut interfaces = Vec::new();
    while count < *interface_count && remaining.len() >= min_size {
        let name_size: u8 = 16;
        let (input, interface_name) = take(name_size)(remaining)?;
        let (_, name) = extract_string(interface_name)?;

        let (input, flag) = le_u64(input)?;
        let (input, alias_offset) = le_i32(input)?;
        let (input, rank) = le_u32(input)?;

        // Either IPv4 or IPv6. 2 = IPv4, 0x1E = IPv6
        let (input, interface_family) = le_u32(input)?;
        let ip_len: u8 = 16;
        let (input, ip_data) = take(ip_len)(input)?;
        let ip = match interface_family {
            0x2 => get_ip_four(ip_data)?.1.to_string(),
            0x1E => get_ip_six(ip_data)?.1.to_string(),
            _ => {
                warn!("[macos-unifiedlogs] Unknown interface family: {interface_family}");
                format!("Unknown interface family: {interface_family}")
            }
        };

        let (input, generation) = le_u64(input)?;
        let (input, reach) = le_u32(input)?;
        let vpn_ip_size: u8 = 28;
        let (input, _vpn_ip_data) = take(vpn_ip_size)(input)?;

        let sig_size: u8 = 20;
        let (input, sig) = take(sig_size)(input)?;

        let (rank_flag, rank_position) = get_rank(&rank);
        let interface = NetworkInterface {
            name,
            ip,
            rank,
            reach,
            signature: format!("0x{sig:02x?}")
                .replace(", ", "")
                .replace("[", "")
                .replace("]", ""),
            generation,
            flag,
            reach_flags: get_reach(&reach),
            rank_flag,
            rank_position,
            alias_offset,
        };

        interfaces.push(interface);

        remaining = input;
        count += 1;
    }

    Ok((remaining, interfaces))
}

#[derive(Debug)]
enum ReachFlags {
    Reachable,
    ConnectionRequired,
    ConnectionOnTraffic,
    InterventionRequired,
    ConnectionOnDemand,
    IsLocalAddress,
    IsDirect,
    /**Not used by network interface: <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_information.c#L595> */
    //TransientConnection,
    IsWwan,
}

/// Determine reach flags. Do the opposite bitwise operation defined here: <https://github.com/orta/tickets/blob/master/SystemConfiguration.framework/Versions/A/Headers/SCNetworkReachability.h>
fn get_reach(reach: &u32) -> Vec<ReachFlags> {
    let mut flags = Vec::new();
    if reach >> 1 != 0 {
        flags.push(ReachFlags::Reachable);
    }
    if reach >> 2 != 0 {
        flags.push(ReachFlags::ConnectionRequired);
    }
    if reach >> 3 != 0 {
        flags.push(ReachFlags::ConnectionOnTraffic);
    }
    if reach >> 4 != 0 {
        flags.push(ReachFlags::InterventionRequired);
    }
    if reach >> 5 != 0 {
        flags.push(ReachFlags::ConnectionOnDemand);
    }
    if reach >> 16 != 0 {
        flags.push(ReachFlags::IsLocalAddress);
    }
    if reach >> 17 != 0 {
        flags.push(ReachFlags::IsDirect);
    }
    if reach >> 18 != 0 {
        flags.push(ReachFlags::IsWwan);
    }

    flags
}

#[derive(Debug, PartialEq)]
enum RankFlag {
    First,
    Default,
    Last,
    Never,
    Scoped,
    Mask,
    Unknown,
}

/// Check the rank flags. See: <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_state_information_priv.h#L62>
fn get_rank(rank: &u32) -> (RankFlag, u32) {
    let top_8_bits = 24;
    let rank_value = rank >> top_8_bits;
    let value = match rank_value {
        0x0 => RankFlag::First,
        0x1 => RankFlag::Default,
        0x2 => RankFlag::Last,
        0x3 => RankFlag::Never,
        0x4 => RankFlag::Scoped,
        0xff => RankFlag::Mask,
        _ => RankFlag::Unknown,
    };

    let bottom_8_bits = 0xffffff;
    (value, (rank & bottom_8_bits))
}

/// Assemble our log message
fn assemble_network_interface(
    ip4: &[NetworkInterface],
    ip6: &[NetworkInterface],
    generation_count: &u64,
    size: &usize,
) -> String {
    let mut message = format!(
        "Network information (generation {generation_count} size={size})\nIPv4 network interface information\n"
    );

    let ip4_count: i32 = ip4.len().try_into().unwrap_or_default();
    let ip6_count: i32 = ip6.len().try_into().unwrap_or_default();

    // ipv4 first
    message = combine_data(&message, ip4, &ip4_count, &ip6_count, &true);
    message += "IPv6 network interface information\n";
    message = combine_data(&message, ip6, &ip4_count, &ip6_count, &false);

    let mut names = HashSet::new();
    for entry in ip4 {
        if entry.rank_flag == RankFlag::Never {
            continue;
        }
        names.insert(entry.name.clone());
    }
    for entry in ip6 {
        if entry.rank_flag == RankFlag::Never {
            continue;
        }
        names.insert(entry.name.clone());
    }

    message += &format!(
        "Network interfaces: {}\n",
        names.into_iter().collect::<Vec<_>>().join(", ")
    );

    message
}

/// Combine interface log data
fn combine_data(
    log_message: &str,
    interfaces: &[NetworkInterface],
    ip4_count: &i32,
    ip6_count: &i32,
    is_ip4: &bool,
) -> String {
    let mut message = log_message.to_string();
    for entry in interfaces {
        let (flag, values) = get_flags(
            &entry.flag,
            ip4_count,
            ip6_count,
            &entry.alias_offset,
            is_ip4,
        );
        let mut ip4_message = format!(
            "     {} : flags      : 0x{flag:01x?} ({})\n",
            entry.name,
            values.join(",")
        );
        ip4_message += &format!("           address    : {}\n", entry.ip);
        ip4_message += &format!(
            "           reach      : 0x{:08x?} {:?}\n",
            entry.reach, entry.reach_flags
        );
        ip4_message += &format!(
            "           rank       : 0x{:08x?} ({:?}, 0x{:x?})\n",
            entry.rank, entry.rank_flag, entry.rank_position
        );
        if entry.signature != "0x0000000000000000000000000000000000000000" {
            ip4_message += &format!(
                "           signature  : {{length = 20, bytes = {}}}\n",
                entry.signature
            );
        }

        ip4_message += &format!("           generation : {}\n", entry.generation);
        ip4_message += &format!(
            "   REACH : flags 0x{:010x?} {:?}\n",
            entry.reach, entry.reach_flags
        );

        message += &ip4_message;
    }
    message
}

/// Get interface flags
fn get_flags(
    flags: &u64,
    ip4_count: &i32,
    ip6_count: &i32,
    alias: &i32,
    is_ip4: &bool,
) -> (u64, Vec<String>) {
    // Combine both because interface flags may reference another interface in out list
    let list_size = ip4_count + ip6_count;
    // <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_information.h#L132>
    let dns = 0x4;
    let cat46 = 0x40;
    let not_in_list = 0x8;
    let not_in_iflist = 0x20;

    let mut flag = if *is_ip4 { 0x1 } else { 0x2 };
    let mut values = if *is_ip4 {
        vec![String::from("IPv4")]
    } else {
        vec![String::from("IPv6")]
    };
    if (flags & dns) != 0 {
        flag |= dns;
        values.push(String::from("DNS"));
    }
    if (flags & cat46) != 0 {
        flag |= cat46;
        // Client address translation. Converts IPv4 to IPv6
        values.push(String::from("CAT46"));
    }
    if (flags & not_in_list) != 0 {
        flag |= not_in_list;
        values.push(String::from("NOT-IN-LIST"));
    }
    if (flags & not_in_iflist) != 0 {
        flag |= not_in_iflist;
        values.push(String::from("NOT-IN-IFLIST"));
    }
    if *alias != 0 {
        if alias > ip4_count && alias < &list_size {
            flag |= 0x2;
            values.push(String::from("IPv6"));
        } else if *alias < 0 && (alias + *ip6_count) == 0 {
            // Go back to top of list to ip4
            flag |= 0x1;
            values.push(String::from("IPv4"));
        }
    }

    (flag, values)
}

#[cfg(test)]
mod tests {
    use super::{
        get_dns_config, get_network_interface, parse_dns_config, parse_dns_resolver,
        parse_nameserver,
    };

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

    #[test]
    fn test_get_network_interface() {
        let test_data = [
            1, 6, 23, 32, 5, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 233, 246, 63, 88, 0, 0, 0, 0, 101, 110, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 20, 16, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 1, 2, 0, 0, 0, 192, 168, 1,
            207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 188, 115, 113, 82, 0, 0, 0, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 79,
            188, 16, 197, 131, 35, 6, 37, 209, 229, 76, 240, 15, 141, 81, 161, 43, 159, 32, 163, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101, 110, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 20, 0, 0, 0, 0, 0, 0, 0, 251, 255, 255, 255, 1, 0, 0, 1, 30, 0, 0, 0, 38, 1, 1, 64,
            130, 127, 145, 89, 8, 12, 44, 28, 204, 148, 197, 68, 188, 115, 113, 82, 0, 0, 0, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 254, 120, 12, 133, 246, 51, 156, 83, 53, 81, 189, 131, 73, 77, 20, 12, 210, 156,
            182, 14, 117, 116, 117, 110, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 255, 255, 255, 3, 30, 0, 0, 0, 254, 128, 0, 24, 0, 0, 0, 0, 53, 110, 77,
            124, 154, 97, 36, 30, 212, 172, 62, 88, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 116, 117, 110, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 3, 30, 0, 0, 0, 254, 128, 0, 22,
            0, 0, 0, 0, 42, 17, 32, 15, 213, 15, 201, 123, 202, 67, 233, 86, 0, 0, 0, 0, 2, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 116, 117, 110, 51, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 3,
            30, 0, 0, 0, 254, 128, 0, 25, 0, 0, 0, 0, 206, 129, 11, 28, 189, 44, 6, 158, 233, 246,
            63, 88, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 117, 116, 117, 110, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 16, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 255, 255, 255, 3, 30, 0, 0, 0, 254, 128, 0, 23, 0, 0, 0, 0, 212, 70, 90,
            241, 2, 170, 244, 54, 34, 65, 8, 88, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];

        let (_, result) = get_network_interface(&test_data).unwrap();
        assert!(result.contains("utun2 : flags      : 0x2a (IPv6,NOT-IN-LIST,NOT-IN-IFLIST)"));
        assert!(result.contains("Network information (generation 1480586985 size=1180)"));
        assert!(result.contains("           signature  : {length = 20, bytes = 0x4fbc10c583230625d1e54cf00f8d51a12b9f20a3}"));
    }
}
