// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use crate::util::decode_standard;
use log::{error, warn};
use nom::{
    bytes::complete::take,
    combinator::map,
    number::complete::{be_u128, be_u16, be_u32, be_u8},
};
use std::net::Ipv6Addr;
use std::{mem::size_of, net::Ipv4Addr};

/// Parse an IPv6 address
pub(crate) fn ipv_six(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode ipv6 data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode ipv6 data");
        }
    };
    let message_result = get_ip_six(&decoded_data);

    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to get ipv6: {:?}", err);
            format!("Failed to get ipv6: {}", data)
        }
    }
}

/// Parse an IPv4 address
pub(crate) fn ipv_four(data: &str) -> String {
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to base64 decode ipv4 data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode ipv4 data");
        }
    };
    let message_result = get_ip_four(&decoded_data);

    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to get ipv4: {:?}", err);
            format!("Failed to get ipv4: {}", data)
        }
    }
}

/// Parse a sockaddr structure
pub(crate) fn sockaddr(data: &str) -> String {
    if data.is_empty() {
        return String::from("<NULL>");
    }
    let decoded_data_result = decode_standard(data);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to bas64 decode sockaddr data {}, error: {:?}",
                data, err
            );
            return String::from("Failed to base64 decode sockaddr data");
        }
    };
    let message_result = get_sockaddr_data(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get sockaddr structure: {:?}",
                err
            );
            format!("Failed to get sockaddr: {}", data)
        }
    }
}

/// Get the sockaddr data
fn get_sockaddr_data(data: &[u8]) -> nom::IResult<&[u8], String> {
    let message;
    let (sock_data, _total_length) = take(size_of::<u8>())(data)?;

    let (sock_data, family_data) = take(size_of::<u8>())(sock_data)?;
    let (_, family) = be_u8(family_data)?;

    // Family types seen so far (AF_INET should be used most often)
    match family {
        2 => {
            // AF_INET
            let (sock_data, port_data) = take(size_of::<u16>())(sock_data)?;
            let (_, ip_data) = take(size_of::<u32>())(sock_data)?;

            let (_, port) = be_u16(port_data)?;
            let (_, ip) = be_u32(ip_data)?;
            let ip_addr = Ipv4Addr::from(ip);

            if port != 0 {
                message = format!("{}:{}", ip_addr, port);
            } else {
                message = ip_addr.to_string();
            }
        }
        30 => {
            // AF_INET6
            let (sock_data, port_data) = take(size_of::<u16>())(sock_data)?;
            let (sock_data, flow_data) = take(size_of::<u32>())(sock_data)?;
            let (sock_data, ip_data) = take(size_of::<u128>())(sock_data)?;
            let (_, scope_data) = take(size_of::<u32>())(sock_data)?;

            let (_, port) = be_u16(port_data)?;
            let (_, flow) = be_u32(flow_data)?;
            let (_, ip) = be_u128(ip_data)?;
            let (_, scope) = be_u32(scope_data)?;

            let ip_addr = Ipv6Addr::from(ip);
            if port != 0 {
                message = format!(
                    "{}:{}, Flow ID: {}, Scope ID: {}",
                    ip_addr, port, flow, scope
                );
            } else {
                message = format!("{}, Flow ID: {}, Scope ID: {}", ip_addr, flow, scope);
            }
        }
        _ => {
            warn!(
                "[macos-unifiedlogs] Unknown sockaddr family: {}. From: {:?}",
                family, data
            );
            message = format!("Unknown sockaddr family: {}", family);
        }
    }
    Ok((sock_data, message))
}

/// Get the IPv4 data
pub(crate) fn get_ip_four(input: &[u8]) -> nom::IResult<&[u8], String> {
    map(be_u32, |val| Ipv4Addr::from(val).to_string())(input)
}

/// Get the IPv6 data
pub(crate) fn get_ip_six(input: &[u8]) -> nom::IResult<&[u8], String> {
    map(be_u128, |val| Ipv6Addr::from(val).to_string())(input)
}

#[cfg(test)]
mod tests {
    use crate::{
        decoders::network::{
            get_ip_four, get_ip_six, get_sockaddr_data, ipv_four, ipv_six, sockaddr,
        },
        util::decode_standard,
    };

    #[test]
    fn test_ipv_six() {
        let test_data = "/wIAAAAAAAAAAAAAAAAA+w==";
        let result = ipv_six(test_data);
        assert_eq!(result, "ff02::fb");
    }

    #[test]
    fn test_get_ip_six() {
        let test_data = "/wIAAAAAAAAAAAAAAAAA+w==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_ip_six(&decoded_data_result).unwrap();
        assert_eq!(result, "ff02::fb");
    }

    #[test]
    fn test_ipv_four() {
        let test_data = "4AAA+w==";
        let result = ipv_four(test_data);
        assert_eq!(result, "224.0.0.251");
    }

    #[test]
    fn test_get_ip_four() {
        let test_data = "4AAA+w==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_ip_four(&decoded_data_result).unwrap();
        assert_eq!(result, "224.0.0.251");
    }

    #[test]
    fn test_sockaddr() {
        let mut test_data = "EAIAALgciWcAAAAAAAAAAA==";
        let mut result = sockaddr(test_data);
        assert_eq!(result, "184.28.137.103");

        test_data = "HB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        result = sockaddr(test_data);
        assert_eq!(result, "::, Flow ID: 0, Scope ID: 0");
    }

    #[test]
    fn test_get_sockaddr_data() {
        let test_data = "EAIAALgciWcAAAAAAAAAAA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_sockaddr_data(&decoded_data_result).unwrap();
        assert_eq!(result, "184.28.137.103");
    }
}
