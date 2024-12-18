// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::DecoderError;
use crate::util::decode_standard;
use log::warn;
use nom::{
    combinator::map,
    number::complete::{be_u128, be_u16, be_u32, be_u8},
    sequence::tuple,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse an IPv6 address
pub(crate) fn ipv_six(input: &str) -> Result<Ipv6Addr, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "ipv vix",
        message: "Failed to base64 decode ipv6 data",
    })?;

    let (_, result) = get_ip_six(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "ipv vix",
        message: "Failed to get ipv6",
    })?;

    Ok(result)
}

/// Parse an IPv4 address
pub(crate) fn ipv_four(input: &str) -> Result<Ipv4Addr, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "ipv four",
        message: "Failed to base64 decode ipv4 data",
    })?;

    let (_, result) = get_ip_four(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "ipv four",
        message: "Failed to get ipv4",
    })?;

    Ok(result)
}

/// Parse a sockaddr structure
pub(crate) fn sockaddr(input: &str) -> Result<String, DecoderError<'_>> {
    if input.is_empty() {
        return Ok(String::from("<NULL>"));
    }

    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sock addr",
        message: "Failed to bas64 decode sockaddr data",
    })?;

    let (_, result) = get_sockaddr_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "ipv four",
        message: "Failed to get sockaddr structure",
    })?;

    Ok(result)
}

/// Get the sockaddr data
fn get_sockaddr_data(input: &[u8]) -> nom::IResult<&[u8], String> {
    let (input, (_total_length, family)) = tuple((be_u8, be_u8))(input)?;

    // Family types seen so far (AF_INET should be used most often)
    match family {
        2 => {
            // AF_INET
            let (input, port) = be_u16(input)?;
            let (input, ip_addr) = get_ip_four(input)?;

            match port {
                0 => Ok((input, ip_addr.to_string())),
                _ => Ok((input, format!("{ip_addr}:{port}"))),
            }
        }
        30 => {
            let (input, (port, flow, ip_addr, scope)) =
                tuple((be_u16, be_u32, get_ip_six, be_u32))(input)?;

            match port {
                0 => Ok((
                    input,
                    format!("{ip_addr}, Flow ID: {flow}, Scope ID: {scope}"),
                )),
                _ => Ok((
                    input,
                    format!("{ip_addr}:{port}, Flow ID: {flow}, Scope ID: {scope}"),
                )),
            }
        }
        _ => {
            warn!("[macos-unifiedlogs] Unknown sockaddr family: {family}. From: {input:?}",);
            Ok((input, format!("Unknown sockaddr family: {family}",)))
        }
    }
}

/// Get the IPv4 data
pub(crate) fn get_ip_four(input: &[u8]) -> nom::IResult<&[u8], Ipv4Addr> {
    map(be_u32, Ipv4Addr::from)(input)
}

/// Get the IPv6 data
pub(crate) fn get_ip_six(input: &[u8]) -> nom::IResult<&[u8], Ipv6Addr> {
    map(be_u128, Ipv6Addr::from)(input)
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
        let result = ipv_six(test_data).unwrap();
        assert_eq!(result.to_string(), "ff02::fb");
    }

    #[test]
    fn test_get_ip_six() {
        let test_data = "/wIAAAAAAAAAAAAAAAAA+w==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_ip_six(&decoded_data_result).unwrap();
        assert_eq!(result.to_string(), "ff02::fb");
    }

    #[test]
    fn test_ipv_four() {
        let test_data = "4AAA+w==";
        let result = ipv_four(test_data).unwrap();
        assert_eq!(result.to_string(), "224.0.0.251");
    }

    #[test]
    fn test_get_ip_four() {
        let test_data = "4AAA+w==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_ip_four(&decoded_data_result).unwrap();
        assert_eq!(result.to_string(), "224.0.0.251");
    }
    #[test]
    fn test_sockaddr() {
        let mut test_data = "EAIAALgciWcAAAAAAAAAAA==";
        let mut result = sockaddr(test_data).unwrap();
        assert_eq!(result, "184.28.137.103");

        test_data = "HB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        result = sockaddr(test_data).unwrap();
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
