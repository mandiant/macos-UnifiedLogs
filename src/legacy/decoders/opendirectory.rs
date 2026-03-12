// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::DecoderError;
use crate::util::{decode_standard, non_empty_cstring};
use log::warn;
use nom::{
    Parser,
    bytes::complete::take,
    multi::fold_many0,
    number::complete::{le_i32, le_u8, le_u32},
};
use std::fmt::Write;

/// Convert Open Directory error codes to message
pub(crate) fn errors(oderror: &str) -> String {
    // Found at https://developer.apple.com/documentation/opendirectory/odframeworkerrors?changes=__2&language=objc
    let message = match oderror {
        "5301" => "ODErrorCredentialsAccountDisabled",
        "5302" => "ODErrorCredentialsAccountExpired",
        "5303" => "ODErrorCredentialsAccountInactive",
        "5300" => "ODErrorCredentialsAccountNotFound",
        "5000" => "ODErrorCredentialsInvalid",
        "5001" => "ODErrorCredentialsInvalidComputer",
        "5500" => "ODErrorCredentialsInvalidLogonHours",
        "5100" => "ODErrorCredentialsMethodNotSupported",
        "5101" => "ODErrorCredentialsNotAuthorized",
        "5103" => "ODErrorCredentialsOperationFailed",
        "5102" => "ODErrorCredentialsParameterError",
        "5401" => "ODErrorCredentialsPasswordChangeRequired",
        "5407" => "ODErrorCredentialsPasswordChangeTooSoon",
        "5400" => "ODErrorCredentialsPasswordExpired",
        "5406" => "ODErrorCredentialsPasswordNeedsDigit",
        "5405" => "ODErrorCredentialsPasswordNeedsLetter",
        "5402" => "ODErrorCredentialsPasswordQualityFailed",
        "5403" => "ODErrorCredentialsPasswordTooShort",
        "5404" => "ODErrorCredentialsPasswordTooLong",
        "5408" => "ODErrorCredentialsPasswordUnrecoverable",
        "5205" => "ODErrorCredentialsServerCommunicationError",
        "5202" => "ODErrorCredentialsServerError",
        "5201" => "ODErrorCredentialsServerNotFound",
        "5203" => "ODErrorCredentialsServerTimeout",
        "5200" => "ODErrorCredentialsServerUnreachable",
        "10002" => "ODErrorDaemonError",
        "2100" => "ODErrorNodeConnectionFailed",
        "2002" => "ODErrorNodeDisabled",
        "2200" => "ODErrorNodeUnknownHost",
        "2000" => "ODErrorNodeUnknownName",
        "2001" => "ODErrorNodeUnknownType",
        "10001" => "ODErrorPluginError",
        "10000" => "ODErrorPluginOperationNotSupported",
        "10003" => "ODErrorPluginOperationTimeout",
        "6001" => "ODErrorPolicyOutOfRange",
        "6000" => "ODErrorPolicyUnsupported",
        "3100" => "ODErrorQueryInvalidMatchType",
        "3000" => "ODErrorQuerySynchronize",
        "3102" => "ODErrorQueryTimeout",
        "3101" => "ODErrorQueryUnsupportedMatchType",
        "4102" => "ODErrorRecordAlreadyExists",
        "4201" => "ODErrorRecordAttributeNotFound",
        "4200" => "ODErrorRecordAttributeUnknownType",
        "4203" => "ODErrorRecordAttributeValueNotFound",
        "4202" => "ODErrorRecordAttributeValueSchemaError",
        "4101" => "ODErrorRecordInvalidType",
        "4104" => "ODErrorRecordNoLongerExists",
        "4100" => "ODErrorRecordParameterError",
        "4001" => "ODErrorRecordPermissionError",
        "4000" => "ODErrorRecordReadOnlyNode",
        "4103" => "ODErrorRecordTypeDisabled",
        "1002" => "ODErrorSessionDaemonNotRunning",
        "1003" => "ODErrorSessionDaemonRefused",
        "1000" => "ODErrorSessionLocalOnlyDaemonInUse",
        "1001" => "ODErrorSessionNormalDaemonInUse",
        "1100" => "ODErrorSessionProxyCommunicationError",
        "1102" => "ODErrorSessionProxyIPUnreachable",
        "1103" => "ODErrorSessionProxyUnknownHost",
        "1101" => "ODErrorSessionProxyVersionMismatch",
        "0" => "ODErrorSuccess",
        "5305" => "ODErrorCredentialsAccountLocked",
        "5304" => "ODErrorCredentialsAccountTemporarilyLocked",
        "5204" => "ODErrorCredentialsContactPrimary",
        "2" => "Not Found",
        _ => {
            warn!("[macos-unifiedlogs] Unknown open directory error code: {oderror}",);
            oderror
        }
    };
    message.to_string()
}

/// Convert Open Directory member ids to string
pub(crate) fn member_id_type(member_string: &str) -> String {
    // Found at /Library/Developer/CommandLineTools/SDKs/MacOSX12.3.sdk/usr/include/membership.h
    let message = match member_string {
        "0" => "UID",
        "1" => "GID",
        "3" => "SID",
        "4" => "USERNAME",
        "5" => "GROUPNAME",
        "6" => "UUID",
        "7" => "GROUP NFS",
        "8" => "USER NFS",
        "10" => "GSS EXPORT NAME",
        "11" => "X509 DN",
        "12" => "KERBEROS",
        _ => {
            warn!("[macos-unifiedlogs] Unknown open directory member id type: {member_string}",);
            member_string
        }
    };
    message.to_string()
}

/// Convert Open Directory member details to string
pub(crate) fn member_details(input: &str) -> Result<String, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "member details",
        message: "Failed to base64 decode open directory member details data",
    })?;

    let (_, result) = get_member_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "member details",
        message: "Failed to get open directory member details",
    })?;

    Ok(result)
}

/// Parse SID log data to SID string
pub(crate) fn sid_details(input: &str) -> Result<String, DecoderError<'_>> {
    let decoded_data = decode_standard(input).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sid details",
        message: "Failed to base64 decode open directory SID details data",
    })?;

    let (_, result) = get_sid_data(&decoded_data).map_err(|_| DecoderError::Parse {
        input: input.as_bytes(),
        parser_name: "sid details",
        message: "Failed to get open directory sid details",
    })?;

    Ok(result)
}

/// Parse Open Directory membership details data
fn get_member_data(input: &[u8]) -> nom::IResult<&[u8], String> {
    let (input, member_type) = le_u8(input)?;
    let (input, member_message) = match member_type {
        35 | 163 => {
            // UID
            let (input, uid) = get_member_id(input)?;
            (input, format!("user: {uid}"))
        }
        36 | 160 | 164 => {
            // USER
            let (input, name) = non_empty_cstring(input)?;
            (input, format!("user: {name}"))
        }
        68 => {
            // GROUP
            let (input, name) = non_empty_cstring(input)?;
            (input, format!("group: {name}"))
        }
        195 => {
            // GID
            let (input, gid) = get_member_id(input)?;
            (input, format!("group: {gid}"))
        }
        _ => {
            warn!("[macos-unifiedlogs] Unknown open directory member type: {member_type}",);
            (input, format!("Unknown Member type {member_type}: @"))
        }
    };

    let (input, source_path) = match non_empty_cstring(input) {
        Ok((input, path)) => (input, format!("@{path}")),
        Err(_) => (input, " <not found>".to_string()),
    };

    let message = format!("{member_message}{source_path}");
    Ok((input, message))
}

/// Get UID/GID for Opendirectory membership
fn get_member_id(input: &[u8]) -> nom::IResult<&[u8], i32> {
    le_i32(input)
}

/// Parse the SID data
fn get_sid_data(input: &[u8]) -> nom::IResult<&[u8], String> {
    let (input, revision) = le_u8(input)?;

    let (input, unknown_size) = le_u8(input)?;
    let (input, _) = take(unknown_size)(input)?;

    let (input, authority) = le_u8(input)?;
    let mut tup = (le_u8, take(3_usize));
    let (input, (subauthority, _)) = tup.parse(input)?;

    let (input, message) = fold_many0(
        le_u32,
        || format!("S-{revision}-{authority}-{subauthority}"),
        |mut acc, additional_subauthority| {
            write!(&mut acc, "-{additional_subauthority}").ok(); // ignored Write error
            acc
        },
    )
    .parse(input)?;

    Ok((input, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::decode_standard;

    #[test]
    fn test_errors() {
        let mut test_data = "1101";
        let mut result = errors(test_data);
        assert_eq!(result, "ODErrorSessionProxyVersionMismatch");

        test_data = "10000";
        result = errors(test_data);
        assert_eq!(result, "ODErrorPluginOperationNotSupported");
    }

    #[test]
    fn test_member_id_type() {
        let mut test_data = "8";
        let mut result = member_id_type(test_data);
        assert_eq!(result, "USER NFS");

        test_data = "1";
        result = member_id_type(test_data);
        assert_eq!(result, "GID");
    }

    #[test]
    fn test_member_details_user() {
        let test_data = "I/7///8vTG9jYWwvRGVmYXVsdAA=";
        let result = member_details(test_data).unwrap();
        assert_eq!(result, "user: -2@/Local/Default");
    }

    #[test]
    fn test_member_details_group() {
        let test_data = "RGNvbS5hcHBsZS5zaGFyZXBvaW50Lmdyb3VwLjEAL0xvY2FsL0RlZmF1bHQA";
        let result = member_details(test_data).unwrap();
        assert_eq!(result, "group: com.apple.sharepoint.group.1@/Local/Default");
    }

    #[test]
    fn test_get_member_data() {
        let test_data = "I/7///8vTG9jYWwvRGVmYXVsdAA=";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_member_data(&decoded_data_result).unwrap();
        assert_eq!(result, "user: -2@/Local/Default");
    }

    #[test]
    fn test_get_member_string() {
        let test_data = [
            110, 111, 98, 111, 100, 121, 0, 47, 76, 111, 99, 97, 108, 47, 68, 101, 102, 97, 117,
            108, 116, 0,
        ];

        let (_, result) = non_empty_cstring(&test_data).unwrap();
        assert_eq!(result, "nobody");
    }

    #[test]
    fn test_get_member_id() {
        let test_data = [232, 3, 0, 0, 0];

        let (_, result) = get_member_id(&test_data).unwrap();
        assert_eq!(result, 1000);
    }

    #[test]
    fn test_sid_details() {
        let test_data = "AQUAAAAAAAUVAAAAxbsdAg3Yp1FTmi50HAYAAA==";
        let result = sid_details(test_data).unwrap();
        assert_eq!(result, "S-1-5-21-35503045-1369954317-1949211219-1564");
    }

    #[test]
    fn test_get_sid_data() {
        let test_data = "AQUAAAAAAAUVAAAAxbsdAg3Yp1FTmi50HAYAAA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_sid_data(&decoded_data_result).unwrap();
        assert_eq!(result, "S-1-5-21-35503045-1369954317-1949211219-1564");
    }
}
