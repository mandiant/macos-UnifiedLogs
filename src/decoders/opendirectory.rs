// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::{error, warn};
use nom::{
    bytes::complete::{take, take_while},
    number::complete::{le_i32, le_u32, le_u8},
};
use std::mem::size_of;

use crate::util::extract_string;

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
            warn!(
                "[macos-unifiedlogs] Unknown open directory error code: {}",
                oderror
            );
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
            warn!(
                "[macos-unifiedlogs] Unknown open directory member id type: {}",
                member_string
            );
            member_string
        }
    };
    message.to_string()
}

/// Convert Open Directory member details to string
pub(crate) fn member_details(member_string: &str) -> String {
    let decoded_data_result = base64::decode(member_string);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to base64 decode open directory member details data {}, error: {:?}", member_string, err);
            return String::from("Failed to base64 decode member details");
        }
    };
    let message_result = get_member_data(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get open directory member details: {:?}",
                err
            );
            format!(
                "Failed to get open directory member details: {}",
                member_string
            )
        }
    }
}

/// Parse SID log data to SID string
pub(crate) fn sid_details(sid_string: &str) -> String {
    let decoded_data_result = base64::decode(sid_string);
    let decoded_data = match decoded_data_result {
        Ok(result) => result,
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to base64 decode open directory SID details data {}, error: {:?}", sid_string, err);
            return String::from("Failed to base64 decode SID details");
        }
    };
    let message_result = get_sid_data(&decoded_data);
    match message_result {
        Ok((_, result)) => result,
        Err(err) => {
            error!(
                "[macos-unifiedlogs] Failed to get open directory sid details: {:?}",
                err
            );

            format!("Failed to get open directory sid details: {}", sid_string)
        }
    }
}

/// Parse Open Directory membership details data
fn get_member_data(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (mut member_details, member_type_data) = take(size_of::<u8>())(data)?;
    let (_, member_type) = le_u8(member_type_data)?;

    let user_type = [36, 160, 164];
    let uid_type = [35, 163];
    let group_type = [68];
    let gid_type = [195];

    let member_message;
    if uid_type.contains(&member_type) {
        let (details, uid) = get_member_id(member_details)?;
        member_details = details;
        member_message = format!("user: {}", uid);
    } else if user_type.contains(&member_type) {
        let (details, name) = get_member_string(member_details)?;
        member_details = details;
        member_message = format!("user: {}", name);
    } else if gid_type.contains(&member_type) {
        let (details, gid) = get_member_id(member_details)?;
        member_details = details;
        member_message = format!("group: {}", gid);
    } else if group_type.contains(&member_type) {
        let (details, name) = get_member_string(member_details)?;
        member_details = details;
        member_message = format!("group: {}", name);
    } else {
        warn!(
            "[macos-unifiedlogs] Unknown open directory member type: {}",
            member_type
        );
        member_message = format!("Unknown Member type {}: @", member_type);
    }

    let mut source_path = String::from(" <not found>");
    if !member_details.is_empty() {
        let (details, path) = get_member_string(member_details)?;
        source_path = path;
        member_details = details;
    }

    if source_path != " <not found>" {
        source_path = format!("@{}", source_path)
    }

    let message = format!("{}{}", member_message, source_path);
    Ok((member_details, message))
}

/// Get UID/GID for Opendirectory membership
fn get_member_id(data: &[u8]) -> nom::IResult<&[u8], i32> {
    let (details, id_data) = take(size_of::<u32>())(data)?;
    let (_, id) = le_i32(id_data)?;
    Ok((details, id))
}

/// Get the username/group name for Opendirectory membership
fn get_member_string(data: &[u8]) -> nom::IResult<&[u8], String> {
    let mut string_value = String::from(" <not found>");
    let (details, string_data) = take_while(|b: u8| b != 0)(data)?;
    if string_data.is_empty() {
        return Ok((details, string_value));
    }

    let (_, value) = extract_string(string_data)?;
    if value != "Could not extract string" {
        string_value = value;
    }

    // Nom of end string character
    let (details, _) = take(size_of::<u8>())(details)?;
    Ok((details, string_value))
}

/// Parse the SID data
fn get_sid_data(data: &[u8]) -> nom::IResult<&[u8], String> {
    let (sid_details, revision_data) = take(size_of::<u8>())(data)?;
    let (sid_details, unknown_size_data) = take(size_of::<u8>())(sid_details)?;
    let (_, unknown_size) = le_u8(unknown_size_data)?;

    let (sid_details, _) = take(unknown_size)(sid_details)?;
    let (sid_details, authority_data) = take(size_of::<u8>())(sid_details)?;
    let (mut sid_details, subauthority_data) = take(size_of::<u32>())(sid_details)?;

    let (_, revision) = le_u8(revision_data)?;
    let (_, authority) = le_u8(authority_data)?;
    let (_, subauthority) = le_u8(subauthority_data)?;

    let mut message = format!("S-{}-{}-{}", revision, authority, subauthority);

    let subauthorit_size = 4;
    while sid_details.len() >= subauthorit_size {
        let (details, additional_subauthority_data) = take(subauthorit_size)(sid_details)?;
        sid_details = details;
        let (_, subauthority) = le_u32(additional_subauthority_data)?;
        message = format!("{}-{}", message, subauthority);
    }
    Ok((sid_details, message))
}

#[cfg(test)]
mod tests {
    use crate::decoders::opendirectory::{
        errors, get_member_data, get_member_id, get_member_string, get_sid_data, member_details,
        member_id_type, sid_details,
    };

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
        let result = member_details(test_data);
        assert_eq!(result, "user: -2@/Local/Default");
    }

    #[test]
    fn test_member_details_group() {
        let test_data = "RGNvbS5hcHBsZS5zaGFyZXBvaW50Lmdyb3VwLjEAL0xvY2FsL0RlZmF1bHQA";
        let result = member_details(test_data);
        assert_eq!(result, "group: com.apple.sharepoint.group.1@/Local/Default");
    }

    #[test]
    fn test_get_member_data() {
        let test_data = "I/7///8vTG9jYWwvRGVmYXVsdAA=";
        let decoded_data_result = base64::decode(test_data).unwrap();

        let (_, result) = get_member_data(&decoded_data_result).unwrap();
        assert_eq!(result, "user: -2@/Local/Default");
    }

    #[test]
    fn test_get_member_string() {
        let test_data = [
            110, 111, 98, 111, 100, 121, 0, 47, 76, 111, 99, 97, 108, 47, 68, 101, 102, 97, 117,
            108, 116, 0,
        ];

        let (_, result) = get_member_string(&test_data).unwrap();
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
        let result = sid_details(test_data);
        assert_eq!(result, "S-1-5-21-35503045-1369954317-1949211219-1564");
    }

    #[test]
    fn test_get_sid_data() {
        let test_data = "AQUAAAAAAAUVAAAAxbsdAg3Yp1FTmi50HAYAAA==";
        let decoded_data_result = base64::decode(test_data).unwrap();

        let (_, result) = get_sid_data(&decoded_data_result).unwrap();
        assert_eq!(result, "S-1-5-21-35503045-1369954317-1949211219-1564");
    }
}
