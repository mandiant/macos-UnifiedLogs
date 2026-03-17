// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use super::DecoderError;
use crate::rewrite::helpers::{decode_standard, non_empty_cstring};
use log::warn;
use nom::{
    Parser,
    bytes::complete::take,
    multi::fold_many0,
    number::complete::{le_i32, le_u8, le_u32},
};

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum OdError {
    #[strum(to_string = "ODErrorCredentialsAccountDisable")]
    CredentialsAccountDisabled,
    #[strum(to_string = "ODErrorCredentialsAccountExpire")]
    CredentialsAccountExpired,
    #[strum(to_string = "ODErrorCredentialsAccountInactiv")]
    CredentialsAccountInactive,
    #[strum(to_string = "ODErrorCredentialsAccountNotFoun")]
    CredentialsAccountNotFound,
    #[strum(to_string = "ODErrorCredentialsInvali")]
    CredentialsInvalid,
    #[strum(to_string = "ODErrorCredentialsInvalidCompute")]
    CredentialsInvalidComputer,
    #[strum(to_string = "ODErrorCredentialsInvalidLogonHour")]
    CredentialsInvalidLogonHours,
    #[strum(to_string = "ODErrorCredentialsMethodNotSupporte")]
    CredentialsMethodNotSupported,
    #[strum(to_string = "ODErrorCredentialsNotAuthorize")]
    CredentialsNotAuthorized,
    #[strum(to_string = "ODErrorCredentialsOperationFaile")]
    CredentialsOperationFailed,
    #[strum(to_string = "ODErrorCredentialsParameterErro")]
    CredentialsParameterError,
    #[strum(to_string = "ODErrorCredentialsPasswordChangeRequire")]
    CredentialsPasswordChangeRequired,
    #[strum(to_string = "ODErrorCredentialsPasswordChangeTooSoo")]
    CredentialsPasswordChangeTooSoon,
    #[strum(to_string = "ODErrorCredentialsPasswordExpire")]
    CredentialsPasswordExpired,
    #[strum(to_string = "ODErrorCredentialsPasswordNeedsDigi")]
    CredentialsPasswordNeedsDigit,
    #[strum(to_string = "ODErrorCredentialsPasswordNeedsLette")]
    CredentialsPasswordNeedsLetter,
    #[strum(to_string = "ODErrorCredentialsPasswordQualityFaile")]
    CredentialsPasswordQualityFailed,
    #[strum(to_string = "ODErrorCredentialsPasswordTooShor")]
    CredentialsPasswordTooShort,
    #[strum(to_string = "ODErrorCredentialsPasswordTooLon")]
    CredentialsPasswordTooLong,
    #[strum(to_string = "ODErrorCredentialsPasswordUnrecoverabl")]
    CredentialsPasswordUnrecoverable,
    #[strum(to_string = "ODErrorCredentialsServerCommunicationErro")]
    CredentialsServerCommunicationError,
    #[strum(to_string = "ODErrorCredentialsServerErro")]
    CredentialsServerError,
    #[strum(to_string = "ODErrorCredentialsServerNotFoun")]
    CredentialsServerNotFound,
    #[strum(to_string = "ODErrorCredentialsServerTimeou")]
    CredentialsServerTimeout,
    #[strum(to_string = "ODErrorCredentialsServerUnreachabl")]
    CredentialsServerUnreachable,
    #[strum(to_string = "ODErrorDaemonErro")]
    DaemonError,
    #[strum(to_string = "ODErrorNodeConnectionFaile")]
    NodeConnectionFailed,
    #[strum(to_string = "ODErrorNodeDisable")]
    NodeDisabled,
    #[strum(to_string = "ODErrorNodeUnknownHos")]
    NodeUnknownHost,
    #[strum(to_string = "ODErrorNodeUnknownNam")]
    NodeUnknownName,
    #[strum(to_string = "ODErrorNodeUnknownTyp")]
    NodeUnknownType,
    #[strum(to_string = "ODErrorPluginErro")]
    PluginError,
    #[strum(to_string = "ODErrorPluginOperationNotSupporte")]
    PluginOperationNotSupported,
    #[strum(to_string = "ODErrorPluginOperationTimeou")]
    PluginOperationTimeout,
    #[strum(to_string = "ODErrorPolicyOutOfRang")]
    PolicyOutOfRange,
    #[strum(to_string = "ODErrorPolicyUnsupporte")]
    PolicyUnsupported,
    #[strum(to_string = "ODErrorQueryInvalidMatchTyp")]
    QueryInvalidMatchType,
    #[strum(to_string = "ODErrorQuerySynchroniz")]
    QuerySynchronize,
    #[strum(to_string = "ODErrorQueryTimeou")]
    QueryTimeout,
    #[strum(to_string = "ODErrorQueryUnsupportedMatchTyp")]
    QueryUnsupportedMatchType,
    #[strum(to_string = "ODErrorRecordAlreadyExist")]
    RecordAlreadyExists,
    #[strum(to_string = "ODErrorRecordAttributeNotFoun")]
    RecordAttributeNotFound,
    #[strum(to_string = "ODErrorRecordAttributeUnknownTyp")]
    RecordAttributeUnknownType,
    #[strum(to_string = "ODErrorRecordAttributeValueNotFoun")]
    RecordAttributeValueNotFound,
    #[strum(to_string = "ODErrorRecordAttributeValueSchemaErro")]
    RecordAttributeValueSchemaError,
    #[strum(to_string = "ODErrorRecordInvalidTyp")]
    RecordInvalidType,
    #[strum(to_string = "ODErrorRecordNoLongerExist")]
    RecordNoLongerExists,
    #[strum(to_string = "ODErrorRecordParameterErro")]
    RecordParameterError,
    #[strum(to_string = "ODErrorRecordPermissionErro")]
    RecordPermissionError,
    #[strum(to_string = "ODErrorRecordReadOnlyNod")]
    RecordReadOnlyNode,
    #[strum(to_string = "ODErrorRecordTypeDisable")]
    RecordTypeDisabled,
    #[strum(to_string = "ODErrorSessionDaemonNotRunnin")]
    SessionDaemonNotRunning,
    #[strum(to_string = "ODErrorSessionDaemonRefuse")]
    SessionDaemonRefused,
    #[strum(to_string = "ODErrorSessionLocalOnlyDaemonInUs")]
    SessionLocalOnlyDaemonInUse,
    #[strum(to_string = "ODErrorSessionNormalDaemonInUs")]
    SessionNormalDaemonInUse,
    #[strum(to_string = "ODErrorSessionProxyCommunicationErro")]
    SessionProxyCommunicationError,
    #[strum(to_string = "ODErrorSessionProxyIPUnreachabl")]
    SessionProxyIPUnreachable,
    #[strum(to_string = "ODErrorSessionProxyUnknownHos")]
    SessionProxyUnknownHost,
    #[strum(to_string = "ODErrorSessionProxyVersionMismatc")]
    SessionProxyVersionMismatch,
    #[strum(to_string = "ODErrorSucces")]
    Success,
    #[strum(to_string = "ODErrorCredentialsAccountLocke")]
    CredentialsAccountLocked,
    #[strum(to_string = "ODErrorCredentialsAccountTemporarilyLocke")]
    CredentialsAccountTemporarilyLocked,
    #[strum(to_string = "ODErrorCredentialsContactPrimar")]
    CredentialsContactPrimary,
    /// Not Found
    #[strum(to_string = "Not Found")]
    NotFound,
    /// Unknown open directory error code
    #[strum(to_string = "Unknown open directory error code: {0}")]
    Unknown(String),
}

/// Convert Open Directory error codes to message
pub(crate) fn errors(oderror: &str) -> OdError {
    // Found at https://developer.apple.com/documentation/opendirectory/odframeworkerrors?changes=__2&language=objc
    match oderror {
        "5301" => OdError::CredentialsAccountDisabled,
        "5302" => OdError::CredentialsAccountExpired,
        "5303" => OdError::CredentialsAccountInactive,
        "5300" => OdError::CredentialsAccountNotFound,
        "5000" => OdError::CredentialsInvalid,
        "5001" => OdError::CredentialsInvalidComputer,
        "5500" => OdError::CredentialsInvalidLogonHours,
        "5100" => OdError::CredentialsMethodNotSupported,
        "5101" => OdError::CredentialsNotAuthorized,
        "5103" => OdError::CredentialsOperationFailed,
        "5102" => OdError::CredentialsParameterError,
        "5401" => OdError::CredentialsPasswordChangeRequired,
        "5407" => OdError::CredentialsPasswordChangeTooSoon,
        "5400" => OdError::CredentialsPasswordExpired,
        "5406" => OdError::CredentialsPasswordNeedsDigit,
        "5405" => OdError::CredentialsPasswordNeedsLetter,
        "5402" => OdError::CredentialsPasswordQualityFailed,
        "5403" => OdError::CredentialsPasswordTooShort,
        "5404" => OdError::CredentialsPasswordTooLong,
        "5408" => OdError::CredentialsPasswordUnrecoverable,
        "5205" => OdError::CredentialsServerCommunicationError,
        "5202" => OdError::CredentialsServerError,
        "5201" => OdError::CredentialsServerNotFound,
        "5203" => OdError::CredentialsServerTimeout,
        "5200" => OdError::CredentialsServerUnreachable,
        "10002" => OdError::DaemonError,
        "2100" => OdError::NodeConnectionFailed,
        "2002" => OdError::NodeDisabled,
        "2200" => OdError::NodeUnknownHost,
        "2000" => OdError::NodeUnknownName,
        "2001" => OdError::NodeUnknownType,
        "10001" => OdError::PluginError,
        "10000" => OdError::PluginOperationNotSupported,
        "10003" => OdError::PluginOperationTimeout,
        "6001" => OdError::PolicyOutOfRange,
        "6000" => OdError::PolicyUnsupported,
        "3100" => OdError::QueryInvalidMatchType,
        "3000" => OdError::QuerySynchronize,
        "3102" => OdError::QueryTimeout,
        "3101" => OdError::QueryUnsupportedMatchType,
        "4102" => OdError::RecordAlreadyExists,
        "4201" => OdError::RecordAttributeNotFound,
        "4200" => OdError::RecordAttributeUnknownType,
        "4203" => OdError::RecordAttributeValueNotFound,
        "4202" => OdError::RecordAttributeValueSchemaError,
        "4101" => OdError::RecordInvalidType,
        "4104" => OdError::RecordNoLongerExists,
        "4100" => OdError::RecordParameterError,
        "4001" => OdError::RecordPermissionError,
        "4000" => OdError::RecordReadOnlyNode,
        "4103" => OdError::RecordTypeDisabled,
        "1002" => OdError::SessionDaemonNotRunning,
        "1003" => OdError::SessionDaemonRefused,
        "1000" => OdError::SessionLocalOnlyDaemonInUse,
        "1001" => OdError::SessionNormalDaemonInUse,
        "1100" => OdError::SessionProxyCommunicationError,
        "1102" => OdError::SessionProxyIPUnreachable,
        "1103" => OdError::SessionProxyUnknownHost,
        "1101" => OdError::SessionProxyVersionMismatch,
        "0" => OdError::Success,
        "5305" => OdError::CredentialsAccountLocked,
        "5304" => OdError::CredentialsAccountTemporarilyLocked,
        "5204" => OdError::CredentialsContactPrimary,
        "2" => OdError::NotFound,
        _ => {
            warn!("[macos-unifiedlogs] Unknown open directory error code: {oderror}",);
            OdError::Unknown(oderror.to_string())
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum MemberIdType {
    #[strum(to_string = "UID")]
    UID,
    #[strum(to_string = "GID")]
    GID,
    #[strum(to_string = "SID")]
    SID,
    #[strum(to_string = "USERNAME")]
    USERNAME,
    #[strum(to_string = "GROUPNAME")]
    GROUPNAME,
    #[strum(to_string = "UUID")]
    UUID,
    #[strum(to_string = "GROUP NFS")]
    GROUP_NFS,
    #[strum(to_string = "USER NFS")]
    USER_NFS,
    #[strum(to_string = "GSS EXPORT NAME")]
    GSS_EXPORT_NAME,
    #[strum(to_string = "X509 DN")]
    X509_DN,
    #[strum(to_string = "KERBEROS")]
    KERBEROS,
    #[strum(to_string = "{0}")]
    UNKNOWN(String),
}

/// Convert Open Directory member ids to string
pub(crate) fn member_id_type(member_string: &str) -> MemberIdType {
    // Found at /Library/Developer/CommandLineTools/SDKs/MacOSX12.3.sdk/usr/include/membership.h
    match member_string {
        "0" => MemberIdType::UID,
        "1" => MemberIdType::GID,
        "3" => MemberIdType::SID,
        "4" => MemberIdType::USERNAME,
        "5" => MemberIdType::GROUPNAME,
        "6" => MemberIdType::UUID,
        "7" => MemberIdType::GROUP_NFS,
        "8" => MemberIdType::USER_NFS,
        "10" => MemberIdType::GSS_EXPORT_NAME,
        "11" => MemberIdType::X509_DN,
        "12" => MemberIdType::KERBEROS,
        _ => {
            warn!("[macos-unifiedlogs] Unknown open directory member id type: {member_string}",);
            MemberIdType::UNKNOWN(member_string.to_string())
        }
    }
}

/// Convert Open Directory member details to string
pub(crate) fn member_details(input: &str) -> Result<MemberDetails, DecoderError<'_>> {
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
pub(crate) fn sid_details(input: &str) -> Result<SidDetails, DecoderError<'_>> {
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

pub struct MemberDetails {
    pub member_type: MemberType,
    pub source_path: String,
}

impl std::fmt::Display for MemberDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.member_type, self.source_path)
    }
}

pub enum MemberType {
    UserId(i32),
    UserName(String),
    GroupId(i32),
    GroupName(String),
    Unknown(u8),
}

impl std::fmt::Display for MemberType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserId(id) => write!(f, "user: {id}"),
            Self::UserName(name) => write!(f, "user: {name}"),
            Self::GroupId(id) => write!(f, "group: {id}"),
            Self::GroupName(name) => write!(f, "group: {name}"),
            Self::Unknown(type_id) => write!(f, "Unknown Member type: {type_id} @"),
        }
    }
}

/// Parse Open Directory membership details data
fn get_member_data(input: &[u8]) -> nom::IResult<&[u8], MemberDetails> {
    let (input, member_type) = le_u8(input)?;
    let (input, member_type) = match member_type {
        35 | 163 => {
            // UID
            let (input, uid) = get_member_id(input)?;
            (input, MemberType::UserId(uid))
        }
        36 | 160 | 164 => {
            // USER
            let (input, name) = non_empty_cstring(input)?;
            (input, MemberType::UserName(name))
        }
        68 => {
            // GROUP
            let (input, name) = non_empty_cstring(input)?;
            (input, MemberType::GroupName(name))
        }
        195 => {
            // GID
            let (input, gid) = get_member_id(input)?;
            (input, MemberType::GroupId(gid))
        }
        _ => {
            warn!("[macos-unifiedlogs] Unknown open directory member type: {member_type}",);
            (input, MemberType::Unknown(member_type))
        }
    };

    let (input, source_path) = match non_empty_cstring(input) {
        Ok((input, path)) => (input, format!("@{path}")),
        Err(_) => (input, " <not found>".to_string()),
    };

    let data = MemberDetails {
        member_type,
        source_path,
    };

    Ok((input, data))
}

/// Get UID/GID for Opendirectory membership
fn get_member_id(input: &[u8]) -> nom::IResult<&[u8], i32> {
    le_i32(input)
}

pub struct SidDetails {
    pub revision: u8,
    pub authority: u8,
    pub subauthorities: Vec<u32>,
}

impl std::fmt::Display for SidDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.authority)?;
        for subauthority in &self.subauthorities {
            write!(f, "-{}", subauthority)?;
        }
        Ok(())
    }
}

/// Parse the SID data
fn get_sid_data(input: &[u8]) -> nom::IResult<&[u8], SidDetails> {
    let (input, revision) = le_u8(input)?;

    let (input, unknown_size) = le_u8(input)?;
    let (input, _) = take(unknown_size)(input)?;

    let (input, authority) = le_u8(input)?;
    let mut tup = (le_u8, take(3_usize));
    let (input, (subauthority, _)) = tup.parse(input)?;

    let (input, subauthorities) = fold_many0(
        le_u32,
        move || {
            let mut subauthorities = Vec::with_capacity(10);
            subauthorities.push(u32::from(subauthority));
            subauthorities
        },
        |mut acc, additional_subauthority| {
            acc.push(additional_subauthority);
            acc
        },
    )
    .parse(input)?;

    let details = SidDetails {
        revision,
        authority,
        subauthorities,
    };

    Ok((input, details))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::helpers::decode_standard;

    #[test]
    fn test_errors() {
        let mut test_data = "1101";
        let mut result = errors(test_data);
        assert_eq!(result, OdError::SessionProxyVersionMismatch);

        test_data = "10000";
        result = errors(test_data);
        assert_eq!(result, OdError::PluginOperationNotSupported);
    }

    #[test]
    fn test_member_id_type() {
        let mut test_data = "8";
        let mut result = member_id_type(test_data);
        assert_eq!(result, MemberIdType::USER_NFS);

        test_data = "1";
        result = member_id_type(test_data);
        assert_eq!(result, MemberIdType::GID);
    }

    #[test]
    fn test_member_details_user() {
        let test_data = "I/7///8vTG9jYWwvRGVmYXVsdAA=";
        let result = member_details(test_data).unwrap();
        assert_eq!(result.to_string(), "user: -2@/Local/Default");
    }

    #[test]
    fn test_member_details_group() {
        let test_data = "RGNvbS5hcHBsZS5zaGFyZXBvaW50Lmdyb3VwLjEAL0xvY2FsL0RlZmF1bHQA";
        let result = member_details(test_data).unwrap();
        assert_eq!(
            result.to_string(),
            "group: com.apple.sharepoint.group.1@/Local/Default"
        );
    }

    #[test]
    fn test_get_member_data() {
        let test_data = "I/7///8vTG9jYWwvRGVmYXVsdAA=";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_member_data(&decoded_data_result).unwrap();
        assert_eq!(result.to_string(), "user: -2@/Local/Default");
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
        assert_eq!(
            result.to_string(),
            "S-1-5-21-35503045-1369954317-1949211219-1564"
        );
    }

    #[test]
    fn test_get_sid_data() {
        let test_data = "AQUAAAAAAAUVAAAAxbsdAg3Yp1FTmi50HAYAAA==";
        let decoded_data_result = decode_standard(test_data).unwrap();

        let (_, result) = get_sid_data(&decoded_data_result).unwrap();
        assert_eq!(
            result.to_string(),
            "S-1-5-21-35503045-1369954317-1949211219-1564"
        );
    }
}
