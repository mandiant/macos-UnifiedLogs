// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::warn;

#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum Errno {
    #[strum(to_string = "Success")]
    Success,
    #[strum(to_string = "Operation not permitted")]
    OperationNotPermitted,
    #[strum(to_string = "No such file or directory")]
    NoSuchFileOrDirectory,
    #[strum(to_string = "No such process")]
    NoSuchProcess,
    #[strum(to_string = "Interrupted system call")]
    InterruptedSystemCall,
    #[strum(to_string = "Input/Output error")]
    InputOutputError,
    #[strum(to_string = "Device not configured")]
    DeviceNotConfigured,
    #[strum(to_string = "Argument list too long")]
    ArgumentListTooLong,
    #[strum(to_string = "Exec format error")]
    ExecFormatError,
    #[strum(to_string = "Bad file descriptor")]
    BadFileDescriptor,
    #[strum(to_string = "No child processes")]
    NoChildProcesses,
    #[strum(to_string = "Resource deadlock avoided")]
    ResourceDeadlockAvoided,
    #[strum(to_string = "Cannot allocate memory")]
    CannotAllocateMemory,
    #[strum(to_string = "Permission denied")]
    PermissionDenied,
    #[strum(to_string = "Bad address")]
    BadAddress,
    #[strum(to_string = "Block device required")]
    BlockDeviceRequired,
    #[strum(to_string = "Device / Resource busy")]
    DeviceResourceBusy,
    #[strum(to_string = "File exists")]
    FileExists,
    #[strum(to_string = "Cross-device link")]
    CrossDeviceLink,
    #[strum(to_string = "Operation not supported by device")]
    OperationNotSupportedByDevice,
    #[strum(to_string = "Not a directory")]
    NotADirectory,
    #[strum(to_string = "Is a directory")]
    IsADirectory,
    #[strum(to_string = "Invalid arguement")]
    InvalidArgument,
    #[strum(to_string = "Too many open files in system")]
    TooManyOpenFilesInSystem,
    #[strum(to_string = "Too many open files")]
    TooManyOpenFiles,
    #[strum(to_string = "Inappropriate ioctl for devices")]
    InappropriateIoctlForDevices,
    #[strum(to_string = "Text file busy")]
    TextFileBusy,
    #[strum(to_string = "File too large")]
    FileTooLarge,
    #[strum(to_string = "No space left on device")]
    NoSpaceLeftOnDevice,
    #[strum(to_string = "Illegal seek")]
    IllegalSeek,
    #[strum(to_string = "Read-only filesystem")]
    ReadOnlyFilesystem,
    #[strum(to_string = "Too many link")]
    TooManyLink,
    #[strum(to_string = "Broken pipe")]
    BrokenPipe,
    #[strum(to_string = "Numerical argument out of domain")]
    NumericalArgumentOutOfDomain,
    #[strum(to_string = "Result too large")]
    ResultTooLarge,
    #[strum(to_string = "Resource temporarily unavailable, operation would block")]
    ResourceTemporarilyUnavailableOperationWouldBlock,
    #[strum(to_string = "Operation now in progress")]
    OperationNowInProgress,
    #[strum(to_string = "Operation already in progress")]
    OperationAlreadyInProgress,
    #[strum(to_string = "Socket operation on non-socket")]
    SocketOperationOnNonSocket,
    #[strum(to_string = "Destination address required")]
    DestinationAddressRequired,
    #[strum(to_string = "Message too long")]
    MessageTooLong,
    #[strum(to_string = "Protocol wrong type for socket")]
    ProtocolWrongTypeForSocket,
    #[strum(to_string = "Protocol not available")]
    ProtocolNotAvailable,
    #[strum(to_string = "Protocol not supported")]
    ProtocolNotSupported,
    #[strum(to_string = "Socket type not supported")]
    SocketTypeNotSupported,
    #[strum(to_string = "Operation not supported, Operation not supported on socket")]
    OperationNotSupportedOperationNotSupportedOnSocket,
    #[strum(to_string = "Protocol family not supported")]
    ProtocolFamilyNotSupported,
    #[strum(to_string = "Address family not supported by protocol family")]
    AddressFamilyNotSupportedByProtocolFamily,
    #[strum(to_string = "Address already in use")]
    AddressAlreadyInUse,
    #[strum(to_string = "Can't assign requested address")]
    CantAssignRequestedAddress,
    #[strum(to_string = "Network is down")]
    NetworkIsDown,
    #[strum(to_string = "Network is unreachable")]
    NetworkIsUnreachable,
    #[strum(to_string = "Network dropped connection on reset")]
    NetworkDroppedConnectionOnReset,
    #[strum(to_string = "Software caused connection abort")]
    SoftwareCausedConnectionAbort,
    #[strum(to_string = "Connection reset by peer")]
    ConnectionResetByPeer,
    #[strum(to_string = "No buffer space available")]
    NoBufferSpaceAvailable,
    #[strum(to_string = "Socket is already connected")]
    SocketIsAlreadyConnected,
    #[strum(to_string = "Socket is not connected")]
    SocketIsNotConnected,
    #[strum(to_string = "Can't send after socket shutdown")]
    CantSendAfterSocketShutdown,
    #[strum(to_string = "Too many references: can't splice")]
    TooManyReferencesCantSplice,
    #[strum(to_string = "Operation timed out")]
    OperationTimedOut,
    #[strum(to_string = "Connection refused")]
    ConnectionRefused,
    #[strum(to_string = "Too many levels of symbolic links")]
    TooManyLevelsOfSymbolicLinks,
    #[strum(to_string = "File name too long")]
    FileNameTooLong,
    #[strum(to_string = "Host is down")]
    HostIsDown,
    #[strum(to_string = "No route to host")]
    NoRouteToHost,
    #[strum(to_string = "Directory not empty")]
    DirectoryNotEmpty,
    #[strum(to_string = "Too many processes")]
    TooManyProcesses,
    #[strum(to_string = "Too many users")]
    TooManyUsers,
    #[strum(to_string = "Disc quota exceeded")]
    DiscQuotaExceeded,
    #[strum(to_string = "Stale NFS file handle")]
    StaleNFSFileHandle,
    #[strum(to_string = "Too many levels of remote in path")]
    TooManyLevelsOfRemoteInPath,
    #[strum(to_string = "RPC struct is bad")]
    RPCStructIsBad,
    #[strum(to_string = "RPC version wrong")]
    RPCVersionWrong,
    #[strum(to_string = "RPC prog. not avail")]
    RPCProgNotAvail,
    #[strum(to_string = "Program version wrong")]
    ProgramVersionWrong,
    #[strum(to_string = "Bad procedure for program")]
    BadProcedureForProgram,
    #[strum(to_string = "No locks available")]
    NoLocksAvailable,
    #[strum(to_string = "Function not implemented")]
    FunctionNotImplemented,
    #[strum(to_string = "Inappropriate file type or format")]
    InappropriateFileTypeOrFormat,
    #[strum(to_string = "Authentication error")]
    AuthenticationError,
    #[strum(to_string = "Need authenticator")]
    NeedAuthenticator,
    #[strum(to_string = "Device power is off")]
    DevicePowerIsOff,
    #[strum(to_string = "Device error, e.g. paper out")]
    DeviceErrorEGPaperOut,
    #[strum(to_string = "Value too large to be stored in data type")]
    ValueTooLargeToBeStoredInDataType,
    #[strum(to_string = "Bad executable")]
    BadExecutable,
    #[strum(to_string = "Bad CPU type in executable")]
    BadCPUTypeInExecutable,
    #[strum(to_string = "Shared library version mismatch")]
    SharedLibraryVersionMismatch,
    #[strum(to_string = "Malformed Macho file")]
    MalformedMachoFile,
    #[strum(to_string = "Operation canceled")]
    OperationCanceled,
    #[strum(to_string = "Identifier removed")]
    IdentifierRemoved,
    #[strum(to_string = "No message of desired type")]
    NoMessageOfDesiredType,
    #[strum(to_string = "Illegal byte sequence")]
    IllegalByteSequence,
    #[strum(to_string = "Attribute not found")]
    AttributeNotFound,
    #[strum(to_string = "Bad message")]
    BadMessage,
    #[strum(to_string = "Reserved")]
    Reserved1,
    #[strum(to_string = "No message available on STREAM")]
    NoMessageAvailableOnSTREAM,
    #[strum(to_string = "Reserved")]
    Reserved2,
    #[strum(to_string = "No STREAM resources")]
    NoSTREAMResources,
    #[strum(to_string = "Not a STREAM")]
    NotASTREAM,
    #[strum(to_string = "Protocol error")]
    ProtocolError,
    #[strum(to_string = "STREAM ioctl timeout")]
    STREAMIoctlTimeout,
    #[strum(to_string = "Operation not supported on socket")]
    OperationNotSupportedOnSocket,
    #[strum(to_string = "No such policy registered")]
    NoSuchPolicyRegistered,
    #[strum(to_string = "State not recoverable")]
    StateNotRecoverable,
    #[strum(to_string = "Previous owner died")]
    PreviousOwnerDied,
    #[strum(to_string = "Interface output queue is full, Must be equal largest errno")]
    InterfaceOutputQueueIsFullMustBeEqualLargestErrno,
    #[strum(to_string = "Restart syscall")]
    RestartSyscall,
    #[strum(to_string = "Don't modify regs, just return")]
    DontModifyRegsJustReturn,
    #[strum(to_string = "Restart lookup under heavy vnode pressure/recycling")]
    RestartLookupUnderHeavyVnodePressureRecycling,
    #[strum(to_string = "Red drive open")]
    RedDriveOpen,
    #[strum(to_string = "Keep looking")]
    KeepLooking,
    #[strum(to_string = "Data less")]
    DataLess,
    #[strum(to_string = "Unknown errno: {0}")]
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum MachErrno {
    #[strum(to_string = "(ipc/send) invalid destination port")]
    InvalidDestinationPort,
    #[strum(to_string = "invalid header")]
    InvalidHeader,
    #[strum(to_string = "invalid memory")]
    InvalidMemory,
    #[strum(to_string = "invalid notify")]
    InvalidNotify,
    #[strum(to_string = "invalid reply")]
    InvalidReply,
    #[strum(to_string = "invalid right")]
    InvalidRight,
    #[strum(to_string = "invalid rt ool size")]
    InvalidRtOolSize,
    #[strum(to_string = "invalid trailer")]
    InvalidTrailer,
    #[strum(to_string = "invalid type")]
    InvalidType,
    #[strum(to_string = "invalid voucher")]
    InvalidVoucher,
    #[strum(to_string = "message too small")]
    MessageTooSmall,
    #[strum(to_string = "no buffer")]
    NoBuffer,
    #[strum(to_string = "timed out")]
    TimedOut,
    #[strum(to_string = "too large")]
    TooLarge,
    #[strum(to_string = "Unknown mach errno: {0}")]
    Unknown(String),
}

/// Convert Darwin errno codes to message
pub(crate) fn errno_codes(errno: &str) -> Errno {
    // Found at https://github.com/apple/darwin-xnu/blob/main/bsd/sys/errno.h
    match errno {
        "0" => Errno::Success,
        "1" => Errno::OperationNotPermitted,
        "2" => Errno::NoSuchFileOrDirectory,
        "3" => Errno::NoSuchProcess,
        "4" => Errno::InterruptedSystemCall,
        "5" => Errno::InputOutputError,
        "6" => Errno::DeviceNotConfigured,
        "7" => Errno::ArgumentListTooLong,
        "8" => Errno::ExecFormatError,
        "9" => Errno::BadFileDescriptor,
        "10" => Errno::NoChildProcesses,
        "11" => Errno::ResourceDeadlockAvoided,
        "12" => Errno::CannotAllocateMemory,
        "13" => Errno::PermissionDenied,
        "14" => Errno::BadAddress,
        "15" => Errno::BlockDeviceRequired,
        "16" => Errno::DeviceResourceBusy,
        "17" => Errno::FileExists,
        "18" => Errno::CrossDeviceLink,
        "19" => Errno::OperationNotSupportedByDevice,
        "20" => Errno::NotADirectory,
        "21" => Errno::IsADirectory,
        "22" => Errno::InvalidArgument,
        "23" => Errno::TooManyOpenFilesInSystem,
        "24" => Errno::TooManyOpenFiles,
        "25" => Errno::InappropriateIoctlForDevices,
        "26" => Errno::TextFileBusy,
        "27" => Errno::FileTooLarge,
        "28" => Errno::NoSpaceLeftOnDevice,
        "29" => Errno::IllegalSeek,
        "30" => Errno::ReadOnlyFilesystem,
        "31" => Errno::TooManyLink,
        "32" => Errno::BrokenPipe,
        "33" => Errno::NumericalArgumentOutOfDomain,
        "34" => Errno::ResultTooLarge,
        "35" => Errno::ResourceTemporarilyUnavailableOperationWouldBlock,
        "36" => Errno::OperationNowInProgress,
        "37" => Errno::OperationAlreadyInProgress,
        "38" => Errno::SocketOperationOnNonSocket,
        "39" => Errno::DestinationAddressRequired,
        "40" => Errno::MessageTooLong,
        "41" => Errno::ProtocolWrongTypeForSocket,
        "42" => Errno::ProtocolNotAvailable,
        "43" => Errno::ProtocolNotSupported,
        "44" => Errno::SocketTypeNotSupported,
        "45" => Errno::OperationNotSupportedOperationNotSupportedOnSocket,
        "46" => Errno::ProtocolFamilyNotSupported,
        "47" => Errno::AddressFamilyNotSupportedByProtocolFamily,
        "48" => Errno::AddressAlreadyInUse,
        "49" => Errno::CantAssignRequestedAddress,
        "50" => Errno::NetworkIsDown,
        "51" => Errno::NetworkIsUnreachable,
        "52" => Errno::NetworkDroppedConnectionOnReset,
        "53" => Errno::SoftwareCausedConnectionAbort,
        "54" => Errno::ConnectionResetByPeer,
        "55" => Errno::NoBufferSpaceAvailable,
        "56" => Errno::SocketIsAlreadyConnected,
        "57" => Errno::SocketIsNotConnected,
        "58" => Errno::CantSendAfterSocketShutdown,
        "59" => Errno::TooManyReferencesCantSplice,
        "60" => Errno::OperationTimedOut,
        "61" => Errno::ConnectionRefused,
        "62" => Errno::TooManyLevelsOfSymbolicLinks,
        "63" => Errno::FileNameTooLong,
        "64" => Errno::HostIsDown,
        "65" => Errno::NoRouteToHost,
        "66" => Errno::DirectoryNotEmpty,
        "67" => Errno::TooManyProcesses,
        "68" => Errno::TooManyUsers,
        "69" => Errno::DiscQuotaExceeded,
        "70" => Errno::StaleNFSFileHandle,
        "71" => Errno::TooManyLevelsOfRemoteInPath,
        "72" => Errno::RPCStructIsBad,
        "73" => Errno::RPCVersionWrong,
        "74" => Errno::RPCProgNotAvail,
        "75" => Errno::ProgramVersionWrong,
        "76" => Errno::BadProcedureForProgram,
        "77" => Errno::NoLocksAvailable,
        "78" => Errno::FunctionNotImplemented,
        "79" => Errno::InappropriateFileTypeOrFormat,
        "80" => Errno::AuthenticationError,
        "81" => Errno::NeedAuthenticator,
        "82" => Errno::DevicePowerIsOff,
        "83" => Errno::DeviceErrorEGPaperOut,
        "84" => Errno::ValueTooLargeToBeStoredInDataType,
        "85" => Errno::BadExecutable,
        "86" => Errno::BadCPUTypeInExecutable,
        "87" => Errno::SharedLibraryVersionMismatch,
        "88" => Errno::MalformedMachoFile,
        "89" => Errno::OperationCanceled,
        "90" => Errno::IdentifierRemoved,
        "91" => Errno::NoMessageOfDesiredType,
        "92" => Errno::IllegalByteSequence,
        "93" => Errno::AttributeNotFound,
        "94" => Errno::BadMessage,
        "95" => Errno::Reserved1,
        "96" => Errno::NoMessageAvailableOnSTREAM,
        "97" => Errno::Reserved2,
        "98" => Errno::NoSTREAMResources,
        "99" => Errno::NotASTREAM,
        "100" => Errno::ProtocolError,
        "101" => Errno::STREAMIoctlTimeout,
        "102" => Errno::OperationNotSupportedOnSocket,
        "103" => Errno::NoSuchPolicyRegistered,
        "104" => Errno::StateNotRecoverable,
        "105" => Errno::PreviousOwnerDied,
        "106" => Errno::InterfaceOutputQueueIsFullMustBeEqualLargestErrno,
        "-1" => Errno::RestartSyscall,
        "-2" => Errno::DontModifyRegsJustReturn,
        "-5" => Errno::RestartLookupUnderHeavyVnodePressureRecycling,
        "-6" => Errno::RedDriveOpen,
        "-7" => Errno::KeepLooking,
        "-8" => Errno::DataLess,
        _ => {
            warn!("[macos-unifiedlogs] Unknown darwin errno code: {errno}");
            Errno::Unknown(errno.to_string())
        }
    }
}

/// Kernel error codes. Have only seen "(ipc/send) invalid destination port"
/// <https://www.koingosw.com/products/macpilot/error-codes.php?page=248>
pub(crate) fn mach_codes(errno: &str) -> MachErrno {
    match errno {
        "268435459" => MachErrno::InvalidDestinationPort,
        "268435472" => MachErrno::InvalidHeader,
        "268435468" => MachErrno::InvalidMemory,
        "268435467" => MachErrno::InvalidNotify,
        "268435465" => MachErrno::InvalidReply,
        "268435466" => MachErrno::InvalidRight,
        "4294967644" => MachErrno::InvalidRtOolSize,
        "268435473" => MachErrno::InvalidTrailer,
        "268435471" => MachErrno::InvalidType,
        "268435461" => MachErrno::InvalidVoucher,
        "268435464" => MachErrno::MessageTooSmall,
        "268435469" => MachErrno::NoBuffer,
        "268435460" => MachErrno::TimedOut,
        "268435470" => MachErrno::TooLarge,
        _ => MachErrno::Unknown(errno.to_string()),
    }
}

/// Parse UNIX permissions to string version
pub(crate) fn permission(permissions: &str) -> super::decoder::Decoded {
    let v = |v: char| match v {
        '1' => 1_u8,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        _ => 0,
    };

    let mut chars = permissions.chars();
    let user = chars.next().map(|c| v(c)).unwrap_or(0);
    let owner = chars.next().map(|c| v(c)).unwrap_or(0);
    let group = chars.next().map(|c| v(c)).unwrap_or(0);
    super::decoder::Decoded::Permission(user, owner, group)
}

pub(crate) fn format_permission(user: u8, owner: u8, group: u8) -> String {
    let v = |v: u8| match v {
        1 => "--x",
        2 => "-w-",
        3 => "-wx",
        4 => "r--",
        5 => "r-x",
        6 => "rw-",
        7 => "rwx",
        _ => "---",
    };
    format!("-{}{}{}", v(user), v(owner), v(group))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_errno_codes() {
        let mut test_data = "1";
        let mut result = errno_codes(test_data);
        assert_eq!(result, Errno::OperationNotPermitted);

        test_data = "35";
        result = errno_codes(test_data);
        assert_eq!(
            result,
            Errno::ResourceTemporarilyUnavailableOperationWouldBlock
        );

        test_data = "58";
        result = errno_codes(test_data);
        assert_eq!(result, Errno::CantSendAfterSocketShutdown);

        test_data = "82";
        result = errno_codes(test_data);
        assert_eq!(result, Errno::DevicePowerIsOff);
    }

    #[test]
    fn test_mach_errno_codes() {
        let mut test_data = "268435465";
        let mut result = mach_codes(test_data);
        assert_eq!(result, MachErrno::InvalidReply);

        test_data = "268435470";
        result = mach_codes(test_data);
        assert_eq!(result, MachErrno::TooLarge);

        test_data = "268435469";
        result = mach_codes(test_data);
        assert_eq!(result, MachErrno::NoBuffer);

        test_data = "268435468";
        result = mach_codes(test_data);
        assert_eq!(result, MachErrno::InvalidMemory);
    }

    #[test]
    fn test_permission() {
        let mut test_data = "111";
        let mut result = permission(test_data).to_string();
        assert_eq!(result.as_str(), "---x--x--x");

        test_data = "448";
        result = permission(test_data).to_string();
        assert_eq!(result.as_str(), "-r--r-----");

        test_data = "777";
        result = permission(test_data).to_string();
        assert_eq!(result.as_str(), "-rwxrwxrwx");

        test_data = "400";
        result = permission(test_data).to_string();
        assert_eq!(result.as_str(), "-r--------");
    }
}
