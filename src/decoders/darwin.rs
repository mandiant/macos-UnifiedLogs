// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use log::warn;

/// Convert Darwin errno codes to message
pub(crate) fn errno_codes(errno: &str) -> String {
    // Found at https://github.com/apple/darwin-xnu/blob/main/bsd/sys/errno.h
    let errno_message = match errno {
        "0" => "Success",
        "1" => "Operation not permitted",
        "2" => "No such file or directory",
        "3" => "No such process",
        "4" => "Interrupted system call",
        "5" => "Input/Output error",
        "6" => "Device not configured",
        "7" => "Argument list too long",
        "8" => "Exec format error",
        "9" => "Bad file descriptor",
        "10" => "No child processes",
        "11" => "Resource deadlock avoided",
        "12" => "Cannot allocate memory",
        "13" => "Permission denied",
        "14" => "Bad address",
        "15" => "Block device required",
        "16" => "Device / Resource busy",
        "17" => "File exists",
        "18" => "Cross-device link",
        "19" => "Operation not supported by device",
        "20" => "Not a directory",
        "21" => "Is a directory",
        "22" => "Invalid arguement",
        "23" => "Too many open files in system",
        "24" => "Too many open files",
        "25" => "Inappropriate ioctl for devices",
        "26" => "Text file busy",
        "27" => "File too large",
        "28" => "No space left on device",
        "29" => "Illegal seek",
        "30" => "Read-only filesystem",
        "31" => "Too many link",
        "32" => "Broken pipe",
        "33" => "Numerical argument out of domain",
        "34" => "Result too large",
        "35" => "Resource temporarily unavailable, operation would block",
        "36" => "Operation now in progress",
        "37" => "Operation already in progress",
        "38" => "Socket operation on non-socket",
        "39" => "Destination address required",
        "40" => "Message too long",
        "41" => "Protocol wrong type for socket",
        "42" => "Protocol not available",
        "43" => "Protocol not supported",
        "44" => "Socket type not supported",
        "45" => "Operation not supported, Operation not supported on socket",
        "46" => "Protocol family not supported",
        "47" => "Address family not supported by protocol family",
        "48" => "Address already in use",
        "49" => "Can't assign requested address",
        "50" => "Network is down",
        "51" => "Network is unreachable",
        "52" => "Network dropped connection on reset",
        "53" => "Software caused connection abort",
        "54" => "Connection reset by peer",
        "55" => "No buffer space available",
        "56" => "Socket is already connected",
        "57" => "Socket is not connected",
        "58" => "Can't send after socket shutdown",
        "59" => "Too many references: can't splice",
        "60" => "Operation timed out",
        "61" => "Connection refused",
        "62" => "Too many levels of symbolic links",
        "63" => "File name too long",
        "64" => "Host is down",
        "65" => "No route to host",
        "66" => "Directory not empty",
        "67" => "Too many processes",
        "68" => "Too many users",
        "69" => "Disc quota exceeded",
        "70" => "Stale NFS file handle",
        "71" => "Too many levels of remote in path",
        "72" => "RPC struct is bad",
        "73" => "RPC version wrong",
        "74" => "RPC prog. not avail",
        "75" => "Program version wrong",
        "76" => "Bad procedure for program",
        "77" => "No locks available",
        "78" => "Function not implemented",
        "79" => "Inappropriate file type or format",
        "80" => "Authentication error",
        "81" => "Need authenticator",
        "82" => "Device power is off",
        "83" => "Device error, e.g. paper out",
        "84" => "Value too large to be stored in data type",
        "85" => "Bad executable",
        "86" => "Bad CPU type in executable",
        "87" => "Shared library version mismatch",
        "88" => "Malformed Macho file",
        "89" => "Operation canceled",
        "90" => "Identifier removed",
        "91" => "No message of desired type",
        "92" => "Illegal byte sequence",
        "93" => "Attribute not found",
        "94" => "Bad message",
        "95" => "Reserved",
        "96" => "No message available on STREAM",
        "97" => "Reserved",
        "98" => "No STREAM resources",
        "99" => "Not a STREAM",
        "100" => "Protocol error",
        "101" => "STREAM ioctl timeout",
        "102" => "Operation not supported on socket",
        "103" => "No such policy registered",
        "104" => "State not recoverable",
        "105" => "Previous owner died",
        "106" => "Interface output queue is full, Must be equal largest errno",
        "-1" => "Restart syscall",
        "-2" => "Don't modify regs, just return",
        "-5" => "Restart lookup under heavy vnode pressure/recycling",
        "-6" => "Red drive open",
        "-7" => "Keep looking",
        "-8" => "Data less",
        _ => {
            warn!("[macos-unifiedlogs] Unknown darwin errno code: {}", errno);
            return format!("Unknown errno: {}", errno);
        }
    };

    errno_message.to_string()
}

/// Parse UNIX permissions to string version
pub(crate) fn permission(permissions: &str) -> String {
    let mut message = String::from("-");
    for bit in permissions.chars() {
        match bit {
            '1' => message = format!("{}--x", message),
            '2' => message = format!("{}-w-", message),
            '4' => message = format!("{}r--", message),
            '3' => message = format!("{}-wx", message),
            '5' => message = format!("{}r-x", message),
            '6' => message = format!("{}rw-", message),
            '7' => message = format!("{}rwx", message),
            _ => message = format!("{}---", message),
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use crate::decoders::darwin::{errno_codes, permission};

    #[test]
    fn test_errno_codes() {
        let mut test_data = "1";
        let mut result = errno_codes(test_data);
        assert_eq!(result, "Operation not permitted");

        test_data = "35";
        result = errno_codes(test_data);
        assert_eq!(
            result,
            "Resource temporarily unavailable, operation would block"
        );

        test_data = "58";
        result = errno_codes(test_data);
        assert_eq!(result, "Can't send after socket shutdown");

        test_data = "82";
        result = errno_codes(test_data);
        assert_eq!(result, "Device power is off");
    }

    #[test]
    fn test_permission() {
        let mut test_data = "111";
        let mut result = permission(test_data);
        assert_eq!(result, "---x--x--x");

        test_data = "448";
        result = permission(test_data);
        assert_eq!(result, "-r--r-----");

        test_data = "777";
        result = permission(test_data);
        assert_eq!(result, "-rwxrwxrwx");

        test_data = "400";
        result = permission(test_data);
        assert_eq!(result, "-r--------");
    }
}
