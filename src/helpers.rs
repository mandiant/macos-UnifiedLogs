use base64::DecodeError;
use base64::{Engine, engine::general_purpose};
use log::{error, warn};
use nom::error::ErrorKind;
use nom::{
    Parser,
    bytes::complete::{take, take_while},
    combinator::opt,
};
use std::str::from_utf8;
use uuid::Uuid;

pub(crate) const INVALID_UTF8: &str = "<Invalid UTF-8>";
const NULL_BYTE: u8 = 0;

/// Returns the padding to consume in order to align to 8 bytes
/// Actual total size is computed as `items_count` * `items_size`
pub(crate) fn anticipated_padding_size_8(items_count: u64, items_size: u64) -> u64 {
    anticipated_padding_size(items_count, items_size, 8)
}

/// Returns the padding to consume in order to align to 'alignment' bytes
/// Actual total size is computed as `items_count` * `items_size`
pub(crate) fn anticipated_padding_size(items_count: u64, items_size: u64, alignment: u64) -> u64 {
    let total_size = items_count * items_size;
    padding_size(total_size, alignment)
}

/// Calculate padding based on provided `alignment`
pub(crate) fn padding_size(data_size: u64, alignment: u64) -> u64 {
    (alignment - (data_size & (alignment - 1))) & (alignment - 1)
}

/// Calculate padding to align to 8 bytes
pub(crate) fn padding_size_8(data_size: u64) -> u64 {
    padding_size(data_size, 8)
}

pub(crate) fn u64_to_usize(n: u64) -> Option<usize> {
    usize::try_from(n).ok()
}

/// Decode UTF-8 bytes that represent a C-style string.
///
/// The first NUL byte terminates the string, so any bytes after it are ignored.
/// Example: `b"a\0b\0"` decodes as `"a"`.
pub(crate) fn utf8_str(data: &[u8]) -> &str {
    std::str::from_utf8(data)
        .inspect_err(|err| log::warn!("{err}"))
        .map(|s| match s.find('\0') {
            Some(pos) => &s[..pos],
            None => s,
        })
        .unwrap_or(INVALID_UTF8)
}

/// Decode UTF-8 bytes that represent a sized string field.
///
/// The full declared field is decoded, embedded NUL bytes are preserved, and
/// only trailing NUL terminators/padding are removed.
/// Example: `b"a\0b\0"` decodes as `"a\0b"`.
pub(crate) fn utf8_str_sized(data: &[u8]) -> &str {
    std::str::from_utf8(data)
        .inspect_err(|err| log::warn!("{err}"))
        .map(|s| s.trim_end_matches('\0'))
        .unwrap_or(INVALID_UTF8)
}

/// Extract an UTF8 string from a byte array, stops at `NULL_BYTE` or END OF STRING
/// Consumes the end byte
/// Fails if the string is empty
pub(crate) fn utf8_str_from_cstring(input: &[u8]) -> nom::IResult<&[u8], &str> {
    if input.is_empty() {
        return Ok((input, ""));
    }
    let mut tup = (take_while(|b: u8| b != NULL_BYTE), opt(take(1_usize)));
    let (input, (str_part, _)) = tup.parse(input)?;
    let str_part = utf8_str(str_part);
    Ok((input, str_part))
}

/// Base64 decode data using the STANDARD engine (alphabet along with "+" and "/")
pub(crate) fn decode_standard(data: &str) -> Result<Vec<u8>, DecodeError> {
    general_purpose::STANDARD.decode(data)
}

/// Base64 encode data using the STANDARD engine (alphabet along with "+" and "/")
pub(crate) fn encode_standard(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Extract strings that contain end of string characters
pub(crate) fn extract_string(data: &[u8]) -> nom::IResult<&[u8], &str> {
    let last_value = data.last();
    match last_value {
        Some(value) => {
            if value != &NULL_BYTE {
                let (input, path) = take(data.len())(data)?;
                let path_string = from_utf8(path);
                match path_string {
                    Ok(results) => return Ok((input, results)),
                    Err(err) => {
                        warn!("[macos-unifiedlogs] Failed to extract full string: {err:?}");
                        return Ok((input, "Could not extract string"));
                    }
                }
            }
        }
        None => {
            error!("[macos-unifiedlogs] Cannot extract string. Empty input.");
            return Ok((data, "Cannot extract string. Empty input."));
        }
    }

    let (input, c_str) = take_while(|b: u8| b != NULL_BYTE)(data)?;

    match from_utf8(c_str) {
        Ok(utf8_string) => Ok((input, utf8_string)),
        Err(err) => {
            warn!("[macos-unifiedlogs] Failed to get string: {err:?}");
            Ok((input, "Could not extract string"))
        }
    }
}

/// Extract a size based on provided string size from Firehose string item entries
pub(crate) fn extract_string_size(data: &[u8], message_size: u64) -> nom::IResult<&[u8], String> {
    const NULL_STRING: u64 = 0;
    if message_size == NULL_STRING {
        return Ok((data, "(null)".to_string()));
    }

    if data.len() < message_size as usize {
        let (input, path) = take(data.len())(data)?;
        let path_string = String::from_utf8(path.to_vec());
        match path_string {
            Ok(results) => {
                return Ok((input, results.trim_end_matches(char::from(0)).to_string()));
            }
            Err(err) => {
                error!("[macos-unifiedlogs] Failed to get extract specific string size: {err:?}")
            }
        }
    }

    let message_size = match u64_to_usize(message_size) {
        Some(m) => m,
        None => {
            error!("[macos-unifiedlogs] u64 is bigger than system usize");
            return Err(nom::Err::Error(nom::error::Error::new(
                data,
                nom::error::ErrorKind::TooLarge,
            )));
        }
    };

    let (input, path) = take(message_size)(data)?;
    let path_string = String::from_utf8(path.to_vec());
    match path_string {
        Ok(results) => return Ok((input, results.trim_end_matches(char::from(0)).to_string())),
        Err(err) => error!("[macos-unifiedlogs] Failed to get specific string: {err:?}"),
    }
    Ok((input, String::from("Could not find path string")))
}

/// Extract an UTF8 string from a byte array, stops at `NULL_BYTE` or END OF STRING.
/// Consumes the end byte. Fails if the string is empty.
pub(crate) fn non_empty_cstring(input: &[u8]) -> nom::IResult<&[u8], String> {
    if input.is_empty() {
        return Ok((input, String::new()));
    }
    let mut tup = (take_while(|b: u8| b != NULL_BYTE), opt(take(1_usize)));
    let (input, (str_part, _)) = tup.parse(input)?;
    match from_utf8(str_part) {
        Ok(s) if !s.is_empty() => Ok((input, s.to_string())),
        _ => Err(nom::Err::Error(nom::error::Error {
            input,
            code: ErrorKind::Fail,
        })),
    }
}

/// Clean and format UUIDs to be pretty
pub(crate) fn format_uuid(uuid: Uuid) -> String {
    format!("{:X}", uuid.simple())
}

/// Returns joined string without having to collect to vec first
pub(crate) fn join_strs(
    strings: impl IntoIterator<Item = impl AsRef<str>>,
    separator: &str,
    decorator: Option<&str>,
) -> String {
    strings.into_iter().fold(String::new(), |mut acc, s| {
        if !acc.is_empty() {
            acc.push_str(separator);
        }
        if let Some(decorator) = decorator {
            acc.push_str(decorator);
        }
        acc.push_str(s.as_ref());
        if let Some(decorator) = decorator {
            acc.push_str(decorator);
        }
        acc
    })
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;

    pub fn test_data_path() -> PathBuf {
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("tests/test_data")
    }
}
