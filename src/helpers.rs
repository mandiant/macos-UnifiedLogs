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

const INVALID_UTF8: &str = "<Invalid UTF-8>";
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

/// Extract a sized string (Firehose string items, DNS URLs). Trailing NUL
/// padding is trimmed; non-UTF-8 bytes yield "Could not find path string",
/// unless the data is also truncated, which is an error.
pub(crate) fn extract_string_size(data: &[u8], size: usize) -> nom::IResult<&[u8], &str> {
    if size == 0 {
        return Ok((data, "(null)"));
    }
    let available = size.min(data.len());
    let (input, bytes) = take(available)(data)?;
    match from_utf8(bytes) {
        Ok(s) => Ok((input, s.trim_end_matches('\0'))),
        Err(err) => {
            error!("[macos-unifiedlogs] Failed to get specific string: {err:?}");
            if available < size {
                return Err(nom::Err::Error(nom::error::Error::new(
                    data,
                    ErrorKind::Eof,
                )));
            }
            Ok((input, "Could not find path string"))
        }
    }
}

/// Extract an UTF8 string from a byte array, stops at `NULL_BYTE` or END OF STRING.
/// Consumes the end byte. Fails if the string is empty.
pub(crate) fn non_empty_cstring(input: &[u8]) -> nom::IResult<&[u8], &str> {
    if input.is_empty() {
        return Ok((input, ""));
    }
    let mut tup = (take_while(|b: u8| b != NULL_BYTE), opt(take(1_usize)));
    let (input, (str_part, _)) = tup.parse(input)?;
    match from_utf8(str_part) {
        Ok(s) if !s.is_empty() => Ok((input, s)),
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
    use super::*;
    use std::path::PathBuf;

    pub fn test_data_path() -> PathBuf {
        PathBuf::from(std::env!("CARGO_MANIFEST_DIR")).join("tests/test_data")
    }

    /// Unwrap a nom result, keeping the (rest, value) pair.
    fn ok<T: std::fmt::Debug>(result: nom::IResult<&[u8], T>) -> (&[u8], T) {
        result.expect("parser should succeed")
    }

    /// Error kind of a failed nom result.
    fn err_kind<T: std::fmt::Debug>(result: nom::IResult<&[u8], T>) -> ErrorKind {
        match result.expect_err("parser should fail") {
            nom::Err::Error(e) | nom::Err::Failure(e) => e.code,
            nom::Err::Incomplete(_) => panic!("complete parsers never report Incomplete"),
        }
    }

    // "é" is a 2-byte sequence; its first byte alone is a truncated multibyte char.
    const E_ACUTE: &[u8] = "é".as_bytes();
    const INVALID: &[u8] = &[0xff, 0xfe];

    mod padding {
        use super::*;

        #[test]
        fn aligned_sizes_need_no_padding() {
            for size in [0, 8, 16, 1024] {
                assert_eq!(padding_size(size, 8), 0, "size {size}");
                assert_eq!(padding_size_8(size), 0, "size {size}");
            }
        }

        #[test]
        fn unaligned_sizes_pad_up_to_next_boundary() {
            for size in 1..8 {
                assert_eq!(padding_size(size, 8), 8 - size, "size {size}");
                assert_eq!(padding_size_8(size), 8 - size, "size {size}");
            }
            assert_eq!(padding_size(9, 8), 7);
            assert_eq!(padding_size(15, 8), 1);
        }

        #[test]
        fn other_power_of_two_alignments() {
            assert_eq!(padding_size(5, 4), 3);
            assert_eq!(padding_size(4, 4), 0);
            assert_eq!(padding_size(17, 16), 15);
            assert_eq!(padding_size(31, 16), 1);
            // Alignment 1 never pads.
            for size in 0..20 {
                assert_eq!(padding_size(size, 1), 0, "size {size}");
            }
        }

        #[test]
        fn anticipated_padding_uses_the_product() {
            // 3 items of 5 bytes = 15 bytes → 1 byte to reach 16.
            assert_eq!(anticipated_padding_size(3, 5, 8), 1);
            assert_eq!(anticipated_padding_size_8(3, 5), 1);
            // 2 × 4 = 8 → aligned.
            assert_eq!(anticipated_padding_size_8(2, 4), 0);
            // Zero items → nothing to align.
            assert_eq!(anticipated_padding_size_8(0, 123), 0);
            assert_eq!(anticipated_padding_size_8(123, 0), 0);
        }
    }

    mod u64_to_usize {
        use super::*;

        #[test]
        fn small_values_convert() {
            assert_eq!(u64_to_usize(0), Some(0));
            assert_eq!(u64_to_usize(42), Some(42));
            assert_eq!(u64_to_usize(usize::MAX as u64), Some(usize::MAX));
        }

        #[cfg(target_pointer_width = "32")]
        #[test]
        fn values_above_usize_are_rejected() {
            assert_eq!(u64_to_usize(u64::MAX), None);
            assert_eq!(u64_to_usize(u64::from(u32::MAX) + 1), None);
        }
    }

    mod utf8_str {
        use super::*;

        #[test]
        fn plain_and_terminated_strings() {
            assert_eq!(utf8_str(b""), "");
            assert_eq!(utf8_str(b"abc"), "abc");
            assert_eq!(utf8_str(b"abc\0"), "abc");
            assert_eq!(utf8_str(b"abc\0\0\0"), "abc");
        }

        #[test]
        fn stops_at_first_nul() {
            assert_eq!(utf8_str(b"a\0b\0"), "a");
            assert_eq!(utf8_str(b"\0abc"), "");
            assert_eq!(utf8_str(b"\0"), "");
        }

        #[test]
        fn multibyte_is_preserved() {
            assert_eq!(utf8_str("héllo\0".as_bytes()), "héllo");
        }

        #[test]
        fn invalid_utf8_yields_placeholder() {
            assert_eq!(utf8_str(INVALID), INVALID_UTF8);
            assert_eq!(utf8_str(&E_ACUTE[..1]), INVALID_UTF8);
            // Validation covers the whole buffer, even bytes after the NUL.
            assert_eq!(utf8_str(b"ok\0\xff"), INVALID_UTF8);
        }
    }

    mod utf8_str_sized {
        use super::*;

        #[test]
        fn trims_only_trailing_nuls() {
            assert_eq!(utf8_str_sized(b""), "");
            assert_eq!(utf8_str_sized(b"abc"), "abc");
            assert_eq!(utf8_str_sized(b"abc\0\0\0"), "abc");
            assert_eq!(utf8_str_sized(b"a\0b\0"), "a\0b");
            assert_eq!(utf8_str_sized(b"\0abc"), "\0abc");
            assert_eq!(utf8_str_sized(b"\0\0"), "");
        }

        #[test]
        fn invalid_utf8_yields_placeholder() {
            assert_eq!(utf8_str_sized(INVALID), INVALID_UTF8);
            assert_eq!(utf8_str_sized(b"ok\0\xff"), INVALID_UTF8);
        }
    }

    mod utf8_str_from_cstring {
        use super::*;

        #[test]
        fn empty_input_is_empty_string() {
            assert_eq!(ok(utf8_str_from_cstring(b"")), (&b""[..], ""));
        }

        #[test]
        fn consumes_the_terminator() {
            assert_eq!(ok(utf8_str_from_cstring(b"abc\0def")), (&b"def"[..], "abc"));
            assert_eq!(ok(utf8_str_from_cstring(b"abc\0")), (&b""[..], "abc"));
            assert_eq!(ok(utf8_str_from_cstring(b"\0abc")), (&b"abc"[..], ""));
            assert_eq!(ok(utf8_str_from_cstring(b"\0")), (&b""[..], ""));
        }

        #[test]
        fn unterminated_input_takes_everything() {
            assert_eq!(ok(utf8_str_from_cstring(b"abc")), (&b""[..], "abc"));
        }

        #[test]
        fn invalid_utf8_yields_placeholder_but_still_advances() {
            assert_eq!(
                ok(utf8_str_from_cstring(b"\xff\xfe\0rest")),
                (&b"rest"[..], INVALID_UTF8)
            );
        }
    }

    mod extract_string {
        use super::*;

        #[test]
        fn empty_input_reports_a_message_without_failing() {
            assert_eq!(
                ok(extract_string(b"")),
                (&b""[..], "Cannot extract string. Empty input.")
            );
        }

        #[test]
        fn unterminated_input_takes_everything() {
            assert_eq!(ok(extract_string(b"abc")), (&b""[..], "abc"));
            assert_eq!(ok(extract_string("héllo".as_bytes())), (&b""[..], "héllo"));
        }

        #[test]
        fn terminated_input_stops_at_first_nul_and_keeps_it() {
            assert_eq!(ok(extract_string(b"abc\0")), (&b"\0"[..], "abc"));
            assert_eq!(ok(extract_string(b"ab\0cd\0")), (&b"\0cd\0"[..], "ab"));
            assert_eq!(ok(extract_string(b"\0")), (&b"\0"[..], ""));
        }

        #[test]
        fn invalid_utf8_yields_placeholder_on_both_paths() {
            // Unterminated path.
            assert_eq!(
                ok(extract_string(b"\xff\xfeabc")),
                (&b""[..], "Could not extract string")
            );
            // Terminated path.
            assert_eq!(
                ok(extract_string(b"\xff\0")),
                (&b"\0"[..], "Could not extract string")
            );
            // Truncated multibyte char right before the terminator.
            let mut data = E_ACUTE[..1].to_vec();
            data.push(0);
            assert_eq!(
                ok(extract_string(&data)),
                (&b"\0"[..], "Could not extract string")
            );
        }
    }

    mod extract_string_size {
        use super::*;

        #[test]
        fn zero_size_is_null_and_consumes_nothing() {
            assert_eq!(ok(extract_string_size(b"", 0)), (&b""[..], "(null)"));
            assert_eq!(ok(extract_string_size(b"abc", 0)), (&b"abc"[..], "(null)"));
        }

        #[test]
        fn takes_exactly_size_bytes() {
            assert_eq!(ok(extract_string_size(b"abc", 3)), (&b""[..], "abc"));
            assert_eq!(ok(extract_string_size(b"abcdef", 3)), (&b"def"[..], "abc"));
            assert_eq!(ok(extract_string_size(b"abc", 1)), (&b"bc"[..], "a"));
        }

        #[test]
        fn trims_trailing_nuls_but_keeps_embedded_ones() {
            assert_eq!(ok(extract_string_size(b"ab\0\0", 4)), (&b""[..], "ab"));
            assert_eq!(ok(extract_string_size(b"a\0b", 3)), (&b""[..], "a\0b"));
            assert_eq!(ok(extract_string_size(b"\0\0\0", 3)), (&b""[..], ""));
            // Only the sized window is trimmed; the rest is untouched.
            assert_eq!(ok(extract_string_size(b"a\0\0\0", 2)), (&b"\0\0"[..], "a"));
        }

        #[test]
        fn oversized_request_is_clamped_to_available_data() {
            assert_eq!(ok(extract_string_size(b"abc", 4)), (&b""[..], "abc"));
            assert_eq!(
                ok(extract_string_size(b"abc", usize::MAX)),
                (&b""[..], "abc")
            );
            assert_eq!(ok(extract_string_size(b"", 5)), (&b""[..], ""));
        }

        #[test]
        fn invalid_utf8_yields_placeholder_when_data_is_complete() {
            assert_eq!(
                ok(extract_string_size(INVALID, 2)),
                (&b""[..], "Could not find path string")
            );
            assert_eq!(
                ok(extract_string_size(b"\xff\xfeXY", 2)),
                (&b"XY"[..], "Could not find path string")
            );
            // A size that splits a multibyte char is invalid but not truncated.
            assert_eq!(
                ok(extract_string_size(E_ACUTE, 1)),
                (&E_ACUTE[1..], "Could not find path string")
            );
        }

        #[test]
        fn invalid_utf8_on_truncated_data_is_an_error() {
            assert_eq!(err_kind(extract_string_size(INVALID, 3)), ErrorKind::Eof);
            assert_eq!(
                err_kind(extract_string_size(&E_ACUTE[..1], 2)),
                ErrorKind::Eof
            );
            match extract_string_size(INVALID, 3) {
                Err(nom::Err::Error(e)) => {
                    assert_eq!(e.input, INVALID, "error points at the input")
                }
                other => panic!("expected recoverable error, got {other:?}"),
            }
        }
    }

    mod non_empty_cstring {
        use super::*;

        #[test]
        fn empty_input_is_empty_string() {
            assert_eq!(ok(non_empty_cstring(b"")), (&b""[..], ""));
        }

        #[test]
        fn consumes_the_terminator() {
            assert_eq!(
                ok(non_empty_cstring(b"nobody\0/Local/Default\0")),
                (&b"/Local/Default\0"[..], "nobody")
            );
            assert_eq!(ok(non_empty_cstring(b"abc\0")), (&b""[..], "abc"));
        }

        #[test]
        fn unterminated_input_takes_everything() {
            assert_eq!(ok(non_empty_cstring(b"abc")), (&b""[..], "abc"));
        }

        #[test]
        fn empty_string_is_a_failure() {
            assert_eq!(err_kind(non_empty_cstring(b"\0abc")), ErrorKind::Fail);
            assert_eq!(err_kind(non_empty_cstring(b"\0")), ErrorKind::Fail);
        }

        #[test]
        fn invalid_utf8_is_a_failure() {
            assert_eq!(err_kind(non_empty_cstring(b"\xff\xfe\0")), ErrorKind::Fail);
            assert_eq!(err_kind(non_empty_cstring(&E_ACUTE[..1])), ErrorKind::Fail);
        }
    }

    mod base64 {
        use super::*;

        #[test]
        fn round_trip() {
            for data in [&b""[..], b"a", b"ab", b"abc", &[0u8, 0xff, 0x80, 0x7f]] {
                let encoded = encode_standard(data);
                assert_eq!(decode_standard(&encoded).unwrap(), data, "{data:?}");
            }
        }

        #[test]
        fn standard_alphabet_and_padding() {
            assert_eq!(encode_standard(b"hello"), "aGVsbG8=");
            assert_eq!(encode_standard(&[0xfb, 0xff]), "+/8=");
            assert_eq!(decode_standard("aGVsbG8=").unwrap(), b"hello");
        }

        #[test]
        fn rejects_garbage() {
            assert!(decode_standard("!!!!").is_err());
            // URL-safe alphabet is not accepted by the STANDARD engine.
            assert!(decode_standard("-_8=").is_err());
            // Missing padding is rejected.
            assert!(decode_standard("YQ").is_err());
        }
    }

    mod format_uuid {
        use super::*;

        #[test]
        fn upper_hex_without_hyphens() {
            let uuid = Uuid::parse_str("2e33403a-6faa-3ee9-a9a7-b6c4d4a9db31").unwrap();
            assert_eq!(format_uuid(uuid), "2E33403A6FAA3EE9A9A7B6C4D4A9DB31");
            assert_eq!(format_uuid(Uuid::nil()), "0".repeat(32));
            assert_eq!(format_uuid(Uuid::max()), "F".repeat(32));
        }
    }

    mod join_strs {
        use super::*;

        #[test]
        fn empty_and_single() {
            assert_eq!(join_strs(Vec::<&str>::new(), ", ", None), "");
            assert_eq!(join_strs(["a"], ", ", None), "a");
            assert_eq!(join_strs(["a"], ", ", Some("'")), "'a'");
        }

        #[test]
        fn separator_and_decorator() {
            assert_eq!(join_strs(["a", "b", "c"], ", ", None), "a, b, c");
            assert_eq!(join_strs(["a", "b"], "", Some("\"")), "\"a\"\"b\"");
            assert_eq!(
                join_strs(vec![String::from("x"), String::from("y")], "-", Some("[")),
                "[x[-[y["
            );
        }

        #[test]
        fn leading_empty_items_do_not_produce_a_separator() {
            // An empty accumulator is indistinguishable from "nothing joined yet",
            // so a leading empty item is silently swallowed without a decorator...
            assert_eq!(join_strs(["", "a"], ", ", None), "a");
            // ...but kept when a decorator makes it non-empty.
            assert_eq!(join_strs(["", "a"], ", ", Some("'")), "'', 'a'");
            // Empty items after the first are always separated.
            assert_eq!(join_strs(["a", "", "b"], ", ", None), "a, , b");
        }
    }
}
