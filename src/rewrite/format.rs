//! Message formatting: expand printf-style format strings with parsed item values.
//!
//! Single-pass scanner replaces format specifiers inline, working directly with
//! typed `RawItemValue` variants (no string reparsing needed).

use crate::rewrite::helpers::utf8_str;

use base64::Engine;

use super::chunks::firehose::item::{RawFirehoseItem, RawItemKind, RawItemValue};
use super::decoders::darwin::errno_codes;
use std::fmt::Write;

// ---------------------------------------------------------------------------
// Apple annotation decoder
// ---------------------------------------------------------------------------

/// Decode an Apple-annotated log value (e.g. `%{network:in_addr}d`, `%{uuid_t}s`).
///
/// Converts the raw item value to a string, then dispatches to the appropriate
/// decoder based on the annotation. Returns `None` if the annotation is not
/// recognized or the decoder fails — the caller falls back to normal formatting.
fn decode_annotation(annotation: &str, item: &RawFirehoseItem<'_>) -> Option<String> {
    let value_str: String = match &item.value {
        RawItemValue::I64(n) => n.to_string(),
        RawItemValue::U64(n) => n.to_string(),
        RawItemValue::Str(s) => s.to_string(),
        RawItemValue::Bytes(b) => base64::engine::general_purpose::STANDARD.encode(b),
        RawItemValue::Private { .. } => return None,
        // Old pipeline calls decoders with empty string for size-0 items (e.g. sockaddr("") →
        // "Unknown sockaddr family: 0"). Most decoders will fail on empty input and we'll
        // return None below, matching the fallthrough behavior.
        RawItemValue::Empty | RawItemValue::Null => String::new(),
    };

    // Replicate check_objects: mask.hash + BaseRaw (0xf2) → return base64 as-is,
    // bypassing all decoders and formatting (matches old pipeline behavior).
    if annotation.contains("mask.hash") && item.item_type == RawItemKind::BaseRaw {
        return Some(value_str);
    }

    match crate::rewrite::decoders::decoder::to_decoded_value(annotation, &value_str) {
        Ok(Some(decoded)) => Some(decoded.to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// FormatSpec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct FormatSpec {
    left_justify: bool,
    show_sign: bool,
    alternate: bool,
    zero_pad: bool,
    width: usize,
    has_width: bool,
    precision: usize,
    has_precision: bool,
    conversion: char,
}

impl FormatSpec {
    fn new(conversion: char) -> Self {
        Self {
            left_justify: false,
            show_sign: false,
            alternate: false,
            zero_pad: false,
            width: 0,
            has_width: false,
            precision: 0,
            has_precision: false,
            conversion,
        }
    }
}

// ---------------------------------------------------------------------------
// Conversion categories
// ---------------------------------------------------------------------------

fn is_int_conversion(c: char) -> bool {
    matches!(c, 'd' | 'D' | 'i' | 'u' | 'U')
}

fn is_float_conversion(c: char) -> bool {
    matches!(c, 'f' | 'F' | 'e' | 'E' | 'g' | 'G')
}

fn is_hex_conversion(c: char) -> bool {
    matches!(c, 'x' | 'X' | 'a' | 'A' | 'p')
}

fn is_octal_conversion(c: char) -> bool {
    matches!(c, 'o' | 'O')
}

fn is_string_conversion(c: char) -> bool {
    matches!(c, 's' | 'S' | '@' | 'P')
}

fn is_char_conversion(c: char) -> bool {
    matches!(c, 'c' | 'C')
}

fn is_error_conversion(c: char) -> bool {
    c == 'm'
}

fn is_conversion_char(c: char) -> bool {
    matches!(
        c,
        'c' | 'm'
            | 'C'
            | 'd'
            | 'D'
            | 'i'
            | 'o'
            | 'O'
            | 'u'
            | 'U'
            | 'x'
            | 'X'
            | 'e'
            | 'E'
            | 'f'
            | 'F'
            | 'g'
            | 'G'
            | 'a'
            | 'A'
            | 'n'
            | 'p'
            | 's'
            | 'S'
            | 'Z'
            | 'P'
            | '@'
    )
}

fn is_length_modifier_start(c: char) -> bool {
    matches!(c, 'h' | 'l' | 'w' | 'I' | 'z' | 't' | 'q')
}

// ---------------------------------------------------------------------------
// Value extraction
// ---------------------------------------------------------------------------

fn extract_int(value: &RawItemValue<'_>) -> i64 {
    match value {
        RawItemValue::I64(n) => *n,
        RawItemValue::U64(n) => (*n).cast_signed(),
        RawItemValue::Str(s) => s.parse::<i64>().unwrap_or(0),
        _ => 0,
    }
}

fn extract_float(value: &RawItemValue<'_>) -> f64 {
    match value {
        RawItemValue::I64(n) => f64::from_bits((*n).cast_unsigned()),
        RawItemValue::U64(n) => f64::from_bits(*n),
        _ => 0.0,
    }
}

fn extract_str<'a>(value: &'a RawItemValue<'a>) -> &'a str {
    match value {
        RawItemValue::Str(s) => s,
        RawItemValue::Bytes(b) => utf8_str(b),
        #[cfg(feature = "rewrite-compat")]
        RawItemValue::Null => "(null)",
        RawItemValue::Private { .. } => "<private>",
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// apply_format — unified formatting with flags/width/precision
// ---------------------------------------------------------------------------

fn apply_format(output: &mut String, item: &RawFirehoseItem<'_>, spec: &FormatSpec) {
    let c = spec.conversion;

    if is_error_conversion(c) {
        let n = extract_int(&item.value);
        let _ = write!(output, "{}", errno_codes(&n.to_string()));
        return;
    }

    if is_char_conversion(c) {
        let n = extract_int(&item.value);
        output.push(n as u8 as char);
        return;
    }

    if is_string_conversion(c) {
        // Old pipeline: extract_string_size() returns "(null)" for ALL items with size=0
        #[cfg(feature = "rewrite-compat")]
        if item.item_size == 0 && matches!(&item.value, RawItemValue::Str(s) if s.is_empty()) {
            apply_string_format(output, "(null)", spec);
            return;
        }

        // Old pipeline base64-encodes Bytes items at parsing stage,
        // so all format specifiers see base64 strings for byte data.
        #[cfg(feature = "rewrite-compat")]
        if let RawItemValue::Bytes(b) = &item.value {
            let encoded = base64::engine::general_purpose::STANDARD.encode(b);
            apply_string_format(output, &encoded, spec);
            return;
        }

        let s = extract_str(&item.value);
        // For string items that are actually numbers (type mismatch), use raw string
        let display: &str = if s.is_empty() {
            if let RawItemValue::I64(n) = &item.value {
                // Legacy: number item with string formatter → show number as string
                let tmp = n.to_string();
                apply_string_format(output, &tmp, spec);
                return;
            }
            s
        } else {
            s
        };
        apply_string_format(output, display, spec);
        return;
    }

    if is_float_conversion(c) {
        let f = extract_float(&item.value);
        apply_float_format(output, f, spec);
        return;
    }

    if is_int_conversion(c) {
        let n = extract_int(&item.value);
        apply_int_format(output, n, spec);
        return;
    }

    if is_hex_conversion(c) {
        let n = extract_int(&item.value);
        apply_hex_format(output, n, spec);
        return;
    }

    if is_octal_conversion(c) {
        let n = extract_int(&item.value);
        apply_octal_format(output, n, spec);
        return;
    }

    // 'n' and 'Z' — just emit the raw value as a string
    #[cfg(feature = "rewrite-compat")]
    if item.item_size == 0 && matches!(&item.value, RawItemValue::Str(s) if s.is_empty()) {
        output.push_str("(null)");
        return;
    }
    let s = extract_str(&item.value);
    output.push_str(s);
}

// --- String formatting ---

fn apply_string_format(output: &mut String, s: &str, spec: &FormatSpec) {
    // Old pipeline: precision=0 for strings means "show full string" (format_right special case).
    // This happens with %.*s when dynamic precision resolves to 0.
    #[cfg(feature = "rewrite-compat")]
    let effective_precision = if spec.has_precision && spec.precision == 0 {
        s.len()
    } else {
        spec.precision
    };
    #[cfg(not(feature = "rewrite-compat"))]
    let effective_precision = spec.precision;

    let displayed = if spec.has_precision && effective_precision < s.len() {
        &s[..effective_precision]
    } else {
        s
    };

    let plus = if spec.show_sign { "+" } else { "" };

    if spec.has_width && spec.width > displayed.len() + plus.len() {
        let pad = spec.width - displayed.len() - plus.len();
        let fill = if spec.zero_pad { '0' } else { ' ' };
        if spec.left_justify {
            output.push_str(plus);
            output.push_str(displayed);
            for _ in 0..pad {
                output.push(fill);
            }
        } else {
            for _ in 0..pad {
                output.push(fill);
            }
            output.push_str(plus);
            output.push_str(displayed);
        }
    } else {
        output.push_str(plus);
        output.push_str(displayed);
    }
}

// --- Integer formatting ---

fn apply_int_format(output: &mut String, n: i64, spec: &FormatSpec) {
    let plus = if spec.show_sign && n >= 0 { "+" } else { "" };
    let formatted = format!("{n}");
    let core = format!("{plus}{formatted}");

    if spec.has_width && spec.width > core.len() {
        let pad = spec.width - core.len();
        if spec.zero_pad && !spec.left_justify {
            // Zero-pad: sign before zeros
            if n < 0 {
                output.push('-');
                let digits = &formatted[1..]; // skip '-'
                let pad = spec.width - 1 - digits.len() - plus.len();
                output.push_str(plus);
                for _ in 0..pad {
                    output.push('0');
                }
                output.push_str(digits);
            } else {
                output.push_str(plus);
                for _ in 0..pad {
                    output.push('0');
                }
                output.push_str(&formatted);
            }
        } else if spec.left_justify {
            output.push_str(&core);
            for _ in 0..pad {
                output.push(if spec.zero_pad { '0' } else { ' ' });
            }
        } else {
            for _ in 0..pad {
                output.push(' ');
            }
            output.push_str(&core);
        }
    } else {
        output.push_str(&core);
    }
}

// --- Hex formatting (legacy: always uppercase) ---

fn apply_hex_format(output: &mut String, n: i64, spec: &FormatSpec) {
    let plus = if spec.show_sign { "+" } else { "" };

    // Legacy quirk: both %x and %X produce uppercase hex
    let hex_str = if spec.alternate {
        format!("0x{:X}", n)
    } else {
        format!("{:X}", n)
    };

    let core = format!("{plus}{hex_str}");

    if spec.has_width && spec.width > core.len() {
        let pad = spec.width - core.len();
        if spec.zero_pad && !spec.left_justify {
            output.push_str(plus);
            if spec.alternate {
                #[cfg(feature = "rewrite-compat")]
                {
                    // Old pipeline bug: format!("{:0>#width$X}") zero-pads the ENTIRE
                    // string including the "0x" prefix from the left.
                    let hex_str_alt = format!("0x{:X}", n);
                    for _ in 0..spec.width.saturating_sub(plus.len() + hex_str_alt.len()) {
                        output.push('0');
                    }
                    output.push_str(&hex_str_alt);
                }
                #[cfg(not(feature = "rewrite-compat"))]
                {
                    output.push_str("0x");
                    for _ in 0..spec
                        .width
                        .saturating_sub(plus.len() + 2 + hex_digits_len(n))
                    {
                        output.push('0');
                    }
                    let _ = write!(output, "{:X}", n);
                }
            } else {
                for _ in 0..pad {
                    output.push('0');
                }
                let _ = write!(output, "{:X}", n);
            }
        } else if spec.left_justify {
            output.push_str(&core);
            for _ in 0..pad {
                output.push(if spec.zero_pad { '0' } else { ' ' });
            }
        } else {
            for _ in 0..pad {
                output.push(' ');
            }
            output.push_str(&core);
        }
    } else {
        output.push_str(&core);
    }
}

#[cfg(not(feature = "rewrite-compat"))]
fn hex_digits_len(n: i64) -> usize {
    format!("{:X}", n).len()
}

// --- Octal formatting ---

fn apply_octal_format(output: &mut String, n: i64, spec: &FormatSpec) {
    let plus = if spec.show_sign { "+" } else { "" };

    // Legacy: uses Rust's `#o` which gives `0o` prefix
    let oct_str = if spec.alternate {
        format!("{n:#o}")
    } else {
        format!("{n:o}")
    };

    let core = format!("{plus}{oct_str}");

    if spec.has_width && spec.width > core.len() {
        let pad = spec.width - core.len();
        if spec.zero_pad && !spec.left_justify {
            output.push_str(plus);
            if spec.alternate {
                output.push_str("0o");
                let digits = &oct_str[2..]; // skip "0o"
                for _ in 0..spec.width.saturating_sub(plus.len() + 2 + digits.len()) {
                    output.push('0');
                }
                output.push_str(digits);
            } else {
                for _ in 0..pad {
                    output.push('0');
                }
                output.push_str(&oct_str);
            }
        } else if spec.left_justify {
            output.push_str(&core);
            for _ in 0..pad {
                output.push(if spec.zero_pad { '0' } else { ' ' });
            }
        } else {
            for _ in 0..pad {
                output.push(' ');
            }
            output.push_str(&core);
        }
    } else {
        output.push_str(&core);
    }
}

// --- Float formatting ---

fn apply_float_format(output: &mut String, f: f64, spec: &FormatSpec) {
    let plus = if spec.show_sign && f >= 0.0 { "+" } else { "" };

    let formatted = if spec.has_precision {
        format!("{f:.prec$}", prec = spec.precision)
    } else {
        // Old pipeline double-converts: format to string, count decimal digits, reformat with that
        // precision. This can round differently than direct formatting.
        #[cfg(feature = "rewrite-compat")]
        {
            let initial = format!("{f}");
            let decimal_digits = initial
                .find('.')
                .map(|pos| initial.len() - pos - 1)
                .unwrap_or(0);
            format!("{f:.prec$}", prec = decimal_digits)
        }
        #[cfg(not(feature = "rewrite-compat"))]
        {
            format!("{f}")
        }
    };

    let core = format!("{plus}{formatted}");

    if spec.has_width && spec.width > core.len() {
        let pad = spec.width - core.len();
        if spec.zero_pad && !spec.left_justify {
            // Sign before zeros
            if f < 0.0 {
                output.push('-');
                let digits = &formatted[1..]; // skip '-'
                output.push_str(plus);
                for _ in 0..spec.width.saturating_sub(1 + plus.len() + digits.len()) {
                    output.push('0');
                }
                output.push_str(digits);
            } else {
                output.push_str(plus);
                for _ in 0..pad {
                    output.push('0');
                }
                output.push_str(&formatted);
            }
        } else if spec.left_justify {
            output.push_str(&core);
            for _ in 0..pad {
                output.push(' ');
            }
        } else {
            for _ in 0..pad {
                output.push(' ');
            }
            output.push_str(&core);
        }
    } else {
        output.push_str(&core);
    }
}

// ---------------------------------------------------------------------------
// Specifier parsing
// ---------------------------------------------------------------------------

/// Parse a format specifier starting after `%`. Returns (`FormatSpec`, `bytes_consumed`, `has_dynamic_width`).
/// `bytes` is the format string slice starting right after `%`.
fn parse_specifier(bytes: &[u8]) -> (FormatSpec, usize, bool) {
    let len = bytes.len();
    let mut pos = 0;
    let mut spec = FormatSpec::new('\0');
    let mut has_dynamic_width = false;

    // 1. Flags
    while pos < len {
        match bytes[pos] {
            b'-' => spec.left_justify = true,
            b'+' => spec.show_sign = true,
            b'#' => spec.alternate = true,
            b'0' => spec.zero_pad = true,
            b' ' => {} // space flag — consumed but ignored
            _ => break,
        }
        pos += 1;
    }

    // 2. Width
    if pos < len && bytes[pos] == b'*' {
        has_dynamic_width = true;
        pos += 1;
    } else {
        let start = pos;
        while pos < len && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos > start
            && let Ok(w) = std::str::from_utf8(&bytes[start..pos])
                .unwrap_or("0")
                .parse::<usize>()
        {
            spec.width = w;
            spec.has_width = true;
        }
    }

    // 3. Precision
    if pos < len && bytes[pos] == b'.' {
        // Old pipeline regex: (?:\.(?:\d+|\*))? — requires digit or * after dot.
        // Bare `%.f` fails to match → treated as literal.
        #[cfg(feature = "rewrite-compat")]
        let should_consume_dot =
            pos + 1 < len && (bytes[pos + 1].is_ascii_digit() || bytes[pos + 1] == b'*');
        #[cfg(not(feature = "rewrite-compat"))]
        let should_consume_dot = true;

        if should_consume_dot {
            pos += 1;
            spec.has_precision = true;
            if pos < len && bytes[pos] == b'*' {
                // Dynamic precision — will be filled from precision item
                pos += 1;
            } else {
                let start = pos;
                while pos < len && bytes[pos].is_ascii_digit() {
                    pos += 1;
                }
                if pos > start
                    && let Ok(p) = std::str::from_utf8(&bytes[start..pos])
                        .unwrap_or("0")
                        .parse::<usize>()
                {
                    spec.precision = p;
                }
            }
        }
    }

    // 4. Length modifier (consumed but ignored)
    if pos < len && is_length_modifier_start(bytes[pos] as char) {
        pos += 1;
        // Handle hh, ll (two-char modifiers)
        if pos < len
            && ((bytes[pos - 1] == b'h' && bytes[pos] == b'h')
                || (bytes[pos - 1] == b'l' && bytes[pos] == b'l'))
        {
            pos += 1;
        }
    }

    // 5. Conversion type
    if pos < len && is_conversion_char(bytes[pos] as char) {
        spec.conversion = bytes[pos] as char;
        pos += 1;
    }

    (spec, pos, has_dynamic_width)
}

// ---------------------------------------------------------------------------
// format_message — main entry point
// ---------------------------------------------------------------------------

/// Format a printf-style log message by substituting items into the format string.
///
/// Returns an owned `String` — this is where the rewrite transitions from
/// zero-copy borrowed data to owned formatted output.
pub fn format_message(format_string: Option<&str>, items: &[RawFirehoseItem<'_>]) -> String {
    let fmt = match format_string {
        None => return String::from("<missing format string>"),
        Some("") if items.is_empty() => return String::new(),
        Some("") => {
            // Empty format string + non-empty items → return first item as string
            return item_to_string(&items[0]);
        }
        Some(s) => s,
    };

    let bytes = fmt.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len);
    let mut pos = 0;
    let mut item_index: usize = 0;

    while pos < len {
        if bytes[pos] != b'%' {
            if bytes[pos] < 0x80 {
                // ASCII byte — safe to cast directly
                result.push(bytes[pos] as char);
                pos += 1;
            } else {
                // Multi-byte UTF-8: decode the full character
                let rest = &fmt[pos..];
                if let Some(ch) = rest.chars().next() {
                    result.push(ch);
                    pos += ch.len_utf8();
                } else {
                    result.push(bytes[pos] as char);
                    pos += 1;
                }
            }
            continue;
        }

        // We have a '%'
        pos += 1; // skip '%'
        if pos >= len {
            result.push('%');
            break;
        }

        // %% → literal %
        if bytes[pos] == b'%' {
            result.push('%');
            pos += 1;
            continue;
        }

        // % followed by space → literal "% "
        if bytes[pos] == b' ' {
            result.push('%');
            result.push(' ');
            pos += 1;
            continue;
        }

        // %{...} → Apple-annotated specifier
        if bytes[pos] == b'{' {
            let (consumed, annotation) = parse_apple_annotation(bytes, pos);
            pos += consumed;

            // If '}' is last char (no conversion type after it) → emit literal
            if pos >= len || !is_conversion_char(bytes[pos] as char) {
                // Old pipeline regex only recognizes [-+0#] as flags (no space), digits,
                // and `*` as valid chars after `}` in annotated specifiers. Anything else
                // (space, `.` without preceding width, etc.) causes the regex to match
                // only `%{annotation}` with `}` as conversion → treated as literal.
                // Old pipeline regex after `}`: flags [-+0#], width [\d*], precision \.\d+|\*,
                // length modifiers [hlwIztq], then conversion. Space and bare `.` (no digits) are NOT valid.
                #[cfg(feature = "rewrite-compat")]
                let is_valid_spec_start = pos < len
                    && (matches!(
                        bytes[pos],
                        b'-' | b'+' | b'0' | b'#' | b'*' | b'1'
                            ..=b'9' | b'h' | b'l' | b'w' | b'I' | b'z' | b't' | b'q'
                    ) || (bytes[pos] == b'.'
                        && pos + 1 < len
                        && (bytes[pos + 1].is_ascii_digit() || bytes[pos + 1] == b'*')));
                #[cfg(not(feature = "rewrite-compat"))]
                let is_valid_spec_start = true;

                if !is_valid_spec_start {
                    // Emit as literal — old pipeline treats this as typeless annotation
                    result.push('%');
                    result.push('{');
                    result.push_str(&annotation);
                    result.push('}');
                    continue;
                }

                // Check for flags/width/length before potential conversion
                let (spec, spec_consumed, _dynamic) = if pos < len {
                    parse_specifier(&bytes[pos..])
                } else {
                    (FormatSpec::new('\0'), 0, false)
                };

                if spec.conversion == '\0' {
                    // No valid conversion found → emit literal
                    result.push('%');
                    result.push('{');
                    result.push_str(&annotation);
                    result.push('}');
                    continue;
                }
                pos += spec_consumed;

                // We have a conversion after annotation+flags
                format_annotated_item(&mut result, &annotation, &spec, items, &mut item_index);
                continue;
            }

            // Parse the specifier after annotation
            let (spec, spec_consumed, _has_dynamic_width) = parse_specifier(&bytes[pos..]);
            pos += spec_consumed;

            if spec.conversion == '\0' {
                // No valid conversion → literal
                result.push('%');
                result.push('{');
                result.push_str(&annotation);
                result.push('}');
                continue;
            }

            format_annotated_item(&mut result, &annotation, &spec, items, &mut item_index);
            continue;
        }

        // Plain specifier
        let (spec, spec_consumed, has_dynamic_width) = parse_specifier(&bytes[pos..]);
        pos += spec_consumed;

        if spec.conversion == '\0' {
            // Not a valid specifier, emit raw
            result.push('%');
            continue;
        }

        // Skip precision items
        skip_precision_items(items, &mut item_index);

        if item_index >= items.len() {
            {
                #[cfg(feature = "rewrite-compat")]
                result.push_str("<Missing message data>");
                #[cfg(not(feature = "rewrite-compat"))]
                result.push_str("<decode: missing data>");
            }
            continue;
        }

        // Handle dynamic width
        let mut spec = spec;
        if has_dynamic_width {
            handle_dynamic_width(items, &mut item_index, &mut spec);
        }

        if item_index >= items.len() {
            {
                #[cfg(feature = "rewrite-compat")]
                result.push_str("<Missing message data>");
                #[cfg(not(feature = "rewrite-compat"))]
                result.push_str("<decode: missing data>");
            }
            continue;
        }

        let item = &items[item_index];

        // Check for private
        if matches!(item.value, RawItemValue::Private { .. }) {
            result.push_str("<private>");
            item_index += 1;
            continue;
        }

        apply_format(&mut result, item, &spec);
        item_index += 1;
    }

    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_apple_annotation(bytes: &[u8], start: usize) -> (usize, String) {
    // start points at '{', scan to '}'
    let mut pos = start + 1; // skip '{'
    let mut annotation = String::new();
    while pos < bytes.len() && bytes[pos] != b'}' {
        annotation.push(bytes[pos] as char);
        pos += 1;
    }
    if pos < bytes.len() {
        pos += 1; // skip '}'
    }
    (pos - start, annotation)
}

fn skip_precision_items(items: &[RawFirehoseItem<'_>], item_index: &mut usize) {
    while *item_index < items.len() {
        if items[*item_index].item_type == RawItemKind::Precision {
            *item_index += 1;
        } else {
            break;
        }
    }
}

fn handle_dynamic_width(
    items: &[RawFirehoseItem<'_>],
    item_index: &mut usize,
    spec: &mut FormatSpec,
) {
    if *item_index < items.len() {
        let item = &items[*item_index];
        if item.item_type == RawItemKind::Number && item.item_size == 0 {
            spec.width = item.item_size as usize;
            spec.has_width = true;
            *item_index += 1;
        }
    }
}

fn format_annotated_item(
    result: &mut String,
    annotation: &str,
    spec: &FormatSpec,
    items: &[RawFirehoseItem<'_>],
    item_index: &mut usize,
) {
    // Skip precision items
    skip_precision_items(items, item_index);

    if *item_index >= items.len() {
        {
            #[cfg(feature = "rewrite-compat")]
            result.push_str("<Missing message data>");
            #[cfg(not(feature = "rewrite-compat"))]
            result.push_str("<decode: missing data>");
        }
        return;
    }

    let item = &items[*item_index];

    // Check for private
    if matches!(item.value, RawItemValue::Private { .. }) {
        result.push_str("<private>");
        *item_index += 1;
        return;
    }

    // Try apple decoder
    if let Some(decoded) = decode_annotation(annotation, item) {
        result.push_str(&decoded);
        *item_index += 1;
        return;
    }

    // Normal formatting
    apply_format(result, item, spec);

    // Signpost annotation
    if annotation.contains("signpost") {
        let signpost_meta = extract_signpost_metadata(annotation);
        result.push_str(" (");
        result.push_str(&signpost_meta);
        result.push(')');
    }

    *item_index += 1;
}

fn extract_signpost_metadata(annotation: &str) -> String {
    // Annotation format: "public,signpost.description:attribute" or "signpost.telemetry:number1,name=..."
    // Extract the signpost part
    let parts: Vec<&str> = annotation.split(',').collect();
    if annotation.starts_with("signpost") || annotation.starts_with("sign") {
        // signpost is the first element
        parts[0].trim().to_string()
    } else {
        // signpost is after a comma (e.g. "public,signpost.description:attr")
        for part in &parts[1..] {
            let trimmed = part.trim();
            if trimmed.contains("signpost") {
                return trimmed.to_string();
            }
        }
        // Fallback
        annotation.to_string()
    }
}

fn item_to_string(item: &RawFirehoseItem<'_>) -> String {
    match &item.value {
        RawItemValue::Str(s) => s.to_string(),
        RawItemValue::I64(n) => n.to_string(),
        RawItemValue::U64(n) => n.to_string(),
        RawItemValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        RawItemValue::Private { .. } => "<private>".to_string(),
        RawItemValue::Empty => String::new(),
        RawItemValue::Null => {
            #[cfg(feature = "rewrite-compat")]
            {
                String::from("(null)")
            }
            #[cfg(not(feature = "rewrite-compat"))]
            {
                String::new()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::chunks::firehose::item::{RawFirehoseItem, RawItemValue};
    use test_case::test_case;

    fn str_item(s: &str) -> RawFirehoseItem<'_> {
        RawFirehoseItem {
            item_type: RawItemKind::String,
            item_size: s.len() as u16,
            value: RawItemValue::Str(s),
        }
    }

    fn i64_item(n: i64) -> RawFirehoseItem<'static> {
        RawFirehoseItem {
            item_type: RawItemKind::Number,
            item_size: 8,
            value: RawItemValue::I64(n),
        }
    }

    fn u64_item(n: u64) -> RawFirehoseItem<'static> {
        RawFirehoseItem {
            item_type: RawItemKind::Number,
            item_size: 8,
            value: RawItemValue::U64(n),
        }
    }

    fn private_item() -> RawFirehoseItem<'static> {
        RawFirehoseItem {
            item_type: RawItemKind::PrivateNumber,
            item_size: 0,
            value: RawItemValue::Private {
                raw_item_type: 0x01,
            },
        }
    }

    fn precision_item() -> RawFirehoseItem<'static> {
        RawFirehoseItem {
            item_type: RawItemKind::Precision,
            item_size: 4,
            value: RawItemValue::Empty,
        }
    }

    // --- Integer/hex/octal/char/error: single i64 item ---

    #[test_case("count: %d", 42  => "count: 42" ; "integer")]
    #[test_case("%x", 255        => "FF" ; "hex uppercase")]
    #[test_case("%#x", 255       => "0xFF" ; "hex alternate")]
    #[test_case("%04d", 2        => "0002" ; "zero pad width")]
    #[test_case("%+d", 42        => "+42" ; "plus sign")]
    #[test_case("%c", 65         => "A" ; "char")]
    #[test_case("err: %m", 2     => "err: No such file or directory" ; "error code")]
    #[test_case("%+04d", 2       => "+002" ; "plus zero pad width")]
    #[test_case("%d", -248       => "-248" ; "negative int")]
    #[test_case("%x", 10         => "A" ; "hex lowercase spec uppercase output")]
    #[test_case("%#4x", 2        => " 0x2" ; "hex hashtag width")]
    #[test_case("%#04o", 100     => "0o144" ; "octal hashtag zero pad")]
    #[test_case("%lld", 42       => "42" ; "length modifier ignored")]
    fn test_format_int(fmt: &str, n: i64) -> String {
        format_message(Some(fmt), &[i64_item(n)])
    }

    #[test]
    fn octal() {
        let result = format_message(Some("%o"), &[i64_item(493)]);
        assert_eq!(result, "755");
    }

    #[test]
    fn octal_zero_pad() {
        let result = format_message(Some("%07o"), &[i64_item(100)]);
        assert_eq!(result, "0000144");
    }

    // --- Float: single i64 item (bits), literal expected ---

    #[test_case("%f", 4_614_253_070_214_989_087      => "3.14" ; "basic float")]
    #[test_case("%.2f", 4_614_253_070_214_989_087    => "3.14" ; "float precision")]
    #[test_case("%f", -4_611_686_018_427_387_904     => "-2" ; "negative float")]
    #[test_case("%+09.4f", 4_570_111_009_880_014_848 => "+000.0035" ; "plus zero pad")]
    #[test_case("%9.4f", 4_570_111_009_880_014_848   => "   0.0035" ; "space pad")]
    #[test_case("%-8.4f", 4_570_111_009_880_014_848  => "0.0035  " ; "left justify")]
    fn test_format_float(fmt: &str, bits: i64) -> String {
        format_message(Some(fmt), &[i64_item(bits)])
    }

    // --- Float: expected computed from bits (Rust default display) ---

    #[test_case("%f", 4_614_286_721_111_404_799  ; "no precision natural")]
    #[test_case("%f", -4_484_628_366_119_329_180 ; "negative float natural")]
    fn test_format_float_natural(fmt: &str, bits: i64) {
        let expected = format!("{}", f64::from_bits(bits as u64));
        let result = format_message(Some(fmt), &[i64_item(bits)]);
        assert_eq!(result, expected);
    }

    // --- String: single str item ---

    #[test_case("%s start", "hello" => "hello start" ; "basic string")]
    #[test_case("%-10s|", "hi"     => "hi        |" ; "left justify")]
    #[test_case("%.3s", "hello"    => "hel" ; "string precision")]
    #[test_case("%{public}s", "hi" => "hi" ; "apple public")]
    #[test_case("value: %@", "objc_value" => "value: objc_value" ; "at sign")]
    #[test_case(
    "opendirectoryd (build %{public}s) launched...", "796.100"
    => "opendirectoryd (build 796.100) launched..." ; "legacy public substitution"
  )]
    fn test_format_str(fmt: &str, s: &str) -> String {
        format_message(Some(fmt), &[str_item(s)])
    }

    // --- No-items tests ---

    #[test_case(Some("100%% done")  => "100% done" ; "literal percent")]
    #[test_case(Some("")            => "" ; "empty both")]
    #[test_case(None                => "<missing format string>" ; "none format")]
    #[test_case(Some("hello world") => "hello world" ; "no specifiers")]
    #[test_case(Some("end%")        => "end%" ; "percent at end")]
    #[test_case(Some("%{public}")   => "%{public}" ; "typeless annotation")]
    fn test_format_no_items(fmt: Option<&str>) -> String {
        format_message(fmt, &[])
    }

    // --- Edge cases (multi-item, special item types) ---

    #[test]
    fn test_private_item() {
        let result = format_message(Some("%{public}s"), &[private_item()]);
        assert_eq!(result, "<private>");
    }

    #[test]
    fn test_missing_items() {
        let result = format_message(Some("%s %s"), &[str_item("hello")]);
        #[cfg(feature = "rewrite-compat")]
        assert_eq!(result, "hello <Missing message data>");
        #[cfg(not(feature = "rewrite-compat"))]
        assert_eq!(result, "hello <decode: missing data>");
    }

    #[test]
    fn test_multiple_specs() {
        let items = [str_item("x"), i64_item(5)];
        let result = format_message(Some("%s=%d"), &items);
        assert_eq!(result, "x=5");
    }

    #[test]
    fn test_signpost_annotation() {
        let result = format_message(
            Some("%{public,signpost.description:attr}d"),
            &[i64_item(42)],
        );
        assert_eq!(result, "42 (signpost.description:attr)");
    }

    #[test]
    fn test_empty_format_with_items() {
        let result = format_message(Some(""), &[str_item("val")]);
        assert_eq!(result, "val");
    }

    #[test]
    fn test_precision_item_skip() {
        let items = [precision_item(), i64_item(42)];
        let result = format_message(Some("%d"), &items);
        assert_eq!(result, "42");
    }

    #[test]
    fn test_u64_as_int() {
        let result = format_message(Some("%d"), &[u64_item(200)]);
        assert_eq!(result, "200");
    }

    #[test]
    fn test_multiple_mixed() {
        let items = [
            str_item("DCPAVSimpleVideoInterface"),
            str_item("setColorElement"),
            i64_item(89),
        ];
        let result = format_message(Some("%s::%s width = %u"), &items);
        assert_eq!(
            result,
            "DCPAVSimpleVideoInterface::setColorElement width = 89"
        );
    }
}
