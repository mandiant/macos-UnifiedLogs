/// Heavily influenced by <https://github.com/fox-it/dissect.util/blob/main/dissect/util/compression/lzbitmap.py> -- Apache license
use log::{error, warn};
use nom::{
    bytes::complete::take,
    error::{Error, ErrorKind},
    number::complete::{le_u8, le_u16, le_u24},
};
use std::iter::Peekable;

/// Decompress lzbitmap data. Seen in Unified Logs starting in Golden Gate
pub(crate) fn lzbitmap_decompress(data: &[u8]) -> nom::IResult<&[u8], Vec<u8>> {
    let (input, signature) = le_u24(data)?;
    // ZBM
    let magic_signature = 5063258;
    if signature != magic_signature {
        error!("[macos-unifiedlogs] Unexpected signature for LZBITMAP {signature}. Wanted ZBM");
        return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
    }

    let (mut input, flags) = le_u8(input)?;

    if !check_flags(flags) {
        return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
    }

    let flag_large = 1;
    let flag_no_run_length = 4;
    let max_chunk = if flags & flag_large != 0 {
        0x8000
    } else {
        0x4000
    };

    let run_length_encoded_tokens = flags & flag_no_run_length == 0;
    let bitmaps_count = if run_length_encoded_tokens { 12 } else { 13 };
    let mut decom_buf = Vec::new();

    let chunk_header_size = 6;
    while !input.is_empty() {
        let (remaining, compress_size) = le_u24(input)?;
        let (remaining, mut decom_size) = le_u24(remaining)?;

        if compress_size > decom_size + chunk_header_size {
            error!(
                "[macos-unifiedlogs] Bad LZBITMAP chunk size: {compress_size} vs {}",
                decom_size + chunk_header_size
            );
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        if decom_size == 0 {
            break;
        }

        if decom_size > max_chunk {
            error!(
                "[macos-unifiedlogs] Chunk decompressed size is larger ({decom_size}) than expected max chunk size: {max_chunk}"
            );
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        // Data is not compressed. We can just append to our decompressed data
        if compress_size == decom_size + chunk_header_size {
            let (remaining, decom_data) = take(decom_size)(remaining)?;
            decom_buf.extend_from_slice(decom_data);
            input = remaining;
            continue;
        }

        // We have compressed data we need to decompress now
        // Distance - Contains distance data needed determine how far back to look in the decompressed data
        // Bitmap - Contains bitmap bits used to determine how to read and decompress the data. Bit 1 - read compressed data, bit 0 - copy decompressed data
        // Token - Determines if distance or bitmap should be used
        let (remaining, mut distance_offset) = le_u24(remaining)?;
        let (remaining, mut bitmap_offset) = le_u24(remaining)?;
        let (_, token_offset) = le_u24(remaining)?;
        let mut current_offset = 15;

        // Compressed data includes the offsets we read above. We need to include it in the total compressed data
        let (remaining, compressed_data) = take(compress_size)(input)?;
        let bitmap_size = 17;
        if bitmap_size > compress_size {
            error!(
                "[macos-unifiedlogs] Bitmap size larger than compressed data size: {bitmap_size} vs {compress_size}"
            );
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }
        let (bits_data, _) = take(compress_size - bitmap_size)(compressed_data)?;

        let mut token_map = vec![(0u8, 0u8), (0, 1), (0, 2)];

        for i in 0..bitmaps_count {
            let bit = i * 10;
            let (_, bytes) = le_u16(&bits_data[bit / 8..])?;
            let value = bytes >> (bit % 8);
            token_map.push(((value & 0xff) as u8, ((value >> 8) & 3) as u8));
        }

        if distance_offset < 15
            || distance_offset > bitmap_offset
            || bitmap_offset > token_offset
            || token_offset > compress_size - bitmap_size
        {
            error!(
                "[macos-unifiedlogs] Token offset {token_offset} larger than compressed data: {compress_size} bytes"
            );
            return Err(nom::Err::Failure(Error::new(input, ErrorKind::LengthValue)));
        }

        let token_bytes =
            &compressed_data[token_offset as usize..compressed_data.len() - bitmap_size as usize];
        let mut tokens = get_tokens(token_bytes).peekable();
        let mut distance = 8;

        while decom_size > 0 {
            let index = tokens
                .next()
                .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;

            let repeat_token = if run_length_encoded_tokens {
                if index == 0xf {
                    return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
                }

                match get_repeat_token(&mut tokens, decom_size as usize) {
                    Some(value) => value,
                    None => return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify))),
                }
            } else {
                1
            };

            for _ in 0..repeat_token {
                let (mut bitmap, distance_bytes) = token_map
                    .get(index as usize)
                    .copied()
                    .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;

                // Indexes less than 3 use bitmap from bitmap bytes
                if index < 3 {
                    bitmap = *compressed_data
                        .get(bitmap_offset as usize)
                        .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;
                    bitmap_offset += 1;
                }

                match distance_bytes {
                    0 => {}
                    1 => {
                        distance = usize::from(
                            *compressed_data
                                .get(distance_offset as usize)
                                .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?,
                        );
                        distance_offset += 1;
                    }
                    2 => {
                        let bytes = compressed_data
                            .get(distance_offset as usize..distance_offset as usize + 2)
                            .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;

                        let (_, value) = le_u16(bytes)?;
                        distance = value as usize;
                        distance_offset += 2;
                    }
                    _ => return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify))),
                }

                for _ in 0..8 {
                    if bitmap & 1 != 0 {
                        let value = *compressed_data
                            .get(current_offset as usize)
                            .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;
                        decom_buf.push(value);
                        current_offset += 1;
                    } else {
                        if distance == 0 {
                            error!(
                                "[macos-unifiedlogs] Got distance 0 for checked_sub on decompressed data"
                            );
                            return Err(nom::Err::Failure(Error::new(input, ErrorKind::Verify)));
                        }
                        let source_offset = decom_buf
                            .len()
                            .checked_sub(distance)
                            .ok_or(nom::Err::Failure(Error::new(input, ErrorKind::Verify)))?;
                        let value = decom_buf[source_offset];
                        decom_buf.push(value);
                    }

                    bitmap >>= 1;
                    decom_size -= 1;

                    if decom_size == 0 {
                        break;
                    }
                }

                if decom_size == 0 {
                    break;
                }
            }
        }

        input = remaining;
    }

    Ok((input, decom_buf))
}

/// Get token region associated with lzbitmap
fn get_tokens(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    data.iter().flat_map(|b| [b & 0xf, b >> 4])
}

/// Determine if the bitmap token should be used again
fn get_repeat_token<I>(tokens: &mut Peekable<I>, remaining: usize) -> Option<u32>
where
    I: Iterator<Item = u8>,
{
    if remaining <= 8 {
        return Some(1);
    }
    match tokens.peek() {
        None => None,
        Some(&value) if value != 0xf => Some(1),
        Some(_) => {
            tokens.next()?;
            let mut total = 4;
            let mut value = 0xf;
            while value == 0xf {
                value = tokens.next()?;

                total += u32::from(value);
            }

            Some(total)
        }
    }
}

/// Check if we get unknown flags
fn check_flags(flag: u8) -> bool {
    match flag {
        0x9 | 0xc => true,
        // These flags could exist but so far have not been seen in wild
        0x8 | 0xd => {
            warn!("[macos-unifiedlogs] Got possible flag {flag}");
            true
        }
        _ => {
            error!("[macos-unifiedlogs] Got unsupported flag {flag}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lzbitmap::lzbitmap_decompress;
    use std::{fs, path::PathBuf};

    // #[test]
    fn test_decompress_lzbitmap() {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push("tests/test_data/lzbitmap/lzbitmap_zbm.raw");

        let buffer = fs::read(test_path).unwrap();

        let (_, results) = lzbitmap_decompress(&buffer).unwrap();
        assert!(results.starts_with(&[1, 96, 0, 0, 0, 0, 0, 0, 6, 16, 0, 0, 0, 0, 0, 0, 80, 2, 0]));
        assert_eq!(results.len(), 65424);
    }
}
