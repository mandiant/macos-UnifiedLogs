use super::*;
use std::str::Utf8Error;

/// Error returned by all rewrite-module parsers.
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error(
        "Unexpected EOF, tried to read at offset {offset:#x}: need {needed:?} bytes, only {available:?} in {context:?}"
    )]
    UnexpectedEof {
        offset: Offset,
        needed: Option<usize>,
        available: Option<usize>,
        context: Option<&'static str>,
    },
    #[error("Unknown chunk tag {tag:#06x} at offset {offset:#x} in {context:?}")]
    UnknownChunkTag {
        offset: Offset,
        tag: u32,
        context: Option<&'static str>,
    },
    #[error("Invalid UTF-8 at offset {offset:#x} in {context:?}: {source}")]
    InvalidUtf8 {
        offset: Offset,
        source: Utf8Error,
        context: Option<&'static str>,
    },
    #[error("LZ4 decompression failed at offset {offset:#x}: {message}")]
    DecompressError {
        offset: Offset,
        message: String,
        context: Option<&'static str>,
    },
    #[error("Nom error parsing {input:?}, code: {code:?}")]
    NomError {
        input: Vec<u8>,
        code: nom::error::ErrorKind,
    },
}

pub trait NomExt {
    fn to_parse_error(self) -> ParseError;
}

impl NomExt for nom::Err<nom::error::Error<&[u8]>> {
    fn to_parse_error(self) -> ParseError {
        match self {
            nom::Err::Incomplete(needed) => ParseError::UnexpectedEof {
                offset: 0,
                needed: match needed {
                    nom::Needed::Unknown => None,
                    nom::Needed::Size(n) => Some(n.into()),
                },
                available: None,
                context: None,
            },
            nom::Err::Error(e) | nom::Err::Failure(e) => ParseError::NomError {
                input: e.input.to_vec(),
                code: e.code,
            },
        }
    }
}

impl ParseError {
    pub fn unexpected_eof(
        offset: Offset,
        needed: usize,
        available: usize,
        context: Option<&'static str>,
    ) -> Self {
        Self::UnexpectedEof {
            offset,
            needed: Some(needed),
            available: Some(available),
            context,
        }
    }
    pub fn unknown_chunk_tag(offset: Offset, tag: u32, context: Option<&'static str>) -> Self {
        Self::UnknownChunkTag {
            offset,
            tag,
            context,
        }
    }
    pub fn invalid_utf8(offset: Offset, source: Utf8Error, context: Option<&'static str>) -> Self {
        Self::InvalidUtf8 {
            offset,
            source,
            context,
        }
    }
    pub fn decompress_error(
        offset: Offset,
        message: String,
        context: Option<&'static str>,
    ) -> Self {
        Self::DecompressError {
            offset,
            message,
            context,
        }
    }
}

impl ParseError {
    pub fn offset(&self) -> Option<Offset> {
        match self {
            Self::UnexpectedEof { offset, .. }
            | Self::UnknownChunkTag { offset, .. }
            | Self::InvalidUtf8 { offset, .. }
            | Self::DecompressError { offset, .. } => Some(*offset),
            Self::NomError { .. } => None,
        }
    }
}
