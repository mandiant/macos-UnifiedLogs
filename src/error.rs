// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use nom::error::{ErrorKind, ParseError};
use std::fmt;

pub struct FirehoseError {
    message: String,
}

#[derive(Debug)]
pub struct CatalogProcessUUIDEntryError {
    pub(crate) message: String,
}

#[derive(Debug)]
pub struct FirehoseFormatterError {
    pub(crate) message: String,
}

impl ParseError<&[u8]> for FirehoseError {
    fn from_error_kind(input: &[u8], kind: ErrorKind) -> Self {
        let message = format!("Failed to parse firehose data: {:?}: {:?}", kind, input);
        FirehoseError { message }
    }

    fn append(input: &[u8], kind: ErrorKind, other: Self) -> Self {
        let message = format!(
            "Failed to parse firehose data: {} {:?}: {:?}",
            other.message, kind, input
        );
        FirehoseError { message }
    }
}

impl ParseError<&[u8]> for CatalogProcessUUIDEntryError {
    fn from_error_kind(input: &[u8], kind: ErrorKind) -> Self {
        let message = format!(
            "Failed to parse Catalog Process UUID Entry metadata: {:?}: {:?}",
            kind, input
        );
        CatalogProcessUUIDEntryError { message }
    }

    fn append(input: &[u8], kind: ErrorKind, other: Self) -> Self {
        let message = format!(
            "Failed to parse Catalog Process UUID Entry metadata: {} {:?}: {:?}",
            other.message, kind, input
        );
        CatalogProcessUUIDEntryError { message }
    }
}

impl ParseError<&[u8]> for FirehoseFormatterError {
    fn from_error_kind(input: &[u8], kind: ErrorKind) -> Self {
        let message = format!("Unknown firehose formatter flag: {:?}: {:?}", kind, input);
        FirehoseFormatterError { message }
    }

    fn append(input: &[u8], kind: ErrorKind, other: Self) -> Self {
        let message = format!(
            "Unknown firehose formatter flag: {} {:?}: {:?}",
            other.message, kind, input
        );
        FirehoseFormatterError { message }
    }
}

#[derive(Debug)]
pub enum ParserError {
    Path,
    Dir,
    Tracev3Parse,
    Read,
    Timesync,
    Dsc,
    UUIDText,
}

impl std::error::Error for ParserError {}

impl fmt::Display for ParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path => write!(f, "Failed to open file path"),
            Self::Dir => write!(f, "Failed to open directory path"),
            Self::Tracev3Parse => write!(f, "Failed to parse tracev3 file"),
            Self::Read => write!(f, "Failed to read file"),
            Self::Timesync => write!(f, "Failed to parse timesync file"),
            Self::Dsc => write!(f, "Failed to parse dsc file"),
            Self::UUIDText => write!(f, "Failedto parse UUIDtext file"),
        }
    }
}
