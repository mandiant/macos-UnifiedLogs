// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

mod bool;
mod darwin;
pub(crate) mod decoder;
mod dns;
pub(crate) mod location;
mod network;
mod opendirectory;
mod time;
mod uuid;

pub enum DecoderError<'a> {
    Parse {
        input: &'a [u8],
        parser_name: &'a str,
        message: &'a str,
    },
}

impl<'a> std::error::Error for DecoderError<'a> {}

impl<'a> std::fmt::Display for DecoderError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { message, .. } => write!(f, "{message}"),
        }
    }
}

impl<'a> std::fmt::Debug for DecoderError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse {
                parser_name,
                message,
                input,
            } => write!(
                f,
                "Failed at {parser_name} parser, data {input:?}: {message}"
            ),
        }
    }
}
