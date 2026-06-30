// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use macos_unifiedlogs::chunk::{Chunk, ChunksReader};
use std::path::PathBuf;

#[test]
fn test_parse_log_big_sur() {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");
    test_path.push("Persist/0000000000000004.tracev3");

    let data = std::fs::read(&test_path).unwrap();

    let mut firehose = Vec::new();
    let mut simpledump = Vec::new();
    let mut headers_count = 0;
    let mut catalog_process_info_entries = Vec::new();
    let mut statedump = Vec::new();
    let mut chunks_count = 0;

    let mut reader = ChunksReader::new(&data);
    reader
        .visit(|chunk| {
            match chunk {
                Chunk::Header(_) => headers_count += 1,
                Chunk::Catalog(catalog) => {
                    firehose.push(0);
                    simpledump.push(0);
                    catalog_process_info_entries.push(catalog.catalog_process_info_entries.len());
                    statedump.push(0);
                }
                Chunk::Firehose(_) => {
                    *firehose.last_mut().unwrap() += 1;
                }
                Chunk::Simpledump(_) => {
                    *simpledump.last_mut().unwrap() += 1;
                }
                Chunk::Statedump(_) => {
                    *statedump.last_mut().unwrap() += 1;
                }
                _ => {}
            };
            chunks_count += 1;
        })
        .unwrap();

    assert_eq!(chunks_count, 3446);
    assert_eq!(firehose[0], 82);
    assert_eq!(simpledump[0], 0);
    assert_eq!(headers_count, 1);
    assert_eq!(catalog_process_info_entries[0], 45);
    assert_eq!(statedump[0], 0);
}
