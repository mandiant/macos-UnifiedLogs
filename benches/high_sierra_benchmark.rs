// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use criterion::{Criterion, criterion_group, criterion_main};
use macos_unifiedlogs::{
    cache::{StringCatalog, StringStorage},
    filesystem::LogarchiveProvider,
    logarchive::load_timesync_data,
    timesync::TimestampResolver,
    tracev3::{OversizeCache, visit_tracev3},
    traits::FileProvider,
};
use std::{path::PathBuf, rc::Rc};

fn visit_file(
    data: &[u8],
    resolver: &TimestampResolver,
    strings: &StringCatalog<'_, impl FileProvider>,
    evidence: &Rc<PathBuf>,
    format_messages: bool,
) {
    let oversize_cache = OversizeCache::new();
    let _ = visit_tracev3(
        data,
        resolver,
        strings,
        &oversize_cache,
        Rc::clone(evidence),
        |entry| {
            if format_messages {
                let _ = entry.message();
            }
        },
    )
    .unwrap();
}

fn high_sierra_benchmark(c: &mut Criterion) {
    let mut archive = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    archive.push("tests/test_data/system_logs_high_sierra.logarchive");
    let provider = LogarchiveProvider::new(&archive);
    let resolver = TimestampResolver::new(load_timesync_data(&provider).unwrap());
    let storage = StringStorage::new(&provider);
    let strings = StringCatalog::new(&storage);
    let file = archive.join("Persist/0000000000000002.tracev3");
    let data = std::fs::read(&file).unwrap();
    let evidence = Rc::new(file);

    c.bench_function("Visit One High Sierra Log (resolve only)", |b| {
        b.iter(|| visit_file(&data, &resolver, &strings, &evidence, false));
    });
    c.bench_function("Visit One High Sierra Log (format messages)", |b| {
        b.iter(|| visit_file(&data, &resolver, &strings, &evidence, true));
    });
}

criterion_group!(benches, high_sierra_benchmark);
criterion_main!(benches);
