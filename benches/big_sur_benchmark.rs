// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use criterion::{Criterion, criterion_group, criterion_main};
use macos_unifiedlogs::{
    filesystem::LogarchiveProvider,
    parser::{build_log, collect_timesync, parse_log},
    timesync::TimesyncBoot,
    traits::FileProvider,
    unified_log::UnifiedLogData,
};
use std::{collections::HashMap, fs::File, path::PathBuf};

fn big_sur_parse_log(path: &str) {
    let handle = File::open(PathBuf::from(path).as_path()).unwrap();
    let _ = parse_log(handle).unwrap();
}

fn bench_build_log(
    log_data: &UnifiedLogData,
    provider: &mut dyn FileProvider,
    timesync_data: &HashMap<String, TimesyncBoot>,
    exclude_missing: bool,
) {
    let (_, _) = build_log(log_data, provider, timesync_data, exclude_missing);
}

fn big_sur_single_log_benchpress(c: &mut Criterion) {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path
        .push("tests/test_data/system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");

    c.bench_function("Benching Parsing One Big Sur Log", |b| {
        b.iter(|| big_sur_parse_log(&test_path.display().to_string()))
    });
}

fn big_sur_build_log_benchbress(c: &mut Criterion) {
    let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    test_path.push("tests/test_data/system_logs_big_sur.logarchive");

    let mut provider = LogarchiveProvider::new(test_path.as_path());
    let timesync_data = collect_timesync(&provider).unwrap();

    test_path.push("Persist/0000000000000004.tracev3");
    let exclude_missing = false;
    let handle = File::open(test_path.as_path()).unwrap();

    let log_data = parse_log(handle).unwrap();

    c.bench_function("Benching Building One Big Sur Log", |b| {
        b.iter(|| bench_build_log(&log_data, &mut provider, &timesync_data, exclude_missing))
    });
}

criterion_group!(
    benches,
    big_sur_single_log_benchpress,
    big_sur_build_log_benchbress
);
criterion_main!(benches);
