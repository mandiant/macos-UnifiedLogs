# How to build
1. Download and install Rust from https://www.rust-lang.org/
   * Windows users will need Windows C++ build tools https://visualstudio.microsoft.com/visual-cpp-build-tools/
     * Select `Desktop development with C++`
     * This is a Rust requirement for Windows
2. Git clone the repo
3. Navigate to cloned repo.
4. Execute `cargo build` to build debug library. `cargo build --release` to build release version
   * Navigate to examples directory and run `cargo build --release` to build the example files
   * `unifiedlog_parser` and `unifiedlog_parser_json` can parse a live macOS system if no arguements are presented. Both can also parse a `logarchive` if passed as an arguement

# Running test suite
1. Follow steps above
2. Download `test_data.zip` from Github releases
3. Copy/move `test_data.zip` to clone repo `tests` directory
4. Decompress `test_data.zip`
5. Execute `cargo test --release` to run tests
   * You can also just use `cargo test` to run tests but it will be slower


# Running benchmarks
1. Download `test_data.zip` from Github releases
2. Copy/move `test_data.zip` to clone repo `tests` directory
3. Decompress `test_data.zip`
4. Run `cargo bench`  
or  
4. Install criterion, `cargo install cargo-criterion`
5. Run `cargo criterion`

